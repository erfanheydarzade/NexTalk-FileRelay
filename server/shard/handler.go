// Package shard — binary HTTP handlers over a storage.Store.
//
// Routes (all POST except hello which allows GET):
//
//	POST /fr/v1/hello      Hello -> Hello
//	POST /fr/v1/send       SendMessage(57) -> SendMessageResponse(58)
//	POST /fr/v1/receive    ReceiveMessages(59) -> ReceiveMessagesResponse(60)
//	POST /fr/v1/ack        MessageAck(61) -> MessageAckResponse(62)
//	POST /fr/v1/xfer/create TransferCreate(63) -> TransferCreateResponse(64)
//	POST /fr/v1/xfer/put    ChunkUpload(65) -> ChunkAck(66)
//	POST /fr/v1/xfer/get    ChunkDownload(67) -> ChunkDownloadResponse(68)
//	POST /fr/v1/xfer/resume ResumeRequest(69) -> ResumeResponse(70)
//	POST /fr/v1/xfer/complete TransferComplete(71) -> TransferCompleteResponse(72)
//	POST /fr/v1/xfer/cancel TransferCancel(73) -> Error-free ack (schema 51 with code 0 is
//	                             never sent; cancel returns Hello-shaped empty? No:
//	                             cancel returns MessageAckResponse-shaped (acked=1).
//	                             To keep the contract explicit we return schema 62
//	                             with acked=1, remaining=0.)
//
// Bodies are raw NanoPack (no WrapPacket). Errors are schema 51 with mapped
// HTTP status. Auth: sender Ed25519 on send/create/complete, read_secret on
// receive/ack/get/resume/cancel.
//
// NOTE on ChunkUpload auth: schema 65 carries no sender signature fields
// (frozen for v1 wire compat with existing vectors). Upload authorization is
// the unguessable 16B transfer_id minted at create (capability-style),
// plus per-transfer + per-IP rate limits and hash/offset/size checks.
// Per-chunk signatures are planned as additive fields 6..9 in a minor bump;
// Complete (schema 71) is sender-signed and seals the transfer.
package shard

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/storage"
)

// Limits for the in-handler fixed-window rate limiter (per 60s).
type RateLimits struct {
	SendsPerSender int
	SendsPerTarget int
	SendsPerIP     int
	ReceivesPerIP  int
	PutsPerXfer    int
	PutsPerIP      int
}

// DefaultRateLimits are production-minded but test-friendly (high).
func DefaultRateLimits() RateLimits {
	return RateLimits{
		SendsPerSender: 600,
		SendsPerTarget: 600,
		SendsPerIP:     1200,
		ReceivesPerIP:  1200,
		PutsPerXfer:    2000,
		PutsPerIP:      4000,
	}
}

type window struct {
	count   int
	resetAt int64
}

type limiter struct {
	mu      sync.Mutex
	buckets map[string]*window
}

func newLimiter() *limiter { return &limiter{buckets: map[string]*window{}} }

// allow returns true if the request may proceed.
func (l *limiter) allow(key string, now int64, max int) bool {
	if max <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.buckets[key]
	if !ok || now >= w.resetAt {
		l.buckets[key] = &window{count: 1, resetAt: now + 60_000}
		return true
	}
	if w.count >= max {
		return false
	}
	w.count++
	return true
}

// Handler serves the shard binary protocol.
type Handler struct {
	store   storage.Store
	now     func() int64
	limits  RateLimits
	limiter *limiter
	mux     *http.ServeMux
}

// NewHandler builds a Handler. now may be nil (wall clock).
func NewHandler(store storage.Store, now func() int64, limits RateLimits) *Handler {
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	h := &Handler{store: store, now: now, limits: limits, limiter: newLimiter(), mux: http.NewServeMux()}
	h.mux.HandleFunc(protocol.RouteHello, h.handleHello)
	h.mux.HandleFunc(protocol.RouteSend, h.handleSend)
	h.mux.HandleFunc(protocol.RouteReceive, h.handleReceive)
	h.mux.HandleFunc(protocol.RouteAck, h.handleAck)
	h.mux.HandleFunc(protocol.RouteTransferCreate, h.handleCreate)
	h.mux.HandleFunc(protocol.RouteChunkPut, h.handlePut)
	h.mux.HandleFunc(protocol.RouteChunkGet, h.handleGet)
	h.mux.HandleFunc(protocol.RouteResume, h.handleResume)
	h.mux.HandleFunc(protocol.RouteComplete, h.handleComplete)
	h.mux.HandleFunc(protocol.RouteCancel, h.handleCancel)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// --- helpers ---

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func httpStatusFor(code uint32) int {
	switch code {
	case protocol.ErrInvalidRequest, protocol.ErrChunkInvalid, protocol.ErrHashMismatch,
		protocol.ErrExpiredRequest, protocol.ErrBatchTooLarge:
		return http.StatusBadRequest
	case protocol.ErrAuthFailed:
		return http.StatusUnauthorized
	case protocol.ErrReplayDetected, protocol.ErrChunkConflict, protocol.ErrTransferConflict:
		return http.StatusConflict
	case protocol.ErrMailboxNotFound, protocol.ErrTransferNotFound:
		return http.StatusNotFound
	case protocol.ErrMailboxExpired, protocol.ErrTransferExpired:
		return http.StatusGone
	case protocol.ErrMessageTooLarge, protocol.ErrPayloadTooLarge, protocol.ErrChunkOutOfRange:
		return http.StatusRequestEntityTooLarge
	case protocol.ErrQuotaExceeded, protocol.ErrRateLimited:
		return http.StatusTooManyRequests
	case protocol.ErrStorageUnavailable, protocol.ErrServerUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

func writeProto(w http.ResponseWriter, schemaID byte, body []byte) {
	w.Header().Set("Content-Type", protocol.ContentType)
	w.Header().Set("X-FileRelay-Schema", itoa(int(schemaID)))
	w.Header().Set("X-FileRelay-Protocol", protocolVersionHeader())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, pe *protocol.ProtocolError) {
	body, err := protocol.MarshalError(pe)
	if err != nil {
		body = []byte{}
	}
	w.Header().Set("Content-Type", protocol.ContentType)
	w.Header().Set("X-FileRelay-Schema", "51")
	w.Header().Set("X-FileRelay-Protocol", protocolVersionHeader())
	w.Header().Set("Cache-Control", "no-store")
	if pe.Code == protocol.ErrRateLimited && pe.RetryAfter == 0 {
		pe.RetryAfter = 60
		body, _ = protocol.MarshalError(pe)
	}
	w.WriteHeader(httpStatusFor(pe.Code))
	_, _ = w.Write(body)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func readBody(r *http.Request, limit int) ([]byte, *protocol.ProtocolError) {
	if r.ContentLength > int64(limit) {
		return nil, &protocol.ProtocolError{Code: protocol.ErrPayloadTooLarge, Detail: "body exceeds limit"}
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return nil, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "unreadable body"}
	}
	if len(b) > limit {
		return nil, &protocol.ProtocolError{Code: protocol.ErrPayloadTooLarge, Detail: "body exceeds limit"}
	}
	if len(b) == 0 {
		return nil, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "empty body"}
	}
	return b, nil
}

func replayKey(domain []byte, pub, nonce []byte) [32]byte {
	h := sha256.New()
	h.Write(domain)
	h.Write(pub)
	h.Write(nonce)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

var replayDomainMsg = []byte("FR1/replay-msg\x00")
var replayDomainCreate = []byte("FR1/replay-create\x00")
var replayDomainComplete = []byte("FR1/replay-complete\x00")

func to32(b []byte) ([32]byte, bool) {
	if len(b) != 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], b)
	return out, true
}

func to16(b []byte) ([16]byte, bool) {
	if len(b) != 16 {
		return [16]byte{}, false
	}
	var out [16]byte
	copy(out[:], b)
	return out, true
}

// protocolVersionHeader tracks protocol.ProtocolMajor/Minor.
func protocolVersionHeader() string {
	return string(rune('0'+protocol.ProtocolMajor)) + "." + string(rune('0'+protocol.ProtocolMinor))
}

// --- hello ---

func (h *Handler) handleHello(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	if r.Method == http.MethodGet {
		body, _ := protocol.MarshalHello(&protocol.Hello{Major: protocol.ProtocolMajor, Minor: protocol.ProtocolMinor, NowMS: uint64(h.now())})
		writeProto(w, protocol.SchemaHello, body)
		return
	}
	raw, pe := readBody(r, 64)
	if pe != nil {
		writeError(w, pe)
		return
	}
	hello, err := protocol.UnmarshalHello(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	_ = hello
	body, _ := protocol.MarshalHello(&protocol.Hello{Major: protocol.ProtocolMajor, Minor: protocol.ProtocolMinor, NowMS: uint64(h.now())})
	writeProto(w, protocol.SchemaHello, body)
}

// --- send ---

func (h *Handler) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	now := h.now()
	raw, pe := readBody(r, protocol.MaxRequestBytes)
	if pe != nil {
		writeError(w, pe)
		return
	}
	msg, err := protocol.UnmarshalSendMessage(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	pub, ok := to32(msg.SenderPub)
	if !ok {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "bad sender pub"})
		return
	}
	mid, ok := to16(msg.MailboxID)
	if !ok {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "bad mailbox"})
		return
	}
	nonce, ok := to16(msg.Nonce)
	if !ok {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "bad nonce"})
		return
	}
	if err := protocol.VerifyMsgSend(msg.SenderPub, mid, msg.Timestamp, nonce, msg.Envelope, msg.Signature, now); err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	if h.store.CheckAndMarkReplay(r.Context(), replayKey(replayDomainMsg, msg.SenderPub, msg.Nonce)) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrReplayDetected, Detail: "replay detected"})
		return
	}
	ip := clientIP(r)
	if !h.limiter.allow("send-sender:"+hex.EncodeToString(msg.SenderPub), now, h.limits.SendsPerSender) ||
		!h.limiter.allow("send-target:"+hex.EncodeToString(msg.MailboxID), now, h.limits.SendsPerTarget) ||
		!h.limiter.allow("send-ip:"+ip, now, h.limits.SendsPerIP) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrRateLimited, Detail: "rate limited", RetryAfter: 60})
		return
	}
	msgID, queued, err := h.store.SendMessage(r.Context(), msg)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	resp, err := protocol.MarshalSendMessageResponse(1, queued, msgID[:])
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	_ = pub
	writeProto(w, protocol.SchemaSendMessageResponse, resp)
}

// --- receive ---

func (h *Handler) handleReceive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	now := h.now()
	raw, pe := readBody(r, 256)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalReceiveMessages(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	if !h.limiter.allow("recv-ip:"+clientIP(r), now, h.limits.ReceivesPerIP) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrRateLimited, Detail: "rate limited", RetryAfter: 60})
		return
	}
	var mid [16]byte
	copy(mid[:], req.MailboxID)
	limit := int(req.Limit)
	if limit <= 0 {
		limit = protocol.MaxBatchMessages
	}
	msgs, consumed, err := h.store.ReceiveMessages(r.Context(), mid, req.ReadSecret, limit, req.Peek == 1)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	out := make([]protocol.ReceivedMessage, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, protocol.ReceivedMessage{MsgID: m.ID[:], Envelope: m.Envelope})
	}
	resp, err := protocol.MarshalReceiveMessagesResponse(out, consumed)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	writeProto(w, protocol.SchemaReceiveMessagesResponse, resp)
}

// --- ack ---

func (h *Handler) handleAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	raw, pe := readBody(r, protocol.MaxBatchMessages*16+256)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalMessageAck(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	var mid [16]byte
	copy(mid[:], req.MailboxID)
	acked, remaining, err := h.store.AckMessages(r.Context(), mid, req.ReadSecret, req.MsgIDs, req.Disposition)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	resp, err := protocol.MarshalMessageAckResponse(acked, remaining)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	writeProto(w, protocol.SchemaMessageAckResponse, resp)
}

// --- transfer create ---

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	now := h.now()
	raw, pe := readBody(r, protocol.MaxManifestBytes+512)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalTransferCreate(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	pub, ok := to32(req.SenderPub)
	if !ok {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "bad sender pub"})
		return
	}
	nonce, ok := to16(req.Nonce)
	if !ok {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "bad nonce"})
		return
	}
	var mid [16]byte
	if len(req.MailboxID) == 16 {
		copy(mid[:], req.MailboxID)
	}
	if err := protocol.VerifyXferCreate(req.SenderPub, mid, req.TotalSize, req.ChunkSize, req.ChunkCount, req.Timestamp, nonce, req.Manifest, req.Signature, now); err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	if h.store.CheckAndMarkReplay(r.Context(), replayKey(replayDomainCreate, req.SenderPub, req.Nonce)) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrReplayDetected, Detail: "replay detected"})
		return
	}
	if !h.limiter.allow("create-sender:"+hex.EncodeToString(req.SenderPub), now, h.limits.SendsPerSender) ||
		!h.limiter.allow("create-ip:"+clientIP(r), now, h.limits.SendsPerIP) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrRateLimited, Detail: "rate limited", RetryAfter: 60})
		return
	}
	tid, ticket, exp, err := h.store.CreateTransfer(r.Context(), req)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	resp, err := protocol.MarshalTransferCreateResponse(&protocol.TransferCreateResponse{TransferID: tid[:], ExpiresAt: exp, ChunkSize: req.ChunkSize, DownloadSecret: ticket})
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	_ = pub
	writeProto(w, protocol.SchemaTransferCreateResponse, resp)
}

// --- chunk put ---

func (h *Handler) handlePut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	now := h.now()
	raw, pe := readBody(r, protocol.MaxChunkBytes+2048)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalChunkUpload(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	var tid [16]byte
	copy(tid[:], req.TransferID)
	if !h.limiter.allow("put-xfer:"+hex.EncodeToString(req.TransferID), now, h.limits.PutsPerXfer) ||
		!h.limiter.allow("put-ip:"+clientIP(r), now, h.limits.PutsPerIP) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrRateLimited, Detail: "rate limited", RetryAfter: 60})
		return
	}
	if _, err := h.store.PutChunk(r.Context(), req); err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	// Ack from capability-scoped progress truth (no read_secret: the
	// uploader holds transfer_id, the recipient uses Resume instead).
	rv, _, err := h.store.Progress(r.Context(), tid)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	_ = subtle.ConstantTimeCompare([]byte{1}, []byte{1})
	resp, err := protocol.MarshalChunkAck(&protocol.ChunkAck{
		TransferID:        tid[:],
		HighestContiguous: rv.HighestContiguous,
		MissingRanges:     rv.MissingRanges,
		Bitmap:            rv.Bitmap,
		Encoding:          rv.Encoding,
	})
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	writeProto(w, protocol.SchemaChunkAck, resp)
}

// --- chunk get ---

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	raw, pe := readBody(r, 256)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalChunkDownload(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	var tid, mid [16]byte
	copy(tid[:], req.TransferID)
	copy(mid[:], req.MailboxID)
	// Single-chunk fetch in v1 (count must be 1 for get; ranges use repeated calls).
	if req.Count != 1 {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "count must be 1 in v1"})
		return
	}
	var payload, hash []byte
	if req.TicketMode() {
		// Ticket path: download-only bearer minted at create. No mailbox
		// lookup, no owner-TTL slide; the ticket dies with the transfer.
		payload, hash, err = h.store.GetChunkByTicket(r.Context(), tid, req.Ticket, req.Index)
	} else {
		payload, hash, err = h.store.GetChunk(r.Context(), tid, mid, req.ReadSecret, req.Index)
	}
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	resp, err := protocol.MarshalChunkDownloadResponse(&protocol.ChunkDownloadResponse{TransferID: tid[:], Index: req.Index, Payload: payload, ChunkHash: hash})
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	writeProto(w, protocol.SchemaChunkDownloadResponse, resp)
}

// --- resume ---

func (h *Handler) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	raw, pe := readBody(r, 256)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalResumeRequest(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	var tid, mid [16]byte
	copy(tid[:], req.TransferID)
	copy(mid[:], req.MailboxID)
	var rv *storage.ResumeView
	var tv *storage.TransferView
	if req.TicketMode() {
		rv, tv, err = h.store.ResumeByTicket(r.Context(), tid, req.Ticket)
	} else {
		rv, tv, err = h.store.Resume(r.Context(), tid, mid, req.ReadSecret)
	}
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	resp, err := protocol.MarshalResumeResponse(&protocol.ResumeResponse{
		TransferID: tid[:], ChunkCount: rv.ChunkCount, HighestContiguous: rv.HighestContiguous,
		Encoding: rv.Encoding, Bitmap: rv.Bitmap, MissingRanges: rv.MissingRanges,
	})
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	_ = tv
	writeProto(w, protocol.SchemaResumeResponse, resp)
}

// --- complete ---

func (h *Handler) handleComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	now := h.now()
	raw, pe := readBody(r, 512)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalTransferComplete(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	pub, ok := to32(req.SenderPub)
	if !ok {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "bad sender pub"})
		return
	}
	var tid [16]byte
	copy(tid[:], req.TransferID)
	var mhash [32]byte
	copy(mhash[:], req.ManifestHash)
	nonce, ok := to16(req.Nonce)
	if !ok {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "bad nonce"})
		return
	}
	if err := protocol.VerifyXferComplete(req.SenderPub, tid, mhash, req.Timestamp, nonce, req.Signature, now); err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	if h.store.CheckAndMarkReplay(r.Context(), replayKey(replayDomainComplete, req.SenderPub, req.Nonce)) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrReplayDetected, Detail: "replay detected"})
		return
	}
	// Sender binding: transfer must belong to this sender.
	tv, err := h.store.GetTransfer(r.Context(), tid)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	if subtle.ConstantTimeCompare(tv.SenderPub, req.SenderPub) != 1 {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "sender mismatch"})
		return
	}
	sealed, present, count, err := h.store.CompleteTransfer(r.Context(), req)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	var sealedU8 uint8
	if sealed {
		sealedU8 = 1
	}
	resp, err := protocol.MarshalTransferCompleteResponse(&protocol.TransferCompleteResponse{Sealed: sealedU8, ChunkCount: count, Present: present})
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	_ = pub
	writeProto(w, protocol.SchemaTransferCompleteResponse, resp)
}

// --- cancel ---

func (h *Handler) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	raw, pe := readBody(r, 256)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalTransferCancel(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	var tid, mid [16]byte
	copy(tid[:], req.TransferID)
	copy(mid[:], req.MailboxID)
	if err := h.store.CancelTransfer(r.Context(), tid, mid, req.ReadSecret); err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	resp, err := protocol.MarshalMessageAckResponse(1, 0)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	writeProto(w, protocol.SchemaMessageAckResponse, resp)
}

// Ensure strings import is used even if IP helper changes.
var _ = strings.TrimSpace
