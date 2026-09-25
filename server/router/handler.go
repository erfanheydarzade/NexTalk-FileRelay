// Package router — binary HTTP handlers.
//
// Routes:
//
//	POST /fr/v1/register  Register(52) -> RegisterResponse(53)
//	POST /fr/v1/resolve   Resolve(54) -> ResolveResponse(55)
//	GET  /fr/v1/table     -> RoutingTable(56)
//	POST /fr/v1/hello     Hello(50) -> Hello(50)
//
// The router derives opaque mailbox IDs (HMAC-SHA256 with SERVER_SECRET),
// picks the owning shard (sha256-hashpoint-modn), ensures the mailbox
// exists on that shard, and publishes the signed routing table. It never
// proxies message bodies. Replication and PoW shard registration are
// explicitly out of scope for this iteration.
package router

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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

// ShardRef binds a shard URL to its backing store (in-process wiring for
// tests and single-binary deployments; production fans out over HTTP).
type ShardRef struct {
	URL   string
	Store storage.Store
}

// Config builds a Handler.
type Config struct {
	Secret            []byte // SERVER_SECRET, required
	Shards            []ShardRef
	Version           uint32
	ReplicationFactor uint32 // forced to 1 (replication excluded)
	RouterPub         [32]byte
	RouterPriv        ed25519.PrivateKey // signs routing table
	Now               func() int64
	MaxRegistersPerIP int
	MaxResolvesPerIP  int
}

// Handler serves the router binary protocol.
type Handler struct {
	secret  []byte
	shards  []ShardRef
	version uint32
	pub     [32]byte
	priv    ed25519.PrivateKey
	now     func() int64
	maxReg  int
	maxRes  int

	mu     sync.Mutex
	regRL  map[string]*rlWindow
	resRL  map[string]*rlWindow
	replay map[[32]byte]int64
}

type rlWindow struct {
	count   int
	resetAt int64
}

// NewHandler builds a router Handler.
func NewHandler(cfg Config) *Handler {
	now := cfg.Now
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	maxReg := cfg.MaxRegistersPerIP
	if maxReg <= 0 {
		maxReg = 600
	}
	maxRes := cfg.MaxResolvesPerIP
	if maxRes <= 0 {
		maxRes = 1200
	}
	rep := cfg.ReplicationFactor
	if rep != 1 {
		rep = 1 // replication excluded this iteration
	}
	_ = rep
	return &Handler{
		secret:  append([]byte(nil), cfg.Secret...),
		shards:  append([]ShardRef(nil), cfg.Shards...),
		version: cfg.Version,
		pub:     cfg.RouterPub,
		priv:    cfg.RouterPriv,
		now:     now,
		maxReg:  maxReg,
		maxRes:  maxRes,
		regRL:   map[string]*rlWindow{},
		resRL:   map[string]*rlWindow{},
		replay:  map[[32]byte]int64{},
	}
}

// Owner maps a mailbox ID to its primary shard URL.
func Owner(mailboxID [16]byte, shardURLs []string) string {
	if len(shardURLs) == 0 {
		return ""
	}
	h := sha256.Sum256(mailboxID[:])
	v := uint(h[0])<<24 | uint(h[1])<<16 | uint(h[2])<<8 | uint(h[3])
	return shardURLs[int(v%uint(len(shardURLs)))]
}

func hashOf(b []byte) [32]byte { return sha256sum(b) }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case protocol.RouteRegister:
		h.handleRegister(w, r)
	case protocol.RouteResolve:
		h.handleResolve(w, r)
	case protocol.RouteTable:
		h.handleTable(w, r)
	case protocol.RouteHello:
		h.handleHello(w, r)
	default:
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "unknown route"})
	}
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *Handler) allowRL(mu *sync.Mutex, table map[string]*rlWindow, key string, now int64, max int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_ = mu
	w, ok := table[key]
	if !ok || now >= w.resetAt {
		table[key] = &rlWindow{count: 1, resetAt: now + 60_000}
		return true
	}
	if w.count >= max {
		return false
	}
	w.count++
	return true
}

func (h *Handler) checkReplay(pub, nonce []byte, now int64) bool {
	var key [32]byte
	hh := sha256.New()
	hh.Write(protocol.DomainRegister)
	hh.Write(pub)
	hh.Write(nonce)
	copy(key[:], hh.Sum(nil))
	h.mu.Lock()
	defer h.mu.Unlock()
	if exp, ok := h.replay[key]; ok && now < exp {
		return true
	}
	for k, exp := range h.replay {
		if now >= exp {
			delete(h.replay, k)
		}
	}
	h.replay[key] = now + protocol.ReplayWindowSeconds*1000
	return false
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
	w.WriteHeader(httpStatusFor(pe.Code))
	_, _ = w.Write(body)
}

func httpStatusFor(code uint32) int {
	switch code {
	case protocol.ErrInvalidRequest, protocol.ErrExpiredRequest, protocol.ErrBatchTooLarge:
		return http.StatusBadRequest
	case protocol.ErrAuthFailed:
		return http.StatusUnauthorized
	case protocol.ErrReplayDetected:
		return http.StatusConflict
	case protocol.ErrMailboxNotFound, protocol.ErrTransferNotFound:
		return http.StatusNotFound
	case protocol.ErrMailboxExpired, protocol.ErrTransferExpired:
		return http.StatusGone
	case protocol.ErrPayloadTooLarge, protocol.ErrMessageTooLarge:
		return http.StatusRequestEntityTooLarge
	case protocol.ErrQuotaExceeded, protocol.ErrRateLimited:
		return http.StatusTooManyRequests
	default:
		return http.StatusBadRequest
	}
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

func (h *Handler) shardURLs() []string {
	urls := make([]string, 0, len(h.shards))
	for _, s := range h.shards {
		urls = append(urls, s.URL)
	}
	return urls
}

func (h *Handler) findShard(url string) *ShardRef {
	for i := range h.shards {
		if h.shards[i].URL == url {
			return &h.shards[i]
		}
	}
	return nil
}

// --- register ---

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	now := h.now()
	if !h.allowRL(&h.mu, h.regRL, "reg-ip:"+clientIP(r), now, h.maxReg) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrRateLimited, Detail: "rate limited", RetryAfter: 60})
		return
	}
	raw, pe := readBody(r, 256)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalRegister(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	var pub [32]byte
	copy(pub[:], req.ClientPub)
	var nonce [16]byte
	copy(nonce[:], req.Nonce)
	if err := protocol.VerifyRegister(req.ClientPub, req.Timestamp, nonce, req.Signature, now); err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	if h.checkReplay(req.ClientPub, req.Nonce, now) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrReplayDetected, Detail: "replay detected"})
		return
	}
	if len(h.secret) == 0 {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrServerUnavailable, Detail: "router not configured"})
		return
	}
	mailboxID := protocol.MailboxIDFromPub(h.secret, req.ClientPub)
	urls := h.shardURLs()
	if len(urls) == 0 {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrServerUnavailable, Detail: "no shards"})
		return
	}
	primary := Owner(mailboxID, urls)
	ref := h.findShard(primary)
	if ref == nil {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrServerUnavailable, Detail: "shard not found"})
		return
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrStorageUnavailable, Detail: "rand failed"})
		return
	}
	var sh [32]byte
	copy(sh[:], secret)
	_ = hex.EncodeToString
	sum := sha256.Sum256(secret)
	var hash [32]byte
	copy(hash[:], sum[:])
	if _, err := ref.Store.CreateMailbox(r.Context(), mailboxID, hash); err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	_ = sh
	resp, err := protocol.MarshalRegisterResponse(&protocol.RegisterResponse{
		MailboxID:    mailboxID[:],
		ReadSecret:   secret,
		ShardURL:     primary,
		TableVersion: h.version,
		ExpiresAt:    uint64(now + protocol.CapabilityTTLSeconds*1000),
	})
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	writeProto(w, protocol.SchemaRegisterResponse, resp)
}

// --- resolve ---

func (h *Handler) handleResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	now := h.now()
	if !h.allowRL(&h.mu, h.resRL, "res-ip:"+clientIP(r), now, h.maxRes) {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrRateLimited, Detail: "rate limited", RetryAfter: 60})
		return
	}
	raw, pe := readBody(r, 128)
	if pe != nil {
		writeError(w, pe)
		return
	}
	req, err := protocol.UnmarshalResolve(raw)
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	if len(h.secret) == 0 || len(h.shards) == 0 {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrServerUnavailable, Detail: "router not configured"})
		return
	}
	mailboxID := protocol.MailboxIDFromPub(h.secret, req.ClientPub)
	// Era-walk: probe each shard for existence, primary first.
	urls := h.shardURLs()
	primary := Owner(mailboxID, urls)
	ordered := []string{primary}
	for _, u := range urls {
		if u != primary {
			ordered = append(ordered, u)
		}
	}
	for _, u := range ordered {
		if ref := h.findShard(u); ref != nil {
			if ref.Store.MailboxExists(r.Context(), mailboxID) {
				resp, err := protocol.MarshalResolveResponse(&protocol.ResolveResponse{
					MailboxID: mailboxID[:], ShardURL: u, Era: 0, TableVersion: h.version,
				})
				if err != nil {
					writeError(w, protocol.AsProtocolError(err))
					return
				}
				writeProto(w, protocol.SchemaResolveResponse, resp)
				return
			}
		}
	}
	// Not confirmed yet: return current-era guess.
	resp, err := protocol.MarshalResolveResponse(&protocol.ResolveResponse{
		MailboxID: mailboxID[:], ShardURL: primary, Era: 0, TableVersion: h.version,
	})
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	writeProto(w, protocol.SchemaResolveResponse, resp)
}

// --- table ---

func (h *Handler) handleTable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "method not allowed"})
		return
	}
	now := h.now()
	urls := h.shardURLs()
	if len(urls) == 0 {
		writeError(w, &protocol.ProtocolError{Code: protocol.ErrServerUnavailable, Detail: "no shards"})
		return
	}
	gen := uint64(now)
	exp := uint64(now + protocol.RoutingTableTTLSeconds*1000)
	sig := ed25519.Sign(h.priv, protocol.CanonicalRoutingTable(h.version, gen, exp, protocol.RoutingAlgoSHA256ModN, urls, h.pub))
	body, err := protocol.MarshalRoutingTable(&protocol.RoutingTable{
		Version: h.version, GeneratedAt: gen, ExpiresAt: exp,
		Algorithm: protocol.RoutingAlgoSHA256ModN, Shards: urls,
		ReplicationFactor: 1, RouterPub: h.pub[:], Signature: sig,
	})
	if err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	w.Header().Set("Content-Type", protocol.ContentType)
	w.Header().Set("X-FileRelay-Schema", "56")
	w.Header().Set("X-FileRelay-Protocol", protocolVersionHeader())
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
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
	if _, err := protocol.UnmarshalHello(raw); err != nil {
		writeError(w, protocol.AsProtocolError(err))
		return
	}
	body, _ := protocol.MarshalHello(&protocol.Hello{Major: protocol.ProtocolMajor, Minor: protocol.ProtocolMinor, NowMS: uint64(h.now())})
	writeProto(w, protocol.SchemaHello, body)
}
