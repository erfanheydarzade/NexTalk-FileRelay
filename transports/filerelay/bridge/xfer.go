// File/mailbox operations for the courier bridge.
//
// Scoped-credential model: per-user-tag ed25519 keypairs (scoped-<tag>.key)
// register FileRelay mailboxes with the router. They control mailbox
// registration and courier-signed sends only — they cannot decrypt NexTalk
// traffic (E2E keys never leave core) and cannot impersonate the NexTalk
// identity (different key). Revoke by deleting the key file + re-register.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
)

var tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

type transferBind struct {
	MailboxID  []byte `json:"mailbox_id"`
	ShardURL   string `json:"shard_url"`
	ChunkCount uint32 `json:"chunk_count"`
}

type xferState struct {
	mu        sync.Mutex
	scoped    map[string]ed25519.PrivateKey // userTag -> key
	transfers map[string]*transferBind      // hex(transferID) -> binding
	dir       string
}

func newXferState() *xferState {
	dir := os.Getenv("NTX_BRIDGE_DIR")
	if dir == "" {
		if exe, err := os.Executable(); err == nil {
			dir = filepath.Dir(exe)
		}
	}
	return &xferState{scoped: map[string]ed25519.PrivateKey{}, transfers: map[string]*transferBind{}, dir: dir}
}

func (x *xferState) scopedKey(userTag string) (ed25519.PrivateKey, error) {
	if !tagRe.MatchString(userTag) {
		return nil, fmt.Errorf("bad user tag")
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if k, ok := x.scoped[userTag]; ok {
		return k, nil
	}
	path := filepath.Join(x.dir, "scoped-"+userTag+".key")
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) == ed25519.PrivateKeySize {
			k := ed25519.PrivateKey(append([]byte(nil), raw...))
			x.scoped[userTag] = k
			return k, nil
		}
		return nil, fmt.Errorf("bad scoped key file")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, err
	}
	x.scoped[userTag] = priv
	return priv, nil
}

func (b *bridge) onRegister(payload []byte) (uint8, []byte) {
	req, err := unmarshalRegisterReq(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	routerURL := req.routerURL
	if routerURL == "" {
		routerURL = b.effectiveRouter()
	}
	if routerURL == "" {
		return opError, errPayload(errTransport, "no router_url")
	}
	priv, err := b.xfer.scopedKey(req.userTag)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	pub := priv.Public().(ed25519.PublicKey)
	var p [32]byte
	copy(p[:], pub)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	ts := uint64(time.Now().UnixMilli())
	sig := ed25519.Sign(priv, protocol.CanonicalRegister(p, ts, nonce))
	body, err := protocol.MarshalRegister(&protocol.Register{
		ClientPub: pub, Timestamp: ts, Nonce: nonce[:], Signature: sig,
	})
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	st, raw, err := b.postBinary(joinURL(routerURL, protocol.RouteRegister), protocol.SchemaRegister, body)
	if err != nil || st != 200 {
		return opError, errPayload(errTransport, xferHTTPError("register", st, raw, err))
	}
	res, err := protocol.UnmarshalRegisterResponse(raw)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	return opRegister, marshalRegisterResult(res.MailboxID, res.ReadSecret, res.ShardURL, routerURL)
}

func (b *bridge) onResolve(payload []byte) (uint8, []byte) {
	req, err := unmarshalResolveReq(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	routerURL := req.routerURL
	if routerURL == "" {
		routerURL = b.effectiveRouter()
	}
	if routerURL == "" {
		return opError, errPayload(errTransport, "no router_url")
	}
	mid, shard, err := b.resolve(req.recipientPub, routerURL)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	return opResolve, marshalResolveResult(mid[:], shard)
}

func (b *bridge) onXferCreate(payload []byte) (uint8, []byte) {
	req, err := unmarshalXferCreate(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	// Resolve recipient mailbox+shard when the pubkey is given (authoritative).
	// An explicit mailbox+shard address (shared out-of-band by the recipient)
	// wins: scoped-credential mailboxes are unguessable from the peer pubkey.
	mailbox := req.mailboxID
	shardURL := req.shardURL
	if len(req.recipientPub) == 32 && (len(mailbox) != 16 || shardURL == "") {
		routerURL := b.effectiveRouter()
		if routerURL == "" {
			return opError, errPayload(errTransport, "no router_url for resolve")
		}
		mid, shard, err := b.resolve(req.recipientPub, routerURL)
		if err != nil {
			return opError, errPayload(errTransport, err.Error())
		}
		mailbox = mid[:]
		shardURL = shard
	}
	if len(mailbox) != 16 || shardURL == "" {
		return opError, errPayload(errTransport, "mailbox+shard or recipient_pub required")
	}
	var mid [16]byte
	copy(mid[:], mailbox)
	pub := b.courierPriv.Public().(ed25519.PublicKey)
	var p [32]byte
	copy(p[:], pub)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	ts := uint64(time.Now().UnixMilli())
	sig := ed25519.Sign(b.courierPriv, protocol.CanonicalXferCreate(p, mid, req.total, req.chunkSize, req.chunkCount, ts, nonce, req.manifest))
	body, err := protocol.MarshalTransferCreate(&protocol.TransferCreate{
		MailboxID: mailbox, TotalSize: req.total, ChunkSize: req.chunkSize, ChunkCount: req.chunkCount,
		Manifest: req.manifest, SenderPub: pub, Timestamp: ts, Nonce: nonce[:], Signature: sig,
	})
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	// Shard for the mailbox: resolved above, or the attached/default shard.
	st, raw, err := b.postBinary(joinURL(shardURL, protocol.RouteTransferCreate), protocol.SchemaTransferCreate, body)
	if err != nil || st != 200 {
		return opError, errPayload(errTransport, xferHTTPError("xfer-create", st, raw, err))
	}
	res, err := protocol.UnmarshalTransferCreateResponse(raw)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	b.xfer.mu.Lock()
	b.xfer.transfers[hex.EncodeToString(res.TransferID)] = &transferBind{
		MailboxID: append([]byte(nil), mailbox...), ShardURL: shardURL,
		ChunkCount: req.chunkCount,
	}
	b.xfer.mu.Unlock()
	b.xfer.saveBindings()
	return opXferCreate, marshalXferCreated(res.TransferID, res.DownloadSecret, shardURL, res.ExpiresAt)
}

func (b *bridge) bindFor(transferID []byte) (*transferBind, bool) {
	key := hex.EncodeToString(transferID)
	b.xfer.mu.Lock()
	defer b.xfer.mu.Unlock()
	if bind, ok := b.xfer.transfers[key]; ok {
		return bind, true
	}
	// Cross-process fallback: bindings persist in transfers.json so each
	// CLI invocation (fresh bridge process) can resume/get/complete.
	if raw, err := os.ReadFile(filepath.Join(b.xfer.dir, "transfers.json")); err == nil {
		var all map[string]*transferBind
		if json.Unmarshal(raw, &all) == nil {
			if bind, ok := all[key]; ok && len(bind.MailboxID) == 16 {
				b.xfer.transfers[key] = bind
				return bind, true
			}
		}
	}
	return nil, false
}

// saveBindings persists transfer bindings (0600) for cross-process resume.
func (x *xferState) saveBindings() {
	raw, err := json.Marshal(x.transfers)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(x.dir, "transfers.json"), raw, 0o600)
}

func (b *bridge) onXferPut(payload []byte) (uint8, []byte) {
	req, err := unmarshalXferPut(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	bind, ok := b.bindFor(req.transferID)
	if !ok {
		return opError, errPayload(errTransport, "unknown transfer (create first via this bridge)")
	}
	body, err := protocol.MarshalChunkUpload(&protocol.ChunkUpload{
		TransferID: req.transferID, Index: req.index, Payload: req.payload,
		ChunkHash: req.hash, Offset: req.offset,
	})
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	st, raw, err := b.postBinary(joinURL(bind.ShardURL, protocol.RouteChunkPut), protocol.SchemaChunkUpload, body)
	if err != nil || st != 200 {
		return opError, errPayload(errTransport, xferHTTPError("xfer-put", st, raw, err))
	}
	ack, err := protocol.UnmarshalChunkAck(raw)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	// Sender-side progress: the put ack carries highest-contiguous; total
	// count is known from create (stored in the binding).
	return opXferPut, marshalXferProgress(ack.HighestContiguous, bind.ChunkCount, ack.MissingRanges, ack.Bitmap, ack.Encoding)
}

func (b *bridge) onXferResume(payload []byte) (uint8, []byte) {
	req, err := unmarshalXferResume(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	// Ticket mode needs no binding: the ticket + explicit shardURL are
	// self-contained (the recipient's bridge never saw the create).
	var shardURL string
	var body []byte
	if len(req.ticket) == 32 {
		if req.shardURL == "" {
			return opError, errPayload(errTransport, "ticket mode: shard_url required")
		}
		shardURL = req.shardURL
		body, err = protocol.MarshalResumeRequest(&protocol.ResumeRequest{
			TransferID: req.transferID, Ticket: req.ticket,
		})
	} else {
		bind, ok := b.bindFor(req.transferID)
		if !ok {
			return opError, errPayload(errTransport, "unknown transfer")
		}
		if string(req.mailboxID) != string(bind.MailboxID) {
			return opError, errPayload(errTransport, "mailbox mismatch")
		}
		shardURL = bind.ShardURL
		body, err = protocol.MarshalResumeRequest(&protocol.ResumeRequest{
			TransferID: req.transferID, MailboxID: req.mailboxID, ReadSecret: req.readSecret,
		})
	}
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	st, raw, err := b.postBinary(joinURL(shardURL, protocol.RouteResume), protocol.SchemaResumeRequest, body)
	if err != nil || st != 200 {
		return opError, errPayload(errTransport, xferHTTPError("xfer-resume", st, raw, err))
	}
	res, err := protocol.UnmarshalResumeResponse(raw)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	return opXferResume, marshalXferProgress(res.HighestContiguous, res.ChunkCount, res.MissingRanges, res.Bitmap, res.Encoding)
}

func (b *bridge) onXferGet(payload []byte) (uint8, []byte) {
	req, err := unmarshalXferGet(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	var shardURL string
	var body []byte
	if len(req.ticket) == 32 {
		if req.shardURL == "" {
			return opError, errPayload(errTransport, "ticket mode: shard_url required")
		}
		shardURL = req.shardURL
		body, err = protocol.MarshalChunkDownload(&protocol.ChunkDownload{
			TransferID: req.transferID, Index: req.index, Count: 1,
			Ticket: req.ticket,
		})
	} else {
		bind, ok := b.bindFor(req.transferID)
		if !ok {
			return opError, errPayload(errTransport, "unknown transfer")
		}
		if string(req.mailboxID) != string(bind.MailboxID) {
			return opError, errPayload(errTransport, "mailbox mismatch")
		}
		shardURL = bind.ShardURL
		body, err = protocol.MarshalChunkDownload(&protocol.ChunkDownload{
			TransferID: req.transferID, Index: req.index, Count: 1,
			MailboxID: req.mailboxID, ReadSecret: req.readSecret,
		})
	}
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	st, raw, err := b.postBinary(joinURL(shardURL, protocol.RouteChunkGet), protocol.SchemaChunkDownload, body)
	if err != nil || st != 200 {
		return opError, errPayload(errTransport, xferHTTPError("xfer-get", st, raw, err))
	}
	res, err := protocol.UnmarshalChunkDownloadResponse(raw)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	h := sha256.Sum256(res.Payload)
	if hex.EncodeToString(h[:]) != hex.EncodeToString(res.ChunkHash) {
		return opError, errPayload(errTransport, "chunk hash mismatch (relay data corrupt)")
	}
	return opXferGet, marshalXferChunk(res.Payload, res.ChunkHash)
}

func (b *bridge) onXferComplete(payload []byte) (uint8, []byte) {
	req, err := unmarshalXferComplete(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	bind, ok := b.bindFor(req.transferID)
	if !ok {
		return opError, errPayload(errTransport, "unknown transfer")
	}
	var tid [16]byte
	copy(tid[:], req.transferID)
	var mhash [32]byte
	copy(mhash[:], req.manifestHash)
	pub := b.courierPriv.Public().(ed25519.PublicKey)
	var p [32]byte
	copy(p[:], pub)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	ts := uint64(time.Now().UnixMilli())
	sig := ed25519.Sign(b.courierPriv, protocol.CanonicalXferComplete(p, tid, mhash, ts, nonce))
	_ = bind
	body, err := protocol.MarshalTransferComplete(&protocol.TransferComplete{
		TransferID: req.transferID, ManifestHash: req.manifestHash, MailboxID: nil,
		SenderPub: pub, Timestamp: ts, Nonce: nonce[:], Signature: sig,
	})
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	// Complete is sender-bound server-side; route via the bound shard.
	b.xfer.mu.Lock()
	shardURL := b.xfer.transfers[hex.EncodeToString(req.transferID)].ShardURL
	b.xfer.mu.Unlock()
	st, raw, err := b.postBinary(joinURL(shardURL, protocol.RouteComplete), protocol.SchemaTransferComplete, body)
	if err != nil || st != 200 {
		return opError, errPayload(errTransport, xferHTTPError("xfer-complete", st, raw, err))
	}
	if _, err := protocol.UnmarshalTransferCompleteResponse(raw); err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	return opXferComplete, marshalAck(true, "")
}

func (b *bridge) onXferCancel(payload []byte) (uint8, []byte) {
	req, err := unmarshalXferCancel(payload)
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	bind, ok := b.bindFor(req.transferID)
	if !ok {
		return opError, errPayload(errTransport, "unknown transfer")
	}
	if string(req.mailboxID) != string(bind.MailboxID) {
		return opError, errPayload(errTransport, "mailbox mismatch")
	}
	body, err := protocol.MarshalTransferCancel(&protocol.TransferCancel{
		TransferID: req.transferID, MailboxID: req.mailboxID, Reason: 0,
		ReadSecret: req.readSecret,
	})
	if err != nil {
		return opError, errPayload(errTransport, err.Error())
	}
	st, raw, err := b.postBinary(joinURL(bind.ShardURL, protocol.RouteCancel), protocol.SchemaTransferCancel, body)
	if err != nil || st != 200 {
		return opError, errPayload(errTransport, xferHTTPError("xfer-cancel", st, raw, err))
	}
	return opXferCancel, marshalAck(true, "")
}

func xferHTTPError(what string, st int, raw []byte, err error) string {
	if err != nil {
		return what + ": " + err.Error()
	}
	if pe, uerr := protocol.UnmarshalError(raw); uerr == nil {
		return fmt.Sprintf("%s: %s", what, pe.Detail)
	}
	return fmt.Sprintf("%s: http %d", what, st)
}
