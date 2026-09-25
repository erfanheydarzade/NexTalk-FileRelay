// Package client adapts FileRelay to NexTalk without breaking its trust model.
//
// NexTalk owns identity, sessions, ratcheting, E2E encrypt/decrypt.
// This adapter only moves opaque bytes: it never encrypts, decrypts, or
// inspects payload semantics. Chunking/encryption decisions belong to NexTalk;
// here we only split opaque bytes, upload with pipelining, resume via
// bitmap/ranges, and verify hashes the sender provided.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
)

// Adapter speaks FileRelay v1 over HTTP with raw NanoPack bodies.
type Adapter struct {
	ShardURL  string
	RouterURL string
	HTTP      *http.Client
}

// joinURL concatenates a base URL and a route path without producing a
// double slash. ShardURL/RouterURL are caller-supplied (often copied
// verbatim from config or a router response) and may carry a trailing
// slash; naive "+" concatenation then sends requests to a path the
// server never registered, which surfaces as a 404. Mirrors the same
// helper in transports/filerelay/bridge; kept local here to avoid an
// import cycle between client and the bridge binary.
func joinURL(base, route string) string {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	return base + route
}

// SendMessage delivers one opaque NexTalk payload to a mailbox.
// payload must already be E2E-encrypted by NexTalk.
func (a *Adapter) SendMessage(ctx context.Context, senderPriv ed25519.PrivateKey, mailboxID [16]byte, payload []byte) ([16]byte, error) {
	if len(payload) == 0 || len(payload) > protocol.MaxMessageBytes {
		return [16]byte{}, &protocol.ProtocolError{Code: protocol.ErrMessageTooLarge}
	}
	pub := senderPriv.Public().(ed25519.PublicKey)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [16]byte{}, err
	}
	ts := nowMillis()
	var spub [32]byte
	copy(spub[:], pub)
	sig := ed25519.Sign(senderPriv, protocol.CanonicalMsgSend(spub, mailboxID, uint64(ts), nonce, payload))
	msg := &protocol.SendMessage{
		MailboxID:  append([]byte(nil), mailboxID[:]...),
		Envelope:   payload,
		SenderPub:  append([]byte(nil), pub...),
		Timestamp:  uint64(ts),
		Nonce:      append([]byte(nil), nonce[:]...),
		Signature:  sig,
		TTLHintSec: uint32(protocol.MsgTTLSeconds),
		Burn:       1,
	}
	body, err := protocol.MarshalSendMessage(msg)
	if err != nil {
		return [16]byte{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", joinURL(a.ShardURL, protocol.RouteSend), bytes.NewReader(body))
	if err != nil {
		return [16]byte{}, err
	}
	req.Header.Set("Content-Type", protocol.ContentType)
	req.Header.Set("X-FileRelay-Schema", "57")
	req.Header.Set("X-FileRelay-Protocol", "1.0")
	hc := a.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return [16]byte{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return [16]byte{}, errors.New("filerelay: send failed: " + res.Status)
	}
	_, _ = io.ReadAll(io.LimitReader(res.Body, 1024))
	var msgID [16]byte
	if _, err := rand.Read(msgID[:]); err != nil {
		return [16]byte{}, err
	}
	return msgID, nil
}

// SplitOpaque splits opaque bytes into chunks of chunkSize (last may be short).
// It does NOT encrypt; caller passes already-encrypted bytes.
func SplitOpaque(data []byte, chunkSize int) ([][]byte, error) {
	if chunkSize <= 0 || chunkSize > protocol.MaxChunkBytes {
		return nil, &protocol.ProtocolError{Code: protocol.ErrChunkInvalid}
	}
	if int64(len(data)) > protocol.MaxFileBytes {
		return nil, &protocol.ProtocolError{Code: protocol.ErrPayloadTooLarge}
	}
	var out [][]byte
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		out = append(out, data[off:end])
	}
	return out, nil
}

// ChunkHash returns sha256(payload) for integrity sidecars.
func ChunkHash(payload []byte) [32]byte { return sha256.Sum256(payload) }
