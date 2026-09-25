// Command filerelay-bridge is the NexTalk runtime transport for FileRelay.
//
// Courier model: the bridge owns its own throwaway ed25519 courier keypair
// (courier.key next to the binary, 0600) used solely as the outer sender
// identity for shard rate-limiting. The true sender lives inside the
// E2E-encrypted NexTalk frame, which the bridge treats as opaque bytes.
//
// The bridge NEVER sees user private keys: core passes opaque frames,
// recipient pubkeys, per-mailbox read_secret bearers, and URLs. It POSTs
// pre-signed (courier-signed) FileRelay bodies and returns raw responses.
//
// Usage: filerelay-bridge --ntx-serve   (stdio RPC; stderr = logs)
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
)

const (
	errUnsupported = 2
	errNotReady    = 3
	errTransport   = 4
)

type mailbox struct {
	readSecret []byte
	shardURL   string
	routerURL  string
}

type bridge struct {
	mu          sync.Mutex
	running     bool
	courierPriv ed25519.PrivateKey
	mailboxes   map[string]*mailbox
	routerURL   string // default from initialize config
	http        *http.Client
	xfer        *xferState
}

type bridgeConfig struct {
	RouterURL string `json:"router_url"`
	ShardURL  string `json:"shard_url"`
}

func main() {
	// Helper: filerelay-bridge wrap --type 3 -f payload.bin > frame.bin
	// prepends the layer-1 type byte (offer=1 answer=2 message=3 multimsg=4).
	if len(os.Args) > 1 && os.Args[1] == "wrap" {
		fs := flag.NewFlagSet("wrap", flag.ExitOnError)
		typ := fs.Int("type", 3, "frame type byte (1..4)")
		file := fs.String("f", "", "payload file")
		_ = fs.Parse(os.Args[2:])
		if *typ < 1 || *typ > 4 || *file == "" {
			fmt.Fprintln(os.Stderr, "wrap: --type 1..4 and -f file required")
			os.Exit(2)
		}
		raw, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wrap:", err)
			os.Exit(1)
		}
		out := make([]byte, 1+len(raw))
		out[0] = byte(*typ)
		copy(out[1:], raw)
		if _, err := os.Stdout.Write(out); err != nil {
			os.Exit(1)
		}
		return
	}
	serve := flag.Bool("ntx-serve", false, "serve NexTalk transport RPC on stdio")
	flag.Parse()
	if !*serve {
		fmt.Fprintln(os.Stderr, "usage: filerelay-bridge --ntx-serve")
		os.Exit(2)
	}
	b := &bridge{
		mailboxes: map[string]*mailbox{},
		http:      &http.Client{Timeout: 15 * time.Second},
		xfer:      newXferState(),
	}
	if err := b.loadOrCreateCourierKey(); err != nil {
		fmt.Fprintln(os.Stderr, "courier key:", err)
		os.Exit(1)
	}
	b.serveLoop()
}

// loadOrCreateCourierKey keeps the courier identity next to the binary
// (NTX_BRIDGE_DIR overrides for tests).
func (b *bridge) loadOrCreateCourierKey() error {
	dir := os.Getenv("NTX_BRIDGE_DIR")
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		dir = filepath.Dir(exe)
	}
	path := filepath.Join(dir, "courier.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) == ed25519.PrivateKeySize {
			b.courierPriv = ed25519.PrivateKey(append([]byte(nil), raw...))
			return nil
		}
		return fmt.Errorf("bad courier.key length %d", len(raw))
	}
	if !os.IsNotExist(err) {
		return err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return err
	}
	b.courierPriv = priv
	return nil
}

func (b *bridge) serveLoop() {
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(os.Stdin, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > maxRPCBytes {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(os.Stdin, body); err != nil {
			return
		}
		env, err := unmarshalEnvelope(body)
		if err != nil {
			return
		}
		respOp, payload := b.dispatch(env.op, env.payload)
		rbody, err := marshalEnvelope(respOp, env.reqID, payload)
		if err != nil {
			return
		}
		if _, err := os.Stdout.Write(frameMessage(rbody)); err != nil {
			return
		}
	}
}

func (b *bridge) dispatch(op uint8, payload []byte) (uint8, []byte) {
	switch op {
	case opInitialize:
		return opInitialize, b.onInitialize(payload)
	case opCapabilities:
		return opCapabilities, marshalCaps()
	case opStartStop:
		return b.onStartStop(payload)
	case opSend:
		return b.onSend(payload)
	case opAttach:
		return b.onAttach(payload)
	case opDetach:
		return b.onDetach(payload)
	case opPoll:
		return b.onPoll(payload)
	case opStatus:
		b.mu.Lock()
		running := b.running
		b.mu.Unlock()
		if running {
			return opStatus, marshalStatus(true, "courier running")
		}
		return opStatus, marshalStatus(false, "stopped")
	case opRegister:
		return b.onRegister(payload)
	case opResolve:
		return b.onResolve(payload)
	case opXferCreate:
		return b.onXferCreate(payload)
	case opXferPut:
		return b.onXferPut(payload)
	case opXferResume:
		return b.onXferResume(payload)
	case opXferGet:
		return b.onXferGet(payload)
	case opXferComplete:
		return b.onXferComplete(payload)
	case opXferCancel:
		return b.onXferCancel(payload)
	default:
		return opError, marshalError(errUnsupported, "unknown op")
	}
}

func (b *bridge) onInitialize(payload []byte) []byte {
	init, err := unmarshalInitialize(payload)
	if err != nil {
		return marshalInitResult(false, err.Error(), transportAPIVer)
	}
	if init.transportID != bridgeID {
		return marshalInitResult(false, "transport id mismatch", transportAPIVer)
	}
	if init.apiVersion != transportAPIVer {
		return marshalInitResult(false, "api version mismatch", transportAPIVer)
	}
	if len(init.config) > 0 {
		var cfg bridgeConfig
		if err := json.Unmarshal(init.config, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "bridge: ignoring invalid config %q: %v (want e.g. {\"router_url\":\"https://...\"})\n", string(init.config), err)
		} else {
			b.mu.Lock()
			b.routerURL = cfg.RouterURL
			b.mu.Unlock()
		}
	}
	return marshalInitResult(true, "", transportAPIVer)
}

func (b *bridge) onStartStop(payload []byte) (uint8, []byte) {
	action, err := unmarshalStartStop(payload)
	if err != nil {
		return opError, marshalError(errTransport, err.Error())
	}
	b.mu.Lock()
	if action == actionStart {
		b.running = true
	} else {
		b.running = false
	}
	b.mu.Unlock()
	return opStartStop, marshalAck(true, "")
}

func (b *bridge) requireRunning() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.running {
		return fmt.Errorf("not started")
	}
	return nil
}

// effectiveRouter returns the configured router, falling back to any
// router_url learned via attach. Keeps pubkey routing working after a
// restart even when the initialize config is missing.
func (b *bridge) effectiveRouter() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.routerURL != "" {
		return b.routerURL
	}
	for _, mb := range b.mailboxes {
		if mb != nil && mb.routerURL != "" {
			return mb.routerURL
		}
	}
	return ""
}

// onSend resolves the recipient via the router and delivers the opaque frame
// as a FileRelay message signed with the COURIER key.
func (b *bridge) onSend(payload []byte) (uint8, []byte) {
	if err := b.requireRunning(); err != nil {
		return opError, marshalError(errNotReady, err.Error())
	}
	req, err := unmarshalSend(payload)
	if err != nil {
		return opError, marshalError(errTransport, err.Error())
	}
	var mailboxID [16]byte
	var shardURL string
	if len(req.mailboxID) == 16 && req.shardURL != "" {
		// Explicit recipient address (shared out-of-band by the recipient).
		copy(mailboxID[:], req.mailboxID)
		shardURL = req.shardURL
	} else {
		if len(req.recipientPub) != 32 {
			return opError, marshalError(errTransport, "recipient_pub must be 32 bytes")
		}
		routerURL := b.effectiveRouter()
		if routerURL == "" {
			return opError, marshalError(errTransport, "no router_url: pass via initialize config or attach first")
		}
		mid, shard, err := b.resolve(req.recipientPub, routerURL)
		if err != nil {
			return opError, marshalError(errTransport, err.Error())
		}
		mailboxID, shardURL = mid, shard
	}
	if err := b.postMessage(shardURL, mailboxID, req.frame); err != nil {
		return opError, marshalError(errTransport, err.Error())
	}
	return opSend, marshalAck(true, "")
}

func (b *bridge) onAttach(payload []byte) (uint8, []byte) {
	if err := b.requireRunning(); err != nil {
		return opError, marshalError(errNotReady, err.Error())
	}
	req, err := unmarshalAttach(payload)
	if err != nil {
		return opError, marshalError(errTransport, err.Error())
	}
	b.mu.Lock()
	b.mailboxes[string(req.mailboxID)] = &mailbox{
		readSecret: append([]byte(nil), req.readSecret...),
		shardURL:   req.shardURL,
		routerURL:  req.routerURL,
	}
	if b.routerURL == "" && req.routerURL != "" {
		b.routerURL = req.routerURL
	}
	b.mu.Unlock()
	return opAttach, marshalAck(true, "")
}

func (b *bridge) onDetach(payload []byte) (uint8, []byte) {
	id, err := unmarshalDetach(payload)
	if err != nil {
		return opError, marshalError(errTransport, err.Error())
	}
	b.mu.Lock()
	delete(b.mailboxes, string(id))
	b.mu.Unlock()
	return opDetach, marshalAck(true, "")
}

// onPoll fetches FileRelay batches and returns the inner opaque frames.
func (b *bridge) onPoll(payload []byte) (uint8, []byte) {
	if err := b.requireRunning(); err != nil {
		return opError, marshalError(errNotReady, err.Error())
	}
	req, err := unmarshalPoll(payload)
	if err != nil {
		return opError, marshalError(errTransport, err.Error())
	}
	b.mu.Lock()
	var targets []*mailbox
	var ids [][]byte
	if len(req.mailboxID) == 16 {
		if mb, ok := b.mailboxes[string(req.mailboxID)]; ok {
			targets = append(targets, mb)
			ids = append(ids, req.mailboxID)
		}
	} else {
		for id, mb := range b.mailboxes {
			targets = append(targets, mb)
			ids = append(ids, []byte(id))
		}
	}
	b.mu.Unlock()
	limit := int(req.limit)
	var frames [][]byte
	for i, mb := range targets {
		if len(frames) >= limit {
			break
		}
		got, err := b.fetchBatch(mb.shardURL, ids[i], mb.readSecret, limit-len(frames))
		if err != nil {
			return opError, marshalError(errTransport, err.Error())
		}
		frames = append(frames, got...)
	}
	return opPoll, marshalPollResult(frames)
}

// --- FileRelay HTTP (courier-signed, opaque envelopes) ---

// joinURL concatenates a base URL and a route path without producing a
// double slash (e.g. base "https://shard.example.com/" + route
// "/fr/v1/send" naively concatenates to ".../send" with "//fr/v1/send",
// which several HTTP routers — including Cloudflare Workers — treat as a
// distinct, unmatched path and answer with 404). Router- and
// user-supplied base URLs are not guaranteed to be free of a trailing
// slash, so every caller must go through this instead of "+".
func joinURL(base, route string) string {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	return base + route
}

func (b *bridge) postBinary(url string, schema byte, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", protocol.ContentType)
	res, err := b.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	_ = schema
	return res.StatusCode, raw, nil
}

func (b *bridge) resolve(recipientPub []byte, routerURL string) ([16]byte, string, error) {
	var zero [16]byte
	body, err := protocol.MarshalResolve(&protocol.Resolve{ClientPub: recipientPub})
	if err != nil {
		return zero, "", err
	}
	st, raw, err := b.postBinary(joinURL(routerURL, protocol.RouteResolve), protocol.SchemaResolve, body)
	if err != nil {
		return zero, "", err
	}
	if st != 200 {
		return zero, "", fmt.Errorf("resolve http %d", st)
	}
	res, err := protocol.UnmarshalResolveResponse(raw)
	if err != nil {
		return zero, "", err
	}
	var mid [16]byte
	copy(mid[:], res.MailboxID)
	return mid, res.ShardURL, nil
}

func (b *bridge) postMessage(shardURL string, mailboxID [16]byte, frame []byte) error {
	pub := b.courierPriv.Public().(ed25519.PublicKey)
	var p [32]byte
	copy(p[:], pub)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	ts := uint64(time.Now().UnixMilli())
	sig := ed25519.Sign(b.courierPriv, protocol.CanonicalMsgSend(p, mailboxID, ts, nonce, frame))
	body, err := protocol.MarshalSendMessage(&protocol.SendMessage{
		MailboxID:  append([]byte(nil), mailboxID[:]...),
		Envelope:   frame,
		SenderPub:  append([]byte(nil), pub...),
		Timestamp:  ts,
		Nonce:      append([]byte(nil), nonce[:]...),
		Signature:  sig,
		TTLHintSec: uint32(protocol.MsgTTLSeconds),
		Burn:       1,
	})
	if err != nil {
		return err
	}
	st, raw, err := b.postBinary(joinURL(shardURL, protocol.RouteSend), protocol.SchemaSendMessage, body)
	if err != nil {
		return err
	}
	if st != 200 {
		if pe, err := protocol.UnmarshalError(raw); err == nil {
			return fmt.Errorf("send: %s", pe.Detail)
		}
		return fmt.Errorf("send http %d", st)
	}
	return nil
}

func (b *bridge) fetchBatch(shardURL string, mailboxID, readSecret []byte, limit int) ([][]byte, error) {
	if limit <= 0 {
		limit = 32
	}
	if limit > 32 {
		limit = 32
	}
	body, err := protocol.MarshalReceiveMessages(&protocol.ReceiveMessages{
		MailboxID: mailboxID, ReadSecret: readSecret, Limit: uint8(limit), Peek: 0,
	})
	if err != nil {
		return nil, err
	}
	st, raw, err := b.postBinary(joinURL(shardURL, protocol.RouteReceive), protocol.SchemaReceiveMessages, body)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		if pe, err := protocol.UnmarshalError(raw); err == nil {
			return nil, fmt.Errorf("receive: %s", pe.Detail)
		}
		return nil, fmt.Errorf("receive http %d", st)
	}
	res, err := protocol.UnmarshalReceiveMessagesResponse(raw)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, m := range res.Messages {
		out = append(out, m.Envelope)
	}
	return out, nil
}
