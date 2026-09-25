// Bridge ↔ FileRelay interop: drives the bridge dispatch functions
// in-process against real router+shard handlers over httptest HTTP.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/erfanheydarzade/NexTalk-FileRelay/server/router"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/shard"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/storage"
	"github.com/erfanheydarzade/nanopack"
)

func nanopackDecode(t *testing.T, body []byte) (map[uint8][]byte, error) {
	t.Helper()
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	m := map[uint8][]byte{}
	for _, f := range fields {
		m[f.ID] = append([]byte(nil), f.Data...)
	}
	return m, nil
}

type fileRig struct {
	routerURL string
	shardURL  string
	b         *bridge
}

func newFileRig(t *testing.T) *fileRig {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("NTX_BRIDGE_DIR", dir)
	st := storage.NewMemStore()
	now := time.Now().UnixMilli()
	clk := func() int64 { return now }
	st.Now = clk
	sh := shard.NewHandler(st, clk, shard.DefaultRateLimits())
	shardSrv := httptest.NewServer(sh)
	t.Cleanup(shardSrv.Close)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	rpub, rpriv, _ := ed25519.GenerateKey(rand.Reader)
	var rpubArr [32]byte
	copy(rpubArr[:], rpub)
	rh := router.NewHandler(router.Config{
		Secret:     secret,
		Shards:     []router.ShardRef{{URL: shardSrv.URL, Store: st}},
		Version:    1,
		RouterPub:  rpubArr,
		RouterPriv: rpriv,
		Now:        clk,
	})
	routerSrv := httptest.NewServer(rh)
	t.Cleanup(routerSrv.Close)

	b := &bridge{
		mailboxes: map[string]*mailbox{},
		http:      &http.Client{Timeout: 15 * time.Second},
		xfer:      newXferState(),
	}
	if err := b.loadOrCreateCourierKey(); err != nil {
		t.Fatal(err)
	}
	// initialize + start through the real dispatch path.
	initBody := npFields(t, []npField{{1, []byte(bridgeID)}, {2, []byte{transportAPIVer}}, {3, []byte(`{"router_url":"` + routerSrv.URL + `"}`)}})
	if op, out := b.dispatch(opInitialize, initBody); op != opInitialize {
		t.Fatalf("init failed: %x", out)
	}
	if op, _ := b.dispatch(opStartStop, npFields(t, []npField{{1, []byte{actionStart}}})); op != opStartStop {
		t.Fatal("start failed")
	}
	os.Unsetenv("NTX_BRIDGE_DIR")
	_ = now
	return &fileRig{routerURL: routerSrv.URL, shardURL: shardSrv.URL, b: b}
}

type npField struct {
	id   uint8
	data []byte
}

func npFields(t *testing.T, fs []npField) []byte {
	t.Helper()
	enc := &nanopack.Encoder{}
	for _, f := range fs {
		enc.AddID(f.id, f.data)
	}
	b, err := enc.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func u32b(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func u64b(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func TestBridgeMessageFlow(t *testing.T) {
	r := newFileRig(t)
	b := r.b

	// Register two users (scoped keys, no user keys involved).
	aliceReg := npFields(t, []npField{{1, []byte("alice")}, {2, []byte(r.routerURL)}})
	op, out := b.dispatch(opRegister, aliceReg)
	if op != opRegister {
		t.Fatalf("alice register failed: %x", out)
	}
	aliceBox, aliceSec := parseRegister(t, out)
	bobReg := npFields(t, []npField{{1, []byte("bob")}, {2, []byte(r.routerURL)}})
	op, out = b.dispatch(opRegister, bobReg)
	if op != opRegister {
		t.Fatalf("bob register failed: %x", out)
	}
	bobBox, bobSec := parseRegister(t, out)

	// Resolve needs a raw recipient pub: register a third key and resolve it.
	_, bobPub, _ := ed25519.GenerateKey(rand.Reader)
	_ = bobPub
	// Resolve bob's mailbox via a fresh registration's pub? Resolve works on
	// any 32B pub (router derives + probes). Use random pub → guess path.
	resBody := npFields(t, []npField{{1, make([]byte, 32)}, {2, []byte(r.routerURL)}})
	op, out = b.dispatch(opResolve, resBody)
	if op != opResolve {
		t.Fatalf("resolve failed: %x", out)
	}

	// Attach bob's mailbox, send a frame to it via direct mailbox send path:
	// emulate core send by resolving through register result (mailbox known).
	attBody := npFields(t, []npField{{1, bobBox}, {2, bobSec}, {3, []byte(r.shardURL)}, {4, []byte(r.routerURL)}})
	if op, _ := b.dispatch(opAttach, attBody); op != opAttach {
		t.Fatal("attach failed")
	}
	_ = aliceBox
	_ = aliceSec
	frame := append([]byte{0x03}, []byte("opaque-from-alice")...)
	// Send via recipient mailbox: use resolve of a registered pub is not
	// directly available, so exercise onSend through the bound shard by
	// registering a routable recipient first.
	routeReg := npFields(t, []npField{{1, []byte("carol")}, {2, []byte(r.routerURL)}})
	op, out = b.dispatch(opRegister, routeReg)
	if op != opRegister {
		t.Fatalf("carol register failed: %x", out)
	}
	// Resolve carol's scoped pub is internal; instead send to bob's mailbox
	// by attaching alice side too and using direct FileRelay post? Keep the
	// courier send path honest: it resolves any 32B pub. Use bob's scoped
	// pub? Not exposed. So verify send→poll with a self-send: register dave,
	// attach dave, resolve a random pub won't hit dave's box.
	//
	// Practical approach: resolve returns the owner shard for ANY pub, and
	// send posts to that mailbox. Attach that same mailbox id with the
	// secret? The secret is unknown (mailbox not registered by us).
	//
	// Instead: full loop via carol→carol using resolve on carol's scoped key
	// is internal-only. Simplify: test send to bobBox by temporarily
	// resolving with bob's *scoped* pub — exposed here only because the test
	// shares the process. That still exercises resolve+send+poll over HTTP.
	scoped := b.xfer.scoped["bob"]
	if scoped == nil {
		t.Fatal("no scoped key")
	}
	bobScopedPub := []byte(scoped.Public().(ed25519.PublicKey))
	resBody2 := npFields(t, []npField{{1, bobScopedPub}, {2, []byte(r.routerURL)}})
	op, out = b.dispatch(opResolve, resBody2)
	if op != opResolve {
		t.Fatalf("resolve bob failed: %x", out)
	}
	mid, shardURL := parseResolve(t, out)
	if string(mid) != string(bobBox) || shardURL != r.shardURL {
		t.Fatalf("resolve mismatch: %x %s", mid, shardURL)
	}
	sendBody := npFields(t, []npField{{1, frame}, {2, bobScopedPub}, {3, nil}})
	if op, _ := b.dispatch(opSend, sendBody); op != opSend {
		t.Fatal("send failed")
	}
	pollBody := npFields(t, []npField{{1, []byte{32}}, {2, bobBox}})
	op, out = b.dispatch(opPoll, pollBody)
	if op != opPoll {
		t.Fatalf("poll failed: %x", out)
	}
	frames := parsePoll(t, out)
	if len(frames) != 1 || !bytes.Equal(frames[0], frame) {
		t.Fatalf("poll mismatch: %v", frames)
	}
}

func TestBridgeXferFlow(t *testing.T) {
	r := newFileRig(t)
	b := r.b

	regBody := npFields(t, []npField{{1, []byte("zoe")}, {2, []byte(r.routerURL)}})
	op, out := b.dispatch(opRegister, regBody)
	if op != opRegister {
		t.Fatalf("register failed: %x", out)
	}
	mbox, sec := parseRegister(t, out)

	const chunkSize = 1024
	const nChunks = 3
	total := uint64(chunkSize * nChunks)
	// Create against zoe's scoped pub (in-package access): resolve yields
	// zoe's mailbox+shard, so resume/get with zoe's secret works.
	zoePub := []byte(b.xfer.scoped["zoe"].Public().(ed25519.PublicKey))
	createBody := npFields(t, []npField{
		{1, u64b(total)}, {2, u32b(chunkSize)}, {3, u32b(nChunks)},
		{4, []byte("manifest")}, {5, nil}, {6, zoePub},
	})
	op, out = b.dispatch(opXferCreate, createBody)
	if op != opXferCreate {
		t.Fatalf("create failed: %x", out)
	}
	tid := parseCreated(t, out)

	// Simulate a fresh bridge process (new CLI invocation): drop the
	// in-memory bindings; put/resume/get must recover from transfers.json.
	b.xfer.mu.Lock()
	b.xfer.transfers = map[string]*transferBind{}
	b.xfer.mu.Unlock()

	payloads := [][]byte{bytes.Repeat([]byte{1}, chunkSize), bytes.Repeat([]byte{2}, chunkSize), bytes.Repeat([]byte{3}, chunkSize)}
	for i, p := range payloads {
		h := sha256.Sum256(p)
		putBody := npFields(t, []npField{
			{1, tid}, {2, u32b(uint32(i))}, {3, p}, {4, h[:]}, {5, u64b(uint64(i * chunkSize))},
		})
		op, out = b.dispatch(opXferPut, putBody)
		if op != opXferPut {
			t.Fatalf("put %d failed: %x", i, out)
		}
	}
	// Duplicate put is idempotent.
	h0 := sha256.Sum256(payloads[0])
	dupBody := npFields(t, []npField{
		{1, tid}, {2, u32b(0)}, {3, payloads[0]}, {4, h0[:]}, {5, u64b(0)},
	})
	if op, _ := b.dispatch(opXferPut, dupBody); op != opXferPut {
		t.Fatal("duplicate put must ACK")
	}
	// Resume as recipient.
	resBody := npFields(t, []npField{{1, tid}, {2, mbox}, {3, sec}})
	op, out = b.dispatch(opXferResume, resBody)
	if op != opXferResume {
		t.Fatalf("resume failed: %x", out)
	}
	count, highest := parseProgress(t, out)
	if count != nChunks || highest != nChunks {
		t.Fatalf("progress mismatch: %d/%d", highest, count)
	}
	// Get + verify each chunk.
	for i, want := range payloads {
		getBody := npFields(t, []npField{{1, tid}, {2, u32b(uint32(i))}, {3, mbox}, {4, sec}})
		op, out = b.dispatch(opXferGet, getBody)
		if op != opXferGet {
			t.Fatalf("get %d failed: %x", i, out)
		}
		got, h := parseChunk(t, out)
		if !bytes.Equal(got, want) {
			t.Fatalf("chunk %d mismatch", i)
		}
		if hh := sha256.Sum256(got); !bytes.Equal(hh[:], h) {
			t.Fatalf("chunk %d hash mismatch", i)
		}
	}
	// Complete with manifest hash.
	mh := sha256.Sum256([]byte("manifest"))
	compBody := npFields(t, []npField{{1, tid}, {2, mh[:]}})
	if op, _ := b.dispatch(opXferComplete, compBody); op != opXferComplete {
		t.Fatal("complete failed")
	}
	// Unknown transfer errors with op 0.
	badPut := npFields(t, []npField{
		{1, bytes.Repeat([]byte{7}, 16)}, {2, u32b(0)}, {3, []byte("x")}, {4, bytes.Repeat([]byte{8}, 32)}, {5, u64b(0)},
	})
	if op, _ := b.dispatch(opXferPut, badPut); op != opError {
		t.Fatal("unknown transfer must error")
	}
}

func TestBridgeXferCancel(t *testing.T) {
	r := newFileRig(t)
	b := r.b

	regBody := npFields(t, []npField{{1, []byte("zed")}, {2, []byte(r.routerURL)}})
	op, out := b.dispatch(opRegister, regBody)
	if op != opRegister {
		t.Fatalf("register failed: %x", out)
	}
	mbox, sec := parseRegister(t, out)

	zedPub := []byte(b.xfer.scoped["zed"].Public().(ed25519.PublicKey))
	createBody := npFields(t, []npField{
		{1, u64b(1024)}, {2, u32b(1024)}, {3, u32b(1)},
		{4, []byte("m")}, {5, nil}, {6, zedPub},
	})
	op, out = b.dispatch(opXferCreate, createBody)
	if op != opXferCreate {
		t.Fatalf("create failed: %x", out)
	}
	tid := parseCreated(t, out)

	// Wrong secret cannot cancel.
	badCancel := npFields(t, []npField{{1, tid}, {2, mbox}, {3, bytes.Repeat([]byte{9}, 32)}})
	if op, _ := b.dispatch(opXferCancel, badCancel); op != opError {
		t.Fatal("wrong-secret cancel must error")
	}
	// Owner cancel works.
	cancelBody := npFields(t, []npField{{1, tid}, {2, mbox}, {3, sec}})
	if op, _ := b.dispatch(opXferCancel, cancelBody); op != opXferCancel {
		t.Fatal("owner cancel must succeed")
	}
	// Transfer is gone: resume by mailbox creds fails.
	resBody := npFields(t, []npField{{1, tid}, {2, mbox}, {3, sec}})
	if op, _ := b.dispatch(opXferResume, resBody); op != opError {
		t.Fatal("resume after cancel must error")
	}
}

// --- response parsers (mirror the response schemas) ---

func fieldMap(t *testing.T, body []byte) map[uint8][]byte {
	t.Helper()
	fields, err := nanopackDecode(t, body)
	if err != nil {
		t.Fatal(err)
	}
	return fields
}

func parseRegister(t *testing.T, body []byte) ([]byte, []byte) {
	t.Helper()
	m := fieldMap(t, body)
	if len(m[1]) != 16 || len(m[2]) != 32 || len(m[3]) == 0 {
		t.Fatalf("bad register result: %v", m)
	}
	return append([]byte(nil), m[1]...), append([]byte(nil), m[2]...)
}

func parseResolve(t *testing.T, body []byte) ([]byte, string) {
	t.Helper()
	m := fieldMap(t, body)
	if len(m[1]) != 16 || len(m[2]) == 0 {
		t.Fatalf("bad resolve result: %v", m)
	}
	return append([]byte(nil), m[1]...), string(m[2])
}

func parsePoll(t *testing.T, body []byte) [][]byte {
	t.Helper()
	m := fieldMap(t, body)
	blob := m[1]
	var count uint32
	if len(m[2]) == 4 {
		count = uint32(blob2u32(m[2]))
	}
	var out [][]byte
	pos := 0
	for uint32(len(out)) < count {
		if pos+4 > len(blob) {
			t.Fatal("poll truncated")
		}
		n := int(uint32(blob[pos])<<24 | uint32(blob[pos+1])<<16 | uint32(blob[pos+2])<<8 | uint32(blob[pos+3]))
		pos += 4
		out = append(out, append([]byte(nil), blob[pos:pos+n]...))
		pos += n
	}
	return out
}

func blob2u32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func parseCreated(t *testing.T, body []byte) []byte {
	t.Helper()
	m := fieldMap(t, body)
	if len(m[1]) != 16 {
		t.Fatalf("bad created: %v", m)
	}
	return append([]byte(nil), m[1]...)
}

func parseCreatedTicket(t *testing.T, body []byte) (tid, secret []byte, shard string) {
	t.Helper()
	m := fieldMap(t, body)
	if len(m[1]) != 16 || len(m[3]) != 32 || len(m[4]) == 0 {
		t.Fatalf("bad created ticket: %v", m)
	}
	return append([]byte(nil), m[1]...), append([]byte(nil), m[3]...), string(m[4])
}

// TestBridgeTicketFlow proves the recipient side needs no create state:
// a second, stateless bridge resumes/gets with the ticket + shard alone.
func TestBridgeTicketFlow(t *testing.T) {
	r := newFileRig(t)
	b := r.b

	regBody := npFields(t, []npField{{1, []byte("sender")}, {2, []byte(r.routerURL)}})
	op, out := b.dispatch(opRegister, regBody)
	if op != opRegister {
		t.Fatalf("register failed: %x", out)
	}
	senderPub := []byte(b.xfer.scoped["sender"].Public().(ed25519.PublicKey))
	createBody := npFields(t, []npField{
		{1, u64b(2048)}, {2, u32b(1024)}, {3, u32b(2)},
		{4, []byte("m")}, {5, nil}, {6, senderPub},
	})
	op, out = b.dispatch(opXferCreate, createBody)
	if op != opXferCreate {
		t.Fatalf("create failed: %x", out)
	}
	tid, ticket, shard := parseCreatedTicket(t, out)
	if shard != r.shardURL {
		t.Fatalf("bad shard %q", shard)
	}
	for i, fill := range []byte{0x11, 0x22} {
		p := bytes.Repeat([]byte{fill}, 1024)
		h := sha256.Sum256(p)
		putBody := npFields(t, []npField{
			{1, tid}, {2, u32b(uint32(i))}, {3, p}, {4, h[:]}, {5, u64b(uint64(i * 1024))},
		})
		if op, _ := b.dispatch(opXferPut, putBody); op != opXferPut {
			t.Fatalf("put %d failed", i)
		}
	}

	// Recipient bridge: fresh state, only the ticket + shard URL.
	b2 := &bridge{mailboxes: map[string]*mailbox{}, http: b.http, xfer: newXferState(), routerURL: r.routerURL}
	b2.running = true
	resBody := npFields(t, []npField{{1, tid}, {4, ticket}, {5, []byte(shard)}})
	op, out = b2.dispatch(opXferResume, resBody)
	if op != opXferResume {
		t.Fatalf("ticket resume failed: %x", out)
	}
	if count, highest := parseProgress(t, out); count != 2 || highest != 2 {
		t.Fatalf("bad ticket progress %d/%d", highest, count)
	}
	for i, fill := range []byte{0x11, 0x22} {
		getBody := npFields(t, []npField{{1, tid}, {2, u32b(uint32(i))}, {5, ticket}, {6, []byte(shard)}})
		op, out = b2.dispatch(opXferGet, getBody)
		if op != opXferGet {
			t.Fatalf("ticket get %d failed: %x", i, out)
		}
		got, _ := parseChunk(t, out)
		if !bytes.Equal(got, bytes.Repeat([]byte{fill}, 1024)) {
			t.Fatalf("chunk %d mismatch", i)
		}
	}
	// Wrong ticket -> op 0 error.
	badBody := npFields(t, []npField{{1, tid}, {4, bytes.Repeat([]byte{9}, 32)}, {5, []byte(shard)}})
	if op, _ := b2.dispatch(opXferResume, badBody); op != opError {
		t.Fatal("wrong ticket must error")
	}
}

func parseProgress(t *testing.T, body []byte) (uint32, uint32) {
	t.Helper()
	m := fieldMap(t, body)
	var highest, count uint32
	if len(m[1]) == 4 {
		highest = blob2u32(m[1])
	}
	if len(m[5]) == 4 {
		count = blob2u32(m[5])
	}
	return count, highest
}

func parseChunk(t *testing.T, body []byte) ([]byte, []byte) {
	t.Helper()
	m := fieldMap(t, body)
	if len(m[1]) == 0 || len(m[2]) != 32 {
		t.Fatalf("bad chunk: %v", m)
	}
	return append([]byte(nil), m[1]...), append([]byte(nil), m[2]...)
}
