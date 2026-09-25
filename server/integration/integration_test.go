// Package integration exercises the full binary path:
//
//	client -> router(register/resolve/table) -> shard(send/receive/ack,
//	create/put/resume/get/complete/cancel)
//
// Replication, PoW, and the NexTalk wrapper are out of scope.
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/router"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/shard"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/storage"
)

// rig wires one router to one shard sharing a single store + clock.
type rig struct {
	clock     *int64
	store     *storage.MemStore
	shardSrv  *httptest.Server
	routerSrv *httptest.Server
	secret    []byte
	routerPub [32]byte
}

func newRig(t *testing.T) *rig {
	t.Helper()
	now := time.Now().UnixMilli()
	clk := &now
	clock := func() int64 { return *clk }
	st := storage.NewMemStore()
	st.Now = clock
	st.NewID = func() [16]byte {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			panic(err)
		}
		return id
	}
	sh := shard.NewHandler(st, clock, shard.DefaultRateLimits())
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
		Version:    7,
		RouterPub:  rpubArr,
		RouterPriv: rpriv,
		Now:        clock,
	})
	_ = rpub
	routerSrv := httptest.NewServer(rh)
	t.Cleanup(routerSrv.Close)
	return &rig{clock: clk, store: st, shardSrv: shardSrv, routerSrv: routerSrv, secret: secret, routerPub: rpubArr}
}

func (r *rig) advance(ms int64) { *r.clock += ms }

// post posts a raw NanoPack body and returns status + body.
func post(t *testing.T, url string, schema byte, body []byte) (int, []byte, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", protocol.ContentType)
	req.Header.Set("X-FileRelay-Schema", string(rune('0'+int(schema)%10)))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	return res.StatusCode, b, res.Header
}

func mustRand(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func register(t *testing.T, r *rig, priv ed25519.PrivateKey) *protocol.RegisterResponse {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	var p [32]byte
	copy(p[:], pub)
	var nonce [16]byte
	copy(nonce[:], mustRand(t, 16))
	ts := uint64(*r.clock)
	sig := ed25519.Sign(priv, protocol.CanonicalRegister(p, ts, nonce))
	body, err := protocol.MarshalRegister(&protocol.Register{
		ClientPub: pub, Timestamp: ts, Nonce: nonce[:], Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, resp, _ := post(t, r.routerSrv.URL+protocol.RouteRegister, protocol.SchemaRegister, body)
	if st != 200 {
		pe, _ := protocol.UnmarshalError(resp)
		t.Fatalf("register status=%d err=%v", st, pe)
	}
	rr, err := protocol.UnmarshalRegisterResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func sendMsg(t *testing.T, r *rig, shardURL string, priv ed25519.PrivateKey, mailbox []byte, env []byte) *protocol.SendMessageResponse {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	var p [32]byte
	copy(p[:], pub)
	var mid [16]byte
	copy(mid[:], mailbox)
	var nonce [16]byte
	copy(nonce[:], mustRand(t, 16))
	ts := uint64(*r.clock)
	sig := ed25519.Sign(priv, protocol.CanonicalMsgSend(p, mid, ts, nonce, env))
	body, err := protocol.MarshalSendMessage(&protocol.SendMessage{
		MailboxID: mailbox, Envelope: env, SenderPub: pub,
		Timestamp: ts, Nonce: nonce[:], Signature: sig, TTLHintSec: 1209600, Burn: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, resp, _ := post(t, shardURL+protocol.RouteSend, protocol.SchemaSendMessage, body)
	if st != 200 {
		pe, _ := protocol.UnmarshalError(resp)
		t.Fatalf("send status=%d err=%v", st, pe)
	}
	sr, err := protocol.UnmarshalSendMessageResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	return sr
}

func receive(t *testing.T, r *rig, shardURL string, mailbox, secret []byte, limit uint8, peek uint8) *protocol.ReceiveMessagesResponse {
	t.Helper()
	body, err := protocol.MarshalReceiveMessages(&protocol.ReceiveMessages{
		MailboxID: mailbox, ReadSecret: secret, Limit: limit, Peek: peek,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, resp, _ := post(t, shardURL+protocol.RouteReceive, protocol.SchemaReceiveMessages, body)
	if st != 200 {
		pe, _ := protocol.UnmarshalError(resp)
		t.Fatalf("receive status=%d err=%v", st, pe)
	}
	rr, err := protocol.UnmarshalReceiveMessagesResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// --- message flow ---

func TestE2E_MessageFlow(t *testing.T) {
	r := newRig(t)
	_, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, recipPriv, _ := ed25519.GenerateKey(rand.Reader)

	senderCap := register(t, r, senderPriv)
	recipCap := register(t, r, recipPriv)
	if len(senderCap.MailboxID) != 16 || len(recipCap.ReadSecret) != 32 {
		t.Fatal("bad capabilities")
	}

	// Resolve recipient pubkey -> same mailbox + shard.
	recipPub := recipPriv.Public().(ed25519.PublicKey)
	resBody, err := protocol.MarshalResolve(&protocol.Resolve{ClientPub: recipPub})
	if err != nil {
		t.Fatal(err)
	}
	st, resRaw, _ := post(t, r.routerSrv.URL+protocol.RouteResolve, protocol.SchemaResolve, resBody)
	if st != 200 {
		t.Fatalf("resolve status=%d", st)
	}
	res, err := protocol.UnmarshalResolveResponse(resRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.MailboxID, recipCap.MailboxID) || res.ShardURL != recipCap.ShardURL {
		t.Fatal("resolve mismatch")
	}

	// Routing table signature verifies.
	tableReq, err := http.Get(r.routerSrv.URL + protocol.RouteTable)
	if err != nil {
		t.Fatal(err)
	}
	tableRaw, _ := io.ReadAll(io.LimitReader(tableReq.Body, 8192))
	tableReq.Body.Close()
	table, err := protocol.UnmarshalRoutingTable(tableRaw)
	if err != nil {
		t.Fatal(err)
	}
	var rpub [32]byte
	copy(rpub[:], table.RouterPub)
	canon := protocol.CanonicalRoutingTable(table.Version, table.GeneratedAt, table.ExpiresAt, table.Algorithm, table.Shards, rpub)
	if !ed25519.Verify(table.RouterPub, canon, table.Signature) {
		t.Fatal("routing table signature invalid")
	}

	// Send + drain.
	env := []byte("hello-e2e-opaque")
	sr := sendMsg(t, r, res.ShardURL, senderPriv, res.MailboxID, env)
	if sr.Accepted != 1 || sr.Queued != 1 || len(sr.MsgID) != 16 {
		t.Fatalf("bad send response %+v", sr)
	}
	got := receive(t, r, res.ShardURL, recipCap.MailboxID, recipCap.ReadSecret, 32, 0)
	if len(got.Messages) != 1 || !bytes.Equal(got.Messages[0].Envelope, env) || !got.Consumed {
		t.Fatalf("bad receive %+v", got)
	}
	empty := receive(t, r, res.ShardURL, recipCap.MailboxID, recipCap.ReadSecret, 32, 0)
	if len(empty.Messages) != 0 {
		t.Fatal("mailbox should be drained")
	}

	// Peek keeps, drain removes; ack-consumed removes peeked.
	sendMsg(t, r, res.ShardURL, senderPriv, res.MailboxID, []byte("m1"))
	sendMsg(t, r, res.ShardURL, senderPriv, res.MailboxID, []byte("m2"))
	peeked := receive(t, r, res.ShardURL, recipCap.MailboxID, recipCap.ReadSecret, 32, 1)
	if len(peeked.Messages) != 2 || peeked.Consumed {
		t.Fatalf("peek should keep: %+v", peeked)
	}
	ackBody, _ := protocol.MarshalMessageAck(&protocol.MessageAck{
		MailboxID: recipCap.MailboxID, ReadSecret: recipCap.ReadSecret,
		MsgIDs: [][]byte{peeked.Messages[0].MsgID}, Disposition: protocol.AckConsumed,
	})
	st, ackRaw, _ := post(t, res.ShardURL+protocol.RouteAck, protocol.SchemaMessageAck, ackBody)
	if st != 200 {
		t.Fatalf("ack status=%d", st)
	}
	ack, _ := protocol.UnmarshalMessageAckResponse(ackRaw)
	if ack.Acked != 1 || ack.Remaining != 1 {
		t.Fatalf("bad ack %+v", ack)
	}
	// received (non-consuming) ack is accounting-only.
	rest := receive(t, r, res.ShardURL, recipCap.MailboxID, recipCap.ReadSecret, 32, 1)
	ackRecv, _ := protocol.MarshalMessageAck(&protocol.MessageAck{
		MailboxID: recipCap.MailboxID, ReadSecret: recipCap.ReadSecret,
		MsgIDs: [][]byte{rest.Messages[0].MsgID}, Disposition: protocol.AckReceived,
	})
	st, ackRaw2, _ := post(t, res.ShardURL+protocol.RouteAck, protocol.SchemaMessageAck, ackRecv)
	if st != 200 {
		t.Fatalf("ack-recv status=%d", st)
	}
	if _, err := protocol.UnmarshalMessageAckResponse(ackRaw2); err != nil {
		t.Fatal(err)
	}
	still := receive(t, r, res.ShardURL, recipCap.MailboxID, recipCap.ReadSecret, 32, 0)
	if len(still.Messages) != 1 {
		t.Fatal("received-ack must not consume")
	}
}

// --- auth + validation errors ---

func TestE2E_AuthErrors(t *testing.T) {
	r := newRig(t)
	_, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	aCap := register(t, r, aPriv)
	bCap := register(t, r, bPriv)
	bPub := bPriv.Public().(ed25519.PublicKey)

	// Bad signature.
	badBody, _ := protocol.MarshalSendMessage(&protocol.SendMessage{
		MailboxID: bCap.MailboxID, Envelope: []byte("x"), SenderPub: aPriv.Public().(ed25519.PublicKey),
		Timestamp: uint64(*r.clock), Nonce: mustRand(t, 16), Signature: make([]byte, 64),
		TTLHintSec: 60, Burn: 1,
	})
	if st, raw, _ := post(t, aCap.ShardURL+protocol.RouteSend, protocol.SchemaSendMessage, badBody); st == 200 {
		t.Fatal("bad sig must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrAuthFailed {
			t.Fatalf("want auth_failed, got %v", pe)
		}
	}

	// Replay: same bytes twice.
	env := []byte("replay-me")
	pub := aPriv.Public().(ed25519.PublicKey)
	var p [32]byte
	copy(p[:], pub)
	var mid [16]byte
	copy(mid[:], bCap.MailboxID)
	var nonce [16]byte
	copy(nonce[:], mustRand(t, 16))
	ts := uint64(*r.clock)
	sig := ed25519.Sign(aPriv, protocol.CanonicalMsgSend(p, mid, ts, nonce, env))
	dup, _ := protocol.MarshalSendMessage(&protocol.SendMessage{
		MailboxID: bCap.MailboxID, Envelope: env, SenderPub: pub,
		Timestamp: ts, Nonce: nonce[:], Signature: sig, TTLHintSec: 60, Burn: 1,
	})
	if st, _, _ := post(t, aCap.ShardURL+protocol.RouteSend, protocol.SchemaSendMessage, dup); st != 200 {
		t.Fatal("first send must succeed")
	}
	if st, raw, _ := post(t, aCap.ShardURL+protocol.RouteSend, protocol.SchemaSendMessage, dup); st == 200 {
		t.Fatal("replay must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrReplayDetected {
			t.Fatalf("want replay_detected, got %v", pe)
		}
	}

	// Expired timestamp.
	oldTS := uint64(*r.clock - protocol.MaxClockSkewMillis - 5000)
	var n2 [16]byte
	copy(n2[:], mustRand(t, 16))
	sig2 := ed25519.Sign(aPriv, protocol.CanonicalMsgSend(p, mid, oldTS, n2, env))
	expBody, _ := protocol.MarshalSendMessage(&protocol.SendMessage{
		MailboxID: bCap.MailboxID, Envelope: env, SenderPub: pub,
		Timestamp: oldTS, Nonce: n2[:], Signature: sig2, TTLHintSec: 60, Burn: 1,
	})
	if st, raw, _ := post(t, aCap.ShardURL+protocol.RouteSend, protocol.SchemaSendMessage, expBody); st == 200 {
		t.Fatal("expired must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrExpiredRequest {
			t.Fatalf("want expired_request, got %v", pe)
		}
	}

	// Unknown mailbox.
	var unknownMid [16]byte
	copy(unknownMid[:], mustRand(t, 16))
	var n3 [16]byte
	copy(n3[:], mustRand(t, 16))
	ts3 := uint64(*r.clock)
	sig3 := ed25519.Sign(aPriv, protocol.CanonicalMsgSend(p, unknownMid, ts3, n3, env))
	unkBody, _ := protocol.MarshalSendMessage(&protocol.SendMessage{
		MailboxID: unknownMid[:], Envelope: env, SenderPub: pub,
		Timestamp: ts3, Nonce: n3[:], Signature: sig3, TTLHintSec: 60, Burn: 1,
	})
	if st, raw, _ := post(t, aCap.ShardURL+protocol.RouteSend, protocol.SchemaSendMessage, unkBody); st == 200 {
		t.Fatal("unknown mailbox must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrMailboxNotFound {
			t.Fatalf("want mailbox_not_found, got %v", pe)
		}
	}

	// Bad read secret.
	recvBody, _ := protocol.MarshalReceiveMessages(&protocol.ReceiveMessages{
		MailboxID: bCap.MailboxID, ReadSecret: mustRand(t, 32), Limit: 10, Peek: 0,
	})
	if st, raw, _ := post(t, bCap.ShardURL+protocol.RouteReceive, protocol.SchemaReceiveMessages, recvBody); st == 200 {
		t.Fatal("bad secret must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrAuthFailed {
			t.Fatalf("want auth_failed, got %v", pe)
		}
	}

	// Oversize envelope (marshal-side validation).
	big := make([]byte, protocol.MaxMessageBytes+1)
	if _, err := protocol.MarshalSendMessage(&protocol.SendMessage{
		MailboxID: bCap.MailboxID, Envelope: big, SenderPub: pub,
		Timestamp: ts3, Nonce: mustRand(t, 16), Signature: make([]byte, 64),
	}); err == nil {
		t.Fatal("oversize marshal must fail")
	}
	_ = bPub
}

// --- file flow ---

func createTransfer(t *testing.T, r *rig, shardURL string, priv ed25519.PrivateKey, mailbox []byte, total uint64, chunkSize, chunkCount uint32, manifest []byte) *protocol.TransferCreateResponse {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	var p [32]byte
	copy(p[:], pub)
	var mid [16]byte
	if len(mailbox) == 16 {
		copy(mid[:], mailbox)
	}
	var nonce [16]byte
	copy(nonce[:], mustRand(t, 16))
	ts := uint64(*r.clock)
	sig := ed25519.Sign(priv, protocol.CanonicalXferCreate(p, mid, total, chunkSize, chunkCount, ts, nonce, manifest))
	body, err := protocol.MarshalTransferCreate(&protocol.TransferCreate{
		MailboxID: mailbox, TotalSize: total, ChunkSize: chunkSize, ChunkCount: chunkCount,
		Manifest: manifest, SenderPub: pub, Timestamp: ts, Nonce: nonce[:], Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, raw, _ := post(t, shardURL+protocol.RouteTransferCreate, protocol.SchemaTransferCreate, body)
	if st != 200 {
		pe, _ := protocol.UnmarshalError(raw)
		t.Fatalf("create status=%d err=%v", st, pe)
	}
	cr, err := protocol.UnmarshalTransferCreateResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cr
}

func putChunk(t *testing.T, r *rig, shardURL string, tid []byte, index uint32, payload []byte, offset uint64) (int, []byte) {
	t.Helper()
	h := sha256.Sum256(payload)
	body, err := protocol.MarshalChunkUpload(&protocol.ChunkUpload{
		TransferID: tid, Index: index, Payload: payload, ChunkHash: h[:], Offset: offset,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, raw, _ := post(t, shardURL+protocol.RouteChunkPut, protocol.SchemaChunkUpload, body)
	return st, raw
}

func TestE2E_FileFlow(t *testing.T) {
	r := newRig(t)
	_, sPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, cPriv, _ := ed25519.GenerateKey(rand.Reader)
	sCap := register(t, r, sPriv)
	cCap := register(t, r, cPriv)

	const chunkSize = 1024
	const nChunks = 3
	total := uint64(chunkSize * nChunks)
	manifest := []byte("opaque-manifest")
	cr := createTransfer(t, r, sCap.ShardURL, sPriv, cCap.MailboxID, total, chunkSize, nChunks, manifest)
	if len(cr.TransferID) != 16 {
		t.Fatal("bad transfer id")
	}

	payloads := [][]byte{bytes.Repeat([]byte{0x11}, chunkSize), bytes.Repeat([]byte{0x22}, chunkSize), bytes.Repeat([]byte{0x33}, chunkSize)}
	for i, p := range payloads {
		st, raw := putChunk(t, r, sCap.ShardURL, cr.TransferID, uint32(i), p, uint64(i*chunkSize))
		if st != 200 {
			pe, _ := protocol.UnmarshalError(raw)
			t.Fatalf("put %d status=%d err=%v", i, st, pe)
		}
		ack, err := protocol.UnmarshalChunkAck(raw)
		if err != nil {
			t.Fatal(err)
		}
		if ack.HighestContiguous != uint32(i+1) {
			t.Fatalf("put %d highest=%d", i, ack.HighestContiguous)
		}
	}

	// Idempotent duplicate.
	if st, _ := putChunk(t, r, sCap.ShardURL, cr.TransferID, 1, payloads[1], chunkSize); st != 200 {
		t.Fatal("duplicate same bytes must ACK")
	}
	// Conflict: same index, different bytes.
	other := bytes.Repeat([]byte{0x99}, chunkSize)
	if st, raw := putChunk(t, r, sCap.ShardURL, cr.TransferID, 1, other, chunkSize); st == 200 {
		t.Fatal("conflict must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrChunkConflict {
			t.Fatalf("want chunk_conflict, got %v", pe)
		}
	}
	// Bad hash.
	badHashBody, _ := protocol.MarshalChunkUpload(&protocol.ChunkUpload{
		TransferID: cr.TransferID, Index: 0, Payload: payloads[0], ChunkHash: make([]byte, 32), Offset: 0,
	})
	if st, raw, _ := post(t, sCap.ShardURL+protocol.RouteChunkPut, protocol.SchemaChunkUpload, badHashBody); st == 200 {
		t.Fatal("bad hash must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrHashMismatch {
			t.Fatalf("want hash_mismatch, got %v", pe)
		}
	}
	// Out of range.
	if st, raw := putChunk(t, r, sCap.ShardURL, cr.TransferID, nChunks+5, payloads[0], 0); st == 200 {
		t.Fatal("out of range must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrChunkOutOfRange && pe.Code != protocol.ErrChunkInvalid {
			t.Fatalf("want out_of_range, got %v", pe)
		}
	}

	// Recipient resume: bitmap, nothing missing.
	resBody, _ := protocol.MarshalResumeRequest(&protocol.ResumeRequest{
		TransferID: cr.TransferID, MailboxID: cCap.MailboxID, ReadSecret: cCap.ReadSecret,
	})
	st, resRaw, _ := post(t, sCap.ShardURL+protocol.RouteResume, protocol.SchemaResumeRequest, resBody)
	if st != 200 {
		t.Fatalf("resume status=%d", st)
	}
	resume, err := protocol.UnmarshalResumeResponse(resRaw)
	if err != nil {
		t.Fatal(err)
	}
	if resume.ChunkCount != nChunks || resume.HighestContiguous != nChunks || resume.Encoding != protocol.ResumeBitmap {
		t.Fatalf("bad resume %+v", resume)
	}

	// Recipient downloads each chunk and verifies hash.
	var reassembled []byte
	for i := range payloads {
		dlBody, _ := protocol.MarshalChunkDownload(&protocol.ChunkDownload{
			TransferID: cr.TransferID, Index: uint32(i), Count: 1,
			MailboxID: cCap.MailboxID, ReadSecret: cCap.ReadSecret,
		})
		st, dlRaw, _ := post(t, sCap.ShardURL+protocol.RouteChunkGet, protocol.SchemaChunkDownload, dlBody)
		if st != 200 {
			t.Fatalf("get %d status=%d", i, st)
		}
		dl, err := protocol.UnmarshalChunkDownloadResponse(dlRaw)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(dl.Payload)
		if !bytes.Equal(h[:], dl.ChunkHash) || !bytes.Equal(dl.Payload, payloads[i]) {
			t.Fatalf("chunk %d corrupt", i)
		}
		reassembled = append(reassembled, dl.Payload...)
	}
	if len(reassembled) != int(total) {
		t.Fatal("reassembly size mismatch")
	}

	// Sender seals.
	mhash := sha256.Sum256(manifest)
	var tid [16]byte
	copy(tid[:], cr.TransferID)
	var spub [32]byte
	copy(spub[:], sPriv.Public().(ed25519.PublicKey))
	var cnonce [16]byte
	copy(cnonce[:], mustRand(t, 16))
	cts := uint64(*r.clock)
	csig := ed25519.Sign(sPriv, protocol.CanonicalXferComplete(spub, tid, mhash, cts, cnonce))
	compBody, _ := protocol.MarshalTransferComplete(&protocol.TransferComplete{
		TransferID: cr.TransferID, ManifestHash: mhash[:], MailboxID: cCap.MailboxID,
		SenderPub: sPriv.Public().(ed25519.PublicKey), Timestamp: cts, Nonce: cnonce[:], Signature: csig,
	})
	st, compRaw, _ := post(t, sCap.ShardURL+protocol.RouteComplete, protocol.SchemaTransferComplete, compBody)
	if st != 200 {
		pe, _ := protocol.UnmarshalError(compRaw)
		t.Fatalf("complete status=%d err=%v", st, pe)
	}
	comp, _ := protocol.UnmarshalTransferCompleteResponse(compRaw)
	if comp.Sealed != 1 || comp.Present != nChunks {
		t.Fatalf("bad complete %+v", comp)
	}
}

// --- sender-owned upload + ticket share ---
// Alice uploads to HER mailbox, shares (transfer_id + download ticket) with
// Bob inside a message; Bob fetches with the ticket alone — no mailbox,
// no read_secret, no session on the relay.

func TestE2E_TicketFlow(t *testing.T) {
	r := newRig(t)
	_, sPriv, _ := ed25519.GenerateKey(rand.Reader)
	sCap := register(t, r, sPriv)

	const chunkSize = 1024
	const nChunks = 2
	total := uint64(chunkSize * nChunks)
	manifest := []byte("ticket-manifest")
	// Sender-owned: bound to Alice's own mailbox.
	cr := createTransfer(t, r, sCap.ShardURL, sPriv, sCap.MailboxID, total, chunkSize, nChunks, manifest)
	if len(cr.DownloadSecret) != 32 {
		t.Fatal("create must mint a download ticket")
	}
	ticket := cr.DownloadSecret

	payloads := [][]byte{bytes.Repeat([]byte{0xAA}, chunkSize), bytes.Repeat([]byte{0xBB}, chunkSize)}
	for i, p := range payloads {
		if st, raw := putChunk(t, r, sCap.ShardURL, cr.TransferID, uint32(i), p, uint64(i*chunkSize)); st != 200 {
			pe, _ := protocol.UnmarshalError(raw)
			t.Fatalf("put %d: %v", i, pe)
		}
	}

	// Ticket resume WITHOUT any mailbox credential.
	resBody, _ := protocol.MarshalResumeRequest(&protocol.ResumeRequest{
		TransferID: cr.TransferID, Ticket: ticket,
	})
	st, resRaw, _ := post(t, sCap.ShardURL+protocol.RouteResume, protocol.SchemaResumeRequest, resBody)
	if st != 200 {
		pe, _ := protocol.UnmarshalError(resRaw)
		t.Fatalf("ticket resume: %v", pe)
	}
	resume, err := protocol.UnmarshalResumeResponse(resRaw)
	if err != nil {
		t.Fatal(err)
	}
	if resume.ChunkCount != nChunks || resume.HighestContiguous != nChunks {
		t.Fatalf("bad ticket resume %+v", resume)
	}

	// Ticket get WITHOUT any mailbox credential.
	for i, want := range payloads {
		dlBody, _ := protocol.MarshalChunkDownload(&protocol.ChunkDownload{
			TransferID: cr.TransferID, Index: uint32(i), Count: 1, Ticket: ticket,
		})
		st, dlRaw, _ := post(t, sCap.ShardURL+protocol.RouteChunkGet, protocol.SchemaChunkDownload, dlBody)
		if st != 200 {
			pe, _ := protocol.UnmarshalError(dlRaw)
			t.Fatalf("ticket get %d: %v", i, pe)
		}
		dl, err := protocol.UnmarshalChunkDownloadResponse(dlRaw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dl.Payload, want) {
			t.Fatalf("chunk %d mismatch", i)
		}
	}

	// Wrong ticket -> auth failure.
	badBody, _ := protocol.MarshalResumeRequest(&protocol.ResumeRequest{
		TransferID: cr.TransferID, Ticket: bytes.Repeat([]byte{0x0}, 32),
	})
	if st, raw, _ := post(t, sCap.ShardURL+protocol.RouteResume, protocol.SchemaResumeRequest, badBody); st == 200 {
		t.Fatal("wrong ticket must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrAuthFailed {
			t.Fatalf("want auth_failed, got %v", pe)
		}
	}

	// Owner mailbox path still works alongside tickets.
	ownBody, _ := protocol.MarshalResumeRequest(&protocol.ResumeRequest{
		TransferID: cr.TransferID, MailboxID: sCap.MailboxID, ReadSecret: sCap.ReadSecret,
	})
	if st, _, _ := post(t, sCap.ShardURL+protocol.RouteResume, protocol.SchemaResumeRequest, ownBody); st != 200 {
		t.Fatal("owner mailbox resume must still work")
	}

	// Owner cancel kills the ticket too.
	cancelBody, _ := protocol.MarshalTransferCancel(&protocol.TransferCancel{
		TransferID: cr.TransferID, MailboxID: sCap.MailboxID, Reason: 0, ReadSecret: sCap.ReadSecret,
	})
	if st, _, _ := post(t, sCap.ShardURL+protocol.RouteCancel, protocol.SchemaTransferCancel, cancelBody); st != 200 {
		t.Fatal("owner cancel must succeed")
	}
	if st, _, _ := post(t, sCap.ShardURL+protocol.RouteResume, protocol.SchemaResumeRequest, resBody); st == 200 {
		t.Fatal("ticket must die with the transfer")
	}
}

// --- cancel + expiry + quotas ---

func TestE2E_CancelExpireQuota(t *testing.T) {
	r := newRig(t)
	_, sPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, cPriv, _ := ed25519.GenerateKey(rand.Reader)
	sCap := register(t, r, sPriv)
	cCap := register(t, r, cPriv)

	// Cancel path (recipient holds read_secret).
	cr := createTransfer(t, r, sCap.ShardURL, sPriv, cCap.MailboxID, 2048, 1024, 2, []byte("m"))
	cancelBody, _ := protocol.MarshalTransferCancel(&protocol.TransferCancel{
		TransferID: cr.TransferID, MailboxID: cCap.MailboxID, Reason: 0, ReadSecret: cCap.ReadSecret,
	})
	if st, _, _ := post(t, sCap.ShardURL+protocol.RouteCancel, protocol.SchemaTransferCancel, cancelBody); st != 200 {
		t.Fatal("cancel must succeed")
	}
	resBody, _ := protocol.MarshalResumeRequest(&protocol.ResumeRequest{
		TransferID: cr.TransferID, MailboxID: cCap.MailboxID, ReadSecret: cCap.ReadSecret,
	})
	if st, _, _ := post(t, sCap.ShardURL+protocol.RouteResume, protocol.SchemaResumeRequest, resBody); st == 200 {
		t.Fatal("resumed cancelled transfer must fail")
	}

	// Upload TTL expiry.
	cr2 := createTransfer(t, r, sCap.ShardURL, sPriv, cCap.MailboxID, 1024, 1024, 1, []byte("m"))
	r.advance(protocol.UploadTTLMaxSeconds*1000 + 1000)
	p := bytes.Repeat([]byte{0xAA}, 1024)
	if st, raw := putChunk(t, r, sCap.ShardURL, cr2.TransferID, 0, p, 0); st == 200 {
		t.Fatal("put on expired transfer must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrTransferExpired && pe.Code != protocol.ErrTransferNotFound {
			t.Fatalf("want transfer_expired, got %v", pe)
		}
	}

	// Message TTL expiry + sweep.
	r2 := newRig(t)
	_, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	register(t, r2, aPriv)
	bCap := register(t, r2, bPriv)
	sendMsg(t, r2, bCap.ShardURL, aPriv, bCap.MailboxID, []byte("ephemeral"))
	r2.advance(protocol.MsgTTLSeconds*1000 + 1000)
	got := receive(t, r2, bCap.ShardURL, bCap.MailboxID, bCap.ReadSecret, 32, 0)
	if len(got.Messages) != 0 {
		t.Fatal("expired message must be gone")
	}
	if nm, _, _ := r2.store.Sweep(context.Background()); nm < 0 {
		t.Fatal("sweep failed")
	}

	// Queue quota: fill to MaxQueuedMessages, next fails.
	r3 := newRig(t)
	_, xPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, yPriv, _ := ed25519.GenerateKey(rand.Reader)
	register(t, r3, xPriv)
	yCap := register(t, r3, yPriv)
	for i := 0; i < protocol.MaxQueuedMessages; i++ {
		sendMsg(t, r3, yCap.ShardURL, xPriv, yCap.MailboxID, []byte{byte(i)})
	}
	// One more must be quota-exceeded.
	pub := xPriv.Public().(ed25519.PublicKey)
	var p32 [32]byte
	copy(p32[:], pub)
	var mid [16]byte
	copy(mid[:], yCap.MailboxID)
	var nonce [16]byte
	copy(nonce[:], mustRand(t, 16))
	ts := uint64(*r3.clock)
	env := []byte("overflow")
	sig := ed25519.Sign(xPriv, protocol.CanonicalMsgSend(p32, mid, ts, nonce, env))
	overBody, _ := protocol.MarshalSendMessage(&protocol.SendMessage{
		MailboxID: yCap.MailboxID, Envelope: env, SenderPub: pub,
		Timestamp: ts, Nonce: nonce[:], Signature: sig, TTLHintSec: 60, Burn: 1,
	})
	if st, raw, _ := post(t, yCap.ShardURL+protocol.RouteSend, protocol.SchemaSendMessage, overBody); st == 200 {
		t.Fatal("over-quota send must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrQuotaExceeded {
			t.Fatalf("want quota_exceeded, got %v", pe)
		}
	}

	// Active-transfer quota.
	r4 := newRig(t)
	_, mPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, nPriv, _ := ed25519.GenerateKey(rand.Reader)
	mCap := register(t, r4, mPriv)
	nCap := register(t, r4, nPriv)
	for i := 0; i < protocol.MaxActiveTransfersPerMailbox; i++ {
		createTransfer(t, r4, mCap.ShardURL, mPriv, nCap.MailboxID, 1024, 1024, 1, []byte("m"))
	}
	pub2 := mPriv.Public().(ed25519.PublicKey)
	var p2 [32]byte
	copy(p2[:], pub2)
	var mid2 [16]byte
	copy(mid2[:], nCap.MailboxID)
	var nonce2 [16]byte
	copy(nonce2[:], mustRand(t, 16))
	ts2 := uint64(*r4.clock)
	sig2 := ed25519.Sign(mPriv, protocol.CanonicalXferCreate(p2, mid2, 1024, 1024, 1, ts2, nonce2, []byte("m")))
	overXfer, _ := protocol.MarshalTransferCreate(&protocol.TransferCreate{
		MailboxID: nCap.MailboxID, TotalSize: 1024, ChunkSize: 1024, ChunkCount: 1,
		Manifest: []byte("m"), SenderPub: pub2, Timestamp: ts2, Nonce: nonce2[:], Signature: sig2,
	})
	if st, raw, _ := post(t, mCap.ShardURL+protocol.RouteTransferCreate, protocol.SchemaTransferCreate, overXfer); st == 200 {
		t.Fatal("over-quota transfer must fail")
	} else {
		pe, _ := protocol.UnmarshalError(raw)
		if pe.Code != protocol.ErrQuotaExceeded {
			t.Fatalf("want quota_exceeded, got %v", pe)
		}
	}
}
