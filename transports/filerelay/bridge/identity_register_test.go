package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
	"github.com/erfanheydarzade/nanopack"
)

func TestIdentityRegisterUsesFileRelayProtocol(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	ts := uint64(time.Now().UnixMilli())
	var pub32 [32]byte
	copy(pub32[:], pub)
	sig := ed25519.Sign(priv, protocol.CanonicalRegister(pub32, ts, nonce))

	wantMailbox := make([]byte, 16)
	wantSecret := make([]byte, 32)
	if _, err := rand.Read(wantMailbox); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(wantSecret); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != protocol.RouteRegister {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != protocol.ContentType {
			t.Fatalf("content-type = %q, want %q", got, protocol.ContentType)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := protocol.UnmarshalRegister(raw)
		if err != nil {
			t.Fatal(err)
		}
		if string(req.ClientPub) != string(pub) || req.Timestamp != ts || string(req.Nonce) != string(nonce[:]) || string(req.Signature) != string(sig) {
			t.Fatal("identity registration proof was changed by the bridge")
		}
		body, err := protocol.MarshalRegisterResponse(&protocol.RegisterResponse{
			MailboxID: wantMailbox, ReadSecret: wantSecret, ShardURL: "http://shard.test",
			TableVersion: 7, ExpiresAt: ts + 60000,
		})
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", protocol.ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	b := &bridge{
		mailboxes: map[string]*mailbox{},
		http: srv.Client(),
		xfer: newXferState(),
		routerURL: srv.URL,
	}

	enc := &nanopack.Encoder{}
	enc.AddID(1, pub)
	enc.AddID(2, putU64(ts))
	enc.AddID(3, nonce[:])
	enc.AddID(4, sig)
	body, err := enc.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	op, raw := b.onIdentityRegister(body)
	if op != opIdentityRegister {
		t.Fatalf("op = %d, want %d; payload=%q", op, opIdentityRegister, raw)
	}
	res, err := unmarshalRegisterResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.MailboxID) != string(wantMailbox) || string(res.ReadSecret) != string(wantSecret) {
		t.Fatal("registration result mismatch")
	}
	if res.ShardURL != "http://shard.test" || res.RouterURL != srv.URL {
		t.Fatalf("unexpected result: %#v", res)
	}
}
