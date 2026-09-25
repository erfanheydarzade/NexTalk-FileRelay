package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
)

func testStore(t *testing.T) (*MemStore, [16]byte, []byte) {
	t.Helper()
	s := NewMemStore()
	var mid [16]byte
	copy(mid[:], bytes.Repeat([]byte{0xA}, 16))
	secret := bytes.Repeat([]byte{0xB}, 32)
	h := sha256.Sum256(secret)
	if _, err := s.CreateMailbox(context.Background(), mid, h); err != nil {
		t.Fatal(err)
	}
	return s, mid, secret
}

func testCreate(t *testing.T, s *MemStore, mid [16]byte, chunks uint32) ([16]byte, []byte) {
	t.Helper()
	size := uint64(chunks) * 1024
	tc := &protocol.TransferCreate{
		MailboxID: mid[:], TotalSize: size, ChunkSize: 1024, ChunkCount: chunks,
		Manifest: []byte("m"), SenderPub: bytes.Repeat([]byte{0xC}, 32),
		Timestamp: uint64(s.now()), Nonce: bytes.Repeat([]byte{0xD}, 16),
		Signature: bytes.Repeat([]byte{0xE}, 64),
	}
	tid, ticket, _, err := s.CreateTransfer(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ticket) != 32 {
		t.Fatal("create must mint a 32B ticket")
	}
	// Ticket must be stored hashed: raw bearer must not equal stored bytes trivially?
	// (Behavioral check: wrong ticket fails, right ticket works — below.)
	return tid, ticket
}

func testPut(t *testing.T, s *MemStore, tid [16]byte, index uint32, fill byte) {
	t.Helper()
	p := bytes.Repeat([]byte{fill}, 1024)
	h := sha256.Sum256(p)
	_, err := s.PutChunk(context.Background(), &protocol.ChunkUpload{
		TransferID: tid[:], Index: index, Payload: p, ChunkHash: h[:],
		Offset: uint64(index) * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTicketResumeGet(t *testing.T) {
	s, mid, secret := testStore(t)
	tid, ticket := testCreate(t, s, mid, 2)
	testPut(t, s, tid, 0, 0x11)
	testPut(t, s, tid, 1, 0x22)

	// Ticket resume works without any mailbox credential.
	rv, _, err := s.ResumeByTicket(context.Background(), tid, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if rv.ChunkCount != 2 || rv.HighestContiguous != 2 {
		t.Fatalf("bad resume: %+v", rv)
	}
	// Ticket get works.
	p, h, err := s.GetChunkByTicket(context.Background(), tid, ticket, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 1024 || len(h) != 32 {
		t.Fatal("bad chunk")
	}
	// Wrong ticket fails.
	if _, _, err := s.GetChunkByTicket(context.Background(), tid, bytes.Repeat([]byte{0x0}, 32), 0); err == nil {
		t.Fatal("wrong ticket must fail")
	}
	if _, _, err := s.ResumeByTicket(context.Background(), tid, bytes.Repeat([]byte{0x0}, 32)); err == nil {
		t.Fatal("wrong ticket must fail")
	}
	// Short ticket fails.
	if _, _, err := s.GetChunkByTicket(context.Background(), tid, []byte{1}, 0); err == nil {
		t.Fatal("short ticket must fail")
	}
	// Mailbox path unaffected.
	if _, _, err := s.Resume(context.Background(), tid, mid, secret); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GetChunk(context.Background(), tid, mid, secret, 0); err != nil {
		t.Fatal(err)
	}
	// Unknown transfer.
	var missing [16]byte
	if _, _, err := s.ResumeByTicket(context.Background(), missing, ticket); err == nil {
		t.Fatal("unknown transfer must fail")
	}
}

func TestTicketDoesNotGrantMailbox(t *testing.T) {
	s, mid, secret := testStore(t)
	tid, ticket := testCreate(t, s, mid, 1)
	testPut(t, s, tid, 0, 0x11)

	// Ticket cannot read mailbox messages (wrong domain entirely).
	if _, _, err := s.ReceiveMessages(context.Background(), mid, ticket, 10, false); err == nil {
		t.Fatal("ticket must not authenticate mailbox reads")
	}
	// Ticket cannot cancel the transfer (mailbox-owner op).
	if err := s.CancelTransfer(context.Background(), tid, mid, ticket); err == nil {
		t.Fatal("ticket must not cancel transfers")
	}
	// Owner cancel still works with the real secret.
	if err := s.CancelTransfer(context.Background(), tid, mid, secret); err != nil {
		t.Fatal(err)
	}
	// Ticket dies with the transfer.
	if _, _, err := s.ResumeByTicket(context.Background(), tid, ticket); err == nil {
		t.Fatal("cancelled transfer must reject tickets")
	}
}

func TestTicketExpiry(t *testing.T) {
	s, mid, _ := testStore(t)
	tid, ticket := testCreate(t, s, mid, 1)
	// Fast-forward past upload TTL max.
	s.Now = func() int64 { return 9999999999999 }
	if _, _, err := s.ResumeByTicket(context.Background(), tid, ticket); err == nil {
		t.Fatal("expired transfer must reject tickets")
	}
}
