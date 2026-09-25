package protocol

import (
	"bytes"
	"testing"

	"github.com/erfanheydarzade/nanopack"
)

func TestTicketCreateResponseRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x7}, 32)
	r := &TransferCreateResponse{TransferID: bytes.Repeat([]byte{0x1}, 16), ExpiresAt: 999, ChunkSize: 1024, DownloadSecret: secret}
	body, err := MarshalTransferCreateResponse(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalTransferCreateResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.DownloadSecret, secret) || got.ChunkSize != 1024 {
		t.Fatal("round trip mismatch")
	}
	// Missing secret (pre-v1.1 server) is rejected.
	bare, _ := func() ([]byte, error) {
		enc := &nanopack.Encoder{}
		enc.AddID(1, r.TransferID)
		enc.AddID(2, putU64(r.ExpiresAt))
		enc.AddID(3, putU32(r.ChunkSize))
		return enc.Bytes()
	}()
	if _, err := UnmarshalTransferCreateResponse(bare); err == nil {
		t.Fatal("response without download_secret must fail")
	}
}

func TestTicketAuthMatrix(t *testing.T) {
	tid := bytes.Repeat([]byte{0x1}, 16)
	mbox := bytes.Repeat([]byte{0x2}, 16)
	sec := bytes.Repeat([]byte{0x3}, 32)
	ticket := bytes.Repeat([]byte{0x4}, 32)

	// Mailbox mode unchanged.
	mr, err := MarshalResumeRequest(&ResumeRequest{TransferID: tid, MailboxID: mbox, ReadSecret: sec})
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalResumeRequest(mr)
	if err != nil || got.TicketMode() {
		t.Fatal("mailbox mode must decode clean")
	}
	// Ticket mode: mailbox + secret empty.
	tr, err := MarshalResumeRequest(&ResumeRequest{TransferID: tid, Ticket: ticket})
	if err != nil {
		t.Fatal(err)
	}
	got, err = UnmarshalResumeRequest(tr)
	if err != nil || !got.TicketMode() || !bytes.Equal(got.Ticket, ticket) {
		t.Fatal("ticket mode must decode")
	}
	// Mixed credentials rejected.
	if _, err := MarshalResumeRequest(&ResumeRequest{TransferID: tid, MailboxID: mbox, ReadSecret: sec, Ticket: ticket}); err == nil {
		t.Fatal("mixed creds must fail marshal")
	}
	if _, err := MarshalResumeRequest(&ResumeRequest{TransferID: tid, MailboxID: mbox, Ticket: ticket}); err == nil {
		t.Fatal("mailbox+ticket must fail marshal")
	}
	if _, err := MarshalResumeRequest(&ResumeRequest{TransferID: tid, ReadSecret: sec, Ticket: ticket}); err == nil {
		t.Fatal("secret+ticket must fail marshal")
	}
	if _, err := MarshalResumeRequest(&ResumeRequest{TransferID: tid}); err == nil {
		t.Fatal("no creds must fail marshal")
	}
	// Bad ticket length rejected.
	if _, err := MarshalResumeRequest(&ResumeRequest{TransferID: tid, Ticket: []byte{1, 2, 3}}); err == nil {
		t.Fatal("short ticket must fail")
	}

	// Same matrix for ChunkDownload.
	md, err := MarshalChunkDownload(&ChunkDownload{TransferID: tid, Index: 0, Count: 1, MailboxID: mbox, ReadSecret: sec})
	if err != nil {
		t.Fatal(err)
	}
	gd, err := UnmarshalChunkDownload(md)
	if err != nil || gd.TicketMode() {
		t.Fatal("mailbox mode must decode clean")
	}
	td, err := MarshalChunkDownload(&ChunkDownload{TransferID: tid, Index: 0, Count: 1, Ticket: ticket})
	if err != nil {
		t.Fatal(err)
	}
	gd, err = UnmarshalChunkDownload(td)
	if err != nil || !gd.TicketMode() {
		t.Fatal("ticket mode must decode")
	}
	if _, err := MarshalChunkDownload(&ChunkDownload{TransferID: tid, Index: 0, Count: 1, MailboxID: mbox, ReadSecret: sec, Ticket: ticket}); err == nil {
		t.Fatal("mixed creds must fail marshal")
	}
}
