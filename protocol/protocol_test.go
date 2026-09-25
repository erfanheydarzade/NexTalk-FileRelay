package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/erfanheydarzade/nanopack"
)

// Shared vectors: Go generates, TS must decode byte-identically (and vice versa).
// Run: go test ./protocol/ -run TestVectors -v ; vectors are also dumped to testdata/.

func TestSendMessageRoundTrip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var mailbox [16]byte
	copy(mailbox[:], "0123456789abcdef")
	var nonce [16]byte
	copy(nonce[:], "0123456789abcdef")
	env := []byte("opaque-encrypted-bytes")
	var spub [32]byte
	copy(spub[:], pub)
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	m := &SendMessage{
		MailboxID: mailbox[:], Envelope: env, SenderPub: pub,
		Timestamp: 1750000000000, Nonce: nonce[:], Signature: sig,
		TTLHintSec: 1209600, Burn: 1,
	}
	body, err := MarshalSendMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalSendMessage(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Envelope, env) || got.Timestamp != 1750000000000 || got.Burn != 1 {
		t.Fatal("round trip mismatch")
	}
}

func TestMalformedRejected(t *testing.T) {
	cases := [][]byte{
		{},
		{0x05},
		{0x01, 0x01},
		{0x01, 0x01, 0x80},       // truncated varint
		{0x01, 0x01, 0x05, 0x41}, // declared len > body
	}
	for i, c := range cases {
		if _, err := nanopack.DecodeID(c); err == nil {
			t.Fatalf("case %d should fail", i)
		}
	}
	// Field ID 0 is accepted by DecodeID (raw path) but rejected by
	// schema-resolved Decode — FileRelay ignores unknown IDs on decode,
	// required-field validation happens in Validate* instead.
	schema := nanopack.MustSchema(57, "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8")
	if _, err := nanopack.Decode(schema, []byte{0x01, 0x00, 0x01, 0x41}); err == nil {
		t.Fatal("field id 0 must fail schema-resolved decode")
	}
	// oversized envelope declared
	big := &SendMessage{MailboxID: make([]byte, 16), Envelope: make([]byte, MaxMessageBytes+1), SenderPub: make([]byte, 32), Nonce: make([]byte, 16), Signature: make([]byte, 64)}
	if _, err := MarshalSendMessage(big); err == nil {
		t.Fatal("oversized envelope must fail")
	}
	// bad chunk index
	c := &ChunkUpload{TransferID: make([]byte, 16), Index: MaxChunksPerTransfer, Payload: []byte{1}, Offset: 0}
	if _, err := MarshalChunkUpload(c); err == nil {
		t.Fatal("out-of-range chunk must fail")
	}
}

func TestChunkHashVerifies(t *testing.T) {
	payload := []byte("chunk-bytes")
	c := &ChunkUpload{TransferID: make([]byte, 16), Index: 3, Payload: payload, Offset: 3 * 1024}
	h := sha256.Sum256(payload)
	c.ChunkHash = h[:]
	body, err := MarshalChunkUpload(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalChunkUpload(body)
	if err != nil {
		t.Fatal(err)
	}
	h2 := sha256.Sum256(got.Payload)
	if !bytes.Equal(h2[:], got.ChunkHash) {
		t.Fatal("chunk hash mismatch")
	}
}

func TestTransferCreateBounds(t *testing.T) {
	if err := ValidateTransferCreate(1024, 512, 2); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTransferCreate(1025, 512, 2); err == nil {
		t.Fatal("count mismatch must fail: 1025/512 needs 3 chunks")
	}
	if err := ValidateTransferCreate(1<<30+1, 65536, 16385); err == nil {
		t.Fatal("oversize must fail")
	}
}

func TestStreamFramingRoundTrip(t *testing.T) {
	body := []byte{0x02, 0x01, 0x01, 0x02, 0x02, 0x68, 0x69}
	framed := WrapStream(SchemaSendMessage, body)
	schema, out, _, err := UnwrapStream(framed)
	if err != nil {
		t.Fatal(err)
	}
	if schema != SchemaSendMessage || !bytes.Equal(out, body) {
		t.Fatal("stream framing mismatch")
	}
	if _, _, _, err := UnwrapStream(framed[:5]); err == nil {
		t.Fatal("truncated stream must fail")
	}
}
