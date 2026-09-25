package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func bytes32(fill byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return b
}

func bytes64() []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func hashOf(b []byte) [32]byte { return sha256.Sum256(b) }

// TestDumpVectors writes deterministic bodies for cross-language checks.
// Other-language codecs must decode these byte-identically (testdata/vectors.json).
func TestDumpVectors(t *testing.T) {
	mk := func() []byte {
		m := &SendMessage{
			MailboxID:  []byte("0123456789abcdef"),
			Envelope:   []byte("opaque-encrypted-bytes"),
			SenderPub:  bytes32(byte(0xAB)),
			Timestamp:  1750000000000,
			Nonce:      []byte("0123456789abcdef"),
			Signature:  bytes64(),
			TTLHintSec: 1209600,
			Burn:       1,
		}
		body, err := MarshalSendMessage(m)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	chunk := func() []byte {
		c := &ChunkUpload{
			TransferID: []byte("0123456789abcdef"),
			Index:      3,
			Payload:    []byte("chunk-bytes"),
			Offset:     3 * 1024,
		}
		h := hashOf(c.Payload)
		c.ChunkHash = h[:]
		body, err := MarshalChunkUpload(c)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	vec := map[string]string{
		"sendmessage_57": hex.EncodeToString(mk()),
		"chunkupload_65": hex.EncodeToString(chunk()),
	}
	data, _ := json.MarshalIndent(vec, "", "  ")
	if err := os.MkdirAll("../testdata", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../testdata/vectors.json", data, 0644); err != nil {
		t.Fatal(err)
	}
}
