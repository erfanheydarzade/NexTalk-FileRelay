package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestGoldenEnvelope pins byte-compat with NexTalk's internal/transport
// MarshalEnvelope: op=7 (status), req_id=1, payload=[0x00].
// NanoPack: [count]([id][len])* then bodies concatenated:
// 03 | 01 01 02 04 03 01 | 07 00 00 00 01 00
func TestGoldenEnvelope(t *testing.T) {
	raw, err := hex.DecodeString("03010102040301070000000100")
	if err != nil {
		t.Fatal(err)
	}
	env, err := unmarshalEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.op != opStatus || env.reqID != 1 || !bytes.Equal(env.payload, []byte{0x00}) {
		t.Fatalf("golden mismatch: %+v", env)
	}
	// Re-encode must be identical.
	back, err := marshalEnvelope(env.op, env.reqID, env.payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, raw) {
		t.Fatalf("re-encode mismatch: %x", back)
	}
}

func TestBridgeCodecs(t *testing.T) {
	init, err := unmarshalInitialize(mustInit(t))
	if err != nil {
		t.Fatal(err)
	}
	if init.transportID != bridgeID || init.apiVersion != transportAPIVer {
		t.Fatalf("init mismatch: %+v", init)
	}
	s, err := unmarshalSend(mustSend(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.frame) == 0 || s.frame[0] != 0x03 {
		t.Fatal("send frame mismatch")
	}
}

func mustInit(t *testing.T) []byte {
	t.Helper()
	// Initialize{transport_id="filerelay", api=1, config={}} hand-encoded:
	// header [03 | 01 09 02 01 03 00] then bodies ["filerelay" 01].
	var buf bytes.Buffer
	buf.Write([]byte{3, 1, 9, 2, 1, 3, 0})
	buf.WriteString("filerelay")
	buf.WriteByte(1)
	return buf.Bytes()
}

func mustSend(t *testing.T) []byte {
	t.Helper()
	frame := []byte{0x03, 0x01, 0x02}
	var buf bytes.Buffer
	buf.Write([]byte{3, 1, byte(len(frame)), 2, 0, 3, 0})
	buf.Write(frame)
	return buf.Bytes()
}
