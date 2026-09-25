// Package protocol — canonical binary authentication.
//
// All Ed25519 signatures cover raw binary canonical bytes, never hex/JSON.
// Domains are ASCII + 0x00 separator, then fixed-width big-endian fields.
package protocol

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"time"
)

var (
	DomainMsgSend        = []byte("FR1/MSG-SEND\x00")
	DomainRegister       = []byte("FR1/REGISTER\x00")
	DomainChunkPut       = []byte("FR1/CHUNK-PUT\x00")
	DomainRoutingTable   = []byte("FR1/ROUTING-TABLE\x00")
	DomainReplicateMsg   = []byte("FR1/REPLICATE-MSG\x00")
	DomainReplicateChunk = []byte("FR1/REPLICATE-CHUNK\x00")
	DomainXferCreate     = []byte("FR1/XFER-CREATE\x00")
	DomainXferComplete   = []byte("FR1/XFER-COMPLETE\x00")
)

// MailboxID derives the 16-byte opaque mailbox ID. Only the router computes
// this (it holds SERVER_SECRET). Shards treat the output as opaque.
func MailboxID(serverSecret []byte, edPubHex string) [16]byte {
	m := hmac.New(sha256.New, serverSecret)
	m.Write([]byte(strings.ToLower(edPubHex)))
	sum := m.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// MailboxIDFromPub derives the mailbox ID from a raw 32B Ed25519 pubkey.
// Canonical input is lowercase hex of the raw pubkey (matches MailboxID).
func MailboxIDFromPub(serverSecret []byte, pub []byte) [16]byte {
	const hextable = "0123456789abcdef"
	lower := make([]byte, 0, len(pub)*2)
	for _, b := range pub {
		lower = append(lower, hextable[b>>4], hextable[b&0x0f])
	}
	m := hmac.New(sha256.New, serverSecret)
	m.Write(lower)
	sum := m.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// CanonicalMsgSend = Domain ‖ sender_pub(32) ‖ mailbox_id(16) ‖ ts(BE64) ‖ nonce(16) ‖ sha256(envelope)(32).
func CanonicalMsgSend(senderPub [32]byte, mailboxID [16]byte, timestampMS uint64, nonce [16]byte, envelope []byte) []byte {
	h := sha256.Sum256(envelope)
	out := make([]byte, 0, len(DomainMsgSend)+32+16+8+16+32)
	out = append(out, DomainMsgSend...)
	out = append(out, senderPub[:]...)
	out = append(out, mailboxID[:]...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], timestampMS)
	out = append(out, b[:]...)
	out = append(out, nonce[:]...)
	out = append(out, h[:]...)
	return out
}

// CanonicalChunkPut = Domain ‖ sender_pub(32) ‖ transfer_id(16) ‖ index(BE32) ‖ ts(BE64) ‖ sha256(payload)(32).
func CanonicalChunkPut(senderPub [32]byte, transferID [16]byte, index uint32, timestampMS uint64, payload []byte) []byte {
	h := sha256.Sum256(payload)
	out := make([]byte, 0, len(DomainChunkPut)+32+16+4+8+32)
	out = append(out, DomainChunkPut...)
	out = append(out, senderPub[:]...)
	out = append(out, transferID[:]...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], index)
	out = append(out, b4[:]...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], timestampMS)
	out = append(out, b8[:]...)
	out = append(out, h[:]...)
	return out
}

// SignMsgSend signs a SendMessage/ChunkUpload-class request.
func SignMsgSend(priv ed25519.PrivateKey, mailboxID [16]byte, timestampMS uint64, nonce [16]byte, envelope []byte) []byte {
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return ed25519.Sign(priv, CanonicalMsgSend(pub, mailboxID, timestampMS, nonce, envelope))
}

// CanonicalRegister = Domain ‖ client_pub(32) ‖ ts(BE64) ‖ nonce(16).
func CanonicalRegister(clientPub [32]byte, timestampMS uint64, nonce [16]byte) []byte {
	out := make([]byte, 0, len(DomainRegister)+32+8+16)
	out = append(out, DomainRegister...)
	out = append(out, clientPub[:]...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], timestampMS)
	out = append(out, b[:]...)
	out = append(out, nonce[:]...)
	return out
}

// VerifyRegister verifies a Register signature + skew.
func VerifyRegister(pub ed25519.PublicKey, timestampMS uint64, nonce [16]byte, sig []byte, nowMillis int64) error {
	if len(pub) != 32 || len(sig) != 64 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "bad pub/sig length"}
	}
	var p [32]byte
	copy(p[:], pub)
	if !ed25519.Verify(pub, CanonicalRegister(p, timestampMS, nonce), sig) {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "signature verification failed"}
	}
	return CheckSkew(timestampMS, nowMillis)
}

// CanonicalXferCreate = Domain ‖ sender_pub(32) ‖ mailbox(16, zeros if empty)
// ‖ total(BE64) ‖ chunkSize(BE32) ‖ chunkCount(BE32) ‖ ts(BE64) ‖ nonce(16) ‖ sha256(manifest)(32).
func CanonicalXferCreate(senderPub [32]byte, mailboxID [16]byte, total uint64, chunkSize, chunkCount uint32, timestampMS uint64, nonce [16]byte, manifest []byte) []byte {
	h := sha256.Sum256(manifest)
	out := make([]byte, 0, len(DomainXferCreate)+32+16+8+4+4+8+16+32)
	out = append(out, DomainXferCreate...)
	out = append(out, senderPub[:]...)
	out = append(out, mailboxID[:]...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], total)
	out = append(out, b8[:]...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], chunkSize)
	out = append(out, b4[:]...)
	binary.BigEndian.PutUint32(b4[:], chunkCount)
	out = append(out, b4[:]...)
	binary.BigEndian.PutUint64(b8[:], timestampMS)
	out = append(out, b8[:]...)
	out = append(out, nonce[:]...)
	out = append(out, h[:]...)
	return out
}

// VerifyXferCreate verifies a TransferCreate signature + skew.
func VerifyXferCreate(pub ed25519.PublicKey, mailboxID [16]byte, total uint64, chunkSize, chunkCount uint32, timestampMS uint64, nonce [16]byte, manifest, sig []byte, nowMillis int64) error {
	if len(pub) != 32 || len(sig) != 64 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "bad pub/sig length"}
	}
	var p [32]byte
	copy(p[:], pub)
	if !ed25519.Verify(pub, CanonicalXferCreate(p, mailboxID, total, chunkSize, chunkCount, timestampMS, nonce, manifest), sig) {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "signature verification failed"}
	}
	return CheckSkew(timestampMS, nowMillis)
}

// CanonicalXferComplete = Domain ‖ sender_pub(32) ‖ transfer_id(16) ‖ sha256(manifestBytes?)...
// Note: Complete binds manifest_hash (32B already a hash), not raw manifest.
func CanonicalXferComplete(senderPub [32]byte, transferID [16]byte, manifestHash [32]byte, timestampMS uint64, nonce [16]byte) []byte {
	out := make([]byte, 0, len(DomainXferComplete)+32+16+32+8+16)
	out = append(out, DomainXferComplete...)
	out = append(out, senderPub[:]...)
	out = append(out, transferID[:]...)
	out = append(out, manifestHash[:]...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], timestampMS)
	out = append(out, b[:]...)
	out = append(out, nonce[:]...)
	return out
}

// VerifyXferComplete verifies a TransferComplete signature + skew.
func VerifyXferComplete(pub ed25519.PublicKey, transferID [16]byte, manifestHash [32]byte, timestampMS uint64, nonce [16]byte, sig []byte, nowMillis int64) error {
	if len(pub) != 32 || len(sig) != 64 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "bad pub/sig length"}
	}
	var p [32]byte
	copy(p[:], pub)
	if !ed25519.Verify(pub, CanonicalXferComplete(p, transferID, manifestHash, timestampMS, nonce), sig) {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "signature verification failed"}
	}
	return CheckSkew(timestampMS, nowMillis)
}

// CanonicalRoutingTable = Domain ‖ version(BE32) ‖ generated(BE64) ‖ expires(BE64)
// ‖ algo(u8) ‖ shardHash(32) ‖ router_pub(32), where shardHash covers encodeShardList-equivalent.
func CanonicalRoutingTable(version uint32, generated, expires uint64, algo uint8, shards []string, routerPub [32]byte) []byte {
	shardHash := Sha256ShardList(shards)
	out := make([]byte, 0, len(DomainRoutingTable)+4+8+8+1+32+32)
	out = append(out, DomainRoutingTable...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], version)
	out = append(out, b4[:]...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], generated)
	out = append(out, b8[:]...)
	binary.BigEndian.PutUint64(b8[:], expires)
	out = append(out, b8[:]...)
	out = append(out, algo)
	out = append(out, shardHash[:]...)
	out = append(out, routerPub[:]...)
	return out
}

// Sha256ShardList hashes the canonical shard list encoding (u16 len + bytes each).
func Sha256ShardList(shards []string) [32]byte {
	h := sha256.New()
	var lb [2]byte
	for _, s := range shards {
		b := []byte(s)
		lb[0] = byte(len(b) >> 8)
		lb[1] = byte(len(b))
		h.Write(lb[:])
		h.Write(b)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// CheckSkew enforces ±MaxClockSkewMillis.
func CheckSkew(timestampMS uint64, nowMillis int64) error {
	dt := nowMillis - int64(timestampMS)
	if dt < 0 {
		dt = -dt
	}
	if dt > MaxClockSkewMillis {
		return &ProtocolError{Code: ErrExpiredRequest, Detail: "timestamp outside skew window"}
	}
	return nil
}

// VerifyMsgSend verifies with explicit nowMillis for skew checking.
func VerifyMsgSend(pub ed25519.PublicKey, mailboxID [16]byte, timestampMS uint64, nonce [16]byte, envelope, sig []byte, nowMillis int64) error {
	if len(pub) != 32 || len(sig) != 64 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "bad pub/sig length"}
	}
	var p [32]byte
	copy(p[:], pub)
	if !ed25519.Verify(pub, CanonicalMsgSend(p, mailboxID, timestampMS, nonce, envelope), sig) {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "signature verification failed"}
	}
	dt := nowMillis - int64(timestampMS)
	if dt < 0 {
		dt = -dt
	}
	if dt > MaxClockSkewMillis {
		return &ProtocolError{Code: ErrExpiredRequest, Detail: "timestamp outside skew window"}
	}
	_ = time.Now // keep time import if skew policy moves to server clock
	return nil
}
