// Package protocol — NanoPack schemas (authoritative field tables).
//
// Tags (bin:"N") drive `bingen` codegen; the hand-written Marshal/Unmarshal
// below match the generated shape exactly so `bingen` can take over later
// without wire change. Unknown field IDs are ignored on decode.
package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/erfanheydarzade/nanopack"
)

// Field cloning: nanopack FieldID.Data aliases input; retained structs clone.

//nanopack:schema id=51
type ErrorMsg struct {
	Code       uint32 `bin:"1"`
	Detail     string `bin:"2"`
	RetryAfter uint32 `bin:"3"`
}

//nanopack:schema id=57
type SendMessage struct {
	MailboxID  []byte `bin:"1"` // 16 B opaque
	Envelope   []byte `bin:"2"` // opaque NexTalk payload, <= MaxMessageBytes
	SenderPub  []byte `bin:"3"` // 32 B Ed25519 raw
	Timestamp  uint64 `bin:"4"`
	Nonce      []byte `bin:"5"` // 16 B
	Signature  []byte `bin:"6"` // 64 B over CanonicalMsgSend
	TTLHintSec uint32 `bin:"7"`
	Burn       uint8  `bin:"8"` // 1 = burn-after-read default
}

//nanopack:schema id=58
type SendMessageResponse struct {
	Accepted uint8  `bin:"1"` // 1 = stored by relay (NOT delivered/read)
	Queued   uint32 `bin:"2"`
	MsgID    []byte `bin:"3"` // 16 B server-assigned
}

//nanopack:schema id=59
type ReceiveMessages struct {
	MailboxID  []byte `bin:"1"` // 16 B
	ReadSecret []byte `bin:"2"` // 32 B raw
	Limit      uint8  `bin:"3"` // clamped to MaxBatchMessages
	Peek       uint8  `bin:"4"` // 1 = do not drain
}

//nanopack:schema id=61
type MessageAck struct {
	MailboxID   []byte   `bin:"1"`
	ReadSecret  []byte   `bin:"2"`
	MsgIDs      [][]byte `bin:"3"` // each 16 B; encoded as concatenated 16B records
	Disposition uint8    `bin:"4"` // 1=received, 2=consumed
}

//nanopack:schema id=63
type TransferCreate struct {
	MailboxID  []byte `bin:"1"` // recipient mailbox (optional for sender-owned staging: may be empty)
	TotalSize  uint64 `bin:"2"`
	ChunkSize  uint32 `bin:"3"`
	ChunkCount uint32 `bin:"4"`
	Manifest   []byte `bin:"5"` // opaque (encrypted manifest from NexTalk), <= 4 KiB
	SenderPub  []byte `bin:"6"`
	Timestamp  uint64 `bin:"7"`
	Nonce      []byte `bin:"8"`
	Signature  []byte `bin:"9"` // over transfer-create canonical (router/shard verifies)
}

//nanopack:schema id=65
type ChunkUpload struct {
	TransferID []byte `bin:"1"` // 16 B
	Index      uint32 `bin:"2"`
	Payload    []byte `bin:"3"` // <= MaxChunkBytes, opaque
	ChunkHash  []byte `bin:"4"` // 32 B sha256(payload), optional
	Offset     uint64 `bin:"5"` // must equal Index*ChunkSize
}

//nanopack:schema id=66
type ChunkAck struct {
	TransferID        []byte `bin:"1"`
	HighestContiguous uint32 `bin:"2"`
	MissingRanges     []byte `bin:"3"` // flat [start BE32,count BE32]* (empty = none missing)
	Bitmap            []byte `bin:"4"` // optional for <=256 chunks
	Encoding          uint8  `bin:"5"` // 0=bitmap, 1=ranges
}

// --- encode helpers ---

func putU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	out := make([]byte, 8)
	copy(out, b[:])
	return out
}

func putU32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	out := make([]byte, 4)
	copy(out, b[:])
	return out
}

func getU64(b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, nanopack.ErrShortBody
	}
	return binary.BigEndian.Uint64(b), nil
}

func getU32(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, nanopack.ErrShortBody
	}
	return binary.BigEndian.Uint32(b), nil
}

// MarshalSendMessage encodes SendMessage (no WrapPacket; see framing.go).
func MarshalSendMessage(m *SendMessage) ([]byte, error) {
	if err := ValidateSendMessage(m); err != nil {
		return nil, err
	}
	e := &nanopack.Encoder{}
	e.AddID(1, m.MailboxID)
	e.AddID(2, m.Envelope)
	e.AddID(3, m.SenderPub)
	e.AddID(4, putU64(m.Timestamp))
	e.AddID(5, m.Nonce)
	e.AddID(6, m.Signature)
	e.AddID(7, putU32(m.TTLHintSec))
	e.AddID(8, []byte{m.Burn})
	return e.Bytes()
}

// UnmarshalSendMessage decodes + validates bounds (never trusts lengths blindly).
func UnmarshalSendMessage(body []byte) (*SendMessage, error) {
	if err := CheckBodyLen(len(body), MaxRequestBytes); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	m := &SendMessage{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			m.MailboxID = append([]byte(nil), f.Data...)
		case 2:
			m.Envelope = append([]byte(nil), f.Data...)
		case 3:
			m.SenderPub = append([]byte(nil), f.Data...)
		case 4:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			m.Timestamp = v
		case 5:
			m.Nonce = append([]byte(nil), f.Data...)
		case 6:
			m.Signature = append([]byte(nil), f.Data...)
		case 7:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			m.TTLHintSec = v
		case 8:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			m.Burn = f.Data[0]
		}
	}
	if err := ValidateSendMessage(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ValidateSendMessage enforces limits before any state change.
func ValidateSendMessage(m *SendMessage) error {
	if len(m.MailboxID) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "mailbox_id must be 16 bytes"}
	}
	if len(m.Envelope) == 0 || len(m.Envelope) > MaxMessageBytes {
		return &ProtocolError{Code: ErrMessageTooLarge, Detail: "envelope size out of bounds"}
	}
	if len(m.SenderPub) != 32 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "sender_pub must be 32 bytes"}
	}
	if len(m.Nonce) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "nonce must be 16 bytes"}
	}
	if len(m.Signature) != 64 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "signature must be 64 bytes"}
	}
	return nil
}

// MarshalChunkUpload / UnmarshalChunkUpload with bounds.
func MarshalChunkUpload(c *ChunkUpload) ([]byte, error) {
	if err := ValidateChunkUpload(c); err != nil {
		return nil, err
	}
	e := &nanopack.Encoder{}
	e.AddID(1, c.TransferID)
	e.AddID(2, putU32(c.Index))
	e.AddID(3, c.Payload)
	if len(c.ChunkHash) > 0 {
		e.AddID(4, c.ChunkHash)
	}
	e.AddID(5, putU64(c.Offset))
	return e.Bytes()
}

// UnmarshalChunkUpload decodes chunk upload.
func UnmarshalChunkUpload(body []byte) (*ChunkUpload, error) {
	if err := CheckBodyLen(len(body), MaxChunkBytes+1024); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	c := &ChunkUpload{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			c.TransferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			c.Index = v
		case 3:
			c.Payload = append([]byte(nil), f.Data...)
		case 4:
			c.ChunkHash = append([]byte(nil), f.Data...)
		case 5:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			c.Offset = v
		}
	}
	if err := ValidateChunkUpload(c); err != nil {
		return nil, err
	}
	return c, nil
}

// ValidateChunkUpload enforces chunk bounds.
func ValidateChunkUpload(c *ChunkUpload) error {
	if len(c.TransferID) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "transfer_id must be 16 bytes"}
	}
	if len(c.Payload) == 0 || len(c.Payload) > MaxChunkBytes {
		return &ProtocolError{Code: ErrChunkInvalid, Detail: "payload size out of bounds"}
	}
	if len(c.ChunkHash) != 0 && len(c.ChunkHash) != 32 {
		return &ProtocolError{Code: ErrChunkInvalid, Detail: "chunk_hash must be 32 bytes"}
	}
	if c.Index >= MaxChunksPerTransfer {
		return &ProtocolError{Code: ErrChunkOutOfRange, Detail: "index out of range"}
	}
	return nil
}

// ValidateTransferCreate enforces file bounds.
func ValidateTransferCreate(totalSize uint64, chunkSize, chunkCount uint32) error {
	if chunkSize == 0 || chunkSize > MaxChunkBytes {
		return &ProtocolError{Code: ErrChunkInvalid, Detail: "chunk_size out of bounds"}
	}
	if chunkCount == 0 || chunkCount > MaxChunksPerTransfer {
		return &ProtocolError{Code: ErrChunkOutOfRange, Detail: "chunk_count out of bounds"}
	}
	if totalSize == 0 || totalSize > uint64(MaxFileBytes) {
		return &ProtocolError{Code: ErrPayloadTooLarge, Detail: "total_size out of bounds"}
	}
	// ceil(total/chunkSize) must equal chunkCount (last chunk may be short).
	expect := uint32((totalSize + uint64(chunkSize) - 1) / uint64(chunkSize))
	if expect != chunkCount {
		return &ProtocolError{Code: ErrChunkInvalid, Detail: "chunk_count mismatch"}
	}
	return nil
}

var errNil = errors.New("nil")
var _ = errNil
