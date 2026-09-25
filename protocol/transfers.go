// Package protocol — file-transfer codecs: TransferCreate (63) codec,
// TransferCreateResponse (64), ChunkAck (66) codec, ChunkDownload (67),
// ChunkDownloadResponse (68), ResumeRequest (69), ResumeResponse (70),
// TransferComplete (71), TransferCompleteResponse (72), TransferCancel (73).
package protocol

import (
	"github.com/erfanheydarzade/nanopack"
)

// MaxManifestBytes bounds the opaque transfer manifest.
const MaxManifestBytes = 4096

// MarshalTransferCreate: 1=mailbox (0 or 16B), 2=total u64, 3=chunk_size u32,
// 4=chunk_count u32, 5=manifest, 6=sender_pub 32B, 7=ts u64, 8=nonce 16B, 9=sig 64B.
func MarshalTransferCreate(t *TransferCreate) ([]byte, error) {
	if err := ValidateTransferCreateMsg(t); err != nil {
		return nil, err
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, t.MailboxID)
	enc.AddID(2, putU64(t.TotalSize))
	enc.AddID(3, putU32(t.ChunkSize))
	enc.AddID(4, putU32(t.ChunkCount))
	enc.AddID(5, t.Manifest)
	enc.AddID(6, t.SenderPub)
	enc.AddID(7, putU64(t.Timestamp))
	enc.AddID(8, t.Nonce)
	enc.AddID(9, t.Signature)
	return enc.Bytes()
}

// UnmarshalTransferCreate decodes schema 63.
func UnmarshalTransferCreate(body []byte) (*TransferCreate, error) {
	if err := CheckBodyLen(len(body), MaxManifestBytes+512); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &TransferCreate{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.TotalSize = v
		case 3:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.ChunkSize = v
		case 4:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.ChunkCount = v
		case 5:
			out.Manifest = append([]byte(nil), f.Data...)
		case 6:
			out.SenderPub = append([]byte(nil), f.Data...)
		case 7:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.Timestamp = v
		case 8:
			out.Nonce = append([]byte(nil), f.Data...)
		case 9:
			out.Signature = append([]byte(nil), f.Data...)
		}
	}
	if err := ValidateTransferCreateMsg(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateTransferCreateMsg checks shapes + size bounds (not signature).
func ValidateTransferCreateMsg(t *TransferCreate) error {
	if len(t.MailboxID) != 0 && len(t.MailboxID) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "mailbox_id must be 0 or 16 bytes"}
	}
	if err := ValidateTransferCreate(t.TotalSize, t.ChunkSize, t.ChunkCount); err != nil {
		return err
	}
	if len(t.Manifest) > MaxManifestBytes {
		return &ProtocolError{Code: ErrPayloadTooLarge, Detail: "manifest too large"}
	}
	if len(t.SenderPub) != 32 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "sender_pub must be 32 bytes"}
	}
	if len(t.Nonce) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "nonce must be 16 bytes"}
	}
	if len(t.Signature) != 64 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "signature must be 64 bytes"}
	}
	return nil
}

// TransferCreateResponse is schema 64: 1=transfer_id 16B, 2=expires_at u64,
// 3=chunk_size u32, 4=download_secret 32B (v1.1 ticket bearer — see below).
type TransferCreateResponse struct {
	TransferID     []byte
	ExpiresAt      uint64
	ChunkSize      uint32
	DownloadSecret []byte
}

// MarshalTransferCreateResponse encodes schema 64.
func MarshalTransferCreateResponse(r *TransferCreateResponse) ([]byte, error) {
	if len(r.TransferID) != 16 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "transfer_id must be 16 bytes"}
	}
	if len(r.DownloadSecret) != 32 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "download_secret must be 32 bytes"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.TransferID)
	enc.AddID(2, putU64(r.ExpiresAt))
	enc.AddID(3, putU32(r.ChunkSize))
	enc.AddID(4, r.DownloadSecret)
	return enc.Bytes()
}

// UnmarshalTransferCreateResponse decodes schema 64.
func UnmarshalTransferCreateResponse(body []byte) (*TransferCreateResponse, error) {
	if err := CheckBodyLen(len(body), 128); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &TransferCreateResponse{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.ExpiresAt = v
		case 3:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.ChunkSize = v
		case 4:
			out.DownloadSecret = append([]byte(nil), f.Data...)
		}
	}
	if len(out.TransferID) != 16 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "transfer_id must be 16 bytes"}
	}
	if len(out.DownloadSecret) != 32 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "download_secret must be 32 bytes (server too old for tickets?)"}
	}
	return out, nil
}

// ResumeEncoding selects ResumeResponse representation.
const (
	ResumeBitmap uint8 = 0
	ResumeRanges uint8 = 1
)

// MarshalChunkAck: 1=transfer 16B, 2=highest u32, 3=ranges flat, 4=bitmap, 5=encoding u8.
func MarshalChunkAck(a *ChunkAck) ([]byte, error) {
	if len(a.TransferID) != 16 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "transfer_id must be 16 bytes"}
	}
	if len(a.MissingRanges)%8 != 0 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "missing_ranges must be n*8 bytes"}
	}
	if len(a.MissingRanges)/8 > MaxMissingRanges {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "too many missing ranges"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, a.TransferID)
	enc.AddID(2, putU32(a.HighestContiguous))
	enc.AddID(3, a.MissingRanges)
	enc.AddID(4, a.Bitmap)
	enc.AddID(5, []byte{a.Encoding})
	return enc.Bytes()
}

// UnmarshalChunkAck decodes schema 66.
func UnmarshalChunkAck(body []byte) (*ChunkAck, error) {
	if err := CheckBodyLen(len(body), 8192); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ChunkAck{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.HighestContiguous = v
		case 3:
			out.MissingRanges = append([]byte(nil), f.Data...)
		case 4:
			out.Bitmap = append([]byte(nil), f.Data...)
		case 5:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Encoding = f.Data[0]
		}
	}
	if len(out.TransferID) != 16 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "transfer_id must be 16 bytes"}
	}
	if len(out.MissingRanges)%8 != 0 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "missing_ranges corrupt"}
	}
	return out, nil
}

// EncodeRanges packs [start,count] pairs as flat BE32.
func EncodeRanges(ranges [][2]uint32) []byte {
	var out []byte
	for _, r := range ranges {
		out = append(out, putU32(r[0])...)
		out = append(out, putU32(r[1])...)
	}
	return out
}

// DecodeRanges unpacks EncodeRanges.
func DecodeRanges(blob []byte) ([][2]uint32, error) {
	if len(blob)%8 != 0 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "ranges corrupt"}
	}
	var out [][2]uint32
	for i := 0; i < len(blob); i += 8 {
		s := uint32(blob[i])<<24 | uint32(blob[i+1])<<16 | uint32(blob[i+2])<<8 | uint32(blob[i+3])
		c := uint32(blob[i+4])<<24 | uint32(blob[i+5])<<16 | uint32(blob[i+6])<<8 | uint32(blob[i+7])
		out = append(out, [2]uint32{s, c})
	}
	return out, nil
}

// ChunkDownload is schema 67: mailbox-scoped recipient auth, or ticket auth.
// 1=transfer_id 16B, 2=index u32, 3=count u32, 4=mailbox 16B, 5=read_secret 32B,
// 6=ticket 32B (v1.1: download-only bearer minted at create; XOR with 4+5).
type ChunkDownload struct {
	TransferID []byte
	Index      uint32
	Count      uint32
	MailboxID  []byte
	ReadSecret []byte
	Ticket     []byte
}

// TicketMode reports whether this request authenticates by download ticket
// instead of mailbox read_secret.
func (r *ChunkDownload) TicketMode() bool { return len(r.Ticket) == 32 }

// MarshalChunkDownload encodes schema 67.
func MarshalChunkDownload(r *ChunkDownload) ([]byte, error) {
	if err := ValidateChunkDownload(r); err != nil {
		return nil, err
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.TransferID)
	enc.AddID(2, putU32(r.Index))
	enc.AddID(3, putU32(r.Count))
	enc.AddID(4, r.MailboxID)
	enc.AddID(5, r.ReadSecret)
	if len(r.Ticket) == 32 {
		enc.AddID(6, r.Ticket)
	}
	return enc.Bytes()
}

// UnmarshalChunkDownload decodes schema 67.
func UnmarshalChunkDownload(body []byte) (*ChunkDownload, error) {
	if err := CheckBodyLen(len(body), 256); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ChunkDownload{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Index = v
		case 3:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Count = v
		case 4:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 5:
			out.ReadSecret = append([]byte(nil), f.Data...)
		case 6:
			out.Ticket = append([]byte(nil), f.Data...)
		}
	}
	if err := ValidateChunkDownload(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateChunkDownload checks shapes: exactly one auth context —
// mailbox read_secret (mailbox 16B + secret 32B, ticket empty) or download
// ticket (ticket 32B, mailbox + secret empty). Mixed credentials are rejected.
func ValidateChunkDownload(r *ChunkDownload) error {
	if len(r.TransferID) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "transfer_id must be 16 bytes"}
	}
	if r.TicketMode() {
		if len(r.MailboxID) != 0 || len(r.ReadSecret) != 0 {
			return &ProtocolError{Code: ErrInvalidRequest, Detail: "ticket mode: mailbox and read_secret must be empty"}
		}
	} else {
		if len(r.MailboxID) != 16 {
			return &ProtocolError{Code: ErrInvalidRequest, Detail: "mailbox_id must be 16 bytes"}
		}
		if len(r.ReadSecret) != 32 {
			return &ProtocolError{Code: ErrAuthFailed, Detail: "read_secret must be 32 bytes"}
		}
	}
	if r.Count == 0 || r.Count > MaxBatchMessages {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "count out of bounds"}
	}
	if r.Index >= MaxChunksPerTransfer || r.Index+r.Count > MaxChunksPerTransfer {
		return &ProtocolError{Code: ErrChunkOutOfRange, Detail: "range out of bounds"}
	}
	return nil
}

// ChunkDownloadResponse is schema 68: 1=transfer 16B, 2=index u32, 3=payload, 4=hash 32B.
type ChunkDownloadResponse struct {
	TransferID []byte
	Index      uint32
	Payload    []byte
	ChunkHash  []byte
}

// MarshalChunkDownloadResponse encodes schema 68.
func MarshalChunkDownloadResponse(r *ChunkDownloadResponse) ([]byte, error) {
	if len(r.TransferID) != 16 || len(r.Payload) == 0 || len(r.Payload) > MaxChunkBytes || len(r.ChunkHash) != 32 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad chunk response"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.TransferID)
	enc.AddID(2, putU32(r.Index))
	enc.AddID(3, r.Payload)
	enc.AddID(4, r.ChunkHash)
	return enc.Bytes()
}

// UnmarshalChunkDownloadResponse decodes schema 68.
func UnmarshalChunkDownloadResponse(body []byte) (*ChunkDownloadResponse, error) {
	if err := CheckBodyLen(len(body), MaxChunkBytes+256); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ChunkDownloadResponse{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Index = v
		case 3:
			out.Payload = append([]byte(nil), f.Data...)
		case 4:
			out.ChunkHash = append([]byte(nil), f.Data...)
		}
	}
	if len(out.TransferID) != 16 || len(out.Payload) == 0 || len(out.Payload) > MaxChunkBytes || len(out.ChunkHash) != 32 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad chunk response"}
	}
	return out, nil
}

// ResumeRequest is schema 69: 1=transfer 16B, 2=mailbox 16B, 3=read_secret 32B,
// 4=ticket 32B (v1.1: XOR with 2+3, same rule as ChunkDownload).
type ResumeRequest struct {
	TransferID []byte
	MailboxID  []byte
	ReadSecret []byte
	Ticket     []byte
}

// TicketMode reports whether this request authenticates by download ticket.
func (r *ResumeRequest) TicketMode() bool { return len(r.Ticket) == 32 }

// MarshalResumeRequest encodes schema 69.
func MarshalResumeRequest(r *ResumeRequest) ([]byte, error) {
	if err := ValidateResumeRequest(r); err != nil {
		return nil, err
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.TransferID)
	enc.AddID(2, r.MailboxID)
	enc.AddID(3, r.ReadSecret)
	if r.TicketMode() {
		enc.AddID(4, r.Ticket)
	}
	return enc.Bytes()
}

// ValidateResumeRequest enforces exactly one auth context (see ChunkDownload).
func ValidateResumeRequest(r *ResumeRequest) error {
	if len(r.TransferID) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "transfer_id must be 16 bytes"}
	}
	if r.TicketMode() {
		if len(r.MailboxID) != 0 || len(r.ReadSecret) != 0 {
			return &ProtocolError{Code: ErrInvalidRequest, Detail: "ticket mode: mailbox and read_secret must be empty"}
		}
		return nil
	}
	if len(r.MailboxID) != 16 || len(r.ReadSecret) != 32 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "bad resume request"}
	}
	return nil
}

// UnmarshalResumeRequest decodes schema 69.
func UnmarshalResumeRequest(body []byte) (*ResumeRequest, error) {
	if err := CheckBodyLen(len(body), 256); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ResumeRequest{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 3:
			out.ReadSecret = append([]byte(nil), f.Data...)
		case 4:
			out.Ticket = append([]byte(nil), f.Data...)
		}
	}
	if err := ValidateResumeRequest(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ResumeResponse is schema 70: 1=transfer 16B, 2=chunk_count u32,
// 3=highest u32, 4=encoding u8, 5=bitmap, 6=ranges flat.
type ResumeResponse struct {
	TransferID        []byte
	ChunkCount        uint32
	HighestContiguous uint32
	Encoding          uint8
	Bitmap            []byte
	MissingRanges     []byte
}

// MarshalResumeResponse encodes schema 70.
func MarshalResumeResponse(r *ResumeResponse) ([]byte, error) {
	if len(r.TransferID) != 16 || r.ChunkCount == 0 || r.ChunkCount > MaxChunksPerTransfer {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad resume response"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.TransferID)
	enc.AddID(2, putU32(r.ChunkCount))
	enc.AddID(3, putU32(r.HighestContiguous))
	enc.AddID(4, []byte{r.Encoding})
	enc.AddID(5, r.Bitmap)
	enc.AddID(6, r.MissingRanges)
	return enc.Bytes()
}

// UnmarshalResumeResponse decodes schema 70.
func UnmarshalResumeResponse(body []byte) (*ResumeResponse, error) {
	if err := CheckBodyLen(len(body), 8192); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ResumeResponse{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.ChunkCount = v
		case 3:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.HighestContiguous = v
		case 4:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Encoding = f.Data[0]
		case 5:
			out.Bitmap = append([]byte(nil), f.Data...)
		case 6:
			out.MissingRanges = append([]byte(nil), f.Data...)
		}
	}
	if len(out.TransferID) != 16 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad resume response"}
	}
	return out, nil
}

// TransferComplete is schema 71: sender-signed seal.
// 1=transfer 16B, 2=manifest_hash 32B, 3=mailbox (0/16B), 4=sender_pub 32B,
// 5=ts u64, 6=nonce 16B, 7=sig 64B.
type TransferComplete struct {
	TransferID   []byte
	ManifestHash []byte
	MailboxID    []byte
	SenderPub    []byte
	Timestamp    uint64
	Nonce        []byte
	Signature    []byte
}

// MarshalTransferComplete encodes schema 71.
func MarshalTransferComplete(t *TransferComplete) ([]byte, error) {
	if err := ValidateTransferComplete(t); err != nil {
		return nil, err
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, t.TransferID)
	enc.AddID(2, t.ManifestHash)
	enc.AddID(3, t.MailboxID)
	enc.AddID(4, t.SenderPub)
	enc.AddID(5, putU64(t.Timestamp))
	enc.AddID(6, t.Nonce)
	enc.AddID(7, t.Signature)
	return enc.Bytes()
}

// UnmarshalTransferComplete decodes schema 71.
func UnmarshalTransferComplete(body []byte) (*TransferComplete, error) {
	if err := CheckBodyLen(len(body), 512); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &TransferComplete{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			out.ManifestHash = append([]byte(nil), f.Data...)
		case 3:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 4:
			out.SenderPub = append([]byte(nil), f.Data...)
		case 5:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.Timestamp = v
		case 6:
			out.Nonce = append([]byte(nil), f.Data...)
		case 7:
			out.Signature = append([]byte(nil), f.Data...)
		}
	}
	if err := ValidateTransferComplete(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateTransferComplete checks shapes.
func ValidateTransferComplete(t *TransferComplete) error {
	if len(t.TransferID) != 16 || len(t.ManifestHash) != 32 || len(t.SenderPub) != 32 || len(t.Nonce) != 16 || len(t.Signature) != 64 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "bad transfer complete"}
	}
	if len(t.MailboxID) != 0 && len(t.MailboxID) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "mailbox_id must be 0 or 16 bytes"}
	}
	return nil
}

// TransferCompleteResponse is schema 72: 1=sealed u8, 2=chunk_count u32, 3=present u32.
type TransferCompleteResponse struct {
	Sealed     uint8
	ChunkCount uint32
	Present    uint32
}

// MarshalTransferCompleteResponse encodes schema 72.
func MarshalTransferCompleteResponse(r *TransferCompleteResponse) ([]byte, error) {
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte{r.Sealed})
	enc.AddID(2, putU32(r.ChunkCount))
	enc.AddID(3, putU32(r.Present))
	return enc.Bytes()
}

// UnmarshalTransferCompleteResponse decodes schema 72.
func UnmarshalTransferCompleteResponse(body []byte) (*TransferCompleteResponse, error) {
	if err := CheckBodyLen(len(body), 64); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &TransferCompleteResponse{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Sealed = f.Data[0]
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.ChunkCount = v
		case 3:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Present = v
		}
	}
	return out, nil
}

// TransferCancel is schema 73: mailbox-scoped.
// 1=transfer 16B, 2=mailbox 16B, 3=reason u8, 4=read_secret 32B.
type TransferCancel struct {
	TransferID []byte
	MailboxID  []byte
	Reason     uint8
	ReadSecret []byte
}

// MarshalTransferCancel encodes schema 73.
func MarshalTransferCancel(t *TransferCancel) ([]byte, error) {
	if len(t.TransferID) != 16 || len(t.MailboxID) != 16 || len(t.ReadSecret) != 32 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad transfer cancel"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, t.TransferID)
	enc.AddID(2, t.MailboxID)
	enc.AddID(3, []byte{t.Reason})
	enc.AddID(4, t.ReadSecret)
	return enc.Bytes()
}

// UnmarshalTransferCancel decodes schema 73.
func UnmarshalTransferCancel(body []byte) (*TransferCancel, error) {
	if err := CheckBodyLen(len(body), 256); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &TransferCancel{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 3:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Reason = f.Data[0]
		case 4:
			out.ReadSecret = append([]byte(nil), f.Data...)
		}
	}
	if len(out.TransferID) != 16 || len(out.MailboxID) != 16 || len(out.ReadSecret) != 32 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad transfer cancel"}
	}
	return out, nil
}
