// Package protocol — stable numeric error codes. Clients switch on Code,
// never on English text (Detail is debug-only and may be empty in production).
package protocol

// Error codes (uint32 on the wire, field 1 of SchemaError).
const (
	ErrOK                  uint32 = 0 // never sent as Error; success uses typed responses
	ErrInvalidRequest      uint32 = 1
	ErrUnsupportedProtocol uint32 = 2
	ErrAuthFailed          uint32 = 3
	ErrReplayDetected      uint32 = 4
	ErrExpiredRequest      uint32 = 5
	ErrMailboxNotFound     uint32 = 6
	ErrMailboxExpired      uint32 = 7
	ErrMessageTooLarge     uint32 = 8
	ErrQuotaExceeded       uint32 = 9
	ErrTransferNotFound    uint32 = 10
	ErrTransferExpired     uint32 = 11
	ErrChunkInvalid        uint32 = 12
	ErrChunkConflict       uint32 = 13 // duplicate index with different bytes
	ErrChunkOutOfRange     uint32 = 14
	ErrStorageUnavailable  uint32 = 15
	ErrRateLimited         uint32 = 16
	ErrServerUnavailable   uint32 = 17
	ErrTransferConflict    uint32 = 18
	ErrHashMismatch        uint32 = 19
	ErrPayloadTooLarge     uint32 = 20
	ErrBatchTooLarge       uint32 = 21
)

// ProtocolError is the Go form of SchemaError (51).
// FID 1=code uint32, 2=detail string, 3=retry_after_s uint32.
type ProtocolError struct {
	Code       uint32
	Detail     string
	RetryAfter uint32
}

func (e *ProtocolError) Error() string {
	if e.Detail != "" {
		return "filerelay error " + itoa(e.Code) + ": " + e.Detail
	}
	return "filerelay error " + itoa(e.Code)
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
