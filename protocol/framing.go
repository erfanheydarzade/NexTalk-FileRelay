// Package protocol — framing decision (authoritative summary; see FRAMING.md).
//
// NanoPack serialization and transport framing are different concerns.
//
//   - HTTP request/response bodies: raw NanoPack payload, NO WrapPacket.
//     The HTTP body length IS the frame boundary. Content-Type:
//     application/x-nanopack with X-FileRelay-Schema: <id>.
//   - Streaming / connection-oriented / multiplexed binary transports:
//     WrapPacket(schemaID, body, flags=0):
//     [B2][major][minor][schema][flags][len BE32][body][crc16 lo][crc16 hi].
//
// Never invent a second framing scheme.
package protocol

import (
	"fmt"

	"github.com/erfanheydarzade/nanopack"
)

// EncodeHTTPBody validates a NanoPack body against MaxRequestBytes and
// returns it unchanged (HTTP needs no extra framing).
func EncodeHTTPBody(body []byte) ([]byte, error) {
	if len(body) > MaxRequestBytes && len(body) > MaxChunkBytes+1024 {
		// ChunkUpload is the only body allowed above MaxRequestBytes up to
		// MaxChunkBytes + header overhead; callers check schema-specific
		// limits in schemas.go Validate functions.
		return nil, &ProtocolError{Code: ErrPayloadTooLarge, Detail: "body exceeds max request"}
	}
	return body, nil
}

// WrapStream frames one NanoPack body for a byte stream.
func WrapStream(schemaID byte, body []byte) []byte {
	return nanopack.WrapPacket(schemaID, body, 0)
}

// UnwrapStream validates one framed packet from the front of buf.
func UnwrapStream(buf []byte) (schemaID byte, body []byte, n int, err error) {
	major, _, schemaID, _, body, n, err := nanopack.UnwrapPacket(buf)
	if err != nil {
		return 0, nil, 0, err
	}
	_ = major // nanopack already enforces its own major; FileRelay protocol
	// version is carried inside Hello / HTTP headers, not in this envelope.
	return schemaID, body, n, nil
}

// CheckBodyLen bounds allocation before decode: call with the declared
// payload length (HTTP Content-Length or stream envelope length).
func CheckBodyLen(n int, limit int) error {
	if n < 0 || n > limit {
		return &ProtocolError{Code: ErrPayloadTooLarge, Detail: fmt.Sprintf("declared len %d exceeds %d", n, limit)}
	}
	return nil
}
