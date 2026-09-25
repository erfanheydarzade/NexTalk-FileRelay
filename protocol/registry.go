// Package protocol defines the FileRelay v1 wire contract.
//
// FileRelay is NanoPack-native. Schema IDs start at 50 to avoid every
// NexTalk-assigned ID (1 SecureMessage, 10/11 multimsg, 20/21 handshakes,
// 40 contacts, 41 mailbox, 44 policies — see NexTalk docs/serialization.md).
// IDs are frozen after the v1 tag; never renumber.
package protocol

// Protocol version. Major bumps on breaking changes, minor on additive ones.
// Separate from nanopack's envelope version (see framing.go).
//
// v1.1 adds per-transfer download tickets: TransferCreateResponse FID 4,
// ChunkDownload FID 6, ResumeRequest FID 4. All additive; v1.0 parsers
// ignore the new fields but cannot use tickets (old servers never mint
// download secrets — treat a missing secret as "server too old").
const (
	ProtocolMajor byte = 1
	ProtocolMinor byte = 1
)

// Schema IDs (NanoPack schema = packet type).
const (
	SchemaHello                    byte = 50
	SchemaError                    byte = 51
	SchemaRegister                 byte = 52
	SchemaRegisterResponse         byte = 53
	SchemaResolve                  byte = 54
	SchemaResolveResponse          byte = 55
	SchemaRoutingTable             byte = 56
	SchemaSendMessage              byte = 57
	SchemaSendMessageResponse      byte = 58
	SchemaReceiveMessages          byte = 59
	SchemaReceiveMessagesResponse  byte = 60
	SchemaMessageAck               byte = 61
	SchemaMessageAckResponse       byte = 62
	SchemaTransferCreate           byte = 63
	SchemaTransferCreateResponse   byte = 64
	SchemaChunkUpload              byte = 65
	SchemaChunkAck                 byte = 66
	SchemaChunkDownload            byte = 67
	SchemaChunkDownloadResponse    byte = 68
	SchemaResumeRequest            byte = 69
	SchemaResumeResponse           byte = 70
	SchemaTransferComplete         byte = 71
	SchemaTransferCompleteResponse byte = 72
	SchemaTransferCancel           byte = 73
	SchemaShardRegister            byte = 74
	SchemaShardHeartbeat           byte = 75
	SchemaReplicateMessage         byte = 76
	SchemaReplicateChunk           byte = 77
)

// HTTP routes. Body of each POST is exactly one NanoPack payload of the
// listed request schema; response body is the listed response schema.
// No WrapPacket on HTTP (length boundary is the HTTP body itself).
const (
	RouteHello          = "/fr/v1/hello"
	RouteRegister       = "/fr/v1/register"
	RouteResolve        = "/fr/v1/resolve"
	RouteTable          = "/fr/v1/table"
	RouteSend           = "/fr/v1/send"
	RouteReceive        = "/fr/v1/receive"
	RouteAck            = "/fr/v1/ack"
	RouteTransferCreate = "/fr/v1/xfer/create"
	RouteChunkPut       = "/fr/v1/xfer/put"
	RouteChunkGet       = "/fr/v1/xfer/get"
	RouteResume         = "/fr/v1/xfer/resume"
	RouteComplete       = "/fr/v1/xfer/complete"
	RouteCancel         = "/fr/v1/xfer/cancel"
	RouteShardRegister  = "/fr/v1/shard/register"
	RouteShardHeartbeat = "/fr/v1/shard/heartbeat"
	RouteReplicateMsg   = "/fr/v1/internal/replicate-msg"
	RouteReplicateChunk = "/fr/v1/internal/replicate-chunk"
)

// ContentType is the only canonical request/response media type.
const ContentType = "application/x-nanopack"
