// Package protocol — bounded limits. Enforced BEFORE allocating buffers:
// check declared lengths against these, then re-check after decode.
package protocol

const (
	MaxMessageBytes                    = 32 * 1024          // 32 KiB per SendMessage.envelope
	MaxChunkBytes                      = 64 * 1024          // 64 KiB per ChunkUpload.payload
	MaxFileBytes                 int64 = 1024 * 1024 * 1024 // 1 GiB per transfer
	MaxChunksPerTransfer               = 16384
	MaxActiveTransfersPerMailbox       = 16
	MaxQueuedMessages                  = 100
	MaxStoredBytesPerMailbox           = 16 * 1024 * 1024 // messages + chunks
	MaxRequestBytes                    = 128 * 1024       // single HTTP body
	MaxBatchMessages                   = 32               // per Receive response
	MaxMissingRanges                   = 1024             // per Resume response

	// TTLs (seconds).
	MsgTTLSeconds          int64 = 14 * 24 * 3600 // 14d, per message
	MailboxTTLSeconds      int64 = 365 * 24 * 3600
	UploadTTLSeconds       int64 = 24 * 3600 // incomplete transfer, sliding (cap 7d)
	UploadTTLMaxSeconds    int64 = 7 * 24 * 3600
	CompleteTTLSeconds     int64 = 14 * 24 * 3600
	CapabilityTTLSeconds   int64 = 365 * 24 * 3600
	RoutingTableTTLSeconds int64 = 3600
	ReplayWindowSeconds    int64 = 90 // skew (30s) + margin, single-use cache
	MaxClockSkewMillis     int64 = 30_000
)
