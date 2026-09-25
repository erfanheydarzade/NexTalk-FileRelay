// Package storage defines the FileRelay storage abstraction.
//
// The shard is dumb storage: mailboxes, message queues, transfers/chunks,
// TTLs, ACK bookkeeping, replay cache. It never sees pubkeys (mailbox IDs
// only), SERVER_SECRET, or plaintext semantics.
//
// Implementations: MemStore (in-process, tests + reference). Production
// KV backends must preserve identical semantics (lazy expiry + sliding
// mailbox TTL + idempotent chunk put + single-use replay).
package storage

import (
	"context"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
)

// StoredMessage is one queued envelope.
type StoredMessage struct {
	ID         [16]byte
	Envelope   []byte
	SenderPub  []byte
	EnqueuedAt int64
	ExpiresAt  int64
}

// TransferState is the lifecycle state of a file transfer.
type TransferState uint8

const (
	TransferCreated   TransferState = 1
	TransferUploading TransferState = 2
	TransferComplete  TransferState = 3
	TransferCancelled TransferState = 4
	TransferExpired   TransferState = 5
)

// TransferView is a copy-out snapshot for resume/complete paths.
type TransferView struct {
	ID                [16]byte
	MailboxID         [16]byte
	HasMailbox        bool
	TotalSize         uint64
	ChunkSize         uint32
	ChunkCount        uint32
	Manifest          []byte
	SenderPub         []byte
	State             TransferState
	PresentCount      uint32
	HighestContiguous uint32
	CreatedAt         int64
	ExpiresAt         int64
}

// ResumeView is the server truth for resume.
type ResumeView struct {
	ChunkCount        uint32
	HighestContiguous uint32
	Encoding          uint8
	Bitmap            []byte
	MissingRanges     []byte // flat BE32 pairs
}

// Store is the full shard persistence contract.
type Store interface {
	// Mailboxes.
	CreateMailbox(ctx context.Context, mailboxID [16]byte, readSecretHash [32]byte) (created bool, err error)
	MailboxExists(ctx context.Context, mailboxID [16]byte) bool
	CheckReadSecret(ctx context.Context, mailboxID [16]byte, readSecret []byte) bool

	// Messages.
	SendMessage(ctx context.Context, msg *protocol.SendMessage) (msgID [16]byte, queued uint32, err error)
	ReceiveMessages(ctx context.Context, mailboxID [16]byte, readSecret []byte, limit int, peek bool) (msgs []StoredMessage, consumed bool, err error)
	AckMessages(ctx context.Context, mailboxID [16]byte, readSecret []byte, msgIDs [][]byte, disposition uint8) (acked, remaining uint32, err error)

	// Transfers.
	CreateTransfer(ctx context.Context, t *protocol.TransferCreate) (transferID [16]byte, downloadSecret []byte, expiresAt uint64, err error)
	PutChunk(ctx context.Context, c *protocol.ChunkUpload) (present uint32, err error)
	GetChunk(ctx context.Context, transferID [16]byte, mailboxID [16]byte, readSecret []byte, index uint32) (payload, hash []byte, err error)
	Resume(ctx context.Context, transferID [16]byte, mailboxID [16]byte, readSecret []byte) (*ResumeView, *TransferView, error)
	// GetChunkByTicket / ResumeByTicket authenticate with the per-transfer
	// download ticket minted at create instead of the mailbox read_secret.
	// Download-only: put/complete/cancel never accept a ticket. Ticket use
	// does not slide the owner mailbox TTL.
	GetChunkByTicket(ctx context.Context, transferID [16]byte, ticket []byte, index uint32) (payload, hash []byte, err error)
	ResumeByTicket(ctx context.Context, transferID [16]byte, ticket []byte) (*ResumeView, *TransferView, error)
	// Progress returns resume truth for the transfer capability holder
	// (uploader post-Put ack path). Knowledge of the unguessable
	// transfer_id authorizes it; content (GetChunk) still needs read_secret.
	Progress(ctx context.Context, transferID [16]byte) (*ResumeView, *TransferView, error)
	CompleteTransfer(ctx context.Context, t *protocol.TransferComplete) (sealed bool, present, count uint32, err error)
	CancelTransfer(ctx context.Context, transferID [16]byte, mailboxID [16]byte, readSecret []byte) error
	GetTransfer(ctx context.Context, transferID [16]byte) (*TransferView, error)

	// Replay cache: reports true if key was already seen (replay).
	CheckAndMarkReplay(ctx context.Context, key [32]byte) bool

	// Sweep removes expired messages/transfers/mailboxes. Returns counts.
	Sweep(ctx context.Context) (messages, transfers, mailboxes int)
}
