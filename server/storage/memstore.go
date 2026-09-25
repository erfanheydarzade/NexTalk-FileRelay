// Package storage — in-memory Store implementation with deterministic clock/ID injection.
package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
)

type mailboxData struct {
	readSecretHash [32]byte
	messages       []StoredMessage
	expiresAt      int64
	storedBytes    int64 // sum of queued envelopes (chunks counted per-transfer below)
}

type transferData struct {
	mailboxID  [16]byte
	hasMailbox bool
	// downloadSecretHash gates ticket auth (resume/get without the mailbox
	// read_secret). Download-only: put/complete/cancel never accept it.
	downloadSecretHash [32]byte
	totalSize          uint64
	chunkSize          uint32
	chunkCount         uint32
	manifest           []byte
	senderPub          []byte
	state              TransferState
	present            []bool
	chunks             map[uint32][]byte
	hashes             map[uint32][]byte
	presentCount       uint32
	highest            uint32
	createdAt          int64
	expiresAt          int64
	storedBytes        int64
}

// MemStore is a reference Store. Zero value is unusable; use NewMemStore.
type MemStore struct {
	mu        sync.Mutex
	mailboxes map[[16]byte]*mailboxData
	transfers map[[16]byte]*transferData
	replay    map[[32]byte]int64 // key -> expiresAt millis

	// Now returns millis. Override in tests for determinism.
	Now func() int64
	// NewID returns random 16B IDs. Override in tests if needed.
	NewID func() [16]byte
}

// NewMemStore returns an empty store with wall clock + CSPRNG IDs.
func NewMemStore() *MemStore {
	return &MemStore{
		mailboxes: map[[16]byte]*mailboxData{},
		transfers: map[[16]byte]*transferData{},
		replay:    map[[32]byte]int64{},
		Now:       func() int64 { return time.Now().UnixMilli() },
		NewID: func() [16]byte {
			var id [16]byte
			_, _ = rand.Read(id[:])
			return id
		},
	}
}

func (s *MemStore) now() int64 {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UnixMilli()
}

func hashSecret(secret []byte) [32]byte { return sha256.Sum256(secret) }

func secretMatches(stored [32]byte, provided []byte) bool {
	if len(provided) != 32 {
		return false
	}
	h := hashSecret(provided)
	return subtle.ConstantTimeCompare(h[:], stored[:]) == 1
}

// --- mailboxes ---

// CreateMailbox is idempotent: re-register refreshes TTL + secret hash, keeps messages.
func (s *MemStore) CreateMailbox(_ context.Context, mailboxID [16]byte, readSecretHash [32]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if mb, ok := s.mailboxes[mailboxID]; ok {
		mb.readSecretHash = readSecretHash
		mb.expiresAt = now + protocol.MailboxTTLSeconds*1000
		return false, nil
	}
	s.mailboxes[mailboxID] = &mailboxData{
		readSecretHash: readSecretHash,
		expiresAt:      now + protocol.MailboxTTLSeconds*1000,
	}
	return true, nil
}

// MailboxExists reports existence without touching TTL (for era-walk probes).
func (s *MemStore) MailboxExists(_ context.Context, mailboxID [16]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	mb, ok := s.mailboxes[mailboxID]
	if !ok {
		return false
	}
	if s.now() >= mb.expiresAt {
		return false
	}
	return true
}

// CheckReadSecret compares sha256(provided) against stored hash in constant time.
func (s *MemStore) CheckReadSecret(_ context.Context, mailboxID [16]byte, readSecret []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	mb, ok := s.mailboxes[mailboxID]
	if !ok {
		return false
	}
	if len(readSecret) != 32 {
		return false
	}
	h := hashSecret(readSecret)
	return subtle.ConstantTimeCompare(h[:], mb.readSecretHash[:]) == 1
}

func (s *MemStore) getMailboxLocked(id [16]byte, now int64) (*mailboxData, bool) {
	mb, ok := s.mailboxes[id]
	if !ok {
		return nil, false
	}
	if now >= mb.expiresAt {
		return nil, false
	}
	return mb, true
}

func (s *MemStore) pruneMessagesLocked(mb *mailboxData, now int64) {
	kept := mb.messages[:0]
	var bytes int64
	for _, m := range mb.messages {
		if now < m.ExpiresAt {
			kept = append(kept, m)
			bytes += int64(len(m.Envelope))
		}
	}
	// Clear tail to avoid retaining envelopes.
	for i := len(kept); i < len(mb.messages); i++ {
		mb.messages[i] = StoredMessage{}
	}
	mb.messages = kept
	mb.storedBytes = bytes
}

// --- messages ---

// SendMessage stores one envelope. Caller (handler) verifies signature+replay first.
func (s *MemStore) SendMessage(_ context.Context, msg *protocol.SendMessage) ([16]byte, uint32, error) {
	if err := protocol.ValidateSendMessage(msg); err != nil {
		return [16]byte{}, 0, err
	}
	var mid [16]byte
	copy(mid[:], msg.MailboxID)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	mb, ok := s.getMailboxLocked(mid, now)
	if !ok {
		return [16]byte{}, 0, &protocol.ProtocolError{Code: protocol.ErrMailboxNotFound, Detail: "mailbox not found"}
	}
	s.pruneMessagesLocked(mb, now)
	if len(mb.messages) >= protocol.MaxQueuedMessages {
		return [16]byte{}, 0, &protocol.ProtocolError{Code: protocol.ErrQuotaExceeded, Detail: "mailbox full"}
	}
	if mb.storedBytes+int64(len(msg.Envelope)) > protocol.MaxStoredBytesPerMailbox {
		return [16]byte{}, 0, &protocol.ProtocolError{Code: protocol.ErrQuotaExceeded, Detail: "mailbox byte quota"}
	}
	id := s.NewID()
	mb.messages = append(mb.messages, StoredMessage{
		ID:         id,
		Envelope:   append([]byte(nil), msg.Envelope...),
		SenderPub:  append([]byte(nil), msg.SenderPub...),
		EnqueuedAt: now,
		ExpiresAt:  now + protocol.MsgTTLSeconds*1000,
	})
	mb.storedBytes += int64(len(msg.Envelope))
	mb.expiresAt = now + protocol.MailboxTTLSeconds*1000
	return id, uint32(len(mb.messages)), nil
}

// ReceiveMessages drains (or peeks) up to limit entries.
func (s *MemStore) ReceiveMessages(_ context.Context, mailboxID [16]byte, readSecret []byte, limit int, peek bool) ([]StoredMessage, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	mb, ok := s.getMailboxLocked(mailboxID, now)
	if !ok {
		return nil, false, &protocol.ProtocolError{Code: protocol.ErrMailboxNotFound, Detail: "mailbox not found"}
	}
	if !secretMatches(mb.readSecretHash, readSecret) {
		return nil, false, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "bad read secret"}
	}
	if limit <= 0 || limit > protocol.MaxBatchMessages {
		limit = protocol.MaxBatchMessages
	}
	s.pruneMessagesLocked(mb, now)
	var out []StoredMessage
	var kept []StoredMessage
	for _, m := range mb.messages {
		if len(out) < limit {
			cp := StoredMessage{ID: m.ID, Envelope: append([]byte(nil), m.Envelope...), SenderPub: append([]byte(nil), m.SenderPub...), EnqueuedAt: m.EnqueuedAt, ExpiresAt: m.ExpiresAt}
			out = append(out, cp)
			if peek {
				kept = append(kept, m)
			}
			continue
		}
		kept = append(kept, m)
	}
	if !peek {
		mb.messages = kept
		var bytes int64
		for _, m := range kept {
			bytes += int64(len(m.Envelope))
		}
		mb.storedBytes = bytes
	}
	mb.expiresAt = now + protocol.MailboxTTLSeconds*1000
	return out, !peek, nil
}

// AckMessages applies received/consumed dispositions. Consumed drops; received is accounting-only.
func (s *MemStore) AckMessages(_ context.Context, mailboxID [16]byte, readSecret []byte, msgIDs [][]byte, disposition uint8) (uint32, uint32, error) {
	if disposition != protocol.AckReceived && disposition != protocol.AckConsumed {
		return 0, 0, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "bad disposition"}
	}
	if len(msgIDs) == 0 || len(msgIDs) > protocol.MaxBatchMessages {
		return 0, 0, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "msg_ids count out of bounds"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	mb, ok := s.getMailboxLocked(mailboxID, now)
	if !ok {
		return 0, 0, &protocol.ProtocolError{Code: protocol.ErrMailboxNotFound, Detail: "mailbox not found"}
	}
	if !secretMatches(mb.readSecretHash, readSecret) {
		return 0, 0, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "bad read secret"}
	}
	s.pruneMessagesLocked(mb, now)
	want := map[[16]byte]bool{}
	for _, raw := range msgIDs {
		if len(raw) != 16 {
			return 0, 0, &protocol.ProtocolError{Code: protocol.ErrInvalidRequest, Detail: "msg_id must be 16 bytes"}
		}
		var id [16]byte
		copy(id[:], raw)
		want[id] = true
	}
	var acked uint32
	if disposition == protocol.AckConsumed {
		kept := mb.messages[:0]
		for _, m := range mb.messages {
			if want[m.ID] {
				acked++
				continue
			}
			kept = append(kept, m)
		}
		for i := len(kept); i < len(mb.messages); i++ {
			mb.messages[i] = StoredMessage{}
		}
		mb.messages = kept
		var bytes int64
		for _, m := range kept {
			bytes += int64(len(m.Envelope))
		}
		mb.storedBytes = bytes
	} else {
		for _, m := range mb.messages {
			if want[m.ID] {
				acked++
			}
		}
	}
	mb.expiresAt = now + protocol.MailboxTTLSeconds*1000
	return acked, uint32(len(mb.messages)), nil
}

// --- transfers ---

func (s *MemStore) activeTransfersLocked(mailboxID [16]byte, now int64) int {
	n := 0
	for _, t := range s.transfers {
		if t.hasMailbox && t.mailboxID == mailboxID && (t.state == TransferCreated || t.state == TransferUploading) && now < t.expiresAt {
			n++
		}
	}
	return n
}

func (s *MemStore) mailboxStoredBytesLocked(mailboxID [16]byte) int64 {
	var total int64
	if mb, ok := s.mailboxes[mailboxID]; ok {
		total += mb.storedBytes
	}
	for _, t := range s.transfers {
		if t.hasMailbox && t.mailboxID == mailboxID {
			total += t.storedBytes + int64(len(t.manifest))
		}
	}
	return total
}

// CreateTransfer mints a transfer. Handler verifies signature+replay first.
func (s *MemStore) CreateTransfer(_ context.Context, t *protocol.TransferCreate) ([16]byte, []byte, uint64, error) {
	if err := protocol.ValidateTransferCreateMsg(t); err != nil {
		return [16]byte{}, nil, 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var mid [16]byte
	hasMailbox := len(t.MailboxID) == 16
	if hasMailbox {
		copy(mid[:], t.MailboxID)
		if _, ok := s.getMailboxLocked(mid, now); !ok {
			return [16]byte{}, nil, 0, &protocol.ProtocolError{Code: protocol.ErrMailboxNotFound, Detail: "mailbox not found"}
		}
		if s.activeTransfersLocked(mid, now) >= protocol.MaxActiveTransfersPerMailbox {
			return [16]byte{}, nil, 0, &protocol.ProtocolError{Code: protocol.ErrQuotaExceeded, Detail: "too many active transfers"}
		}
		if s.mailboxStoredBytesLocked(mid)+int64(t.TotalSize) > protocol.MaxStoredBytesPerMailbox {
			return [16]byte{}, nil, 0, &protocol.ProtocolError{Code: protocol.ErrQuotaExceeded, Detail: "mailbox byte quota"}
		}
	}
	id := s.NewID()
	var ticket [32]byte
	if _, err := rand.Read(ticket[:]); err != nil {
		return [16]byte{}, nil, 0, &protocol.ProtocolError{Code: protocol.ErrStorageUnavailable, Detail: "rand failed"}
	}
	exp := uint64(now + protocol.UploadTTLSeconds*1000)
	s.transfers[id] = &transferData{
		mailboxID:          mid,
		hasMailbox:         hasMailbox,
		downloadSecretHash: sha256.Sum256(ticket[:]),
		totalSize:          t.TotalSize,
		chunkSize:          t.ChunkSize,
		chunkCount:         t.ChunkCount,
		manifest:           append([]byte(nil), t.Manifest...),
		senderPub:          append([]byte(nil), t.SenderPub...),
		state:              TransferCreated,
		present:            make([]bool, t.ChunkCount),
		chunks:             map[uint32][]byte{},
		hashes:             map[uint32][]byte{},
		createdAt:          now,
		expiresAt:          int64(exp),
	}
	if hasMailbox {
		if mb, ok := s.mailboxes[mid]; ok {
			mb.expiresAt = now + protocol.MailboxTTLSeconds*1000
		}
	}
	return id, append([]byte(nil), ticket[:]...), exp, nil
}

func (s *MemStore) getTransferLocked(id [16]byte, now int64) (*transferData, bool) {
	t, ok := s.transfers[id]
	if !ok {
		return nil, false
	}
	if now >= t.expiresAt && t.state != TransferComplete {
		t.state = TransferExpired
		return nil, false
	}
	return t, true
}

// PutChunk stores one chunk idempotently. Same bytes => ACK; different => conflict.
func (s *MemStore) PutChunk(_ context.Context, c *protocol.ChunkUpload) (uint32, error) {
	if err := protocol.ValidateChunkUpload(c); err != nil {
		return 0, err
	}
	var tid [16]byte
	copy(tid[:], c.TransferID)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.getTransferLocked(tid, now)
	if !ok {
		if _, exists := s.transfers[tid]; exists {
			return 0, &protocol.ProtocolError{Code: protocol.ErrTransferExpired, Detail: "transfer expired"}
		}
		return 0, &protocol.ProtocolError{Code: protocol.ErrTransferNotFound, Detail: "transfer not found"}
	}
	if t.state == TransferComplete || t.state == TransferCancelled {
		return 0, &protocol.ProtocolError{Code: protocol.ErrTransferConflict, Detail: "transfer closed"}
	}
	if c.Index >= t.chunkCount {
		return 0, &protocol.ProtocolError{Code: protocol.ErrChunkOutOfRange, Detail: "index out of range"}
	}
	if c.Offset != uint64(c.Index)*uint64(t.chunkSize) {
		// Last chunk may be short, but offset must still match index*size.
		return 0, &protocol.ProtocolError{Code: protocol.ErrChunkInvalid, Detail: "offset mismatch"}
	}
	// Last-chunk short check: non-final chunks must be full size.
	isLast := c.Index == t.chunkCount-1
	if !isLast && uint64(len(c.Payload)) != uint64(t.chunkSize) {
		// Allow smaller only if totalSize implies? Strict: non-final must be full.
		return 0, &protocol.ProtocolError{Code: protocol.ErrChunkInvalid, Detail: "non-final chunk must equal chunk_size"}
	}
	if isLast {
		expectLast := t.totalSize - uint64(c.Index)*uint64(t.chunkSize)
		if uint64(len(c.Payload)) != expectLast {
			return 0, &protocol.ProtocolError{Code: protocol.ErrChunkInvalid, Detail: "final chunk size mismatch"}
		}
	}
	if len(c.ChunkHash) == 32 {
		h := sha256.Sum256(c.Payload)
		if subtle.ConstantTimeCompare(h[:], c.ChunkHash) != 1 {
			return 0, &protocol.ProtocolError{Code: protocol.ErrHashMismatch, Detail: "chunk hash mismatch"}
		}
	}
	if old, exists := t.chunks[c.Index]; exists {
		if len(old) == len(c.Payload) && subtle.ConstantTimeCompare(hashBytes(old), hashBytes(c.Payload)) == 1 {
			return t.presentCount, nil // idempotent replay
		}
		return 0, &protocol.ProtocolError{Code: protocol.ErrChunkConflict, Detail: "chunk exists with different bytes"}
	}
	if t.hasMailbox && s.mailboxStoredBytesLocked(t.mailboxID)+int64(len(c.Payload)) > protocol.MaxStoredBytesPerMailbox {
		return 0, &protocol.ProtocolError{Code: protocol.ErrQuotaExceeded, Detail: "mailbox byte quota"}
	}
	t.chunks[c.Index] = append([]byte(nil), c.Payload...)
	if len(c.ChunkHash) == 32 {
		t.hashes[c.Index] = append([]byte(nil), c.ChunkHash...)
	} else {
		h := sha256.Sum256(c.Payload)
		t.hashes[c.Index] = h[:]
	}
	if !t.present[c.Index] {
		t.present[c.Index] = true
		t.presentCount++
		t.storedBytes += int64(len(c.Payload))
	}
	if t.state == TransferCreated {
		t.state = TransferUploading
	}
	// Slide upload TTL (cap total age at UploadTTLMax).
	t.expiresAt = now + protocol.UploadTTLSeconds*1000
	if max := t.createdAt + protocol.UploadTTLMaxSeconds*1000; t.expiresAt > max {
		t.expiresAt = max
	}
	// Recompute highest contiguous.
	var h uint32
	for h < t.chunkCount && t.present[h] {
		h++
	}
	t.highest = h
	if t.hasMailbox {
		if mb, ok := s.mailboxes[t.mailboxID]; ok {
			mb.expiresAt = now + protocol.MailboxTTLSeconds*1000
		}
	}
	return t.presentCount, nil
}

func hashBytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// GetChunk returns one stored chunk. Requires mailbox read secret match.
func (s *MemStore) GetChunk(_ context.Context, transferID [16]byte, mailboxID [16]byte, readSecret []byte, index uint32) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.getTransferLocked(transferID, now)
	if !ok {
		if _, exists := s.transfers[transferID]; exists {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferExpired, Detail: "transfer expired"}
		}
		return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferNotFound, Detail: "transfer not found"}
	}
	if t.hasMailbox {
		if t.mailboxID != mailboxID {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "mailbox mismatch"}
		}
		mb, ok := s.getMailboxLocked(mailboxID, now)
		if !ok {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrMailboxNotFound, Detail: "mailbox not found"}
		}
		if !secretMatches(mb.readSecretHash, readSecret) {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "bad read secret"}
		}
		mb.expiresAt = now + protocol.MailboxTTLSeconds*1000
	}
	if index >= t.chunkCount {
		return nil, nil, &protocol.ProtocolError{Code: protocol.ErrChunkOutOfRange, Detail: "index out of range"}
	}
	p, ok := t.chunks[index]
	if !ok {
		return nil, nil, &protocol.ProtocolError{Code: protocol.ErrChunkInvalid, Detail: "chunk missing"}
	}
	return append([]byte(nil), p...), append([]byte(nil), t.hashes[index]...), nil
}

// checkTicketLocked verifies a download ticket against the stored hash.
// Ticket auth is download-only: resume/get. Put/complete/cancel never
// accept it. No mailbox TTL is slid: ticket use is not owner activity.
func checkTicketLocked(t *transferData, ticket []byte) error {
	if len(ticket) != 32 {
		return &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "ticket must be 32 bytes"}
	}
	h := sha256.Sum256(ticket)
	if subtle.ConstantTimeCompare(h[:], t.downloadSecretHash[:]) != 1 {
		return &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "bad ticket"}
	}
	return nil
}

// buildResumeViewLocked snapshots bitmap/range resume truth. Caller holds mu.
func buildResumeViewLocked(t *transferData, transferID [16]byte) (*ResumeView, *TransferView) {
	view := &TransferView{
		MailboxID: t.mailboxID, HasMailbox: t.hasMailbox,
		TotalSize: t.totalSize, ChunkSize: t.chunkSize, ChunkCount: t.chunkCount,
		Manifest: append([]byte(nil), t.manifest...), SenderPub: append([]byte(nil), t.senderPub...),
		State: t.state, PresentCount: t.presentCount, HighestContiguous: t.highest,
		CreatedAt: t.createdAt, ExpiresAt: t.expiresAt,
	}
	copy(view.ID[:], transferID[:])
	rv := &ResumeView{ChunkCount: t.chunkCount, HighestContiguous: t.highest}
	if t.chunkCount <= 256 {
		n := (t.chunkCount + 7) / 8
		bm := make([]byte, n)
		for i := uint32(0); i < t.chunkCount; i++ {
			if t.present[i] {
				bm[i/8] |= 1 << (i % 8)
			}
		}
		rv.Encoding = protocol.ResumeBitmap
		rv.Bitmap = bm
	} else {
		var ranges [][2]uint32
		var start, run uint32
		inGap := false
		for i := uint32(0); i < t.chunkCount; i++ {
			if !t.present[i] {
				if !inGap {
					start = i
					run = 1
					inGap = true
				} else {
					run++
				}
			} else if inGap {
				ranges = append(ranges, [2]uint32{start, run})
				inGap = false
				if len(ranges) >= protocol.MaxMissingRanges {
					break
				}
			}
		}
		if inGap {
			ranges = append(ranges, [2]uint32{start, run})
		}
		rv.Encoding = protocol.ResumeRanges
		rv.MissingRanges = protocol.EncodeRanges(ranges)
	}
	return rv, view
}

// Resume builds bitmap/ranges truth.
func (s *MemStore) Resume(_ context.Context, transferID [16]byte, mailboxID [16]byte, readSecret []byte) (*ResumeView, *TransferView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.getTransferLocked(transferID, now)
	if !ok {
		if _, exists := s.transfers[transferID]; exists {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferExpired, Detail: "transfer expired"}
		}
		return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferNotFound, Detail: "transfer not found"}
	}
	if t.hasMailbox {
		if t.mailboxID != mailboxID {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "mailbox mismatch"}
		}
		mb, ok := s.getMailboxLocked(mailboxID, now)
		if !ok {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrMailboxNotFound, Detail: "mailbox not found"}
		}
		if !secretMatches(mb.readSecretHash, readSecret) {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "bad read secret"}
		}
		mb.expiresAt = now + protocol.MailboxTTLSeconds*1000
	}
	rv, view := buildResumeViewLocked(t, transferID)
	return rv, view, nil
}

// Progress returns resume truth for the transfer_id holder (no read_secret).
// Knowledge of the unguessable transfer_id authorizes it.
func (s *MemStore) Progress(_ context.Context, transferID [16]byte) (*ResumeView, *TransferView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.getTransferLocked(transferID, now)
	if !ok {
		if _, exists := s.transfers[transferID]; exists {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferExpired, Detail: "transfer expired"}
		}
		return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferNotFound, Detail: "transfer not found"}
	}
	rv, view := buildResumeViewLocked(t, transferID)
	return rv, view, nil
}

// GetChunkByTicket returns one stored chunk for a ticket holder.
// Same bytes as the mailbox path; no mailbox lookup, no TTL slide.
func (s *MemStore) GetChunkByTicket(_ context.Context, transferID [16]byte, ticket []byte, index uint32) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.getTransferLocked(transferID, now)
	if !ok {
		if _, exists := s.transfers[transferID]; exists {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferExpired, Detail: "transfer expired"}
		}
		return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferNotFound, Detail: "transfer not found"}
	}
	if err := checkTicketLocked(t, ticket); err != nil {
		return nil, nil, err
	}
	if index >= t.chunkCount {
		return nil, nil, &protocol.ProtocolError{Code: protocol.ErrChunkOutOfRange, Detail: "index out of range"}
	}
	p, ok := t.chunks[index]
	if !ok {
		return nil, nil, &protocol.ProtocolError{Code: protocol.ErrChunkInvalid, Detail: "chunk missing"}
	}
	return append([]byte(nil), p...), append([]byte(nil), t.hashes[index]...), nil
}

// ResumeByTicket builds resume truth for a ticket holder.
func (s *MemStore) ResumeByTicket(_ context.Context, transferID [16]byte, ticket []byte) (*ResumeView, *TransferView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.getTransferLocked(transferID, now)
	if !ok {
		if _, exists := s.transfers[transferID]; exists {
			return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferExpired, Detail: "transfer expired"}
		}
		return nil, nil, &protocol.ProtocolError{Code: protocol.ErrTransferNotFound, Detail: "transfer not found"}
	}
	if err := checkTicketLocked(t, ticket); err != nil {
		return nil, nil, err
	}
	rv, view := buildResumeViewLocked(t, transferID)
	return rv, view, nil
}

// CompleteTransfer seals a fully-uploaded transfer. Handler verifies signature first.
func (s *MemStore) CompleteTransfer(_ context.Context, t *protocol.TransferComplete) (bool, uint32, uint32, error) {
	if err := protocol.ValidateTransferComplete(t); err != nil {
		return false, 0, 0, err
	}
	var tid [16]byte
	copy(tid[:], t.TransferID)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	tr, ok := s.getTransferLocked(tid, now)
	if !ok {
		if _, exists := s.transfers[tid]; exists {
			return false, 0, 0, &protocol.ProtocolError{Code: protocol.ErrTransferExpired, Detail: "transfer expired"}
		}
		return false, 0, 0, &protocol.ProtocolError{Code: protocol.ErrTransferNotFound, Detail: "transfer not found"}
	}
	if tr.state == TransferComplete {
		return true, tr.presentCount, tr.chunkCount, nil
	}
	if tr.state == TransferCancelled {
		return false, 0, 0, &protocol.ProtocolError{Code: protocol.ErrTransferConflict, Detail: "transfer cancelled"}
	}
	if tr.presentCount != tr.chunkCount {
		return false, tr.presentCount, tr.chunkCount, &protocol.ProtocolError{Code: protocol.ErrTransferConflict, Detail: "chunks missing"}
	}
	tr.state = TransferComplete
	tr.expiresAt = now + protocol.CompleteTTLSeconds*1000
	return true, tr.presentCount, tr.chunkCount, nil
}

// CancelTransfer removes a transfer + chunks. Requires read secret.
func (s *MemStore) CancelTransfer(_ context.Context, transferID [16]byte, mailboxID [16]byte, readSecret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	tr, ok := s.transfers[transferID]
	if !ok {
		return &protocol.ProtocolError{Code: protocol.ErrTransferNotFound, Detail: "transfer not found"}
	}
	if tr.hasMailbox {
		if tr.mailboxID != mailboxID {
			return &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "mailbox mismatch"}
		}
		mb, ok := s.getMailboxLocked(mailboxID, now)
		if !ok {
			return &protocol.ProtocolError{Code: protocol.ErrMailboxNotFound, Detail: "mailbox not found"}
		}
		if !secretMatches(mb.readSecretHash, readSecret) {
			return &protocol.ProtocolError{Code: protocol.ErrAuthFailed, Detail: "bad read secret"}
		}
		mb.expiresAt = now + protocol.MailboxTTLSeconds*1000
	}
	tr.state = TransferCancelled
	delete(s.transfers, transferID)
	return nil
}

// GetTransfer returns a snapshot (for tests/handlers).
func (s *MemStore) GetTransfer(_ context.Context, transferID [16]byte) (*TransferView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.getTransferLocked(transferID, now)
	if !ok {
		if _, exists := s.transfers[transferID]; exists {
			return nil, &protocol.ProtocolError{Code: protocol.ErrTransferExpired, Detail: "transfer expired"}
		}
		return nil, &protocol.ProtocolError{Code: protocol.ErrTransferNotFound, Detail: "transfer not found"}
	}
	view := &TransferView{
		MailboxID: t.mailboxID, HasMailbox: t.hasMailbox,
		TotalSize: t.totalSize, ChunkSize: t.chunkSize, ChunkCount: t.chunkCount,
		Manifest: append([]byte(nil), t.manifest...), SenderPub: append([]byte(nil), t.senderPub...),
		State: t.state, PresentCount: t.presentCount, HighestContiguous: t.highest,
		CreatedAt: t.createdAt, ExpiresAt: t.expiresAt,
	}
	copy(view.ID[:], transferID[:])
	return view, nil
}

// CheckAndMarkReplay returns true on replay (already seen).
func (s *MemStore) CheckAndMarkReplay(_ context.Context, key [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if exp, ok := s.replay[key]; ok && now < exp {
		return true
	}
	// Opportunistic prune.
	for k, exp := range s.replay {
		if now >= exp {
			delete(s.replay, k)
		}
	}
	s.replay[key] = now + protocol.ReplayWindowSeconds*1000
	return false
}

// Sweep drops expired messages, transfers, mailboxes, replay keys.
func (s *MemStore) Sweep(_ context.Context) (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var nm, nt, nb int
	for id, mb := range s.mailboxes {
		if now >= mb.expiresAt && len(mb.messages) == 0 {
			delete(s.mailboxes, id)
			nb++
			continue
		}
		before := len(mb.messages)
		s.pruneMessagesLocked(mb, now)
		nm += before - len(mb.messages)
		if now >= mb.expiresAt && len(mb.messages) == 0 {
			// Mailbox TTL reached and backlog empty -> reclaim.
			hasLiveTransfer := false
			for _, t := range s.transfers {
				if t.hasMailbox && t.mailboxID == id && now < t.expiresAt {
					hasLiveTransfer = true
					break
				}
			}
			if !hasLiveTransfer {
				delete(s.mailboxes, id)
				nb++
			}
		}
	}
	for id, t := range s.transfers {
		if now >= t.expiresAt && t.state != TransferComplete {
			delete(s.transfers, id)
			nt++
		} else if t.state == TransferComplete && now >= t.expiresAt {
			delete(s.transfers, id)
			nt++
		}
	}
	for k, exp := range s.replay {
		if now >= exp {
			delete(s.replay, k)
		}
	}
	return nm, nt, nb
}
