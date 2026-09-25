// Package shard is the dumb FileRelay storage edge.
//
// Owns: mailbox/message/chunk storage, TTL, delivery ACK bookkeeping,
// per-op authentication, rate limiting. Never: pubkey directory,
// SERVER_SECRET, decryption, chat logic.
//
// Storage lives in server/storage (Store interface + MemStore). This file
// keeps the legacy Server wrapper as a thin delegate for existing callers;
// new code should use Handler (handler.go) + storage.Store directly.
package shard

import (
	"context"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
	"github.com/erfanheydarzade/NexTalk-FileRelay/server/storage"
)

// Server is a thin in-memory reference shard backed by storage.MemStore.
type Server struct {
	store *storage.MemStore
}

// New returns an empty shard.
func New() *Server { return &Server{store: storage.NewMemStore()} }

// NewWithStore wraps an existing store (tests share one store between
// shard Handler and Server).
func NewWithStore(st *storage.MemStore) *Server { return &Server{store: st} }

// Store exposes the backing store.
func (s *Server) Store() *storage.MemStore { return s.store }

// Send stores one SendMessage after quota/TTL checks. Returns msgID.
// Auth verification (signature+replay) is done by the HTTP edge via
// protocol.VerifyMsgSend + replay cache; this layer enforces quotas/TTL.
func (s *Server) Send(m *protocol.SendMessage, _ int64) ([16]byte, error) {
	id, _, err := s.store.SendMessage(context.Background(), m)
	return id, err
}

// Receive drains (or peeks) up to limit messages.
func (s *Server) Receive(mailboxID, readSecret []byte, limit int, peek bool, _ int64) ([][]byte, error) {
	var mid [16]byte
	copy(mid[:], mailboxID)
	msgs, _, err := s.store.ReceiveMessages(context.Background(), mid, readSecret, limit, !peek)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, m.Envelope)
	}
	return out, nil
}
