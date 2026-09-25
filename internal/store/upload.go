package store

import (
	"os"
	"path/filepath"
	"time"
)

// Upload represents a single file relay upload session.
type Upload struct {
	ID        string    // hex-encoded UUID for the upload
	PubKey    string    // sender's NexTalk pubkey
	Sig       string    // Ed25519 signature of payload hash
	StorePath string    // directory on disk where encrypted chunks are stored
	ExpiresAt time.Time // TTL expiry
	Size      int64     // total bytes received
}

// Destroy removes the upload's storage from disk.
func (u *Upload) Destroy() error {
	return os.RemoveAll(u.StorePath)
}

// WriteChunk writes a chunk of the encrypted payload to disk.
func (u *Upload) WriteChunk(chunk []byte) error {
	chunkPath := filepath.Join(u.StorePath, "chunk.bin")
	f, err := os.OpenFile(chunkPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(chunk)
	return err
}

// HasExpired returns true if the upload has passed its expiry.
func (u *Upload) HasExpired() bool {
	return time.Now().After(u.ExpiresAt)
}
