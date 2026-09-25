package shard

import (
	"crypto/sha256"
)

func hash16(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:16]
}

func checkSecret(stored [32]byte, provided []byte) bool {
	h := sha256.Sum256(provided)
	if len(provided) != 32 {
		return false
	}
	for i := range stored {
		if stored[i] != h[i] {
			return false
		}
	}
	return true
}
