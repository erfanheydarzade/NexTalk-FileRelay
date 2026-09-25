package router

import (
	"crypto/sha256"

	"github.com/erfanheydarzade/NexTalk-FileRelay/protocol"
)

func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }

var _ = protocol.ProtocolMajor
