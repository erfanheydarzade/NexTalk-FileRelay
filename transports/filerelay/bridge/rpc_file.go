// File/mailbox RPC codecs (schemas 115–126) mirroring NexTalk
// internal/transport. See rpc.go header for the drift policy.
package main

import (
	"encoding/binary"
	"fmt"

	"github.com/erfanheydarzade/nanopack"
)

const (
	opRegister     = 9
	opResolve      = 10
	opXferCreate   = 11
	opXferPut      = 12
	opXferResume   = 13
	opXferGet      = 14
	opXferComplete = 15
	opXferCancel   = 16
	opError        = 0
)

func getU32(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, nanopack.ErrShortBody
	}
	return binary.BigEndian.Uint32(b), nil
}

func getU64(b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, nanopack.ErrShortBody
	}
	return binary.BigEndian.Uint64(b), nil
}

func putU32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	out := make([]byte, 4)
	copy(out, b[:])
	return out
}

func putU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	out := make([]byte, 8)
	copy(out, b[:])
	return out
}

func errPayload(code uint32, detail string) []byte { return marshalError(code, detail) }

type registerReq struct {
	userTag   string
	routerURL string
}

func unmarshalRegisterReq(body []byte) (*registerReq, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &registerReq{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.userTag = string(append([]byte(nil), f.Data...))
		case 2:
			out.routerURL = string(append([]byte(nil), f.Data...))
		}
	}
	if out.userTag == "" {
		return nil, fmt.Errorf("rpc: bad register")
	}
	return out, nil
}

func marshalRegisterResult(mailboxID, readSecret []byte, shardURL, routerURL string) []byte {
	enc := &nanopack.Encoder{}
	enc.AddID(1, mailboxID)
	enc.AddID(2, readSecret)
	enc.AddID(3, []byte(shardURL))
	enc.AddID(4, []byte(routerURL))
	b, _ := enc.Bytes()
	return b
}

type resolveReq struct {
	recipientPub []byte
	routerURL    string
}

func unmarshalResolveReq(body []byte) (*resolveReq, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &resolveReq{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.recipientPub = append([]byte(nil), f.Data...)
		case 2:
			out.routerURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.recipientPub) != 32 {
		return nil, fmt.Errorf("rpc: bad resolve")
	}
	return out, nil
}

func marshalResolveResult(mailboxID []byte, shardURL string) []byte {
	enc := &nanopack.Encoder{}
	enc.AddID(1, mailboxID)
	enc.AddID(2, []byte(shardURL))
	b, _ := enc.Bytes()
	return b
}

type xferCreate struct {
	total        uint64
	chunkSize    uint32
	chunkCount   uint32
	manifest     []byte
	mailboxID    []byte
	recipientPub []byte
	shardURL     string
}

func unmarshalXferCreate(body []byte) (*xferCreate, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &xferCreate{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.total = v
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.chunkSize = v
		case 3:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.chunkCount = v
		case 4:
			out.manifest = append([]byte(nil), f.Data...)
		case 5:
			out.mailboxID = append([]byte(nil), f.Data...)
		case 6:
			out.recipientPub = append([]byte(nil), f.Data...)
		case 7:
			out.shardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if out.total == 0 || out.chunkSize == 0 || out.chunkCount == 0 {
		return nil, fmt.Errorf("rpc: bad xfer params")
	}
	return out, nil
}

func marshalXferCreated(transferID, downloadSecret []byte, shardURL string, expires uint64) []byte {
	enc := &nanopack.Encoder{}
	enc.AddID(1, transferID)
	enc.AddID(2, putU64(expires))
	enc.AddID(3, downloadSecret)
	enc.AddID(4, []byte(shardURL))
	b, _ := enc.Bytes()
	return b
}

type xferPut struct {
	transferID []byte
	index      uint32
	payload    []byte
	hash       []byte
	offset     uint64
}

func unmarshalXferPut(body []byte) (*xferPut, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &xferPut{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.transferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.index = v
		case 3:
			out.payload = append([]byte(nil), f.Data...)
		case 4:
			out.hash = append([]byte(nil), f.Data...)
		case 5:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.offset = v
		}
	}
	if len(out.transferID) != 16 || len(out.payload) == 0 || len(out.hash) != 32 {
		return nil, fmt.Errorf("rpc: bad chunk")
	}
	return out, nil
}

func marshalXferProgress(highest, count uint32, missing, bitmap []byte, encoding uint8) []byte {
	enc := &nanopack.Encoder{}
	enc.AddID(1, putU32(highest))
	enc.AddID(2, missing)
	enc.AddID(3, bitmap)
	enc.AddID(4, []byte{encoding})
	enc.AddID(5, putU32(count))
	b, _ := enc.Bytes()
	return b
}

type xferResume struct {
	transferID []byte
	mailboxID  []byte
	readSecret []byte
	ticket     []byte
	shardURL   string
}

func unmarshalXferResume(body []byte) (*xferResume, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &xferResume{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.transferID = append([]byte(nil), f.Data...)
		case 2:
			out.mailboxID = append([]byte(nil), f.Data...)
		case 3:
			out.readSecret = append([]byte(nil), f.Data...)
		case 4:
			out.ticket = append([]byte(nil), f.Data...)
		case 5:
			out.shardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.transferID) != 16 {
		return nil, fmt.Errorf("rpc: bad resume")
	}
	if err := checkResumeAuth(out.mailboxID, out.readSecret, out.ticket); err != nil {
		return nil, err
	}
	return out, nil
}

// checkResumeAuth enforces exactly one auth context: mailbox bearer
// (mailbox 16B + secret 32B) or download ticket (32B, mailbox + secret empty).
func checkResumeAuth(mailboxID, readSecret, ticket []byte) error {
	if len(ticket) == 32 {
		if len(mailboxID) != 0 || len(readSecret) != 0 {
			return fmt.Errorf("rpc: ticket mode: mailbox and read_secret must be empty")
		}
		return nil
	}
	if len(ticket) != 0 {
		return fmt.Errorf("rpc: ticket must be 32 bytes")
	}
	if len(mailboxID) != 16 || len(readSecret) != 32 {
		return fmt.Errorf("rpc: bad resume")
	}
	return nil
}

type xferGet struct {
	transferID []byte
	index      uint32
	mailboxID  []byte
	readSecret []byte
	ticket     []byte
	shardURL   string
}

func unmarshalXferGet(body []byte) (*xferGet, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &xferGet{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.transferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.index = v
		case 3:
			out.mailboxID = append([]byte(nil), f.Data...)
		case 4:
			out.readSecret = append([]byte(nil), f.Data...)
		case 5:
			out.ticket = append([]byte(nil), f.Data...)
		case 6:
			out.shardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.transferID) != 16 {
		return nil, fmt.Errorf("rpc: bad get")
	}
	if err := checkResumeAuth(out.mailboxID, out.readSecret, out.ticket); err != nil {
		return nil, fmt.Errorf("rpc: bad get: %v", err)
	}
	return out, nil
}

func marshalXferChunk(payload, hash []byte) []byte {
	enc := &nanopack.Encoder{}
	enc.AddID(1, payload)
	enc.AddID(2, hash)
	b, _ := enc.Bytes()
	return b
}

type xferComplete struct {
	transferID   []byte
	manifestHash []byte
}

func unmarshalXferComplete(body []byte) (*xferComplete, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &xferComplete{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.transferID = append([]byte(nil), f.Data...)
		case 2:
			out.manifestHash = append([]byte(nil), f.Data...)
		}
	}
	if len(out.transferID) != 16 || len(out.manifestHash) != 32 {
		return nil, fmt.Errorf("rpc: bad complete")
	}
	return out, nil
}

type xferCancel struct {
	transferID []byte
	mailboxID  []byte
	readSecret []byte
}

func unmarshalXferCancel(body []byte) (*xferCancel, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &xferCancel{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.transferID = append([]byte(nil), f.Data...)
		case 2:
			out.mailboxID = append([]byte(nil), f.Data...)
		case 3:
			out.readSecret = append([]byte(nil), f.Data...)
		}
	}
	if len(out.transferID) != 16 || len(out.mailboxID) != 16 || len(out.readSecret) != 32 {
		return nil, fmt.Errorf("rpc: bad cancel")
	}
	return out, nil
}
