// Package main — NanoPack RPC codec subset for the NexTalk runtime transport
// API (api_version 1). Canonical contract lives in NexTalk's
// internal/transport (schemas 100–114); this copy is byte-compatible and
// the initialize api_version gate catches any drift. Only the ops the
// courier bridge needs are implemented.
package main

import (
	"encoding/binary"
	"fmt"

	"github.com/erfanheydarzade/nanopack"
)

const (
	schemaEnvelope  = 100
	opInitialize    = 1
	opStartStop     = 2
	opSend          = 3
	opAttach        = 4
	opDetach        = 5
	opPoll          = 6
	opStatus        = 7
	opCapabilities  = 8
	actionStart     = 1
	actionStop      = 2
	transportAPIVer = 1
	bridgeVersion   = "1.0.0"
	bridgeID        = "filerelay"
	maxFrameBytes   = 40 * 1024
	maxRPCBytes     = 2 << 20
)

type envelope struct {
	op      uint8
	reqID   uint32
	payload []byte
}

func marshalEnvelope(op uint8, reqID uint32, payload []byte) ([]byte, error) {
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte{op})
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], reqID)
	enc.AddID(2, b[:])
	enc.AddID(3, payload)
	return enc.Bytes()
}

func unmarshalEnvelope(body []byte) (*envelope, error) {
	if len(body) == 0 || len(body) > maxRPCBytes {
		return nil, fmt.Errorf("rpc: bad envelope length")
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &envelope{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, fmt.Errorf("rpc: bad op")
			}
			out.op = f.Data[0]
		case 2:
			if len(f.Data) != 4 {
				return nil, nanopack.ErrShortBody
			}
			out.reqID = binary.BigEndian.Uint32(f.Data)
		case 3:
			out.payload = append([]byte(nil), f.Data...)
		}
	}
	return out, nil
}

func frameMessage(body []byte) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out
}

type initialize struct {
	transportID string
	apiVersion  uint8
	config      []byte
}

func unmarshalInitialize(body []byte) (*initialize, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &initialize{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.transportID = string(append([]byte(nil), f.Data...))
		case 2:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.apiVersion = f.Data[0]
		case 3:
			out.config = append([]byte(nil), f.Data...)
		}
	}
	return out, nil
}

func marshalInitResult(ok bool, detail string, api uint8) []byte {
	enc := &nanopack.Encoder{}
	if ok {
		enc.AddID(1, []byte{1})
	} else {
		enc.AddID(1, []byte{0})
	}
	enc.AddID(2, []byte(detail))
	enc.AddID(3, []byte{api})
	b, _ := enc.Bytes()
	return b
}

func marshalAck(ok bool, detail string) []byte {
	enc := &nanopack.Encoder{}
	if ok {
		enc.AddID(1, []byte{1})
	} else {
		enc.AddID(1, []byte{0})
	}
	enc.AddID(2, []byte(detail))
	b, _ := enc.Bytes()
	return b
}

func unmarshalAck(body []byte) (bool, string) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return false, err.Error()
	}
	ok := false
	detail := ""
	for _, f := range fields {
		switch f.ID {
		case 1:
			ok = len(f.Data) == 1 && f.Data[0] == 1
		case 2:
			detail = string(f.Data)
		}
	}
	return ok, detail
}

type sendReq struct {
	frame        []byte
	recipientPub []byte
	mailboxID    []byte
	shardURL     string
}

func unmarshalSend(body []byte) (*sendReq, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &sendReq{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.frame = append([]byte(nil), f.Data...)
		case 2:
			out.recipientPub = append([]byte(nil), f.Data...)
		case 4:
			out.mailboxID = append([]byte(nil), f.Data...)
		case 5:
			out.shardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.frame) == 0 || len(out.frame) > maxFrameBytes {
		return nil, fmt.Errorf("rpc: frame out of bounds")
	}
	return out, nil
}

type attachReq struct {
	mailboxID  []byte
	readSecret []byte
	shardURL   string
	routerURL  string
}

func unmarshalAttach(body []byte) (*attachReq, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &attachReq{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.mailboxID = append([]byte(nil), f.Data...)
		case 2:
			out.readSecret = append([]byte(nil), f.Data...)
		case 3:
			out.shardURL = string(append([]byte(nil), f.Data...))
		case 4:
			out.routerURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.mailboxID) != 16 || len(out.readSecret) != 32 || out.shardURL == "" {
		return nil, fmt.Errorf("rpc: bad attach")
	}
	return out, nil
}

func unmarshalDetach(body []byte) ([]byte, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	for _, f := range fields {
		if f.ID == 1 {
			if len(f.Data) != 16 {
				return nil, fmt.Errorf("rpc: bad detach")
			}
			return append([]byte(nil), f.Data...), nil
		}
	}
	return nil, fmt.Errorf("rpc: bad detach")
}

type pollReq struct {
	limit     uint8
	mailboxID []byte
}

func unmarshalPoll(body []byte) (*pollReq, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &pollReq{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.limit = f.Data[0]
		case 2:
			out.mailboxID = append([]byte(nil), f.Data...)
		}
	}
	if out.limit == 0 {
		out.limit = 32
	}
	return out, nil
}

func marshalPollResult(frames [][]byte) []byte {
	var blob []byte
	for _, f := range frames {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(len(f)))
		blob = append(blob, b[:]...)
		blob = append(blob, f...)
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, blob)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], uint32(len(frames)))
	enc.AddID(2, c[:])
	b, _ := enc.Bytes()
	return b
}

func marshalStatus(running bool, detail string) []byte {
	enc := &nanopack.Encoder{}
	if running {
		enc.AddID(1, []byte{1})
	} else {
		enc.AddID(1, []byte{0})
	}
	enc.AddID(2, []byte(detail))
	b, _ := enc.Bytes()
	return b
}

func marshalCaps() []byte {
	caps := []string{"message", "binary-transfer"}
	var blob []byte
	for _, c := range caps {
		blob = append(blob, byte(len(c)>>8), byte(len(c)))
		blob = append(blob, c...)
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, blob)
	enc.AddID(2, []byte(bridgeID))
	enc.AddID(3, []byte(bridgeVersion))
	b, _ := enc.Bytes()
	return b
}

func marshalError(code uint32, detail string) []byte {
	enc := &nanopack.Encoder{}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], code)
	enc.AddID(1, b[:])
	enc.AddID(2, []byte(detail))
	out, _ := enc.Bytes()
	return out
}

func unmarshalStartStop(body []byte) (uint8, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return 0, err
	}
	for _, f := range fields {
		if f.ID == 1 && len(f.Data) == 1 {
			return f.Data[0], nil
		}
	}
	return 0, fmt.Errorf("rpc: missing action")
}
