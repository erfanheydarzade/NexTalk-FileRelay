// Package protocol — message-plane codecs: SendMessageResponse (58),
// ReceiveMessages (59) codec, ReceiveMessagesResponse (60),
// MessageAck (61) codec, MessageAckResponse (62).
//
// Ack dispositions: 1=received, 2=consumed.
package protocol

import (
	"github.com/erfanheydarzade/nanopack"
)

const (
	AckReceived uint8 = 1
	AckConsumed uint8 = 2
)

// MarshalSendMessageResponse: 1=accepted u8, 2=queued u32, 3=msg_id 16B.
func MarshalSendMessageResponse(accepted uint8, queued uint32, msgID []byte) ([]byte, error) {
	if len(msgID) != 16 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "msg_id must be 16 bytes"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte{accepted})
	enc.AddID(2, putU32(queued))
	enc.AddID(3, msgID)
	return enc.Bytes()
}

// SendMessageResponse is defined in schemas.go; decoded form of schema 58.

// UnmarshalSendMessageResponse decodes schema 58.
func UnmarshalSendMessageResponse(body []byte) (*SendMessageResponse, error) {
	if err := CheckBodyLen(len(body), 256); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &SendMessageResponse{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Accepted = f.Data[0]
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Queued = v
		case 3:
			out.MsgID = append([]byte(nil), f.Data...)
		}
	}
	if len(out.MsgID) != 16 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "msg_id must be 16 bytes"}
	}
	return out, nil
}

// MarshalReceiveMessages: 1=mailbox 16B, 2=read_secret 32B, 3=limit u8, 4=peek u8.
func MarshalReceiveMessages(r *ReceiveMessages) ([]byte, error) {
	if err := ValidateReceiveMessages(r); err != nil {
		return nil, err
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.MailboxID)
	enc.AddID(2, r.ReadSecret)
	enc.AddID(3, []byte{r.Limit})
	enc.AddID(4, []byte{r.Peek})
	return enc.Bytes()
}

// UnmarshalReceiveMessages decodes schema 59.
func UnmarshalReceiveMessages(body []byte) (*ReceiveMessages, error) {
	if err := CheckBodyLen(len(body), 256); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ReceiveMessages{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 2:
			out.ReadSecret = append([]byte(nil), f.Data...)
		case 3:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Limit = f.Data[0]
		case 4:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Peek = f.Data[0]
		}
	}
	if err := ValidateReceiveMessages(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateReceiveMessages checks shapes.
func ValidateReceiveMessages(r *ReceiveMessages) error {
	if len(r.MailboxID) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "mailbox_id must be 16 bytes"}
	}
	if len(r.ReadSecret) != 32 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "read_secret must be 32 bytes"}
	}
	return nil
}

// ReceivedMessage is one entry of a ReceiveMessagesResponse batch.
type ReceivedMessage struct {
	MsgID    []byte // 16 B
	Envelope []byte // opaque
}

// MarshalReceiveMessagesResponse: 1=count u32, 2=ids (count*16B),
// 3=payloads (each BE32 len + bytes), 4=consumed u8.
func MarshalReceiveMessagesResponse(msgs []ReceivedMessage, consumed bool) ([]byte, error) {
	if len(msgs) > MaxBatchMessages {
		return nil, &ProtocolError{Code: ErrBatchTooLarge, Detail: "batch too large"}
	}
	ids := make([]byte, 0, len(msgs)*16)
	var payloads []byte
	for _, m := range msgs {
		if len(m.MsgID) != 16 {
			return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "msg_id must be 16 bytes"}
		}
		if len(m.Envelope) == 0 || len(m.Envelope) > MaxMessageBytes {
			return nil, &ProtocolError{Code: ErrMessageTooLarge, Detail: "envelope out of bounds"}
		}
		ids = append(ids, m.MsgID...)
		payloads = append(payloads, putU32(uint32(len(m.Envelope)))...)
		payloads = append(payloads, m.Envelope...)
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, putU32(uint32(len(msgs))))
	enc.AddID(2, ids)
	enc.AddID(3, payloads)
	if consumed {
		enc.AddID(4, []byte{1})
	} else {
		enc.AddID(4, []byte{0})
	}
	return enc.Bytes()
}

// ReceiveMessagesResponse is the decoded form of schema 60.
type ReceiveMessagesResponse struct {
	Messages []ReceivedMessage
	Consumed bool
}

// UnmarshalReceiveMessagesResponse decodes schema 60.
func UnmarshalReceiveMessagesResponse(body []byte) (*ReceiveMessagesResponse, error) {
	// Batch responses can be large: up to MaxBatchMessages * MaxMessageBytes.
	if err := CheckBodyLen(len(body), MaxBatchMessages*MaxMessageBytes+4096); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	var count uint32
	var ids, payloads []byte
	consumed := false
	seenConsumed := false
	for _, f := range fields {
		switch f.ID {
		case 1:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			count = v
		case 2:
			ids = append([]byte(nil), f.Data...)
		case 3:
			payloads = append([]byte(nil), f.Data...)
		case 4:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			consumed = f.Data[0] == 1
			seenConsumed = true
		}
	}
	if count > MaxBatchMessages {
		return nil, &ProtocolError{Code: ErrBatchTooLarge, Detail: "batch too large"}
	}
	if uint32(len(ids)) != count*16 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "ids length mismatch"}
	}
	msgs := make([]ReceivedMessage, 0, count)
	pos := 0
	for i := uint32(0); i < count; i++ {
		if pos+4 > len(payloads) {
			return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "payloads truncated"}
		}
		n := int(uint32(payloads[pos])<<24 | uint32(payloads[pos+1])<<16 | uint32(payloads[pos+2])<<8 | uint32(payloads[pos+3]))
		pos += 4
		if n <= 0 || n > MaxMessageBytes || pos+n > len(payloads) {
			return nil, &ProtocolError{Code: ErrMessageTooLarge, Detail: "envelope out of bounds"}
		}
		msgs = append(msgs, ReceivedMessage{
			MsgID:    append([]byte(nil), ids[i*16:(i+1)*16]...),
			Envelope: append([]byte(nil), payloads[pos:pos+n]...),
		})
		pos += n
	}
	if pos != len(payloads) {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "payloads trailing bytes"}
	}
	_ = seenConsumed
	return &ReceiveMessagesResponse{Messages: msgs, Consumed: consumed}, nil
}

// MarshalMessageAck: 1=mailbox 16B, 2=read_secret 32B, 3=msg_ids (n*16B), 4=disposition u8.
func MarshalMessageAck(a *MessageAck) ([]byte, error) {
	if err := ValidateMessageAck(a); err != nil {
		return nil, err
	}
	var flat []byte
	for _, id := range a.MsgIDs {
		flat = append(flat, id...)
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, a.MailboxID)
	enc.AddID(2, a.ReadSecret)
	enc.AddID(3, flat)
	enc.AddID(4, []byte{a.Disposition})
	return enc.Bytes()
}

// UnmarshalMessageAck decodes schema 61.
func UnmarshalMessageAck(body []byte) (*MessageAck, error) {
	if err := CheckBodyLen(len(body), MaxBatchMessages*16+256); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &MessageAck{}
	var flat []byte
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 2:
			out.ReadSecret = append([]byte(nil), f.Data...)
		case 3:
			flat = append([]byte(nil), f.Data...)
		case 4:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Disposition = f.Data[0]
		}
	}
	if len(flat)%16 != 0 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "msg_ids must be n*16 bytes"}
	}
	for i := 0; i < len(flat); i += 16 {
		out.MsgIDs = append(out.MsgIDs, append([]byte(nil), flat[i:i+16]...))
	}
	if err := ValidateMessageAck(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateMessageAck checks shapes + disposition.
func ValidateMessageAck(a *MessageAck) error {
	if len(a.MailboxID) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "mailbox_id must be 16 bytes"}
	}
	if len(a.ReadSecret) != 32 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "read_secret must be 32 bytes"}
	}
	if len(a.MsgIDs) == 0 || len(a.MsgIDs) > MaxBatchMessages {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "msg_ids count out of bounds"}
	}
	for _, id := range a.MsgIDs {
		if len(id) != 16 {
			return &ProtocolError{Code: ErrInvalidRequest, Detail: "msg_id must be 16 bytes"}
		}
	}
	if a.Disposition != AckReceived && a.Disposition != AckConsumed {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "bad disposition"}
	}
	return nil
}

// MessageAckResponse is the decoded form of schema 62.
type MessageAckResponse struct {
	Acked     uint32
	Remaining uint32
}

// MarshalMessageAckResponse: 1=acked u32, 2=remaining u32.
func MarshalMessageAckResponse(acked, remaining uint32) ([]byte, error) {
	enc := &nanopack.Encoder{}
	enc.AddID(1, putU32(acked))
	enc.AddID(2, putU32(remaining))
	return enc.Bytes()
}

// UnmarshalMessageAckResponse decodes schema 62.
func UnmarshalMessageAckResponse(body []byte) (*MessageAckResponse, error) {
	if err := CheckBodyLen(len(body), 64); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &MessageAckResponse{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Acked = v
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Remaining = v
		}
	}
	return out, nil
}
