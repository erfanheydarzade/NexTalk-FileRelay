// Package protocol — ErrorMsg (51) codec.
package protocol

import (
	"github.com/erfanheydarzade/nanopack"
)

// MarshalError encodes ErrorMsg. FID 1=code u32, 2=detail string, 3=retry_after u32.
func MarshalError(e *ProtocolError) ([]byte, error) {
	enc := &nanopack.Encoder{}
	enc.AddID(1, putU32(e.Code))
	if e.Detail != "" {
		enc.AddID(2, []byte(e.Detail))
	}
	if e.RetryAfter != 0 {
		enc.AddID(3, putU32(e.RetryAfter))
	}
	return enc.Bytes()
}

// UnmarshalError decodes ErrorMsg. Unknown fields ignored.
func UnmarshalError(body []byte) (*ProtocolError, error) {
	if err := CheckBodyLen(len(body), 4096); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ProtocolError{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Code = v
		case 2:
			out.Detail = string(append([]byte(nil), f.Data...))
		case 3:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.RetryAfter = v
		}
	}
	if out.Code == 0 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "error code 0 is reserved"}
	}
	return out, nil
}

// AsProtocolError maps arbitrary decode failures to a stable code.
func AsProtocolError(err error) *ProtocolError {
	if pe, ok := err.(*ProtocolError); ok {
		return pe
	}
	return &ProtocolError{Code: ErrInvalidRequest, Detail: "invalid request"}
}
