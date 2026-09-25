// Package protocol — control-plane schemas: Hello (50), Register (52),
// RegisterResponse (53), Resolve (54), ResolveResponse (55), RoutingTable (56).
package protocol

import (
	"github.com/erfanheydarzade/nanopack"
)

//nanopack:schema id=50
type Hello struct {
	Major uint8
	Minor uint8
	NowMS uint64
}

// MarshalHello: FID 1=major u8, 2=minor u8, 3=now_ms u64.
func MarshalHello(h *Hello) ([]byte, error) {
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte{h.Major})
	enc.AddID(2, []byte{h.Minor})
	enc.AddID(3, putU64(h.NowMS))
	return enc.Bytes()
}

// UnmarshalHello decodes Hello.
func UnmarshalHello(body []byte) (*Hello, error) {
	if err := CheckBodyLen(len(body), 64); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Hello{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Major = f.Data[0]
		case 2:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Minor = f.Data[0]
		case 3:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.NowMS = v
		}
	}
	return out, nil
}

//nanopack:schema id=52
type Register struct {
	ClientPub []byte // 32 B Ed25519 raw
	Timestamp uint64
	Nonce     []byte // 16 B
	Signature []byte // 64 B over CanonicalRegister
}

// MarshalRegister: 1=pub, 2=ts u64, 3=nonce, 4=sig.
func MarshalRegister(r *Register) ([]byte, error) {
	if err := ValidateRegister(r); err != nil {
		return nil, err
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.ClientPub)
	enc.AddID(2, putU64(r.Timestamp))
	enc.AddID(3, r.Nonce)
	enc.AddID(4, r.Signature)
	return enc.Bytes()
}

// UnmarshalRegister decodes + validates shapes.
func UnmarshalRegister(body []byte) (*Register, error) {
	if err := CheckBodyLen(len(body), 256); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Register{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.ClientPub = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.Timestamp = v
		case 3:
			out.Nonce = append([]byte(nil), f.Data...)
		case 4:
			out.Signature = append([]byte(nil), f.Data...)
		}
	}
	if err := ValidateRegister(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateRegister checks field shapes (not signature validity).
func ValidateRegister(r *Register) error {
	if len(r.ClientPub) != 32 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "client_pub must be 32 bytes"}
	}
	if len(r.Nonce) != 16 {
		return &ProtocolError{Code: ErrInvalidRequest, Detail: "nonce must be 16 bytes"}
	}
	if len(r.Signature) != 64 {
		return &ProtocolError{Code: ErrAuthFailed, Detail: "signature must be 64 bytes"}
	}
	return nil
}

//nanopack:schema id=53
type RegisterResponse struct {
	MailboxID    []byte // 16 B opaque
	ReadSecret   []byte // 32 B raw (presented once)
	ShardURL     string
	TableVersion uint32
	ExpiresAt    uint64
}

// MarshalRegisterResponse: 1=mailbox, 2=read_secret, 3=shard_url, 4=table_version u32, 5=expires_at u64.
func MarshalRegisterResponse(r *RegisterResponse) ([]byte, error) {
	if len(r.MailboxID) != 16 || len(r.ReadSecret) != 32 || r.ShardURL == "" {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad register response"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.MailboxID)
	enc.AddID(2, r.ReadSecret)
	enc.AddID(3, []byte(r.ShardURL))
	enc.AddID(4, putU32(r.TableVersion))
	enc.AddID(5, putU64(r.ExpiresAt))
	return enc.Bytes()
}

// UnmarshalRegisterResponse decodes RegisterResponse.
func UnmarshalRegisterResponse(body []byte) (*RegisterResponse, error) {
	if err := CheckBodyLen(len(body), 1024); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &RegisterResponse{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 2:
			out.ReadSecret = append([]byte(nil), f.Data...)
		case 3:
			out.ShardURL = string(append([]byte(nil), f.Data...))
		case 4:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.TableVersion = v
		case 5:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.ExpiresAt = v
		}
	}
	if len(out.MailboxID) != 16 || len(out.ReadSecret) != 32 || out.ShardURL == "" {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad register response"}
	}
	return out, nil
}

//nanopack:schema id=54
type Resolve struct {
	ClientPub []byte // 32 B raw, unauthenticated probe
}

// MarshalResolve: 1=pub.
func MarshalResolve(r *Resolve) ([]byte, error) {
	if len(r.ClientPub) != 32 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "client_pub must be 32 bytes"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.ClientPub)
	return enc.Bytes()
}

// UnmarshalResolve decodes Resolve.
func UnmarshalResolve(body []byte) (*Resolve, error) {
	if err := CheckBodyLen(len(body), 128); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Resolve{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.ClientPub = append([]byte(nil), f.Data...)
		}
	}
	if len(out.ClientPub) != 32 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "client_pub must be 32 bytes"}
	}
	return out, nil
}

//nanopack:schema id=55
type ResolveResponse struct {
	MailboxID    []byte // 16 B
	ShardURL     string
	Era          uint32
	TableVersion uint32
}

// MarshalResolveResponse: 1=mailbox, 2=shard_url, 3=era u32, 4=table_version u32.
func MarshalResolveResponse(r *ResolveResponse) ([]byte, error) {
	if len(r.MailboxID) != 16 || r.ShardURL == "" {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad resolve response"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, r.MailboxID)
	enc.AddID(2, []byte(r.ShardURL))
	enc.AddID(3, putU32(r.Era))
	enc.AddID(4, putU32(r.TableVersion))
	return enc.Bytes()
}

// UnmarshalResolveResponse decodes ResolveResponse.
func UnmarshalResolveResponse(body []byte) (*ResolveResponse, error) {
	if err := CheckBodyLen(len(body), 1024); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ResolveResponse{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 2:
			out.ShardURL = string(append([]byte(nil), f.Data...))
		case 3:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Era = v
		case 4:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.TableVersion = v
		}
	}
	if len(out.MailboxID) != 16 || out.ShardURL == "" {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad resolve response"}
	}
	return out, nil
}

// Routing algorithm IDs.
const (
	RoutingAlgoSHA256ModN uint8 = 1
)

//nanopack:schema id=56
type RoutingTable struct {
	Version           uint32
	GeneratedAt       uint64
	ExpiresAt         uint64
	Algorithm         uint8
	Shards            []string
	ReplicationFactor uint32
	RouterPub         []byte // 32 B
	Signature         []byte // 64 B over CanonicalRoutingTable
}

// encodeShardList packs shards as concat of (u16 BE len + bytes).
func encodeShardList(shards []string) []byte {
	var out []byte
	for _, s := range shards {
		b := []byte(s)
		out = append(out, byte(len(b)>>8), byte(len(b)))
		out = append(out, b...)
	}
	return out
}

// decodeShardList unpacks encodeShardList.
func decodeShardList(blob []byte) ([]string, error) {
	var out []string
	pos := 0
	for pos < len(blob) {
		if pos+2 > len(blob) {
			return nil, nanopack.ErrShortBody
		}
		n := int(blob[pos])<<8 | int(blob[pos+1])
		pos += 2
		if n <= 0 || pos+n > len(blob) {
			return nil, nanopack.ErrShortBody
		}
		out = append(out, string(blob[pos:pos+n]))
		pos += n
	}
	return out, nil
}

// MarshalRoutingTable: 1=version u32, 2=generated u64, 3=expires u64, 4=algo u8,
// 5=shards blob, 6=replication u32, 7=router_pub, 8=sig.
func MarshalRoutingTable(t *RoutingTable) ([]byte, error) {
	if len(t.RouterPub) != 32 || len(t.Signature) != 64 || len(t.Shards) == 0 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad routing table"}
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, putU32(t.Version))
	enc.AddID(2, putU64(t.GeneratedAt))
	enc.AddID(3, putU64(t.ExpiresAt))
	enc.AddID(4, []byte{t.Algorithm})
	enc.AddID(5, encodeShardList(t.Shards))
	enc.AddID(6, putU32(t.ReplicationFactor))
	enc.AddID(7, t.RouterPub)
	enc.AddID(8, t.Signature)
	return enc.Bytes()
}

// UnmarshalRoutingTable decodes RoutingTable.
func UnmarshalRoutingTable(body []byte) (*RoutingTable, error) {
	if err := CheckBodyLen(len(body), 8192); err != nil {
		return nil, err
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &RoutingTable{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Version = v
		case 2:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.GeneratedAt = v
		case 3:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.ExpiresAt = v
		case 4:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Algorithm = f.Data[0]
		case 5:
			shards, err := decodeShardList(f.Data)
			if err != nil {
				return nil, err
			}
			out.Shards = shards
		case 6:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.ReplicationFactor = v
		case 7:
			out.RouterPub = append([]byte(nil), f.Data...)
		case 8:
			out.Signature = append([]byte(nil), f.Data...)
		}
	}
	if len(out.RouterPub) != 32 || len(out.Signature) != 64 || len(out.Shards) == 0 {
		return nil, &ProtocolError{Code: ErrInvalidRequest, Detail: "bad routing table"}
	}
	return out, nil
}
