# FileRelay — Framing (authoritative)

NanoPack serialization and transport framing are different concerns.

## NanoPack payload (all transports)

```text
[fieldCount u8]([fieldID u8][len ULEB128])* + raw bodies concatenated
```

Integers are big-endian fixed-width (`u64=8B`, `u32=4B`). Field names never
travel. Unknown field IDs are ignored; missing required fields are errors.

## HTTP (reliable, length-delimited) — NO WrapPacket

Each `POST <route>` body is exactly one NanoPack payload:

```text
POST /fr/v1/send
Content-Type: application/x-nanopack
X-FileRelay-Schema: 57
X-FileRelay-Protocol: 1.0

<nanopack body for schema 57>
```

The HTTP body length IS the frame. Do not add magic+CRC. Responses mirror
this (single NanoPack body of the response schema, same headers).

## Streams (UART/BLE/TCP-multiplexed) — YES WrapPacket

```text
[B2][major][minor][schema][flags][len BE32][body][crc16 lo][crc16 hi]
```

`major/minor` = nanopack library version (currently 1.0), `schema` =
FileRelay schema ID, `flags = 0`, `len` bounds-checked against
`MaxPacketLen` (1 MiB) before allocation, CRC-16/CCITT-FALSE over all
preceding bytes. `UnwrapPacket` returns consumed `n` so `buf[n:]` reads the
next packet.

FileRelay protocol version (1.0) travels in `Hello`/HTTP headers, not in
this envelope. Check both on streams.

## Rule

One framing scheme per transport class. Never add per-module framing.
