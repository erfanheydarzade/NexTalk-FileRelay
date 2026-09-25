# FileRelay — Design Document (v1, implemented)

Status: `implemented`. The protocol below ships: `protocol/` codecs,
`server/router` + `server/shard` handlers over a `server/storage`
abstraction, `cmd/filerelayd`, the `transports/filerelay` courier bridge,
and cross-language vectors. Schema IDs and field IDs are frozen at
protocol major `1`; see `docs/server.md` for the deployed API.

Built on top of (no architectural assumptions):

- NexTalk core packages: schemas 20/21, hybrid key exchange (schema 1),
  the relay `Type 0x01..0x04` envelope wrapping, and the serialization
  registry (1/10/11/20/21/40/41/44).
- NanoPack: envelope `0xB2` (major 1/minor 0, `MaxPacketLen=1MiB`,
  CRC-16/CCITT-FALSE) and ULEB128 varints.

---

## 1. Architecture

```text
NexTalk Core (crypto/core/client)
  │ opaque encrypted payload (already E2E-encrypted SecureMessage / fan-out delivery)
  ▼
FileRelay Client Adapter (Go, implements NexTalk Relay-like Send/Receive;
  also standalone TransferClient for chunks)
  │ NanoPack binary bodies over HTTP
  ▼
FileRelay Router (off-hot-path: register/resolve/table/push, never proxies send/read)
  │ routing-table publication + mailbox-ID derivation
  ├──────────────┼──────────────┐
  ▼              ▼              ▼
Shard A        Shard B        Shard C   (dumb storage: mailbox/msg/chunk/TTL/ACK/RL)
  │              │              │
  └──────────────┼──────────────┘
           opaque storage (KV)
```

`FileRelay/` layout in this repo:

```text
FileRelay/
  DESIGN.md            ← this file (canonical before code)
  FRAMING.md           ← §3 decision, HTTP mapping
  protocol/            ← registry, errors, limits, schemas, auth, framing
  client/              ← NexTalk adapter (opaque bytes only) + transfer client
  server/shard/        ← storage, TTL, ACK, resume, RL (no app logic)
  server/router/       ← HMAC mailbox IDs, signed table, shard registry
  testdata/            ← shared cross-language vectors
```

NexTalk integration (no pollution of `core/`/`crypto/`):

```text
NexTalk/transport/filerelay/  → thin wrapper around FileRelay/client
FileRelay/protocol|client|server|router|shard
```

## 2. Trust boundaries

| Layer | Trust | Owns | Must never |
|---|---|---|---|
| NexTalk `crypto`/`core`/`client` | trusted | identity, handshake, ratchet, E2E encrypt/decrypt, session state | transport decisions |
| FileRelay client adapter | trusted (client side) | chunking, reassembly, resume bookkeeping, final verification | plaintext crypto decisions; it only carries what NexTalk gives it |
| FileRelay router | semi-trusted transport | HMAC mailbox-ID derivation (`SERVER_SECRET`), signed table, shard membership, resolve | plaintext, E2E keys, app semantics, proxying message bodies |
| FileRelay shard | **untrusted** | opaque `mailbox_id` storage, TTL, quotas, ACK bookkeeping, per-op Ed25519 verify, RL | pubkey→mailbox mapping, `SERVER_SECRET`, decryption, chat logic |
| Network/storage/replica | untrusted | bytes | integrity (receiver verifies hashes) |

Shard never sees recipient pubkey. Router never sees message/chunk bodies
(it only mints capabilities and answers `resolve` from HMAC + `exists` probes).
Replica never learns plaintext (replicated objects are opaque).

## 3. Protocol framing vs NanoPack framing (decision)

NanoPack serialization (`[count]([id][ULEB128 len])* + bodies`, ints
big-endian fixed-width) and transport framing are separate.

- **HTTP request/response bodies: NO `WrapPacket`.** An HTTP body already has
  an unambiguous length boundary (`Content-Length` / chunked framing). The
  body is exactly one NanoPack payload whose schema is implied by the
  endpoint (`Content-Type: application/x-nanopack; schema=<id>` + `FRAMING.md`).
  Adding magic+CRC here is redundant and is forbidden.
- **Streaming / connection-oriented / multiplexed binary streams: YES
  `WrapPacket`.** Use `WrapPacket(schemaID, body, flags=0)`:
  `[B2][major][minor][schema][flags][len BE32][body][crc16 lo-hi]`.
  This gives resync + dispatch + corruption detection. `MaxPacketLen`
  bounds allocation before reading `len`.
- One rule only. Never invent a second framing scheme per-module.

`Content-Type: application/x-nanopack`, `X-FileRelay-Schema: <id>`,
`X-FileRelay-Protocol: 1.0`. Debug/admin JSON (if any) lives only under
`/debug/*`, never canonical.

## 4. Message lifecycle

```text
queued → available → consumed | expired
                    ↘ (peek → available, no drain)
```

1. `SendMessage{mailbox_id, envelope, opts}` → shard verifies sender auth,
   checks quotas/RL/size, appends `{msg_id,time,envelope,sender_pub,expires_at}`.
   Response distinguishes `accepted_by_relay` (= stored) — never claims
   `delivered/consumed`.
2. `ReceiveMessages{mailbox_id, read_secret, limit, peek}` → returns batch
   (transport batching, not group messaging). Default drains
   (burn-after-read); `peek=1` leaves `available`.
3. `MessageAck{mailbox_id, read_secret, msg_ids[], disposition}` with
   `disposition ∈ {received, consumed}` → shard drops `consumed`, keeps
   accounting for `received`. Ack is recipient-authenticated (read_secret),
   not sender-signed.
4. Lazy expiry on every touch: `now - enqueued_at ≥ msg_ttl → drop backlog`;
   sliding mailbox TTL renewed on create/send/read/ack.

Small encrypted messages never create a transfer. No
create/upload/commit/poll/download/finalize for the message path.

## 5. File lifecycle

```text
created → uploading → complete → available → downloading → consumed
   ↘ expired / cancelled (any pre-consumed state, bounded TTL)
```

1. `TransferCreate{mailbox_id?, params(size,chunk_size,chunk_count,manifest)}`
   → `transfer_id` (server-random 16 B) + `download_secret` (server-random
   32 B, v1.1) + `expires_at`. Sender-authenticated.
2. `ChunkUpload{transfer_id, index, payload[, hash]}` pipelined, multiple
   in-flight. Idempotent (duplicate index+same hash = ACK, no error).
3. `ResumeRequest{transfer_id}` → `ResumeResponse{bitmap|r anges|missing}`.
4. `TransferComplete{transfer_id, manifest_hash}` → server marks `complete`
   iff `chunks_present == chunk_count` (or seals sparse + records missing).
5. Recipient `ChunkDownload{transfer_id, index|range}` → opaque bytes.
   Client reassembles + verifies `chunk_hash` + `manifest_hash`.
6. `TransferCancel` / lazy `expired` reaps incomplete state (bounded TTL,
   see §15). `consumed` after recipient ACK or sender cancel.

### 5.1 Sender-owned upload + ticket share (v1.1)

The sender may bind the transfer to **their own** mailbox instead of the
recipient's. The create response's `download_secret` plus
`(transfer_id, shard_url, file manifest)` form a **ticket** the sender
relays to the recipient inside an ordinary E2E message (any message relay,
or a dedicated ticket-only message). The recipient resumes/gets with the
ticket alone — no mailbox, no session, no `read_secret` on the relay
(schemas 67/69 accept exactly one auth context; mixed credentials are
rejected). The ticket is download-only (resume/get), dies with the transfer
(expiry/cancel), and never touches mailbox state: no mailbox lookup, no
owner-TTL slide, no mailbox reads, no put/complete/cancel. Quota still
counts against the owner's mailbox while the transfer lives.

Encryption boundary (§9): NexTalk decides whole-file-vs-per-chunk crypto;
relay stores opaque chunk bytes either way.

## 6. Protocol state machines

Message (per `msg_id`): `QUEUED → AVAILABLE → CONSUMED | EXPIRED`.
Ack moves `AVAILABLE → CONSUMED` only with valid `read_secret`.

Transfer (per `transfer_id`):

```text
CREATED --first ChunkUpload--> UPLOADING --all chunks--> COMPLETE --recipient fetch--> AVAILABLE
   │                              │                         │                              │
   └─CANCELLED/EXPIRED◀───────────┴───TTL/UploadTTL─────────┴──TTL─────────────────────────┘
```

Chunk (per index): `MISSING → STORED (hash-verified at edge where provided)
→ ACKED`. `out_of_range / too_large / hash_mismatch → Error`, no state change.
Duplicate `STORED` with identical bytes = idempotent ACK; different bytes =
`chunk_conflict` error (never silent overwrite).

## 7. NanoPack schema registry (FileRelay v1)

NexTalk already owns `1,10,11,20,21,40,41,44` (see `docs/serialization.md`).
FileRelay starts at **50** to avoid all collisions. Frozen after v1 tag.

| Schema | Name | Direction |
|---|---|---|
| 50 | `Hello` (protocol/version/caps probe) | C↔S |
| 51 | `Error` | S→C |
| 52 | `Register` | C→Router |
| 53 | `RegisterResponse` (mailbox_id, read_secret, shard, replicas, table_version) | Router→C |
| 54 | `Resolve` | C→Router |
| 55 | `ResolveResponse` | Router→C |
| 56 | `RoutingTable` (signed) | Router→all |
| 57 | `SendMessage` | C→Shard |
| 58 | `SendMessageResponse` | Shard→C |
| 59 | `ReceiveMessages` | C→Shard |
| 60 | `ReceiveMessagesResponse` (batch) | Shard→C |
| 61 | `MessageAck` | C→Shard |
| 62 | `MessageAckResponse` | Shard→C |
| 63 | `TransferCreate` | C→Shard |
| 64 | `TransferCreateResponse` (+FID 4 `download_secret`, v1.1) | Shard→C |
| 65 | `ChunkUpload` | C→Shard |
| 66 | `ChunkAck` (ranges/bitmap/highest-contiguous) | Shard→C |
| 67 | `ChunkDownload` (+FID 6 `ticket`, v1.1) | C→Shard |
| 68 | `ChunkDownloadResponse` | Shard→C |
| 69 | `ResumeRequest` (+FID 4 `ticket`, v1.1) | C→Shard |
| 70 | `ResumeResponse` | Shard→C |
| 71 | `TransferComplete` | C→Shard |
| 72 | `TransferCompleteResponse` | Shard→C |
| 73 | `TransferCancel` | C→Shard |
| 74 | `ShardRegister` | Shard→Router |
| 75 | `ShardHeartbeat` | Shard→Router |
| 76 | `ReplicateMessage` | Shard→Shard |
| 77 | `ReplicateChunk` | Shard→Shard |

Field IDs are per-schema, start at 1, never renumbered. `bingen`
(`bin:"N"`) generates `MarshalBinID/UnmarshalBinID`. Unknown field IDs are
ignored on decode (forward-compat); missing required fields are errors.

Binary layouts are defined in `protocol/schemas.go` + `FRAMING.md`
(canonical table, not duplicated here to avoid drift).

## 8. Binary packet layouts

Common rules: `[]byte` = raw bytes; `string` = UTF-8 bytes (only for URLs/debug,
never for keys/hashes/sigs); `uint64/32/16/8` = big-endian fixed-width;
pubkey = 32 B raw, signature = 64 B raw, hash = 32 B raw, `timestamp_ms` =
`uint64` BE, `transfer_id`/`msg_id` = 16 B random.

Example — `SendMessage (57)`:

| FID | Field | Type | Notes |
|---|---|---|---|
| 1 | `mailbox_id` | `[]byte` (16 B) | opaque, never pubkey |
| 2 | `envelope` | `[]byte` (≤32 KiB) | opaque NexTalk payload |
| 3 | `sender_pub` | `[]byte` (32 B) | Ed25519 raw |
| 4 | `timestamp_ms` | `uint64` | skew ±30 s |
| 5 | `nonce` | `[]byte` (16 B) | replay scope |
| 6 | `signature` | `[]byte` (64 B) | over canonical §10 |
| 7 | `ttl_hint_s` | `uint32` | clamped to server max |
| 8 | `burn` | `uint8` | 1 = drain on first read |

Example — `ChunkUpload (65)`:

| FID | Field | Type |
|---|---|---|
| 1 | `transfer_id` | 16 B |
| 2 | `index` | `uint32` |
| 3 | `payload` | `[]byte` (≤64 KiB) |
| 4 | `chunk_hash` | 32 B (SHA-256 of payload, optional but recommended) |
| 5 | `offset` | `uint64` (= index×chunk_size, redundant-checked) |

Full table: `protocol/schemas.go` is authoritative; this doc is rationale.

## 9. Authentication / signature formats

All signatures are Ed25519 over **canonical binary bytes**, never over
hex/JSON strings. Raw keys/hashes on the wire.

Domain separation (ASCII prefix + `0x00` separator + big-endian fields):

```text
"FR1/MSG-SEND\x00" ‖ sender_pub(32) ‖ mailbox_id(16) ‖ timestamp_ms(BE64)
                   ‖ nonce(16) ‖ sha256(envelope)(32)
"FR1/REGISTER\x00" ‖ client_pub(32) ‖ timestamp_ms(BE64) ‖ nonce(16)
"FR1/CHUNK-PUT\x00" ‖ sender_pub(32) ‖ transfer_id(16) ‖ index(BE32)
                    ‖ timestamp_ms(BE64) ‖ sha256(payload)(32)
"FR1/ROUTING-TABLE\x00" ‖ version(BE32) ‖ generated_at(BE64) ‖ expires_at(BE64)
                    ‖ algorithm_id(u8) ‖ shard_table_hash(32) ‖ router_pub(32)
```

- `timestamp_ms` = `uint64` millis, skew ±30 s (same as current relay
  `MAX_CLOCK_SKEW`). `nonce` = 16 B random per request.
- Routing-table signature covers the binary canonical above, **not** JSON.
  `shard_table_hash = sha256(canonical shard list encoding)`. Exact encoder
  in `protocol/auth.go` (`canonicalRoutingTableBytes`).
- Shard→shard replication authenticates with shard identity keys over
  `FR1/REPLICATE-*` domains; no unauthenticated `/internal/*`.
- `read_secret` (32 B random, presented raw or base64url only at HTTP edge
  for `Receive/Ack/Download`, hashed `sha256` at rest) authenticates
  recipient-side ops; sender-side ops use Ed25519.

This replaces the legacy string formats
(`send:{hex}:{hex}:{ts}:{hex}`, `register:{hex}:{ts}`, `cap:v2:…`) with
byte-exact equivalents. No hex/base64 inside signed bytes.

## 10. Replay protection

- Every sender-authenticated request binds `operation domain ‖ sender ‖
  scope (mailbox/transfer) ‖ timestamp ‖ nonce ‖ payload_hash`. A captured
  `SendMessage` cannot become a `ChunkUpload` or target another mailbox.
- Server caches `sha256(domain ‖ sender_pub ‖ nonce)` for `skew_window + 60 s`
  (single-use). Duplicate → `replay_detected` error.
- `timestamp_ms` outside ±30 s → `expired_request` (no storage touch).
- Recipient `Ack` binds `mailbox_id ‖ read_secret_hash ‖ msg_ids ‖
  disposition`; replaying an ACK is idempotent, never resurrects consumed data.

## 11. Mailbox semantics

- `mailbox_id = HMAC-SHA256(key=SERVER_SECRET, msg=lowercase_hex(ed25519_pub))`
  truncated to 16 B raw (not hex string). Router-only computation; shard
  validates `len==16` and treats as opaque.
- Shard primary key `mailbox:{raw16}`; stores `{read_secret_hash,
  messages[], transfers[], created_at, expires_at}`. Never stores pubkey.
- Router `resolve(pubkey)` → HMAC → probe `exists` across eras (current +
  `prior_shard_counts`) → `{mailbox_id, shard, replicas, era}`.
- `create` is idempotent (re-register slides TTL, rotates `read_secret` only
  on explicit rotation, never duplicates mailbox).
- `exists` is an unauthenticated probe (rate-limited) for era-walk only.

## 12. Chunk semantics

- `transfer_id` = 16 B server-random. `chunk_size` negotiated at create
  (clamped ≤64 KiB), `chunk_count = ceil(total_size/chunk_size)`,
  `total_size ≤ 1 GiB`, `chunk_count ≤ 16384`.
- Upload is idempotent per `(transfer_id, index, sha256(payload))`.
  Same bytes → ACK; different bytes → `chunk_conflict`.
- `offset` must equal `index × chunk_size` (last chunk may be short);
  violation → `chunk_out_of_range`.
- Server never assembles file; it stores opaque chunks + manifest
  `{total_size, chunk_size, chunk_count, manifest_hash}`.
- Download by `index` or `range{start,count}`; server returns stored bytes
  verbatim + recorded `chunk_hash` for receiver verification.

## 13. Resume semantics

`ResumeRequest{transfer_id, sender_auth}` →
`ResumeResponse{chunk_count, highest_contiguous, missing_ranges|bitmap}`:

- Small transfers (≤256 chunks): `bitmap` (`ceil(n/8)` bytes, bit=1 present).
- Large transfers: `missing_ranges[]` (`{start,count}` varint-friendly;
  `count` as `uint32`), plus `highest_contiguous` for fast-path append.
- Server is source of truth; client reconciles and uploads only missing.
- Choice is server-driven via `encoding` flag (`0=bitmap, 1=ranges`);
  client must accept both. Never return N individual chunk objects for large N.

## 14. Storage model

Per shard (KV or equivalent):

```text
mailbox:{id16}       → {read_secret_hash(32), created_at, expires_at, msg_list_head}
msg:{id16}:{msg_id}  → {envelope, sender_pub, enqueued_at, expires_at}
xfer:{transfer_id}   → {mailbox_id, manifest, state, chunk_present_bitmap, created_at, expires_at}
chunk:{transfer_id}:{index} → opaque bytes (+ hash sidecar)
replay:{hash}        → 1 (TTL = skew+60s)
rl:{bucket}:{minute} → counter
table_cache          → signed RoutingTable (no TTL, replaced on push)
```

No secondary indexes by pubkey. No joins. Replication stores identical opaque
records on `r` shards (see §18).

## 15. TTL model

| Object | Default | Sliding? | Enforcement |
|---|---|---|---|
| message backlog entry | 14 d | no (per-message `expires_at`) | lazy clear on send/read/ack + sweeper |
| mailbox record | 365 d | yes (any create/send/read/ack/transfer touch) | `expirationTtl` rewrite |
| incomplete transfer + chunks | 24 h (upload TTL) | yes on chunk upload (cap 7 d) | reaper deletes manifest + chunks |
| complete transfer | 14 d | no | lazy + sweeper |
| capability (`RegisterResponse`) | 365 d | no (re-register) | `expires_at` check |
| routing table | 1 h | no | version + `expires_at` |
| replay cache | skew+60 s | no | KV TTL |
| RL buckets | 60 s +5 s | no | KV TTL |

Incomplete state is always bounded. No forever-pending transfers.

## 16. Quotas

Enforced **before** allocating buffers (check declared `len` against limit,
then re-check after decode; never trust declared length):

```text
max_message_bytes      32 KiB
max_chunk_bytes        64 KiB
max_file_bytes         1 GiB
max_chunks_per_transfer 16384
max_active_transfers_per_mailbox 16
max_queued_messages    100
max_stored_bytes_per_mailbox 16 MiB (messages + chunks)
max_request_bytes      128 KiB (single HTTP body)
max_batch              32 (messages per Receive response)
max_missing_ranges     1024 (per Resume response)
```

Violation → typed `Error` (§20), no partial writes.

## 17. Router/shard protocol (all NanoPack)

| Endpoint | Req schema | Res schema | Notes |
|---|---|---|---|
| `POST /fr/v1/register` | 52 | 53 | client auth; router fans `create` to replicas |
| `POST /fr/v1/resolve` | 54 | 55 | no ownership proof; era-walk via `exists` |
| `GET  /fr/v1/table` | — (headers) | 56 | cacheable, signed |
| `POST /fr/v1/send` (shard) | 57 | 58 | sender Ed25519 |
| `POST /fr/v1/receive` (shard) | 59 | 60 | `read_secret` |
| `POST /fr/v1/ack` (shard) | 61 | 62 | `read_secret` |
| `POST /fr/v1/xfer/create` | 63 | 64 | sender Ed25519 |
| `POST /fr/v1/xfer/put` | 65 | 66 | sender Ed25519, pipelined |
| `POST /fr/v1/xfer/get` | 67 | 68 | `read_secret` or sender auth |
| `POST /fr/v1/xfer/resume` | 69 | 70 | either auth |
| `POST /fr/v1/xfer/complete` | 71 | 72 | sender Ed25519 |
| `POST /fr/v1/xfer/cancel` | 73 | 51 | sender Ed25519 |
| `POST /fr/v1/shard/register` | 74 | 51/53 | PoW + key proof (retain existing PoW design) |
| `POST /fr/v1/shard/heartbeat` | 75 | 51 | shard identity sig |
| `POST /fr/v1/internal/replicate-msg` | 76 | 51 | shard identity sig |
| `POST /fr/v1/internal/replicate-chunk` | 77 | 51 | shard identity sig |
| `GET  /fr/v1/hello` | 50 | 50 | version/caps probe |

Legacy JSON (`/create`, `/send`, `/read`, `/routing_table.json`,
`/register`, `/resolve`) is **not** served by FileRelay. A `/debug/*` JSON
mirror may exist for operators, never canonical.

## 18. Replication model

- What replicates: `message envelope + metadata`, `chunk bytes + hash`,
  `transfer manifest`, `mailbox capability shell` (id/secret-hash/replicas).
  All opaque.
- Router fans `create` to `r` replicas at register; shard fire-and-forgets
  `replicate-msg/chunk` to `replica_set − self` (8 s timeout, best-effort,
  idempotent, dedupe by `msg_id` / `(transfer_id,index,hash)`).
- Trust: shard-to-shard Ed25519 with keys pinned via signed routing table
  (`origin_pub ∈ table.shards`). No bearer-secret-only internal endpoints.
- No quorum / read-repair in v1. `r=1` disables. Client may query replicas
  on primary `unavailable` using cached `replica_urls`.

## 19. Versioning

- `protocol_major=1`, `protocol_minor=1` (HTTP header `X-FileRelay-Protocol`,
  served from the constants — never hardcoded per handler).
  Major bump = breaking (renamed/retyped field, removed schema, changed
  canonical signed bytes). Minor = additive (new schema, new optional field,
  new error code). v1.1 added download tickets (schema 64 FID 4, schema 67
  FID 6, schema 69 FID 4); v1.0 parsers ignore the new fields but cannot use
  tickets, and v1.1 servers always mint secrets.
- NanoPack envelope major/minor (for streamed `WrapPacket` framing) tracks
  the nanopack library version, **not** FileRelay protocol version — they are
  separate. Streamed receivers check both.
- Unknown schemas → `unsupported_protocol`; unknown fields → ignored;
  never reinterpret a field ID.

## 20. Error codes (stable `uint32`)

```text
0 OK (never sent as Error; success uses typed responses)
1 invalid_request   2 unsupported_protocol  3 auth_failed
4 replay_detected   5 expired_request       6 mailbox_not_found
7 mailbox_expired   8 message_too_large     9 quota_exceeded
10 transfer_not_found 11 transfer_expired    12 chunk_invalid
13 chunk_exists_conflict 14 chunk_out_of_range 15 storage_unavailable
16 rate_limited      17 server_unavailable  18 transfer_conflict
19 hash_mismatch     20 payload_too_large   21 batch_too_large
```

`Error (51){code:uint32, detail:string(debug only), retry_after_s:uint32}`.
Clients switch on `code`, never on English text.

## 21. Security considerations

- Untrusted transport preserved: relay never sees plaintext, never holds E2E
  keys, never performs NexTalk encrypt/decrypt.
- Purpose-bound binary signatures (§9); hex/base64 only at HTTP edge, never
  inside signed bytes.
- Replay cache + skew + nonce (§10); triple-auth (sender Ed25519,
  recipient `read_secret`, per-transfer download ticket) with least privilege
  per op: tickets unlock resume/get only, never mailboxes, puts, seals, or
  cancels, and ticket use slides no mailbox TTL.
- Bounded allocation: check lengths before alloc, `MaxPacketLen` on streams,
  per-mailbox byte caps, independent transfer/chunk quotas (abandoned
  transfers cannot exhaust storage).
- Defense-in-depth RL by sender / mailbox / IP / transfer (retain current
  `send-sender/target/ip`, `create-ip`, `read-ip`, `replicate-origin` split).
- Burn-after-read default; `peek` explicit; ACK dispositions never conflate
  `stored` with `delivered/consumed`.
- Hash-verified chunks + manifest (`sha256` per chunk + whole-transfer);
  TCP/HTTP integrity is not trusted.
- Fuzz every parser; invariant: no malformed input causes panic, unbounded
  alloc, or state corruption.

## 22. Compatibility strategy

- v1 is **not** wire-compatible with the earlier NexTalk relay JSON protocol (deliberate break).
  No JSON fallback on canonical endpoints.
- NexTalk app payloads (`SecureMessage` schema 1, offers 20/21) are carried
  **opaque** inside `SendMessage.envelope` — no re-encoding, no version coupling.
- FileRelay schemas start at 50; NexTalk local schemas (10/11/40/41/44) are
  untouched. Future FileRelay additions use minor bumps + new schemas/fields.
- Migration path: NexTalk `transport/filerelay` adapter speaks FileRelay v1
  alongside legacy `worker` adapter; operators run both relays during cutover.
  Routing-table `algorithm` string is versioned
  (`filerelay-sha256-modn-v1`) and `prior_shard_counts` retained for era fallback.

## 23. Test strategy

- Unit: encode/decode round-trips, truncated/malformed/invalid-schema/
  invalid-field/invalid-len, integer boundaries, oversized, bad sig, replay,
  expired, bad chunk index, duplicate chunk, transfer expiry.
- Cross-language: Go → `testdata/vectors.json` → other-language decoders (any external codec, e.g. a TypeScript port maintained outside this repo, must decode the vectors byte-identically);
  byte-identical (`testdata/vectors-*.json` + `vectors_test.go`).
- Integration: `client → router → shard → router → client` for register,
  resolve, send, receive, ack, create, put, interrupt, resume, missing,
  complete, expiry, quota.
- Fuzz: `FuzzDecodeID`-style targets over every FileRelay parser; invariant:
  no panic / unbounded alloc / state corruption on hostile input.
