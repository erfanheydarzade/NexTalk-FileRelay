# FileRelay server — runbook + HTTP API reference

Two processes serve the protocol: the **router** (mailbox derivation,
signed routing table) and the **shard** (dumb opaque storage). Both speak
raw NanoPack request/response bodies (`Content-Type: application/x-nanopack`,
no `WrapPacket` — the HTTP body is the frame; see `FRAMING.md`). Failing
requests answer HTTP 4xx/5xx with a schema-51 `Error` body: switch on the
numeric `code`, never on the debug `detail` string.

## Runbook

```bash
# Demo / LAN: single binary, one shared in-memory store, replication 1
go run ./cmd/filerelayd --addr 127.0.0.1:8080 --server-secret <64hex>
# Without --server-secret a fresh secret is generated and printed.
# Save it: rotating SERVER_SECRET orphans every mailbox ID.

# Flags: --addr (default 127.0.0.1:8080), --server-secret (64 hex),
# --print-template (prints ROUTER_URL/SHARD_URL and exits)
```

Production multi-shard: construct `router.NewHandler(router.Config{...})`
and `shard.NewHandler(store, clock, shard.DefaultRateLimits())` against
shared KV-backed `storage.Store` implementations (same handlers, same
semantics as the demo). Schemas 74–77 (`ShardRegister`, `ShardHeartbeat`,
`Replicate*`) are **reserved and unserved** — replication is out of scope;
do not send them.

## Auth model (all Ed25519, raw 32B pubs / 64B sigs, never hex on the wire)

- Mailbox IDs are opaque 16B: `HMAC-SHA256(SERVER_SECRET, lowercase_hex(pub))[:16]`
  (`protocol.MailboxID`). The shard never learns the pubkey.
- Every sender-signed request binds domain + identity + scope + `timestamp_ms`
  (`uint64`, skew ±30 s) + 16B nonce + payload hash, and each
  `(domain, pub, nonce)` is single-use inside the 90 s replay window:
  `FR1/MSG-SEND` (send), `FR1/REGISTER` (register), `FR1/XFER-CREATE`,
  `FR1/XFER-COMPLETE`, `FR1/ROUTING-TABLE` (table signature over the
  canonical binary form, not JSON).
- Recipient-side ops (`receive`, `ack`, `cancel`, and mailbox-mode chunk
  `get`/`resume`) present the 32B `read_secret` bearer (stored as SHA-256);
  no signatures.
- Ticket ops (v1.1, §Transfer tickets) present the 32B per-transfer
  `download_secret` bearer (stored as SHA-256) with an empty mailbox — no
  mailbox lookup, no owner-TTL slide, download-only.

## Transfer tickets (v1.1)

The sender-owned share pattern: Alice uploads to **her own** mailbox space,
`xfer/create` mints a per-transfer `download_secret` (schema 64 FID 4) next
to the `transfer_id`, and Alice sends `{transfer, secret, shard, manifest}`
to Bob inside an ordinary E2E message (any message relay — or a dedicated
ticket-only message). Bob resumes/gets with the ticket alone: schemas 67
(`ChunkDownload` FID 6) and 69 (`ResumeRequest` FID 4) accept **exactly one**
auth context — mailbox bearer (`mailbox` 16B + `read_secret` 32B) or ticket
(32B, mailbox + secret empty). Mixed credentials are rejected.

Ticket powers: `resume` + `get` only. It cannot read mailboxes, upload,
complete, or cancel; it dies with the transfer (expiry/cancel). The
transfer still counts against the owner's mailbox quota while alive.

## Endpoints

| Route | Req → Res (schema IDs) | Auth |
|---|---|---|
| `POST /fr/v1/hello` (GET ok) | 50 → 50 | none (version probe) |
| `POST /fr/v1/register` (router) | 52 → 53 `RegisterResponse{mailbox_id, read_secret, shard_url, table_version, expires_at}` | `FR1/REGISTER` sig |
| `POST /fr/v1/resolve` (router) | 54 → 55 `{mailbox_id, shard_url, era, table_version}` | none (probe; era-walk) |
| `GET|POST /fr/v1/table` (router) | → 56 signed `RoutingTable` | router sig, cache 60 s |
| `POST /fr/v1/send` | 57 → 58 `{accepted, queued, msg_id}` (`accepted` = stored, **not** delivered/read) | `FR1/MSG-SEND` sig |
| `POST /fr/v1/receive` | 59 `{mailbox, read_secret, limit, peek}` → 60 batch `{count, ids, BE32-len payloads, consumed}` | bearer |
| `POST /fr/v1/ack` | 61 `{mailbox, read_secret, msg_ids, disposition=received\|consumed}` → 62 `{acked, remaining}` | bearer |
| `POST /fr/v1/xfer/create` | 63 → 64 `{transfer_id, expires_at, chunk_size, download_secret}` | `FR1/XFER-CREATE` sig |
| `POST /fr/v1/xfer/put` | 65 `{transfer_id, index, payload, chunk_hash?, offset=index×size}` → 66 `ChunkAck` | transfer-id capability |
| `POST /fr/v1/xfer/get` | 67 `{transfer_id, index, count=1, mailbox, read_secret}` **or** `{transfer_id, index, ticket}` → 68 `{payload, hash}` | bearer **or** ticket |
| `POST /fr/v1/xfer/resume` | 69 `{transfer_id, mailbox, read_secret}` **or** `{transfer_id, ticket}` → 70 `{chunk_count, highest_contiguous, encoding, bitmap\|ranges}` (bitmap ≤256 chunks, else ranges) | bearer **or** ticket |
| `POST /fr/v1/xfer/complete` | 71 → 72 `{sealed, chunk_count, present}` | `FR1/XFER-COMPLETE` sig |
| `POST /fr/v1/xfer/cancel` | 73 → 62 `{acked=1}` | bearer |

Chunk puts are idempotent per `(transfer, index, sha256(payload))`: same
bytes re-ACK, different bytes → `chunk_conflict` (13). Non-final chunks must
equal `chunk_size`; the final chunk must equal the remainder. `complete`
requires all chunks present and the sender binding to match.

## Errors (schema 51: `code u32`, `detail`, `retry_after_s`)

`1 invalid_request · 2 unsupported_protocol · 3 auth_failed ·
4 replay_detected · 5 expired_request · 6 mailbox_not_found ·
7 mailbox_expired · 8 message_too_large · 9 quota_exceeded ·
10 transfer_not_found · 11 transfer_expired · 12 chunk_invalid ·
13 chunk_conflict · 14 chunk_out_of_range · 15 storage_unavailable ·
16 rate_limited · 17 server_unavailable · 18 transfer_conflict ·
19 hash_mismatch · 20 payload_too_large · 21 batch_too_large`
(`0` is never sent; success uses typed responses.)

## Limits and TTLs (`protocol/limits.go`)

Bounds are enforced **before** allocating buffers; declared lengths are
never trusted.

| Cap | Value |
|---|---|
| message envelope | 32 KiB |
| chunk payload | 64 KiB |
| file total | 1 GiB |
| chunks / transfer | 16384 |
| active transfers / mailbox | 16 |
| queued messages | 100 |
| stored bytes / mailbox | 16 MiB |
| single HTTP body | 128 KiB |
| batch / receive | 32 messages |
| ranges / resume | 1024 |

| TTL | Value | Sliding? |
|---|---|---|
| message backlog entry | 14 d | no |
| mailbox record | 365 d | yes (any touch) |
| incomplete transfer | 24 h | yes on put (cap 7 d total age) |
| complete transfer | 14 d | no |
| capability / routing table | 365 d / 1 h | no |
| replay cache | skew + 60 s | no |

Rate limits (fixed 60 s windows, `shard.DefaultRateLimits`): sends 600/sender,
600/target, 1200/IP; receives 1200/IP; puts 2000/transfer, 4000/IP.
Failures return `16 rate_limited` with `retry_after_s`.
