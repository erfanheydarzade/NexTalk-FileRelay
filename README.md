# NexTalk-FileRelay

[![CI](https://github.com/erfanheydarzade/NexTalk-FileRelay/actions/workflows/ci.yml/badge.svg)](https://github.com/erfanheydarzade/NexTalk-FileRelay/actions/workflows/ci.yml)
[![Release](https://github.com/erfanheydarzade/NexTalk-FileRelay/actions/workflows/release.yml/badge.svg)](https://github.com/erfanheydarzade/NexTalk-FileRelay/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> A message + file relay for [NexTalk](https://github.com/erfanheydarzade/NexTalk) — opaque, untrusted transport for encrypted messages and chunked file transfers, speaking a frozen binary protocol (NanoPack) over HTTP.

FileRelay never sees plaintext, never holds E2E keys, and never performs
NexTalk's encrypt/decrypt. It moves opaque bytes between mailboxes derived
from a client's public key, with burn-after-read messages, resumable
chunked file transfers, and a full authentication/replay/quota model. See
[`DESIGN.md`](DESIGN.md) for the architecture and rationale, and
[`docs/server.md`](docs/server.md) for the deployed HTTP API reference.

> **Security status:** the protocol's security properties are enforced by this
> implementation, but the project **has not undergone an independent security
> audit**. "Secure" here is a design claim, not an audited assurance.

## Architecture

Two processes serve the protocol:

- **Router** — derives opaque 16-byte mailbox IDs (`HMAC-SHA256(SERVER_SECRET, pubkey)`),
  publishes a signed routing table, and answers `register`/`resolve`. It never
  proxies message or chunk bodies.
- **Shard** — untrusted, dumb opaque storage: mailboxes, message backlog,
  transfer/chunk state, TTLs, quotas, rate limits. It never learns the
  recipient's real public key.

```text
NexTalk core (crypto/session/ratchet)
  │ opaque encrypted payload
  ▼
FileRelay client adapter / bridge  →  Router (register/resolve/table)
  │ NanoPack binary bodies over HTTP        │
  ▼                                          ▼
Shard(s) — opaque mailbox/message/chunk storage (KV)
```

Everything on the wire is raw NanoPack (`Content-Type: application/x-nanopack`),
not JSON — see [`FRAMING.md`](FRAMING.md) for the framing decision and
`docs/server.md` for the full endpoint/schema table.

## Features

- **Opaque by design**: the relay never decrypts anything; envelopes and
  chunks are carried verbatim and hash-verified by the client.
- **Burn-after-read messaging**: `SendMessage` → `ReceiveMessages` → `MessageAck`,
  with `peek` support and TTL-based lazy expiry.
- **Resumable chunked file transfers**: create → put (pipelined, idempotent) →
  resume (bitmap or ranges) → complete → get, up to 1 GiB per file.
- **Sender-owned transfer tickets (v1.1)**: share a download-only capability
  inside an ordinary E2E message instead of binding a transfer to the
  recipient's mailbox.
- **Ed25519 auth + replay protection**: domain-separated canonical binary
  signatures, ±30s clock skew, single-use nonce cache.
- **Bounded everything**: per-message, per-chunk, per-file, per-mailbox, and
  per-request size caps, all enforced before buffers are allocated.

## Quick Start

```bash
# Build from source
go build -o filerelayd ./cmd/filerelayd

# Run a demo single-binary deployment (router + shard, one shared store)
./filerelayd --addr 127.0.0.1:8080
# Without --server-secret a fresh secret is generated and printed — save it:
# rotating it orphans every mailbox.

# Print version info
./filerelayd --version
```

Flags: `--addr` (default `127.0.0.1:8080`), `--server-secret` (64 hex chars,
generated if omitted), `--print-template` (print `ROUTER_URL`/`SHARD_URL`
and exit), `--version`.

For production multi-shard deployments, construct `router.NewHandler` and
`shard.NewHandler` against shared KV-backed `storage.Store` implementations
directly — see [`docs/server.md`](docs/server.md).

## API

FileRelay exposes a binary NanoPack HTTP API, not JSON:

```
POST /fr/v1/register        Register with the router, get a mailbox
POST /fr/v1/resolve         Resolve a pubkey to its mailbox/shard
GET  /fr/v1/table           Signed routing table
POST /fr/v1/send            Send an opaque message envelope
POST /fr/v1/receive         Receive queued messages (burn-after-read)
POST /fr/v1/ack             Acknowledge/consume received messages
POST /fr/v1/xfer/create     Start a chunked file transfer
POST /fr/v1/xfer/put        Upload one chunk
POST /fr/v1/xfer/resume     Ask which chunks are missing
POST /fr/v1/xfer/get        Download one chunk
POST /fr/v1/xfer/complete   Seal a transfer once all chunks are present
POST /fr/v1/xfer/cancel     Cancel/expire a transfer early
```

Full request/response schema table, auth requirements, and error codes are
in [`docs/server.md`](docs/server.md). Requests failing validation return
HTTP 4xx/5xx with a typed `Error` body — clients should switch on the
numeric error code, never on the debug detail string.

## NexTalk Transport (the `.ntx` bridge)

`transports/filerelay/` packages a standalone courier bridge that NexTalk's
CLI installs as a transport plugin (`nextalk transport install filerelay.ntx`)
— no NexTalk rebuild required. See
[`transports/filerelay/README.md`](transports/filerelay/README.md) for the
build, packaging, and installation steps, and its trust model (throwaway
courier identity, never sees NexTalk's private keys).

## Security Notes

- The relay never stores or transmits plaintext; it only ever sees what the
  client already encrypted.
- Every sender-authenticated request is Ed25519-signed over canonical binary
  bytes (never hex/JSON) and checked against a replay cache.
- Burn-after-read is the default for messages; `peek` is explicit.
- Chunks and the whole-transfer manifest are hash-verified by the receiving
  client — the relay's integrity guarantee is "returns exactly what was
  stored," not "verified plaintext."
- Rate limits (sender/target/IP/transfer) return HTTP 429 with `retry_after_s`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache 2.0 — see [LICENSE](LICENSE).
