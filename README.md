# NexTalk-FileRelay

[![CI](https://github.com/erfanheydarzade/NexTalk-FileRelay/actions/workflows/ci.yml/badge.svg)](https://github.com/erfanheydarzade/NexTalk-FileRelay/actions/workflows/ci.yml)
[![Release](https://github.com/erfanheydarzade/NexTalk-FileRelay/actions/workflows/release.yml/badge.svg)](https://github.com/erfanheydarzade/NexTalk-FileRelay/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> A message + file relay for [NexTalk](https://github.com/erfanheydarzade/NexTalk): opaque, untrusted transport for encrypted messages and chunked file transfers, speaking a frozen binary protocol (NanoPack) over HTTP.

FileRelay never sees plaintext, never holds E2E keys, and never performs NexTalk's encrypt/decrypt. It moves opaque bytes between mailboxes derived from a client's public key, with burn-after-read messages, resumable chunked file transfers, and a full authentication/replay/quota model. See [`DESIGN.md`](DESIGN.md) for the architecture and rationale, and [`docs/server.md`](docs/server.md) for the deployed HTTP API reference.

> **Security status:** the protocol's security properties are enforced by this implementation, but the project **has not undergone an independent security audit**. "Secure" here is a design claim, not an audited assurance.

- [Prebuilt packages](#prebuilt-packages-no-build-needed)
- [Quick start: run the server](#quick-start-run-the-server) · [Quick start: use it from NexTalk](#quick-start-use-it-from-nextalk)
- [Which command do I need?](#which-command-do-i-need) · [Troubleshooting](#troubleshooting)
- [Architecture](#architecture) · [Features](#features)
- [Server configuration](#server-configuration) · [API](#api)
- [NexTalk transport (`.ntx`) & browser package](#nextalk-transport-the-ntx-bridge) · [Security notes](#security-notes)

---

## Prebuilt packages (no build needed)

You don't have to compile anything to use FileRelay from NexTalk. The [**Releases page**](https://github.com/erfanheydarzade/NexTalk-FileRelay/releases/latest) has the ready-made `filerelay` transport packages (`.ntx`), the browser `filerelay-wasm.ntx` demo package, and a SHA-256 checksum file. Download the `.ntx` for your OS/CPU, verify it, and install it:

```bash
nextalk transport install <path-to-downloaded>.ntx --enable
```

The **server** (`filerelayd`) is separate from the transport. Build it from source as below unless the release also lists a `filerelayd` binary for your platform.

---

## Quick start: run the server

```bash
# Build from source
go build -o filerelayd ./cmd/filerelayd

# Run a demo single-binary deployment (router + shard, one shared store)
./filerelayd --addr 127.0.0.1:8080
# Without --server-secret a fresh secret is generated and printed. Save it:
# rotating it orphans every mailbox.

# Print version info
./filerelayd --version
```

For production multi-shard deployments, construct `router.NewHandler` and `shard.NewHandler` against shared KV-backed `storage.Store` implementations directly. See [`docs/server.md`](docs/server.md).

---

## Quick start: use it from NexTalk

The server above is what NexTalk talks to through the installable `filerelay` transport. There are two separate things you might want, and they use different mailboxes.

### A. Send and receive files

```bash
# Install the bridge (prebuilt .ntx from Releases, or one you built) and point it at your server
nextalk transport install filerelay.ntx --enable
nextalk transport config filerelay '{"router_url":"http://127.0.0.1:8080"}'

# Mint a file-transfer mailbox (auto-attached)
nextalk transport register filerelay --id <YOU> --router http://127.0.0.1:8080

# Sender uploads; recipient downloads with the ticket
nextalk transport xfer-send filerelay -i <YOU> --to <PEER> --mailbox <M> --shard <URL> -f photo.bin
nextalk transport xfer-recv filerelay -i <YOU> --from <PEER> --ticket <base64> -o photo.bin
```

PowerShell needs the inner JSON quotes escaped:

```powershell
.\nextalk transport config filerelay '{\"router_url\":\"http://127.0.0.1:8080\"}'
```

### B. Chat by peer ID

Each person registers their **real identity** on the same server, then connects:

```bash
nextalk transport register-identity filerelay -i <YOU> --router http://127.0.0.1:8080
nextalk transport resolve filerelay --to <YOU> --router http://127.0.0.1:8080   # verify
```

```
identity load <YOU>
use relay filerelay
peer connect <PEER>        # the peer must have run register-identity too
transport poll             # both sides poll to finish the handshake
message send <PEER> hello
```

Build, packaging, the offline two-user scenario and every `xfer-*` command are in [`transports/filerelay/README.md`](transports/filerelay/README.md).

---

## Which command do I need?

| I want to… | Use | Why |
|---|---|---|
| Move files without tying a mailbox to my identity | `transport register` (alias `xfer-register`) | Registers a throwaway key owned by the bridge. Nobody can compute the address from your peer ID, so you share mailbox + shard, or a download ticket, yourself. |
| Chat with someone using only their peer ID | `transport register-identity` | Registers your real identity key. Anyone can compute your mailbox from your peer ID, so `peer connect` finds you automatically. |
| Check whether a peer is reachable | `transport resolve --to <id> --router <url>` | Asks the router where that identity's mailbox is. |

**Most common mistake:** running `transport register` and expecting `peer connect` to work. They use different mailboxes. You can use both side by side.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `recipient mailbox is not registered on the relay` | The **peer** has no identity mailbox on this server. | They run `transport register-identity` against the **same** server. Check with `transport resolve --to <their-id>`. |
| Every command fails with `replay attach <id>` | NexTalk replays saved mailboxes on start, and they are stale after the server was reset or `--server-secret` changed. | `transport detach filerelay --mailbox <32-hex>` for each, then register again. |
| Registered, but nobody can find you after a restart | The server started without `--server-secret`, so it generated a **new** one. Mailbox IDs are `HMAC-SHA256(SERVER_SECRET, pubkey)`, so every old mailbox is orphaned. | Always pass the same `--server-secret`. Save the one it printed the first time. |
| `filerelay transport does not support identity registration` | The installed `filerelay.ntx` is older than your NexTalk core. | Rebuild, package and reinstall the bridge. |
| Works on one server, not another | Registrations are per server. | Use the same `router_url` on both sides. |
| Authentication errors | Client and server clocks differ by more than ±30 s. | Fix the system clock. |
| HTTP 429 | A rate limit (sender / target / IP / transfer) was hit. | Wait for `retry_after_s` from the response. |

`router_url` may be the server root or the `/fr/v1/` API root, with or without a trailing slash. The bridge normalizes all of these.

---

## Architecture

Two processes serve the protocol:

- **Router**: derives opaque 16-byte mailbox IDs (`HMAC-SHA256(SERVER_SECRET, pubkey)`), publishes a signed routing table, and answers `register`/`resolve`. It never proxies message or chunk bodies.
- **Shard**: untrusted, dumb opaque storage: mailboxes, message backlog, transfer/chunk state, TTLs, quotas, rate limits. It never learns the recipient's real public key.

```text
NexTalk core (crypto/session/ratchet)
  │ opaque encrypted payload
  ▼
FileRelay client adapter / bridge  →  Router (register/resolve/table)
  │ NanoPack binary bodies over HTTP        │
  ▼                                          ▼
Shard(s): opaque mailbox/message/chunk storage (KV)
```

Everything on the wire is raw NanoPack (`Content-Type: application/x-nanopack`), not JSON. See [`FRAMING.md`](FRAMING.md) for the framing decision and `docs/server.md` for the full endpoint/schema table.

## Features

- **Opaque by design**: the relay never decrypts anything; envelopes and chunks are carried verbatim and hash-verified by the client.
- **Burn-after-read messaging**: `SendMessage` → `ReceiveMessages` → `MessageAck`, with `peek` support and TTL-based lazy expiry.
- **Resumable chunked file transfers**: create → put (pipelined, idempotent) → resume (bitmap or ranges) → complete → get, up to 1 GiB per file.
- **Sender-owned transfer tickets (v1.1)**: share a download-only capability inside an ordinary E2E message instead of binding a transfer to the recipient's mailbox.
- **Ed25519 auth + replay protection**: domain-separated canonical binary signatures, ±30 s clock skew, single-use nonce cache.
- **Bounded everything**: per-message, per-chunk, per-file, per-mailbox and per-request size caps, all enforced before buffers are allocated.

---

## Server configuration

`filerelayd` flags:

| Flag | Default | Description |
|---|---|---|
| `--addr` | `127.0.0.1:8080` | Listen address |
| `--server-secret` | generated and printed | 64 hex chars. **Keep it stable**: rotating it orphans every mailbox. |
| `--print-template` | off | Print `ROUTER_URL` / `SHARD_URL` and exit |
| `--version` | off | Print version info and exit |

On the NexTalk side, the only setting is `router_url` (`transport config filerelay '{"router_url":"…"}'`, or `--router` per command).

---

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

Full request/response schema table, auth requirements and error codes are in [`docs/server.md`](docs/server.md). Requests failing validation return HTTP 4xx/5xx with a typed `Error` body. Clients should switch on the numeric error code, never on the debug detail string.

---

## NexTalk transport (the `.ntx` bridge)

`transports/filerelay/` packages a standalone courier bridge that NexTalk's CLI installs as a transport plugin (`nextalk transport install filerelay.ntx`), with no NexTalk rebuild required. See [`transports/filerelay/README.md`](transports/filerelay/README.md) for build, packaging and installation steps, and its trust model (throwaway courier identity, never sees NexTalk's private keys).

After rebuilding the bridge you must **reinstall** it: it is a separate executable, so a new `nextalk.exe` does not update it.

The extension also has a browser (WebAssembly) package, `filerelay-wasm.ntx`, built by `transports/build-wasm.mjs` with Node alone and attached to every release. Under WASM transport ABI v1 it is an in-tab loopback queue (messages only; the ABI has no network or file-transfer ops). The native bridge is what talks to a relay. Only the extension targets the browser: the router/shard server never runs there. Details in the transport README.

## Security notes

- The relay never stores or transmits plaintext; it only ever sees what the client already encrypted.
- Every sender-authenticated request is Ed25519-signed over canonical binary bytes (never hex/JSON) and checked against a replay cache.
- Burn-after-read is the default for messages; `peek` is explicit.
- Chunks and the whole-transfer manifest are hash-verified by the receiving client. The relay's integrity guarantee is "returns exactly what was stored," not "verified plaintext."
- Rate limits (sender/target/IP/transfer) return HTTP 429 with `retry_after_s`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache 2.0. See [LICENSE](LICENSE).