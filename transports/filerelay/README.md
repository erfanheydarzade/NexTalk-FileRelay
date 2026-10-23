# filerelay — NexTalk transport package (`.ntx`)

Lets NexTalk send **messages and files** through a FileRelay server (router +
shard). It installs into NexTalk like a plugin: no NexTalk rebuild needed.
Build the bridge, zip it with the manifest, install.

- [Use a prebuilt package](#use-a-prebuilt-package-no-build-needed)
- [Quick start: files](#quick-start-send-a-file) · [Quick start: chat](#quick-start-chat-by-peer-id)
- [Which command do I need?](#which-command-do-i-need) · [Troubleshooting](#troubleshooting)
- [Two-user message scenario](#two-user-message-scenario-alice--bob) · [Configuration](#configuration)
- [Build & package](#build--package) · [Browser (WASM) package](#browser-webassembly-package)

---

## Use a prebuilt package (no build needed)

You do **not** need Go to use this transport. Every [GitHub release](https://github.com/erfanheydarzade/NexTalk-FileRelay/releases) ships ready-made packages:

1. Open the [latest release](https://github.com/erfanheydarzade/NexTalk-FileRelay/releases/latest) and download the `.ntx` for your OS and CPU (the release has one per platform; the file name says which).
2. *(Recommended)* Check it against the SHA-256 checksum file attached to the same release:
   ```bash
   sha256sum -c SHA256SUMS --ignore-missing      # Linux / macOS
   ```
   ```powershell
   Get-FileHash -Algorithm SHA256 .\filerelay.ntx    # Windows: compare with the checksum file
   ```
3. Install the file you downloaded:
   ```bash
   nextalk transport install <path-to-downloaded>.ntx --enable
   ```

The release also contains `filerelay-wasm.ntx`. That is the browser build, an in-tab loopback demo that never contacts a server. For real use, pick the native package for your OS.

Build from source only if you want to change the bridge (see [Build & package](#build--package)).

---

## Install and configure

```bash
nextalk transport install filerelay.ntx --enable
```

Tell NexTalk where your FileRelay router is.

**Bash / POSIX shells:**

```bash
nextalk transport config filerelay '{"router_url":"http://127.0.0.1:8080"}'
```

**Windows PowerShell** (the Windows `nextalk.exe` needs the inner quotes
escaped with backslashes):

```powershell
.\nextalk transport config filerelay '{\"router_url\":\"http://127.0.0.1:8080\"}'
```

The backslashes are only command-line escaping. The transport receives normal
JSON: `{"router_url":"http://127.0.0.1:8080"}`.

`router_url` can be the server root or the `/fr/v1/` API root, with or without
a trailing slash. The bridge normalizes all of these.

---

## Quick start: send a file

File transfers use a **file-transfer mailbox**, minted by plain `register`.
You share its address (mailbox + shard) or a ticket with the other side, so no
one needs to look you up by peer ID.

```bash
# 1. Mint a file-transfer mailbox (auto-attached, so it can be polled right away)
nextalk transport register filerelay --id <YOU> --router http://127.0.0.1:8080
# -> mailbox, read_secret, shard   (share mailbox + shard; keep read_secret private)

# 2. Sender: upload an end-to-end-encrypted file
nextalk transport xfer-send filerelay -i <YOU> --to <PEER> --mailbox <M> --shard <URL> -f photo.bin
# -> prints a download ticket (base64). Send it inside any E2E message,
#    or share it out-of-band. The recipient needs only the ticket.

# 3. Recipient: download by ticket
nextalk transport xfer-recv filerelay -i <YOU> --from <PEER> --ticket <base64> -o photo.bin
```

Other transfer commands: `xfer-resume` (continue an interrupted transfer),
`xfer-cancel`, `xfer-inspect --ticket <base64>` (look at a ticket without
downloading). Files are encrypted whole, then uploaded in opaque chunks
(`--chunk-size`, default 32 KiB). Transfer state is saved in `transfers.json`,
so a fresh process can resume.

---

## Quick start: chat by peer ID

To use `peer connect <peer-id>` and `message send`, **each person registers
their real identity with the Router, on the same Router.** This is different
from the file-transfer mailbox above.

```bash
nextalk transport register-identity filerelay -i <YOU> --router http://127.0.0.1:8080
nextalk transport resolve filerelay --to <YOU> --router http://127.0.0.1:8080   # verify
```

Then in the shell:

```
identity load <YOU>
use relay filerelay
peer connect <PEER>        # the peer must have run register-identity too
transport poll             # both sides poll to finish the handshake
message send <PEER> hello
```

> `register-identity` needs the updated `filerelay.ntx` (the older one answers
> `filerelay transport does not support identity registration`). Rebuild,
> package and reinstall the bridge.

---

## Which command do I need?

| I want to… | Use | Why |
|---|---|---|
| Send or receive files without tying the mailbox to my identity | `transport register` (alias `xfer-register`) | Registers a throwaway key owned by the bridge. Nobody can compute the address from your peer ID, so you share mailbox + shard (or a ticket) yourself. |
| Chat with someone using only their peer ID | `transport register-identity` | Registers your real identity key. Anyone can compute your mailbox from your peer ID, so `peer connect` finds you automatically. |
| Check whether a peer is reachable | `transport resolve --to <id> --router <url>` | Asks the Router where that identity's mailbox is. |
| Drop a stale mailbox from local state | `transport detach filerelay --mailbox <32-hex>` | See [Troubleshooting](#troubleshooting). |

**Most common mistake:** running `transport register` and expecting
`peer connect` to work. They use different mailboxes. Plain `register` even
prints a reminder: *"This is a file-transfer mailbox. It does NOT let peers
reach you by peer ID."*

Registrations are **per Router**: a mailbox registered on one Router does not
exist on another (for example local dev vs. deployed).

You can use both side by side: identity registration for chat, plain register
for files.

---

## Two-user message scenario (Alice ↔ Bob)

Same machine, offline handshake first, then messages through the relay using
file-transfer mailboxes shared out-of-band:

```bash
mkdir alice bob && cd alice && nextalk offline init          # -> ALICE
cd ../bob && nextalk offline init                            # -> BOB
cd ../alice && nextalk offline offer -i ALICE -r BOB -o offer.bin
cd ../bob && nextalk offline accept -i BOB -f ../alice/offer.bin -o answer.bin
cd ../alice && nextalk offline finish -i ALICE -f ../bob/answer.bin

cd ../alice
nextalk transport register filerelay --id ALICE --router <ROUTER>
nextalk transport attach filerelay --mailbox <M> --secret <S> --shard <SHARD> --router <ROUTER>
cd ../bob
nextalk transport register filerelay --id BOB --router <ROUTER>
nextalk transport attach filerelay --mailbox <M> --secret <S> --shard <SHARD> --router <ROUTER>

cd ../alice
nextalk offline encrypt -i ALICE -r BOB -m "hello bob" -o msg.bin
filerelay-bridge wrap --type 3 -f msg.bin > frame.bin
nextalk transport send-frame filerelay --to BOB -f frame.bin
cd ../bob && nextalk transport poll filerelay -i BOB
# [+] Message from <ALICE> (utf-8) — stored in mailbox
```

`register` already attaches the mailbox it mints, so the explicit `attach` is
only needed to refresh a secret or to attach on another machine. `send-frame
--to` accepts a peer ID or 64-hex pubkey (resolved via the Router, which
requires that peer to have run `register-identity`), or an explicit
`--mailbox <alias> --shard <url>` the recipient shared out-of-band.

Full runs: `NexTalk/docs/real-scenario.md` (scenarios B and C). Command
reference: `NexTalk/docs/transport-cli.md`.

---

## Troubleshooting

| Message | What it means | Fix |
|---|---|---|
| `recipient mailbox is not registered on the relay` | The **recipient** has no identity mailbox on this Router. | They run `transport register-identity` against the **same** Router. Verify with `transport resolve --to <their-id>`. |
| `replay attach <id>` fails on every command | NexTalk replays the mailboxes saved in `state.json` each time it starts the bridge. They are stale (Router/shard reset, or secrets changed). | `transport detach filerelay --mailbox <32-hex>` for each, then register again. If `detach` fails the same way, close NexTalk and delete the `"attach"` block in `state.json`. |
| `filerelay transport does not support identity registration` | The installed `filerelay.ntx` is older than your NexTalk core. | Rebuild, package and reinstall the bridge. |
| `no router_url` | No Router configured. | `transport config filerelay …` or pass `--router`. |
| Works against one Router, not another | Registrations are per Router. | Use the same Router URL on both sides. |

`state.json` lives in `os.UserConfigDir()/nextalk/transports/` (Windows:
`%APPDATA%\nextalk\transports\`) unless `NEXTALK_TRANSPORTS_DIR` is set.

---

## How it works

`filerelay-bridge` is a courier transport (`message` + `binary-transfer`
capabilities, `network` + `storage` permissions). It speaks the NexTalk
transport API v1 (stdio RPC, schemas 100–126) to NexTalk and the FileRelay
router/shard protocol (raw NanoPack over HTTP) to the network.

- Message ops 1–10: initialize, start/stop, send, attach, detach, poll,
  status, capabilities, register, resolve.
- File ops 11–16: xfer-create / put / resume / get / complete / cancel.
- Anything else answers op 0 + `SchemaError`.

**Trust model (courier):**

- The bridge owns its own throwaway ed25519 keys and **never sees your identity
  private key**. NexTalk core passes only opaque `[type][nanopack]` frames,
  32-byte recipient pubkeys, explicit recipient addresses (mailbox + shard,
  shared out-of-band), per-mailbox `read_secret` bearers, and shard/router URLs.
- `courier.key` (shard-side sender binding for abuse/rate limiting) is created
  next to the binary (`0600`) on first run. The true sender lives inside the
  E2E frame and is verified by NexTalk core.
- Plain `register` uses per-user scoped keys (`scoped-<tag>.key`, `0600`) that
  control only that mailbox's registration and courier sends. They never touch
  identity keys or decryption. Delete the key file and re-register to revoke.
- `register-identity` is signed by NexTalk core, where the identity key lives.
  The bridge only receives the resulting mailbox details.
- FileRelay mailbox IDs are 16 bytes natively, so unlike the Worker Relay
  bridge there is no alias map.
- Never commit `*.key`, `transfers.json` or `*.ntx` (the root `.gitignore`
  excludes them).

---

## Configuration

The bridge reads `router_url` from its initialize config blob (what
`transport config` passes at start) or from the first `attach`.

---

## Build & package

> Skip this section if you use a [prebuilt package](#use-a-prebuilt-package-no-build-needed).

```bash
cd transports/filerelay
go vet ./bridge/...
go test ./bridge/... -count=1
go build -o filerelay-bridge ./bridge
```

Windows: `go build -o filerelay-bridge.exe ./bridge` (and use
`manifest.windows.json`, whose `entry` is the `.exe` name).

Helpers built into the bridge (no server needed):

```bash
filerelay-bridge wrap --type 3 -f payload.bin > frame.bin   # prepend layer-1 type byte
filerelay-bridge --ntx-serve                                # stdio RPC; stderr = logs
```

`.ntx` is a zip with the manifest at its root:

```bash
./package.sh        # -> filerelay.ntx (manifest.json + filerelay-bridge)
```

```powershell
.\package.ps1       # -> filerelay.ntx (manifest.windows.json renamed to
                    #    manifest.json + filerelay-bridge.exe)
```

Both scripts run `go vet` + `go test` first and refuse to package on failure.
Never commit the built `.ntx`.

After rebuilding the bridge you must **reinstall** it
(`nextalk transport install filerelay.ntx --enable`): it is a separate
executable, so a new `nextalk.exe` does not update it.

---

## Browser (WebAssembly) package

NexTalk's browser build cannot spawn processes or touch a filesystem, so it only
runs `.wasm` packages. The extension therefore also ships as
**`filerelay-wasm.ntx`**, built with Node alone (no Go, TinyGo or wat2wasm) and
reproducible byte-for-byte:

```bash
cd transports
node build-wasm.mjs                  # -> dist/filerelay-wasm.ntx + dist/SHA256SUMS
node build-wasm.mjs --version 1.4.0  # stamp manifest.version (the release workflow does this)
node --test test/wasm-package.test.mjs
```

Every package is validated with NexTalk's manifest rules and checked against
WASM transport **ABI v1** (exports, sandboxed imports, behaviour) before it is
written. CI: `.github/workflows/ci.yml` builds, tests and uploads it
on every change; `release.yml` attaches it to each release.

**What it does, and what it does not.** ABI v1 gives a module linear memory plus
an optional `ntx.log` import: no sockets, no `fetch`, no filesystem, and no
file-transfer ops. So `filerelay-wasm` is an **in-memory loopback queue**
(`message` only, no permissions): frames sent in a tab come back out of the same
tab. It is useful for trying the transport flow and for two identities in one
tab, but it never contacts a Router or shard. **Use the native `filerelay.ntx`
package for the real relay.** The ids differ (`filerelay` vs `filerelay-wasm`),
so both can be installed side by side. A networked browser build needs a
host-mediated network import in the ABI first.

Only the *extension* is built for the browser; the relay servers themselves are
never compiled to or run in WebAssembly.

---

## Files

```
transports/filerelay/
├── manifest.json          # linux/macOS package metadata (entry: filerelay-bridge)
├── manifest.windows.json  # same, entry: filerelay-bridge.exe
├── bridge/
│   ├── main.go            # stdio loop, courier/scoped keys, message dispatch
│   ├── rpc.go             # transport API v1 codec (schemas 100–114)
│   ├── rpc_file.go        # file/mailbox codecs (schemas 115–126)
│   ├── xfer.go            # register/resolve + xfer ops (scoped keys, bindings)
│   └── *_test.go          # codec + bridge↔server interop tests
├── wasm/                  # browser package: manifest.json, build.mjs, verify.json
├── package.sh / package.ps1
└── README.md              # this file
```