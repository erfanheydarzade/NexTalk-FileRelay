# FileRelay transport for NexTalk (`filerelay`)

NexTalk's first external runtime transport, packaged as an installable
`.ntx`. No NexTalk rebuild, ever: build this bridge, zip it with the
manifest, install.

## What it is

`filerelay-bridge` is a courier transport (`message` + `binary-transfer`
capabilities, `network` + `storage` permissions) that speaks the NexTalk
transport API v1 (stdio RPC, schemas 100–126) on one side and the FileRelay
router/shard protocol (raw NanoPack over HTTP) on the other. Message ops
(1–10: initialize, start/stop, send, attach, detach, poll, status,
capabilities, register, resolve) plus file ops (11–16: xfer-create/put/
resume/get/complete/cancel) are all live; anything else answers op 0 +
`SchemaError`.

Trust model — courier:

- The bridge owns its own throwaway ed25519 identities and **never sees
  user private keys**. Core passes only: opaque `[type][nanopack]` frames,
  32B recipient pubkeys, explicit recipient addresses (mailbox+shard, shared
  out-of-band), per-mailbox `read_secret` bearers, shard/router URLs.
- `courier.key` (shard-side sender binding: abuse/rate-limit identity) is
  created next to the binary (`0600`) on first run. The true sender lives
  inside the E2E frame and is verified by NexTalk core.
- Mailbox registration uses per-user scoped keys (`scoped-<tag>.key`,
  `0600`) controlling only that mailbox's registration + courier sends —
  never NexTalk identity keys, never decryption. Delete the key file +
  re-register to revoke.
- Transfer bindings persist in `transfers.json` (`0600`) so each CLI
  invocation (fresh bridge process) can resume/get/complete.
- Never commit `*.key`, `transfers.json`, or `*.ntx` (root `.gitignore`
  excludes them).

## Build

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

## Package (`.ntx` = zip, manifest at root)

```bash
./package.sh        # -> filerelay.ntx (manifest.json + filerelay-bridge)
```

```powershell
.\package.ps1       # -> filerelay.ntx (manifest.windows.json renamed to
                    #    manifest.json + filerelay-bridge.exe)
```

Both scripts run `go vet` + `go test` first and refuse to package on
failure. Never commit the built `.ntx`.

## Install & use (in NexTalk, no rebuild)

```bash
nextalk transport install filerelay.ntx --enable
nextalk transport config filerelay '{"router_url":"http://127.0.0.1:8080"}'
nextalk transport register filerelay --user alice --router http://127.0.0.1:8080
# -> {"mailbox_id":"...","read_secret":"...","shard_url":"..."}  (share mailbox+shard with senders)
nextalk transport poll filerelay -i <YOU>                                   # like worker listen
nextalk transport send-frame filerelay --to <PEER> -f frame.bin
```

The bridge reads `router_url` from its initialize config blob
(`transport config` passes it at start) or from the first `attach`.

Two-user message scenario (Alice ↔ Bob, same machine):

```bash
mkdir alice bob && cd alice && nextalk offline init          # -> ALICE
cd ../bob && nextalk offline init                            # -> BOB
cd ../alice && nextalk offline offer -i ALICE -r BOB -o offer.bin
cd ../bob && nextalk offline accept -i BOB -f ../alice/offer.bin -o answer.bin
cd ../alice && nextalk offline finish -i ALICE -f ../bob/answer.bin

cd ../alice
nextalk transport register filerelay --user alice --router <ROUTER>
nextalk transport attach filerelay --mailbox <M> --secret <S> --shard <SHARD> --router <ROUTER>
cd ../bob
nextalk transport register filerelay --user bob --router <ROUTER>
nextalk transport attach filerelay --mailbox <M> --secret <S> --shard <SHARD> --router <ROUTER>

cd ../alice
nextalk offline encrypt -i ALICE -r BOB -m "hello bob" -o msg.bin
filerelay-bridge wrap --type 3 -f msg.bin > frame.bin
nextalk transport send-frame filerelay --to BOB -f frame.bin
cd ../bob && nextalk transport poll filerelay -i BOB
# [+] Message from <ALICE> (utf-8) — stored in mailbox
```

Files (E2E-encrypted whole-file, chunked opaquely through xfer ops):

```bash
nextalk transport xfer-send filerelay -i <YOU> --to <PEER> --mailbox <M> --shard <URL> -f photo.bin
# -> download ticket (base64 NanoPack): send it inside any E2E message — or mint
#    it with xfer-create and share out-of-band; the recipient fetches by ticket alone
nextalk transport xfer-recv filerelay -i <YOU> --from <PEER> --ticket <base64> -o photo.bin
```

Full runs: `NexTalk/docs/real-scenario.md` scenarios B and C. Command
reference: `NexTalk/docs/transport-cli.md`.

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
│   ├── *_test.go          # codec + bridge↔server interop tests
├── package.sh / package.ps1
└── README.md              # this file
```
