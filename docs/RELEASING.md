# Releasing NexTalk-FileRelay

This document describes how to cut a new release of `nextalk-file-relay`.

## Prerequisites

- Go 1.25+ installed locally
- [GoReleaser](https://goreleaser.com/) installed (`brew install goreleaser` or download from releases)
- A GitHub personal access token with `repo` scope (for pushing tags and publishing releases)

## Release Process

### Option 1: Manual Tag + Push (Recommended for CI-triggered release)

```bash
# 1. Ensure tests pass locally first
go test ./... -v

# 2. Commit any pending changes
git add .
git commit -m "chore: bump version to v0.1.0"

# 3. Tag the release
git tag v0.1.0
git push origin main --tags
```

The `push` of the tag triggers `.github/workflows/release.yml`, which runs GoReleaser and publishes assets to GitHub Releases.

### Option 2: GitHub Actions "Run Workflow" Button

1. Go to the repo's **Actions** tab → select the **Release** workflow
2. Click **"Run workflow"**
3. Enter a version like `v0.1.0` (must match semver)
4. Check "prerelease" if it's a beta/rc build
5. The workflow will:
   - Validate the version format
   - Create and push the tag
   - Run GoReleaser (builds binaries, generates checksums, creates changelog)
   - Publish the release to GitHub

### Option 3: Local Release (Debugging)

```bash
# Build without publishing — useful for testing the pipeline
goreleaser release --snapshot --clean
```

This builds into `./dist/` and prints artifacts but does NOT push tags or publish releases.

## What Gets Published

Each release produces:
- `nextalk-file-relay_v0.1.0_linux_amd64.tar.gz` (and .zip for Windows) — the
  `filerelayd` server, for every supported OS/arch
- Raw binary `nextalk-file-relay_v0.1.0_linux_amd64/nextalk-file-relay`
- `checksums.txt` with SHA256 hashes of the server archives
- `filerelay-bridge_v0.1.0_<os>_<arch>.ntx` — the NexTalk transport bridge
  (`transports/filerelay/`), packaged per OS/arch with its manifest's
  `version` field stamped to the release tag, for every supported OS/arch
- `filerelay-bridge_checksums.txt` with SHA256 hashes of the `.ntx` bundles

The `.ntx` bundles are built and uploaded by the `package-bridge` job in
`.github/workflows/release.yml` after GoReleaser publishes the server
archives — it cross-compiles `filerelay-bridge`, refuses to package if
`go vet`/`go test` on the bridge fail, and uploads the results to the same
GitHub Release via `gh release upload --clobber`.

## Versioning

We follow [Semantic Versioning](https://semver.org). The server's version is
injected into the binary via ldflags:

```bash
go build -ldflags="-X github.com/erfanheydarzade/NexTalk-FileRelay/internal/buildinfo.Version=v0.1.0" ./cmd/filerelayd
```

Check it with `filerelayd --version`. The release workflow reads this from
`.goreleaser.yaml` and the `version:` field in the config.

The bridge (`transports/filerelay/bridge`) doesn't link `internal/buildinfo`
— its version identity is the `version` field in `manifest.json`/
`manifest.windows.json`, which the release workflow stamps to the release
tag when packaging the `.ntx` bundles (the value committed in the repo,
`1.0.0`, is only a local-dev placeholder used by `package.sh`/`package.ps1`).
