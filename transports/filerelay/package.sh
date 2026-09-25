#!/usr/bin/env bash
# Package the filerelay transport as filerelay.ntx
# (zip with manifest.json + entry binary at root). Refuses to package
# unless vet + tests pass.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> go vet"
go vet ./bridge/...
echo "==> go test"
go test ./bridge/... -count=1

echo "==> build filerelay-bridge"
go build -o filerelay-bridge ./bridge

echo "==> zip filerelay.ntx"
rm -f filerelay.ntx
zip -j filerelay.ntx manifest.json filerelay-bridge
echo "packaged: filerelay.ntx"
unzip -l filerelay.ntx
