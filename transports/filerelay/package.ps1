# Package the filerelay transport as filerelay.ntx
# (zip with manifest.json + entry binary at root). Refuses to package
# unless vet + tests pass. Run from transports\filerelay\.
$ErrorActionPreference = "Stop"

Write-Host "==> go vet"
go vet ./bridge/...
if (!$?) { exit 1 }
Write-Host "==> go test"
go test ./bridge/... -count=1
if (!$?) { exit 1 }

Write-Host "==> build filerelay-bridge.exe"
go build -o filerelay-bridge.exe ./bridge
if (!$?) { exit 1 }

Write-Host "==> zip filerelay.ntx"
if (Test-Path "filerelay.ntx") { Remove-Item "filerelay.ntx" }
if (Test-Path "filerelay.zip") { Remove-Item "filerelay.zip" }
# The installed manifest must be named manifest.json with the .exe entry.
# (Compress-Archive only accepts .zip, so zip first, then rename to .ntx.)
New-Item -ItemType Directory -Force -Path ".ntx-stage" | Out-Null
Copy-Item -Force "manifest.windows.json" ".ntx-stage\manifest.json"
Copy-Item -Force "filerelay-bridge.exe" ".ntx-stage\"
Compress-Archive -Path ".ntx-stage\manifest.json", ".ntx-stage\filerelay-bridge.exe" -DestinationPath "filerelay.zip" -Force
Remove-Item -Recurse -Force ".ntx-stage"
Rename-Item -Force "filerelay.zip" "filerelay.ntx"
Write-Host "packaged: filerelay.ntx"
