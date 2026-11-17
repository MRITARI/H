# Builds dist\H.exe + dist\H.exe.sha256 (needs Go 1.26+)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
go mod tidy
go vet ./...
go build -trimpath -ldflags '-s -w' -o dist\H.exe .
$h = (Get-FileHash dist\H.exe -Algorithm SHA256).Hash.ToLower()
"$h  H.exe" | Set-Content dist\H.exe.sha256 -Encoding ascii
Write-Host "built dist\H.exe  sha256=$h"
