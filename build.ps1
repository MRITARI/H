# Builds every release file into dist\ (needs Go 1.26+):
#   H.exe                 Windows x64
#   H-linux-amd64         Linux x64
#   H-linux-arm64         Linux ARM64 (Raspberry Pi, ARM laptops, ...)
# plus a .sha256 next to each; the bootstrap scripts (H.ps1, H.sh) verify them.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:CGO_ENABLED = '0'
go mod tidy
foreach ($t in @('windows','linux')) { $env:GOOS = $t; $env:GOARCH = 'amd64'; go vet ./... }

New-Item -ItemType Directory -Force dist | Out-Null
$targets = @(
    @{ os = 'windows'; arch = 'amd64'; file = 'H.exe' },
    @{ os = 'linux';   arch = 'amd64'; file = 'H-linux-amd64' },
    @{ os = 'linux';   arch = 'arm64'; file = 'H-linux-arm64' }
)
foreach ($t in $targets) {
    $env:GOOS = $t.os; $env:GOARCH = $t.arch
    $out = Join-Path dist $t.file
    go build -trimpath -ldflags '-s -w' -o $out .
    $h = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
    "$h  $($t.file)" | Set-Content "$out.sha256" -Encoding ascii
    Write-Host ("built {0,-16} sha256={1}" -f $t.file, $h)
}
Remove-Item Env:GOOS, Env:GOARCH
Write-Host "`nPublish:  gh release create vX.Y.Z dist\H.exe dist\H.exe.sha256 dist\H-linux-amd64 dist\H-linux-amd64.sha256 dist\H-linux-arm64 dist\H-linux-arm64.sha256 --latest"
