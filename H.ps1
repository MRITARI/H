# H bootstrapper:  irm https://raw.githubusercontent.com/MRITARI/H/main/H.ps1 | iex
# Downloads H.exe (SHA-256 verified) into %TEMP%\H and opens the toolbox TUI.
# The tool is a compiled program, so the PowerShell execution policy does not apply to it.
#
# Optional env vars (set before running):
#   H_PATH=D:\          folder/drive the disk scanner starts on (default: system drive)
#   H_CLEAN=1           delete the downloaded files when the TUI exits

function Invoke-H {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference    = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

    $release = 'https://github.com/MRITARI/H/releases/latest/download'
    $dir = Join-Path $env:TEMP 'H'
    New-Item -ItemType Directory -Force $dir | Out-Null
    $exe = Join-Path $dir 'H.exe'

    try {
        # Always fetch the published hash first; re-download when the cached exe is missing or outdated.
        $raw = (Invoke-WebRequest "$release/H.exe.sha256" -UseBasicParsing).Content
        if ($raw -is [byte[]]) { $raw = [Text.Encoding]::ASCII.GetString($raw) }   # GitHub serves octet-stream
        $want = ($raw.Trim() -split '\s+')[0].ToLower()

        $have = if (Test-Path $exe) { (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower() } else { '' }
        if ($have -ne $want) {
            Write-Host '  downloading H.exe ...' -ForegroundColor Cyan
            $tmp = "$exe.part"
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe -L --fail --progress-bar -o $tmp "$release/H.exe"
                if ($LASTEXITCODE -ne 0) { throw 'download failed' }
            } else {
                Invoke-WebRequest "$release/H.exe" -OutFile $tmp -UseBasicParsing
            }
            if ((Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower() -ne $want) { Remove-Item $tmp -Force; throw 'SHA-256 mismatch for H.exe - aborting.' }
            Move-Item $tmp $exe -Force
        }

        $a = @()
        if ($env:H_PATH) { $a += $env:H_PATH }
        & $exe @a
    }
    finally {
        if ($env:H_CLEAN) { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
Invoke-H
