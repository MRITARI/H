# H

A terminal toolbox for Windows: disk analyzer plus network, PC, performance, update, security, hardware and printing troubleshooters, with categorized quick fixes.
Go + Bubble Tea, one small exe, no AI, no login, no install. Everything runs locally and read-only until you confirm a fix.

## Run (end users)
```powershell
irm https://raw.githubusercontent.com/MRITARI/H/main/H.ps1 | iex
```
Downloads `H.exe` (SHA-256 verified) into `%TEMP%\H`, runs it and optionally cleans up.
It is a compiled program, so a locked-down PowerShell execution policy does not block it.
Env vars: `H_PATH` (disk scanner start folder), `H_CLEAN=1` (delete the download afterwards).
For repairs that need administrator rights, start the terminal with "Run as administrator" first.

## Menu
| # | Screen | What it does |
|---|---|---|
| 1 | Disk scanner (dirscope) | WizTree-style size tree with SAFE / CAUTION / KEEP verdicts |
| 2 | Network diagnostics | adapter, IP/DHCP, router ping, internet, DNS servers, captive portal, clock, hosts file, VPN, link speed, proxy, Wi-Fi |
| 3 | PC troubleshooter | CPU, memory, disks, drive health, uptime, reboot, crashes and blue screens, app crashes, driver errors, Windows version/activation, RAM |
| 4 | Performance check | CPU/RAM/disk load, commit charge, startup programs, temp folder, Recycle Bin, hibernation file, boot time, top processes |
| 5 | Windows Update & services | update services, policies, BITS, cache size, failed installs and error code, Store services, metered connection |
| 6 | Security check | Defender (protection, definitions, scan age), firewall, UAC, SMBv1, Remote Desktop, auto sign-in, admins, BitLocker, Secure Boot/TPM |
| 7 | Hardware & battery | battery charge and wear, drive failure prediction/wear/temperature, CPU temperature, RAM, GPU driver and BIOS age, USB errors |
| 8 | Printing & peripherals | spooler, stuck print jobs, offline printers, audio, Bluetooth, camera, keyboard and mouse |
| 9 | Quick fixes | pick a category, then a fix; each asks before it runs |

Checks run in parallel and show PASS / WARN / FAIL with a plain-language explanation and, when one applies, a suggested fix (press `f`).
Nothing runs until you press `y`. Every fix shows a risk level: **safe** (opens a tool or changes nothing important),
**disruptive** (brief disconnect, service restart, easy to undo) or **heavy** (long-running, needs a restart, or deletes data permanently).

### Quick fix categories
| Category | Fixes |
|---|---|
| Network | flush DNS, re-register DNS, renew IP, restart adapters, clear ARP, turn off proxy, reset Winsock, reset TCP/IP |
| Windows Update | start update scan, restart update services, reset update cache, reset all update components, open settings |
| System repair | restart Explorer, rebuild icon cache, resync clock, reset Store, chkdsk scan, sfc, DISM scan, DISM repair, memory test |
| Cleanup | delete old temp files, thumbnail cache, crash dumps, empty Recycle Bin, Disk Cleanup, Storage settings |
| Performance | Task Manager, Startup apps, Resource Monitor, Balanced / High performance power plan, turn off hibernation |
| Printing & audio | restart spooler, clear print queue, restart audio, restart Bluetooth, printer settings |
| Security | Windows Security, update Defender definitions, Defender quick scan, enable firewall |
| Hardware | battery report, Device Manager, Disk Management |
| Open tools | Event Viewer, Services, System Information, Network status |

Fixes marked admin need an elevated terminal: press **a** on the main menu to restart H as administrator (UAC prompt).
Some checks (BitLocker, Secure Boot/TPM, drive SMART data) also only work when elevated and say so instead of guessing.

## Keys
| Key | Action |
|---|---|
| ↑↓ / j k, PgUp/PgDn, g G | move |
| Enter / 1-9 | open from the menus |
| a | (main menu) restart as administrator |
| f | (troubleshooters) run the suggested fix, then `y` to confirm |
| r | re-run checks / rescan |
| q / Esc | back to the menu · q on the menu quits · Ctrl+C quits anywhere |
| → l Enter / ← h Backspace | (disk scanner) drill in / up |
| space / c / u | (disk scanner) mark / mark all safe / clear marks |
| d / Del | (disk scanner) delete: `y` Recycle Bin, `p` permanent, anything else cancels |
| o | (disk scanner) reveal in Explorer |

Disk verdicts are rule-based (`junk.go`): only known temp/cache locations and file types are SAFE; Windows and program files are KEEP.

## Build (developers)
```powershell
.\build.ps1          # -> dist\H.exe and dist\H.exe.sha256
```
Publish:
```powershell
gh release create v1.0.0 dist\H.exe dist\H.exe.sha256
```
`H.ps1` downloads the latest release, so publish a new release whenever you change the code.
Run locally: `dist\H.exe D:\`
