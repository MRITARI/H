package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// A fix is a fixed, reviewed action. Checks only ever reference a fix by id,
// and nothing runs until the user presses y.
//
// Risk tells the user what to expect before they confirm:
//
//	safe       - opens a tool or changes nothing important
//	disruptive - brief disconnect, service restart or settings change; easy to undo
//	heavy      - long-running, needs a restart, or permanently deletes data
type fix struct {
	Desc  string
	Admin bool
	Risk  string
	Run   func() (string, error)
}

type fixCat struct {
	Name, Blurb string
	IDs         []string
}

// fixCats is the display order. Every fix id must appear in exactly one category (see TestFixesExist).
var fixCats = []fixCat{
	{"Network", "DNS, IP, adapters, Winsock, proxy", []string{"flushdns", "register-dns", "renew-ip", "restart-adapter", "clear-arp", "reset-proxy", "winsock-reset", "reset-tcpip"}},
	{"Windows Update", "stuck or failing updates", []string{"start-update-scan", "restart-wu", "clear-wu-cache", "reset-wu-components", "open-wu-settings"}},
	{"System repair", "system files, Explorer, Store, clock, memory", []string{"restart-explorer", "rebuild-icon-cache", "time-sync", "reset-store", "chkdsk-scan", "sfc", "dism-scan", "dism", "memory-diagnostic"}},
	{"Cleanup", "free disk space", []string{"clear-user-temp", "clear-thumbcache", "clear-crash-dumps", "empty-recycle-bin", "open-disk-cleanup", "open-storage-settings"}},
	{"Performance", "power plan, startup, hibernation", []string{"open-taskmgr", "open-startup-apps", "open-resmon", "power-balanced", "power-high", "disable-hibernate"}},
	{"Printing & audio", "printers, sound, Bluetooth", []string{"restart-spooler", "clear-print-queue", "restart-audio", "restart-bluetooth", "open-printers-settings"}},
	{"Security", "Defender, firewall", []string{"open-windows-security", "update-defender-signatures", "defender-quick-scan", "enable-firewall"}},
	{"Hardware", "battery, drives, devices", []string{"battery-report", "open-devmgmt", "open-diskmgmt"}},
	{"Open tools", "Windows admin consoles", []string{"open-eventvwr", "open-services", "open-msinfo", "open-network-status"}},
}

// ---- constructors keep the table below short ----

func runFixCmd(timeout time.Duration, name string, args ...string) func() (string, error) {
	return func() (string, error) { return run(timeout, name, args...) }
}

func psFix(script string) func() (string, error) {
	return func() (string, error) { return ps(script) }
}

func openFix(msg, name string, args ...string) func() (string, error) {
	return func() (string, error) { return msg, exec.Command(name, args...).Start() }
}

func consoleFix(msg, title, command string) func() (string, error) {
	return func() (string, error) { return msg, openConsole(title, command) }
}

var fixes = map[string]fix{
	// ---- Network ----
	"flushdns":     {"Flush the DNS cache", false, "safe", runFixCmd(20*time.Second, "ipconfig.exe", "/flushdns")},
	"register-dns": {"Re-register this PC's DNS records", false, "safe", runFixCmd(20*time.Second, "ipconfig.exe", "/registerdns")},
	"renew-ip": {"Release and renew the IP address (brief disconnect)", true, "disruptive", func() (string, error) {
		a, _ := run(30*time.Second, "ipconfig.exe", "/release")
		b, err := run(60*time.Second, "ipconfig.exe", "/renew")
		return a + "\n" + b, err
	}},
	"restart-adapter": {"Restart the active network adapters (brief disconnect)", true, "disruptive",
		psFix(`Get-NetAdapter | Where-Object Status -eq 'Up' | Restart-NetAdapter -Confirm:$false; 'Adapters restarted.'`)},
	"clear-arp": {"Clear the ARP cache (forgets known neighbours on the LAN)", true, "safe",
		runFixCmd(20*time.Second, "netsh.exe", "interface", "ip", "delete", "arpcache")},
	"reset-proxy": {"Turn off the user proxy setting (Windows Internet settings)", false, "disruptive",
		psFix(`Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0; 'Proxy turned off for this user.'`)},
	"winsock-reset": {"Reset the Winsock catalog (restart needed afterwards)", true, "heavy",
		runFixCmd(30*time.Second, "netsh.exe", "winsock", "reset")},
	"reset-tcpip": {"Reset the TCP/IP stack to defaults (restart needed afterwards)", true, "heavy",
		runFixCmd(30*time.Second, "netsh.exe", "int", "ip", "reset")},

	// ---- Windows Update ----
	"start-update-scan": {"Ask Windows Update to scan for updates now", false, "safe",
		func() (string, error) {
			return "Scan requested. Check Settings > Windows Update.", exec.Command("UsoClient.exe", "StartScan").Start()
		}},
	"restart-wu": {"Restart the Windows Update and BITS services", true, "disruptive",
		psFix(`Restart-Service wuauserv,bits -Force; 'Services restarted.'`)},
	"clear-wu-cache": {"Reset the update download cache (renames SoftwareDistribution)", true, "disruptive",
		psFix(`$ErrorActionPreference='Stop'; try { Stop-Service wuauserv,bits -Force; Remove-Item "$env:SystemRoot\SoftwareDistribution.old" -Recurse -Force -ErrorAction SilentlyContinue; ` +
			`Rename-Item "$env:SystemRoot\SoftwareDistribution" 'SoftwareDistribution.old' -Force; 'Cache reset. Windows rebuilds it on the next update check.' } finally { Start-Service bits,wuauserv -ErrorAction SilentlyContinue }`)},
	"reset-wu-components": {"Reset all update components (cache + catroot2, services restarted)", true, "heavy",
		psFix(`$ErrorActionPreference='Stop'; try { Stop-Service wuauserv,bits,cryptsvc -Force; ` +
			`Remove-Item "$env:SystemRoot\SoftwareDistribution.old","$env:SystemRoot\System32\catroot2.old" -Recurse -Force -ErrorAction SilentlyContinue; ` +
			`Rename-Item "$env:SystemRoot\SoftwareDistribution" 'SoftwareDistribution.old' -Force; Rename-Item "$env:SystemRoot\System32\catroot2" 'catroot2.old' -Force; ` +
			`'Update components reset.' } finally { Start-Service cryptsvc,bits,wuauserv -ErrorAction SilentlyContinue }`)},
	"open-wu-settings": {"Open Windows Update settings", false, "safe", openFix("Opened Windows Update settings.", "explorer.exe", "ms-settings:windowsupdate")},

	// ---- System repair ----
	"restart-explorer": {"Restart Windows Explorer (taskbar and desktop flicker)", false, "disruptive",
		psFix(`Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; Start-Sleep 2; if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }; 'Explorer restarted.'`)},
	"rebuild-icon-cache": {"Rebuild the icon cache (fixes wrong or blank icons)", false, "disruptive",
		psFix(`Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; Start-Sleep 1; ` +
			`Remove-Item "$env:LOCALAPPDATA\IconCache.db","$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache*" -Force -ErrorAction SilentlyContinue; ` +
			`Start-Sleep 1; if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }; 'Icon cache rebuilt.'`)},
	"time-sync":   {"Resync the system clock with the time server", true, "safe", runFixCmd(30*time.Second, "w32tm.exe", "/resync")},
	"reset-store": {"Reset the Microsoft Store cache", false, "safe", openFix("Store cache reset started; the Store opens when it is done.", "wsreset.exe")},
	"chkdsk-scan": {"Scan the system drive for errors, read-only (opens a console)", true, "safe",
		consoleFix("Opened a console window running chkdsk /scan.", "Check Disk", "chkdsk %SystemDrive% /scan")},
	"sfc": {"Scan and repair system files (opens a console, takes minutes)", true, "heavy",
		consoleFix("Opened a console window running sfc /scannow.", "System File Checker", "sfc /scannow")},
	"dism-scan": {"Check the Windows image for damage, read-only (opens a console)", true, "safe",
		consoleFix("Opened a console window running DISM /ScanHealth.", "DISM scan", "DISM /Online /Cleanup-Image /ScanHealth")},
	"dism": {"Repair the Windows image (opens a console, takes minutes)", true, "heavy",
		consoleFix("Opened a console window running DISM /RestoreHealth.", "DISM repair", "DISM /Online /Cleanup-Image /RestoreHealth")},
	"memory-diagnostic": {"Test the RAM at next restart (Windows Memory Diagnostic)", true, "heavy", openFix("Opened Windows Memory Diagnostic.", "mdsched.exe")},

	// ---- Cleanup ----
	"clear-user-temp": {"Delete your temp files older than 1 day (files in use are skipped)", false, "disruptive",
		psFix(`$cut=(Get-Date).AddDays(-1); $n=0; $b=0; Get-ChildItem $env:TEMP -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt $cut } | ` +
			`ForEach-Object { $len=$_.Length; try { Remove-Item $_.FullName -Force -ErrorAction Stop; $n++; $b+=$len } catch {} }; "Removed $n files, freed $([math]::Round($b/1MB)) MB."`)},
	"clear-thumbcache": {"Delete the thumbnail cache (rebuilds itself; files in use are skipped)", false, "safe",
		psFix(`Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue; 'Thumbnail cache cleared.'`)},
	"clear-crash-dumps": {"Delete Windows crash dumps (Minidump and MEMORY.DMP)", true, "disruptive",
		psFix(`Remove-Item "$env:SystemRoot\Minidump\*" -Force -ErrorAction SilentlyContinue; Remove-Item "$env:SystemRoot\MEMORY.DMP" -Force -ErrorAction SilentlyContinue; 'Crash dumps removed.'`)},
	"empty-recycle-bin":     {"Empty the Recycle Bin (PERMANENT: recycled files cannot be restored)", false, "heavy", psFix(`Clear-RecycleBin -Force -ErrorAction Stop; 'Recycle Bin emptied.'`)},
	"open-disk-cleanup":     {"Open Disk Cleanup", false, "safe", openFix("Opened Disk Cleanup.", "cleanmgr.exe")},
	"open-storage-settings": {"Open Storage settings", false, "safe", openFix("Opened Storage settings.", "explorer.exe", "ms-settings:storagesense")},

	// ---- Performance ----
	"open-taskmgr":      {"Open Task Manager", false, "safe", openFix("Opened Task Manager.", "taskmgr.exe")},
	"open-startup-apps": {"Open Startup apps settings (turn off what you don't need)", false, "safe", openFix("Opened Startup apps.", "explorer.exe", "ms-settings:startupapps")},
	"open-resmon":       {"Open Resource Monitor", false, "safe", openFix("Opened Resource Monitor.", "resmon.exe")},
	"power-balanced":    {"Switch to the Balanced power plan", false, "safe", runFixCmd(15*time.Second, "powercfg.exe", "/setactive", "SCHEME_BALANCED")},
	"power-high":        {"Switch to the High performance power plan (more heat and battery use)", false, "disruptive", runFixCmd(15*time.Second, "powercfg.exe", "/setactive", "SCHEME_MIN")},
	"disable-hibernate": {"Turn off hibernation and fast startup (frees hiberfil.sys)", true, "heavy", runFixCmd(15*time.Second, "powercfg.exe", "/hibernate", "off")},

	// ---- Printing & audio ----
	"restart-spooler": {"Restart the print spooler", true, "disruptive", psFix(`Restart-Service spooler -Force; 'Print spooler restarted.'`)},
	"clear-print-queue": {"Clear all stuck print jobs (cancels every pending print)", true, "disruptive",
		psFix(`try { Stop-Service spooler -Force; Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue; 'Print queue cleared.' } finally { Start-Service spooler -ErrorAction SilentlyContinue }`)},
	"restart-audio":          {"Restart the Windows audio services (sound cuts out briefly)", true, "disruptive", psFix(`Restart-Service AudioEndpointBuilder -Force; Start-Service audiosrv -ErrorAction SilentlyContinue; 'Audio services restarted.'`)},
	"restart-bluetooth":      {"Restart the Bluetooth service (devices reconnect)", true, "disruptive", psFix(`Restart-Service bthserv -Force; 'Bluetooth service restarted.'`)},
	"open-printers-settings": {"Open Printers & scanners settings", false, "safe", openFix("Opened Printers & scanners.", "explorer.exe", "ms-settings:printers")},

	// ---- Security ----
	"open-windows-security":      {"Open Windows Security", false, "safe", openFix("Opened Windows Security.", "explorer.exe", "windowsdefender:")},
	"update-defender-signatures": {"Update Defender virus definitions", true, "safe", psFix(`Update-MpSignature -ErrorAction Stop; 'Definitions updated.'`)},
	"defender-quick-scan": {"Run a Defender quick scan (opens a console)", true, "safe",
		consoleFix("Opened a console window running a Defender quick scan.", "Defender quick scan", `powershell -NoProfile -Command "Start-MpScan -ScanType QuickScan"`)},
	"enable-firewall": {"Turn the Windows Firewall on for all profiles", true, "disruptive",
		psFix(`Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True; 'Firewall enabled for all profiles.'`)},

	// ---- Hardware ----
	"battery-report": {"Create and open a battery health report", false, "safe",
		psFix(`$p = Join-Path $env:USERPROFILE 'battery-report.html'; powercfg /batteryreport /output $p | Out-Null; Start-Process $p; "Report saved to $p"`)},
	"open-devmgmt":  {"Open Device Manager", false, "safe", openFix("Opened Device Manager.", "mmc.exe", "devmgmt.msc")},
	"open-diskmgmt": {"Open Disk Management", false, "safe", openFix("Opened Disk Management.", "mmc.exe", "diskmgmt.msc")},

	// ---- Open tools ----
	"open-eventvwr":       {"Open Event Viewer", false, "safe", openFix("Opened Event Viewer.", "mmc.exe", "eventvwr.msc")},
	"open-services":       {"Open the Services console", false, "safe", openFix("Opened Services.", "mmc.exe", "services.msc")},
	"open-msinfo":         {"Open System Information", false, "safe", openFix("Opened System Information.", "msinfo32.exe")},
	"open-network-status": {"Open Network status settings", false, "safe", openFix("Opened Network status.", "explorer.exe", "ms-settings:network-status")},
}

// fixCatOf returns the category name a fix belongs to.
func fixCatOf(id string) string {
	for _, c := range fixCats {
		for _, x := range c.IDs {
			if x == id {
				return c.Name
			}
		}
	}
	return ""
}

// runFix executes a fix by id, refusing admin fixes in a normal terminal.
func runFix(id string) (string, error) {
	f, ok := fixes[id]
	if !ok {
		return "", fmt.Errorf("unknown fix %q", id)
	}
	if f.Admin && !isAdmin() {
		return "", fmt.Errorf("needs administrator rights - press a on the main menu to restart as administrator")
	}
	out, err := f.Run()
	return strings.TrimSpace(out), err
}
