package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

// psCheck runs a PowerShell snippet and hands its output lines to f.
// "; exit 0" keeps a harmless non-terminating error from looking like a failed probe.
func psCheck(name, script string, f func(l []string) Check) checkDef {
	return checkDef{name, func() Check {
		l, err := psLines(script + "; exit 0")
		if err != nil && len(l) == 0 {
			return probeErr(name, err)
		}
		return f(l)
	}}
}

func regDWORD(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err == nil
}

func regString(root registry.Key, path, name string) (string, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	return v, err == nil
}

func ageDays(date string) (int, bool) {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(date))
	if err != nil {
		return 0, false
	}
	return int(time.Since(t).Hours() / 24), true
}

func gbi(b int64) string { return fmt.Sprintf("%.1f GB", float64(b)/(1<<30)) }

// ---------- network extras ----------

type httpProbe struct {
	once sync.Once
	body string
	date time.Time
	err  error
}

func (h *httpProbe) get() (string, time.Time, error) {
	h.once.Do(func() {
		c := &http.Client{Timeout: 7 * time.Second}
		r, err := c.Get("http://www.msftconnecttest.com/connecttest.txt")
		if err != nil {
			h.err = err
			return
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(r.Body, 512))
		h.body = strings.TrimSpace(string(b))
		h.date, _ = http.ParseTime(r.Header.Get("Date"))
	})
	return h.body, h.date, h.err
}

func dnsServerOK(srv string) bool {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		return d.DialContext(ctx, "udp", net.JoinHostPort(srv, "53"))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, "www.microsoft.com")
	return err == nil && len(addrs) > 0
}

func netExtraDefs(parts func() (string, string, string)) []checkDef {
	web := &httpProbe{}
	return []checkDef{
		{"DNS servers", func() Check {
			_, _, dns := parts()
			var srvs []string
			for _, s := range strings.Split(dns, ",") {
				if s = strings.TrimSpace(s); s != "" && !strings.Contains(s, "%") && !strings.HasPrefix(strings.ToLower(s), "fe80") {
					srvs = append(srvs, s)
				}
			}
			if len(srvs) == 0 {
				return info("DNS servers", "none known")
			}
			var bad []string
			for _, s := range srvs {
				if !dnsServerOK(s) {
					bad = append(bad, s)
				}
			}
			switch {
			case len(bad) == 0:
				return pass("DNS servers", strings.Join(srvs, ", ")+" all answer")
			case len(bad) == len(srvs):
				return fail("DNS servers", "none answer: "+strings.Join(bad, ", "),
					"Your DNS servers do not reply, so names cannot be resolved. Flush the cache; if it persists, change the DNS server in the adapter settings or check the router.", "flushdns")
			}
			return warn("DNS servers", "not answering: "+strings.Join(bad, ", "),
				"One of your DNS servers is down. Windows falls back to the others, which can make browsing slow.", "flushdns")
		}},
		{"Captive portal / HTTP", func() Check {
			body, _, err := web.get()
			switch {
			case err != nil:
				return fail("Captive portal / HTTP", "plain HTTP request failed",
					"Web requests do not get through: no internet, a firewall or a proxy problem.", "reset-proxy")
			case body != "Microsoft Connect Test":
				return warn("Captive portal / HTTP", "unexpected response",
					"Windows got a different page than expected. On public Wi-Fi this means a sign-in page (captive portal) is blocking you; open a browser and sign in. Filtering proxies can cause it too.", "")
			}
			return pass("Captive portal / HTTP", "Windows connectivity test page returned as expected")
		}},
		{"Clock accuracy", func() Check {
			_, d, err := web.get()
			if err != nil || d.IsZero() {
				return info("Clock accuracy", "could not compare with a web server")
			}
			skew := time.Since(d)
			if skew < 0 {
				skew = -skew
			}
			if skew > 5*time.Minute {
				return warn("Clock accuracy", fmt.Sprintf("clock is off by about %d minutes", int(skew.Minutes())),
					"A wrong clock breaks HTTPS, sign-ins and Windows Update. Resync the time (and check the time zone).", "time-sync")
			}
			return pass("Clock accuracy", fmt.Sprintf("within %d seconds of the web", int(skew.Seconds())+1))
		}},
		{"Hosts file", func() Check {
			b, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`))
			if err != nil {
				return info("Hosts file", "could not be read")
			}
			var entries []string
			for _, l := range lines(string(b)) {
				if !strings.HasPrefix(l, "#") {
					entries = append(entries, l)
				}
			}
			if len(entries) == 0 {
				return pass("Hosts file", "no custom entries")
			}
			show := entries
			if len(show) > 3 {
				show = append(show[:3:3], "...")
			}
			st := "INFO"
			if len(entries) > 20 {
				st = "WARN"
			}
			return Check{"Hosts file", st, fmt.Sprintf("%d custom entries: %s", len(entries), strings.Join(show, " | ")),
				"The hosts file overrides DNS for those names. Unexpected entries (often from malware or old tools) can block or redirect sites.", ""}
		}},
		psCheck("VPN / virtual adapters", `Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'VPN|TAP|Tailscale|WireGuard|Virtual|Hyper-V|VMware|Fortinet|Cisco|OpenVPN|Zscaler' } | ForEach-Object { $_.Name }`,
			func(l []string) Check {
				if len(l) == 0 {
					return pass("VPN / virtual adapters", "none active")
				}
				return info("VPN / virtual adapters", strings.Join(l, ", ")+" - a VPN or virtual switch can change routes and DNS; disconnect it to test")
			}),
		psCheck("Physical link speed", `Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object { "$($_.Name)|$($_.PhysicalMediaType)|$($_.ReceiveLinkSpeed)" }`,
			func(l []string) Check {
				var slow []string
				for _, x := range l {
					p := strings.Split(x, "|")
					if len(p) == 3 && strings.Contains(p[1], "802.3") && atoi(p[2]) > 0 && atoi(p[2]) < 100000000 {
						slow = append(slow, fmt.Sprintf("%s at %d Mbps", p[0], atoi(p[2])/1000000))
					}
				}
				if len(slow) > 0 {
					return warn("Physical link speed", strings.Join(slow, ", "),
						"A wired link negotiated below 100 Mbps. This usually means a damaged cable or a bad port; try another cable.", "restart-adapter")
				}
				return pass("Physical link speed", "no slow wired links")
			}),
	}
}

// ---------- PC extras ----------

func pcExtraDefs() []checkDef {
	return []checkDef{
		psCheck("Crashes & unexpected shutdowns (30d)",
			`$k=(Get-WinEvent -FilterHashtable @{LogName='System';Id=41;StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | Measure-Object).Count; `+
				`$b=(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-WER-SystemErrorReporting';Id=1001;StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | Measure-Object).Count; "$k|$b"`,
			func(l []string) Check {
				p := strings.Split(strings.Join(l, ""), "|")
				if len(p) != 2 {
					return info("Crashes & unexpected shutdowns (30d)", "unknown")
				}
				k, b := atoi(p[0]), atoi(p[1])
				txt := fmt.Sprintf("%d unexpected shutdown(s), %d blue screen(s)", k, b)
				if k+b > 0 {
					return warn("Crashes & unexpected shutdowns (30d)", txt,
						"The PC lost power or crashed. Repeated blue screens point at a driver, failing RAM or overheating. Event Viewer shows the details; the memory test checks the RAM.", "open-eventvwr")
				}
				return pass("Crashes & unexpected shutdowns (30d)", "none")
			}),
		psCheck("App crashes (7d)",
			`Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000;StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | ForEach-Object { $_.Properties[0].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Count)x $($_.Name)" }`,
			func(l []string) Check {
				if len(l) == 0 {
					return pass("App crashes (7d)", "none")
				}
				st := "INFO"
				if atoi(strings.SplitN(l[0], "x", 2)[0]) >= 5 {
					st = "WARN"
				}
				return Check{"App crashes (7d)", st, strings.Join(l, ", "),
					"These programs crashed repeatedly. Update or reinstall the first one; if it is a Windows component, run the system file scan.", "sfc"}
			}),
		psCheck("Device Manager errors", `Get-PnpDevice -Status ERROR -ErrorAction SilentlyContinue | ForEach-Object { $_.FriendlyName }`,
			func(l []string) Check {
				if len(l) == 0 {
					return pass("Device Manager errors", "no devices reporting errors")
				}
				if len(l) > 4 {
					l = append(l[:4:4], "...")
				}
				return warn("Device Manager errors", strings.Join(l, ", "),
					"These devices have a driver problem. Open Device Manager, right-click the device and update or reinstall its driver.", "open-devmgmt")
			}),
		psCheck("Windows version", `$o=Get-CimInstance Win32_OperatingSystem; "$($o.Caption)|$($o.BuildNumber)"`,
			func(l []string) Check {
				p := strings.Split(strings.Join(l, ""), "|")
				if len(p) != 2 {
					return info("Windows version", "unknown")
				}
				txt := fmt.Sprintf("%s (build %s)", strings.TrimSpace(p[0]), p[1])
				if strings.Contains(p[0], "Windows 10") {
					return warn("Windows version", txt, "Windows 10 reached end of support on 14 October 2025 and no longer gets free security updates. Plan an upgrade to Windows 11.", "open-wu-settings")
				}
				return pass("Windows version", txt)
			}),
		psCheck("Windows activation", `$l = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND Name LIKE 'Windows%'" | Select-Object -First 1; if ($l) { $l.LicenseStatus } else { 'none' }`,
			func(l []string) Check {
				switch strings.Join(l, "") {
				case "1":
					return pass("Windows activation", "licensed")
				case "none", "":
					return info("Windows activation", "license status unknown")
				}
				return warn("Windows activation", "not fully activated",
					"Unactivated Windows limits personalization and shows a watermark. Check Settings > System > Activation.", "")
			}),
		psCheck("Installed vs usable RAM", `$i=(Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum; $u=(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize*1KB; "$i|$u"`,
			func(l []string) Check {
				p := strings.Split(strings.Join(l, ""), "|")
				if len(p) != 2 {
					return info("Installed vs usable RAM", "unknown")
				}
				var inst, use float64
				fmt.Sscan(p[0], &inst)
				fmt.Sscan(p[1], &use)
				if inst <= 0 || use <= 0 {
					return info("Installed vs usable RAM", "unknown")
				}
				txt := fmt.Sprintf("%.1f GB usable of %.1f GB installed", use/(1<<30), inst/(1<<30))
				if use/inst < 0.85 {
					return warn("Installed vs usable RAM", txt,
						"A lot of memory is reserved by hardware (integrated graphics) or not detected. Reseat the RAM or check BIOS settings if a module is missing.", "open-msinfo")
				}
				return pass("Installed vs usable RAM", txt)
			}),
	}
}

// ---------- performance extras ----------

func perfExtraDefs() []checkDef {
	return []checkDef{
		psCheck("Commit charge (RAM + page file)", `$o=Get-CimInstance Win32_OperatingSystem; "$($o.TotalVirtualMemorySize)|$($o.FreeVirtualMemory)"`,
			func(l []string) Check {
				p := strings.Split(strings.Join(l, ""), "|")
				if len(p) != 2 || atoi(p[0]) == 0 {
					return info("Commit charge (RAM + page file)", "unknown")
				}
				pct := 100 * (atoi(p[0]) - atoi(p[1])) / atoi(p[0])
				txt := fmt.Sprintf("%d%% of RAM + page file committed", pct)
				if pct > 90 {
					return warn("Commit charge (RAM + page file)", txt, "Windows is close to running out of memory including the page file; apps may crash. Close heavy programs or add RAM.", "open-taskmgr")
				}
				return pass("Commit charge (RAM + page file)", txt)
			}),
		psCheck("Running processes", `(Get-Process | Measure-Object).Count`,
			func(l []string) Check {
				n := atoi(strings.Join(l, ""))
				if n > 300 {
					return warn("Running processes", fmt.Sprintf("%d", n), "Unusually many processes. Check Startup apps and background programs.", "open-startup-apps")
				}
				return pass("Running processes", fmt.Sprintf("%d", n))
			}),
		{"Your temp folder", func() Check {
			size, done := dirSize(os.TempDir(), 8*time.Second)
			txt := gbi(size)
			if !done {
				txt += "+ (still counting when stopped)"
			}
			if size > 2<<30 {
				return warn("Your temp folder", txt, "Temp files pile up and are safe to clear when no installer is running.", "clear-user-temp")
			}
			return pass("Your temp folder", txt)
		}},
		psCheck("Recycle Bin", `$s=(New-Object -ComObject Shell.Application).Namespace(10).Items(); $t=0; foreach ($i in $s) { $t += [int64]$i.Size }; $t`,
			func(l []string) Check {
				var n int64
				fmt.Sscan(strings.Join(l, ""), &n)
				if n > 5<<30 {
					return warn("Recycle Bin", gbi(n), "The Recycle Bin holds a lot of data. Check it first, then empty it to free the space.", "empty-recycle-bin")
				}
				return pass("Recycle Bin", gbi(n))
			}),
		{"Hibernation file", func() Check {
			st, err := os.Stat(sysDriveRoot() + "hiberfil.sys")
			if err != nil {
				return pass("Hibernation file", "hibernation is off or the file is hidden from this account")
			}
			if st.Size() > 10<<30 {
				return warn("Hibernation file", gbi(st.Size()), "hiberfil.sys is very large. Turning hibernation off frees it but also disables fast startup.", "disable-hibernate")
			}
			return info("Hibernation file", gbi(st.Size())+" (used by hibernate and fast startup)")
		}},
		psCheck("Last boot time", `$e=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational';Id=100} -MaxEvents 1 -ErrorAction SilentlyContinue; `+
			`if ($e) { $x=[xml]$e.ToXml(); ($x.Event.EventData.Data | Where-Object Name -eq 'BootTime').'#text' }`,
			func(l []string) Check {
				ms := atoi(strings.Join(l, ""))
				if ms == 0 {
					return info("Last boot time", "no boot measurement recorded")
				}
				txt := fmt.Sprintf("%d seconds", ms/1000)
				if ms > 120000 {
					return warn("Last boot time", txt, "Slow boots are usually caused by too many startup programs or a slow disk.", "open-startup-apps")
				}
				return pass("Last boot time", txt)
			}),
	}
}

// ---------- Windows Update extras ----------

func updateExtraDefs() []checkDef {
	return []checkDef{
		{"Update policies", func() Check {
			const p = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
			var notes []string
			if v, ok := regString(registry.LOCAL_MACHINE, p, "WUServer"); ok && v != "" {
				notes = append(notes, "managed by WSUS server "+v)
			}
			if v, ok := regDWORD(registry.LOCAL_MACHINE, p+`\AU`, "NoAutoUpdate"); ok && v == 1 {
				return warn("Update policies", "automatic updates are disabled by policy",
					"A group policy or registry setting turns automatic updates off. That is normal on managed PCs, otherwise remove the setting.", "open-wu-settings")
			}
			if len(notes) > 0 {
				return info("Update policies", strings.Join(notes, "; ")+" - updates come from your organization, not Microsoft")
			}
			return pass("Update policies", "no overrides")
		}},
		psCheck("BITS transfer errors", `(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.JobState -in 'Error','TransientError' } | Measure-Object).Count`,
			func(l []string) Check {
				if n := atoi(strings.Join(l, "")); n > 0 {
					return warn("BITS transfer errors", fmt.Sprintf("%d stuck transfer(s)", n), "Background downloads are stuck, which blocks updates. Resetting the update components clears them.", "reset-wu-components")
				}
				return pass("BITS transfer errors", "none")
			}),
		{"Update download cache", func() Check {
			size, done := dirSize(filepath.Join(os.Getenv("SystemRoot"), `SoftwareDistribution\Download`), 8*time.Second)
			txt := gbi(size)
			if !done {
				txt += "+"
			}
			if size > 5<<30 {
				return warn("Update download cache", txt, "The update cache is large, often from stuck updates. Resetting it frees the space and fixes stuck downloads.", "clear-wu-cache")
			}
			return pass("Update download cache", txt)
		}},
		psCheck("Latest update error code", `$e=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';Id=20} -MaxEvents 1 -ErrorAction SilentlyContinue; if ($e) { "$($e.TimeCreated.ToString('yyyy-MM-dd'))|$($e.Message)" }`,
			func(l []string) Check {
				if len(l) == 0 {
					return pass("Latest update error code", "no failed install on record")
				}
				p := strings.SplitN(strings.Join(l, " "), "|", 2)
				code := "unknown code"
				for _, w := range strings.Fields(p[len(p)-1]) {
					if strings.HasPrefix(w, "0x") {
						code = strings.Trim(w, ".,;:")
						break
					}
				}
				return info("Latest update error code", fmt.Sprintf("%s on %s - search this code to find the exact cause", code, p[0]))
			}),
		psCheck("Store & install services", `Get-Service ClipSVC,InstallService -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.StartType)" }`,
			func(l []string) Check {
				for _, x := range l {
					if p := strings.Split(x, "|"); len(p) == 2 && p[1] == "Disabled" {
						return warn("Store & install services", p[0]+" is disabled", "Microsoft Store apps and some updates need this service. Set it to Manual in Services.", "open-services")
					}
				}
				return pass("Store & install services", "not disabled")
			}),
		psCheck("Metered connection", `try { [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile().GetConnectionCost().NetworkCostType } catch { 'ERR' }`,
			func(l []string) Check {
				switch v := strings.Join(l, ""); v {
				case "Unrestricted":
					return pass("Metered connection", "not metered")
				case "", "ERR":
					return info("Metered connection", "could not be determined")
				default:
					return warn("Metered connection", "connection is set as "+strings.ToLower(v),
						"Windows delays big updates on metered connections. Turn metered off for this network in Settings > Network if it is not a mobile hotspot.", "open-network-status")
				}
			}),
	}
}
