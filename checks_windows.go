package main

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// ---------- network ----------

var reSignal = regexp.MustCompile(`:\s*(\d+)%`)
var reSSID = regexp.MustCompile(`(?m)^\s*SSID\s*:\s*(.+)$`)

func netTool() tool {
	ipinfo := &lazy{f: func() (string, error) {
		return ps(`$c = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1; ` +
			`if ($c) { "$($c.IPv4Address.IPAddress)|$($c.IPv4DefaultGateway.NextHop)|$($c.DnsServer.ServerAddresses -join ',')" }`)
	}}
	parts := func() (ip, gw, dns string) {
		out, _ := ipinfo.get()
		p := strings.Split(strings.TrimSpace(out), "|")
		if len(p) == 3 {
			return p[0], p[1], p[2]
		}
		return
	}
	t := tool{
		Title: "Network diagnostics",
		Blurb: "no internet, slow Wi-Fi, DNS problems",
		Defs: []checkDef{
			{"Network adapter", func() Check {
				out, err := ps(`Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { "$($_.Name) ($($_.LinkSpeed))" }`)
				if err != nil {
					return probeErr("Network adapter", err)
				}
				l := lines(out)
				if len(l) == 0 {
					return fail("Network adapter", "no adapter is connected",
						"Cable unplugged, Wi-Fi off, airplane mode or the adapter is disabled. Check those first, then restart the adapter.", "restart-adapter")
				}
				return pass("Network adapter", strings.Join(l, ", "))
			}},
			{"IP configuration", func() Check {
				ip, gw, dns := parts()
				switch {
				case ip == "":
					return fail("IP configuration", "no IPv4 address with a default gateway",
						"The PC did not get an address from the router (DHCP). Renewing the IP often fixes this.", "renew-ip")
				case strings.HasPrefix(ip, "169.254."):
					return fail("IP configuration", "self-assigned address "+ip,
						"DHCP failed, so Windows gave itself a 169.254.x.x address. Renew the IP or check the router.", "renew-ip")
				}
				return pass("IP configuration", fmt.Sprintf("ip %s, gateway %s, dns %s", ip, gw, dns))
			}},
			{"Gateway (router) ping", func() Check {
				_, gw, _ := parts()
				if gw == "" {
					return info("Gateway (router) ping", "no gateway known")
				}
				if ok, ms := pingHost(gw); ok {
					return pass("Gateway (router) ping", fmt.Sprintf("%s answers (%d ms)", gw, ms))
				}
				return fail("Gateway (router) ping", gw+" does not answer",
					"The router is unreachable: weak Wi-Fi, bad cable or router problem. Restarting the adapter or the router can help.", "restart-adapter")
			}},
			{"Internet ping", func() Check {
				for _, h := range []string{"1.1.1.1", "8.8.8.8"} {
					if ok, ms := pingHost(h); ok {
						if ms > 150 {
							return warn("Internet ping", fmt.Sprintf("%s answers slowly (%d ms)", h, ms),
								"High latency: Wi-Fi interference, a VPN or a congested connection.", "")
						}
						return pass("Internet ping", fmt.Sprintf("%s answers (%d ms)", h, ms))
					}
				}
				return warn("Internet ping", "1.1.1.1 and 8.8.8.8 do not answer",
					"No reply by IP. Some networks block ping, so trust the DNS and HTTPS checks if they pass.", "")
			}},
			{"DNS lookup", func() Check {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				addrs, err := net.DefaultResolver.LookupHost(ctx, "www.microsoft.com")
				if err != nil || len(addrs) == 0 {
					return fail("DNS lookup", "cannot resolve www.microsoft.com",
						"Names do not resolve, so sites will not open even if the connection works. Flush the DNS cache; if it persists, the DNS server is down.", "flushdns")
				}
				return pass("DNS lookup", "www.microsoft.com -> "+addrs[0])
			}},
			{"HTTPS (port 443)", func() Check {
				c, err := net.DialTimeout("tcp", "www.microsoft.com:443", 5*time.Second)
				if err != nil {
					return fail("HTTPS (port 443)", "cannot connect to www.microsoft.com:443",
						"Web traffic is blocked or broken: firewall, proxy, a stuck network stack or no internet. Resetting Winsock fixes a stuck stack.", "winsock-reset")
				}
				c.Close()
				return pass("HTTPS (port 443)", "www.microsoft.com:443 reachable")
			}},
			{"System proxy", func() Check {
				k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
				if err != nil {
					return probeErr("System proxy", err)
				}
				defer k.Close()
				if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil && v == 1 {
					srv, _, _ := k.GetStringValue("ProxyServer")
					return warn("System proxy", "enabled: "+srv,
						"Traffic goes through a proxy. If the internet is broken, a dead proxy is a common cause (Settings > Network > Proxy).", "")
				}
				return pass("System proxy", "not enabled")
			}},
			{"Wi-Fi signal", func() Check {
				out, _ := run(10*time.Second, "netsh.exe", "wlan", "show", "interfaces")
				m := reSignal.FindStringSubmatch(out)
				if m == nil {
					return info("Wi-Fi signal", "no Wi-Fi connection")
				}
				ssid := "?"
				if s := reSSID.FindStringSubmatch(out); s != nil {
					ssid = strings.TrimSpace(s[1])
				}
				if sig := atoi(m[1]); sig < 40 {
					return warn("Wi-Fi signal", fmt.Sprintf("%d%% on '%s'", sig, ssid),
						"Weak signal causes drops and slow speeds. Move closer to the router or use a cable.", "")
				}
				return pass("Wi-Fi signal", fmt.Sprintf("%s%% on '%s'", m[1], ssid))
			}},
		},
	}
	t.Defs = append(t.Defs, netExtraDefs(parts)...)
	return t
}

// ---------- shared system probes ----------

func osProbe() *lazy {
	return &lazy{f: func() (string, error) {
		return ps(`$o = Get-CimInstance Win32_OperatingSystem; "$($o.TotalVisibleMemorySize)|$($o.FreePhysicalMemory)|$([int]((Get-Date) - $o.LastBootUpTime).TotalDays)"`)
	}}
}

func cpuCheck() checkDef {
	return checkDef{"CPU load", func() Check {
		out, err := ps(`[int](Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average`)
		if err != nil || out == "" {
			return probeErr("CPU load", err)
		}
		if n := atoi(out); n > 85 {
			return warn("CPU load", out+"%", "The CPU is nearly maxed out right now. Open Task Manager and sort by CPU to find the process responsible.", "open-taskmgr")
		}
		return pass("CPU load", out+"%")
	}}
}

func memCheck(osp *lazy) checkDef {
	return checkDef{"Memory use", func() Check {
		out, err := osp.get()
		p := strings.Split(out, "|")
		if err != nil || len(p) < 3 {
			return probeErr("Memory use", err)
		}
		total, free := atoi(p[0]), atoi(p[1])
		if total == 0 {
			return probeErr("Memory use", nil)
		}
		pct := 100 * (total - free) / total
		d := fmt.Sprintf("%d%% of %.1f GB in use", pct, float64(total)/1048576)
		if pct > 85 {
			return warn("Memory use", d, "Memory is nearly full, which makes everything slow. Close heavy apps (Task Manager > Memory) or restart.", "open-taskmgr")
		}
		return pass("Memory use", d)
	}}
}

func uptimeCheck(osp *lazy) checkDef {
	return checkDef{"Uptime", func() Check {
		out, err := osp.get()
		p := strings.Split(out, "|")
		if err != nil || len(p) < 3 {
			return probeErr("Uptime", err)
		}
		d := atoi(p[2])
		txt := fmt.Sprintf("%d day(s) since the last restart", d)
		if d > 14 {
			return warn("Uptime", txt, "Long uptimes pile up memory leaks and pending updates. A restart fixes many odd problems.", "")
		}
		return pass("Uptime", txt)
	}}
}

func diskFreeChecks() []checkDef {
	var defs []checkDef
	for _, d := range fixedDrives() {
		d := d
		name := "Disk " + strings.TrimSuffix(d.Root, `\`) + " free space"
		defs = append(defs, checkDef{name, func() Check {
			pct := int(100 * d.Free / d.Total)
			txt := fmt.Sprintf("%d%% free (%s of %s)", pct, gb(d.Free), gb(d.Total))
			switch {
			case pct < 5:
				return fail(name, txt, "Almost full: Windows slows down and updates fail. Free space with the Disk scanner.", "")
			case pct < 15:
				return warn(name, txt, "Getting full. Aim for at least 15% free. Use the Disk scanner to find big or junk files.", "")
			}
			return pass(name, txt)
		}})
	}
	return defs
}

func rebootCheck() checkDef {
	return checkDef{"Pending reboot", func() Check {
		if why := pendingReboot(); len(why) > 0 {
			return warn("Pending reboot", "restart required: "+strings.Join(why, ", "),
				"Windows is waiting for a restart to finish installing something. Restart soon; many update and install problems clear after it.", "")
		}
		return pass("Pending reboot", "none")
	}}
}

// ---------- PC troubleshooter ----------

func pcTool() tool {
	osp := osProbe()
	defs := []checkDef{cpuCheck(), memCheck(osp)}
	defs = append(defs, diskFreeChecks()...)
	defs = append(defs,
		checkDef{"Physical disk health", func() Check {
			out, err := ps(`Get-PhysicalDisk | ForEach-Object { "$($_.FriendlyName)|$($_.HealthStatus)" }`)
			if err != nil || out == "" {
				return info("Physical disk health", "not available on this PC")
			}
			var bad []string
			for _, l := range lines(out) {
				if p := strings.Split(l, "|"); len(p) == 2 && p[1] != "Healthy" {
					bad = append(bad, p[0]+": "+p[1])
				}
			}
			if len(bad) > 0 {
				return fail("Physical disk health", strings.Join(bad, "; "), "Windows reports a drive problem. Back up important files now and have the drive checked.", "")
			}
			return pass("Physical disk health", "all drives report Healthy")
		}},
		uptimeCheck(osp),
		rebootCheck(),
		checkDef{"Errors in the last 24h", func() Check {
			out, err := ps(`$e = Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 300 -ErrorAction SilentlyContinue; ` +
				`if (-not $e) { '0' } else { "$($e.Count)"; $e | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 4 | ForEach-Object { "$($_.Count)x $($_.Name)" } }`)
			l := lines(out)
			if err != nil || len(l) == 0 {
				return probeErr("Errors in the last 24h", err)
			}
			n := atoi(l[0])
			if n == 0 {
				return pass("Errors in the last 24h", "none")
			}
			txt := fmt.Sprintf("%d error event(s); top sources: %s", n, strings.Join(l[1:], ", "))
			if n > 20 {
				return warn("Errors in the last 24h", txt, "Many errors. The top sources point at the failing app or driver; Event Viewer shows details. sfc can repair damaged system files.", "open-eventvwr")
			}
			return info("Errors in the last 24h", txt)
		}},
		checkDef{"Stopped auto-start services", func() Check {
			out, err := ps(`Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State='Stopped'" | Select-Object -ExpandProperty DisplayName`)
			if err != nil {
				return probeErr("Stopped auto-start services", err)
			}
			l := lines(out)
			if len(l) > 8 {
				l = append(l[:8], "...")
			}
			return info("Stopped auto-start services", fmt.Sprintf("%d: %s", len(lines(out)), strings.Join(l, ", ")))
		}},
	)
	defs = append(defs, pcExtraDefs()...)
	return tool{Title: "PC troubleshooter", Blurb: "general health: CPU, memory, disks, errors, services", Defs: defs}
}

// ---------- performance ----------

func perfTool() tool {
	osp := osProbe()
	startup := &lazy{f: func() (string, error) {
		return ps(`Get-CimInstance Win32_StartupCommand | Select-Object -ExpandProperty Name -Unique`)
	}}
	defs := []checkDef{cpuCheck(), memCheck(osp),
		{"Disk busy", func() Check {
			out, err := ps(`(Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'").PercentDiskTime`)
			if err != nil || out == "" {
				return probeErr("Disk busy", err)
			}
			if atoi(out) > 90 {
				return warn("Disk busy", out+"% busy", "The disk is saturated, so everything waits on it. Look for a backup, scan, update or indexing job in Task Manager.", "open-taskmgr")
			}
			return pass("Disk busy", out+"%")
		}},
	}
	defs = append(defs, diskFreeChecks()...)
	defs = append(defs, uptimeCheck(osp),
		checkDef{"Startup programs", func() Check {
			out, err := startup.get()
			if err != nil {
				return probeErr("Startup programs", err)
			}
			l := lines(out)
			txt := fmt.Sprintf("%d entries", len(l))
			if len(l) > 15 {
				return warn("Startup programs", txt, "Many programs start with Windows and slow down boot. Disable ones you do not need in Task Manager > Startup apps.", "open-taskmgr")
			}
			return pass("Startup programs", txt)
		}},
		checkDef{"Power plan", func() Check {
			out, _ := run(10*time.Second, "powercfg.exe", "/getactivescheme")
			name := out
			if i := strings.Index(out, "("); i >= 0 {
				name = strings.TrimSuffix(out[i+1:], ")")
			}
			if strings.Contains(strings.ToLower(name), "saver") {
				return warn("Power plan", name, "A power-saver plan throttles the CPU. Switch to Balanced or High performance for more speed.", "")
			}
			return info("Power plan", name)
		}},
		checkDef{"Top CPU processes", func() Check {
			out, err := ps(`Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -notin '_Total','Idle' } | Sort-Object PercentProcessorTime -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) $($_.PercentProcessorTime)%" }`)
			if err != nil {
				return probeErr("Top CPU processes", err)
			}
			return info("Top CPU processes", strings.Join(lines(out), ", "))
		}},
		checkDef{"Top memory processes", func() Check {
			out, err := ps(`Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 | ForEach-Object { "$($_.ProcessName) $([int]($_.WorkingSet64/1MB)) MB" }`)
			if err != nil {
				return probeErr("Top memory processes", err)
			}
			return info("Top memory processes", strings.Join(lines(out), ", "))
		}},
	)
	defs = append(defs, perfExtraDefs()...)
	return tool{Title: "Performance check", Blurb: "why is my PC slow?", Defs: defs}
}

// ---------- Windows Update & services ----------

func updateTool() tool {
	svc := &lazy{f: func() (string, error) {
		return ps(`Get-CimInstance Win32_Service -Filter "Name='wuauserv' OR Name='bits' OR Name='cryptsvc' OR Name='UsoSvc'" | ForEach-Object { "$($_.Name)|$($_.State)|$($_.StartMode)" }`)
	}}
	var defs []checkDef
	for _, n := range []string{"wuauserv", "bits", "cryptsvc", "UsoSvc"} {
		n := n
		name := "Service " + n
		defs = append(defs, checkDef{name, func() Check {
			out, err := svc.get()
			if err != nil {
				return probeErr(name, err)
			}
			for _, l := range lines(out) {
				if p := strings.Split(l, "|"); len(p) == 3 && strings.EqualFold(p[0], n) {
					if p[2] == "Disabled" {
						return fail(name, "disabled", "This update service is disabled, so updates cannot install. Set it to Manual or Automatic in Services.", "open-services")
					}
					return pass(name, fmt.Sprintf("%s (start mode %s)", p[1], p[2]))
				}
			}
			return warn(name, "not found", "The service is missing, which suggests damaged system files. sfc can repair them.", "sfc")
		}})
	}
	defs = append(defs,
		checkDef{"Core services", func() Check {
			out, err := ps(`Get-Service EventLog,Dhcp,Dnscache,LanmanWorkstation,mpssvc,WinDefend,Schedule,W32Time -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.Status)" }`)
			if err != nil {
				return probeErr("Core services", err)
			}
			var bad []string
			for _, l := range lines(out) {
				if p := strings.Split(l, "|"); len(p) == 2 && p[1] != "Running" {
					bad = append(bad, p[0]+" ("+p[1]+")")
				}
			}
			if len(bad) > 0 {
				return warn("Core services", "not running: "+strings.Join(bad, ", "), "A core Windows service is stopped. Start it in Services or restart the PC.", "open-services")
			}
			return pass("Core services", "all running")
		}},
		rebootCheck(),
		checkDef{"Free space for updates", func() Check {
			for _, d := range fixedDrives() {
				if strings.EqualFold(d.Root, sysDriveRoot()) {
					txt := fmt.Sprintf("%s free on %s", gb(d.Free), d.Root)
					if d.Free < 10<<30 {
						return warn("Free space for updates", txt, "Windows needs roughly 10 GB free to download and install updates. Free space with the Disk scanner.", "")
					}
					return pass("Free space for updates", txt)
				}
			}
			return info("Free space for updates", "system drive not found")
		}},
		checkDef{"Failed update installs (14d)", func() Check {
			out, err := ps(`(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';Id=20;StartTime=(Get-Date).AddDays(-14)} -ErrorAction SilentlyContinue | Measure-Object).Count`)
			if err != nil || out == "" {
				return probeErr("Failed update installs (14d)", err)
			}
			if n := atoi(out); n > 0 {
				return fail("Failed update installs (14d)", fmt.Sprintf("%d failure(s)", n),
					"Updates failed to install. Resetting the update cache fixes most stuck updates; sfc/DISM help if that is not enough.", "clear-wu-cache")
			}
			return pass("Failed update installs (14d)", "none")
		}},
		checkDef{"Last installed update", func() Check {
			out, err := ps(`$h = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h) { "$($h.HotFixID)|$($h.InstalledOn.ToString('yyyy-MM-dd'))" }`)
			p := strings.Split(strings.TrimSpace(out), "|")
			if err != nil || len(p) != 2 {
				return info("Last installed update", "unknown")
			}
			t, perr := time.Parse("2006-01-02", p[1])
			if perr != nil {
				return info("Last installed update", out)
			}
			age := int(time.Since(t).Hours() / 24)
			txt := fmt.Sprintf("%s on %s (%d days ago)", p[0], p[1], age)
			if age > 60 {
				return warn("Last installed update", txt, "No update for over two months. Check Windows Update; if it fails, use the update cache reset.", "open-wu-settings")
			}
			return pass("Last installed update", txt)
		}},
	)
	defs = append(defs, updateExtraDefs()...)
	return tool{Title: "Windows Update & services", Blurb: "updates failing, stuck or services stopped", Defs: defs}
}
