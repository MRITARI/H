package main

// Linux: system troubleshooter and performance screens (no build tag, see lx.go).

import (
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func na(name string) Check { return info(name, "not available on this system") }

func exists(path string) bool {
	m, _ := globFiles(path)
	return len(m) > 0
}

// rebootReasons lists why this machine wants a restart.
func rebootReasons() []string {
	var why []string
	if exists("/var/run/reboot-required") || exists("/run/reboot-required") {
		why = append(why, "package updates (reboot-required)")
	}
	rel := readStr("/proc/sys/kernel/osrelease")
	if rel != "" && !exists("/lib/modules/"+rel) && !exists("/usr/lib/modules/"+rel) &&
		(exists("/lib/modules/*") || exists("/usr/lib/modules/*")) {
		why = append(why, "the running kernel "+rel+" was replaced by an update")
	}
	return why
}

// journalAccess reports whether this user can read the whole system journal.
func journalAccess() bool {
	if isAdmin() {
		return true
	}
	groups, _ := cmd("id", "-nG")
	for _, g := range strings.Fields(groups) {
		if g == "systemd-journal" || g == "adm" || g == "wheel" {
			return true
		}
	}
	return false
}

// kernelLog returns kernel messages (journal first, dmesg as fallback); since "" means this boot.
func kernelLog(since string) (string, bool) {
	if haveCmd("journalctl") {
		args := []string{"-k", "--no-pager", "-q"}
		if since == "" {
			args = append(args, "-b")
		} else {
			args = append(args, "--since", since)
		}
		if out, _ := cmd("journalctl", args...); out != "" {
			return out, true
		}
	}
	if haveCmd("dmesg") {
		if out, err := cmd("dmesg"); err == nil && out != "" {
			return out, true
		}
	}
	return "", false
}

func countLines(s string, subs ...string) (n int, hits []string) {
	for _, l := range lines(s) {
		for _, sub := range subs {
			if strings.Contains(l, sub) {
				n++
				hits = append(hits, l)
				break
			}
		}
	}
	return
}

// cpuPercent samples /proc/stat twice.
func cpuPercent() (int, bool) {
	i1, t1 := parseCPUStat(readStr("/proc/stat"))
	if t1 == 0 {
		return 0, false
	}
	time.Sleep(600 * time.Millisecond)
	i2, t2 := parseCPUStat(readStr("/proc/stat"))
	if t2 <= t1 {
		return 0, false
	}
	return int(100 * (1 - float64(i2-i1)/float64(t2-t1))), true
}

func lxCPU() checkDef {
	return checkDef{"CPU load", func() Check {
		pct, ok := cpuPercent()
		if !ok {
			return na("CPU load")
		}
		l1, _, l15 := parseLoadavg(readStr("/proc/loadavg"))
		cores := runtime.NumCPU()
		txt := fmt.Sprintf("%d%% busy now; load average %.2f (1 min) / %.2f (15 min) on %d cores", pct, l1, l15, cores)
		if pct > 85 || l15 > float64(cores)*1.5 {
			return warn("CPU load", txt, "The CPU is overloaded. Find the process responsible (top/htop) - a sustained load above the core count means work is queueing.", "show-top-processes")
		}
		return pass("CPU load", txt)
	}}
}

func lxMem() checkDef {
	return checkDef{"Memory use", func() Check {
		m := parseMeminfo(readStr("/proc/meminfo"))
		total, avail := m["MemTotal"], m["MemAvailable"]
		if total == 0 {
			return na("Memory use")
		}
		pct := int(100 * (total - avail) / total)
		txt := fmt.Sprintf("%d%% of %s in use (%s available)", pct, gbKB(total), gbKB(avail))
		if st := m["SwapTotal"]; st > 0 {
			used := st - m["SwapFree"]
			txt += fmt.Sprintf("; swap %d%% used", 100*used/st)
			if pct > 85 && used*2 > st {
				return fail("Memory use", txt, "Memory and swap are both nearly full: the system is thrashing and the kernel may kill programs. Close heavy apps or add RAM/zram.", "show-top-processes")
			}
		}
		if pct > 90 {
			return warn("Memory use", txt, "Memory is nearly full, which makes everything slow. Close heavy apps (see the top processes) or add swap/zram.", "show-top-processes")
		}
		return pass("Memory use", txt)
	}}
}

func lxSwap() checkDef {
	return checkDef{"Swap", func() Check {
		m := parseMeminfo(readStr("/proc/meminfo"))
		if m["MemTotal"] == 0 {
			return na("Swap")
		}
		if m["SwapTotal"] == 0 {
			if m["MemTotal"] < 4<<20 {
				return warn("Swap", "none configured with only "+gbKB(m["MemTotal"])+" RAM",
					"Without swap, a memory spike makes the kernel kill programs. Add a swap file or enable zram.", "")
			}
			return info("Swap", "none configured")
		}
		return info("Swap", gbKB(m["SwapTotal"])+" configured")
	}}
}

func lxDiskChecks() []checkDef {
	var defs []checkDef
	for _, d := range fixedDrives() {
		d := d
		name := "Disk " + d.Root + " free space"
		defs = append(defs, checkDef{name, func() Check {
			pct := int(100 * d.Free / d.Total)
			txt := fmt.Sprintf("%d%% free (%s of %s)", pct, gb(d.Free), gb(d.Total))
			switch {
			case pct < 5:
				return fail(name, txt, "Almost full: programs fail to write files and updates break. Free space with the Disk scanner or the Cleanup fixes.", "show-disk-usage")
			case pct < 15:
				return warn(name, txt, "Getting full. Aim for at least 15% free. Use the Disk scanner to find big or junk files.", "show-disk-usage")
			}
			return pass(name, txt)
		}})
	}
	return defs
}

func lxInodes() checkDef {
	return checkDef{"Inodes", func() Check {
		var bad, seen []string
		for _, d := range fixedDrives() {
			if d.Inodes == 0 {
				continue
			}
			used := 100 * (d.Inodes - d.InodesFree) / d.Inodes
			seen = append(seen, d.Root)
			if used > 90 {
				bad = append(bad, fmt.Sprintf("%s %d%%", d.Root, used))
			}
		}
		if len(seen) == 0 {
			return na("Inodes")
		}
		if len(bad) > 0 {
			return fail("Inodes", "nearly exhausted: "+strings.Join(bad, ", "),
				"The file system is out of file slots even if it has free space (millions of tiny files, often caches or mail). New files cannot be created.", "clear-cache-old")
		}
		return pass("Inodes", "plenty free on "+trimList(seen, 4))
	}}
}

func lxReadOnly() checkDef {
	return checkDef{"Read-only file systems", func() Check {
		mounts := parseMounts(readStr("/proc/mounts"))
		if len(mounts) == 0 {
			return na("Read-only file systems")
		}
		var ro []string
		root := false
		for _, m := range mounts {
			if realFS[m.FS] && hasOpt(m.Opts, "ro") {
				ro = append(ro, m.Dir)
				if m.Dir == "/" {
					root = true
				}
			}
		}
		switch {
		case root:
			return fail("Read-only file systems", "the root file system is read-only",
				"Linux remounts a disk read-only after serious errors. Nothing can be saved. Check dmesg for I/O errors, back up, and run fsck from a rescue boot.", "show-kernel-errors")
		case len(ro) > 0:
			return warn("Read-only file systems", "mounted read-only: "+strings.Join(ro, ", "),
				"These disks are read-only. That is normal for install media but a sign of errors on a data disk. Check dmesg.", "show-kernel-errors")
		}
		return pass("Read-only file systems", "none")
	}}
}

func lxFailedUnits() checkDef {
	return checkDef{"Failed services", func() Check {
		if !haveCmd("systemctl") {
			return info("Failed services", "this system does not use systemd")
		}
		out, err := cmd("systemctl", "--failed", "--no-legend", "--plain")
		if err != nil && out == "" {
			return probeErr("Failed services", err)
		}
		failed := parseFailedUnits(out)
		if len(failed) == 0 {
			return pass("Failed services", "no failed units")
		}
		return warn("Failed services", plural(len(failed), "unit", "units")+": "+trimList(failed, 6),
			"These services crashed or could not start. 'systemctl status <unit>' and 'journalctl -u <unit>' show why. Restarting fixes transient failures.", "restart-failed-units")
	}}
}

func lxJournalErrors() checkDef {
	return checkDef{"Errors in the last 24h", func() Check {
		if !haveCmd("journalctl") {
			return info("Errors in the last 24h", "no systemd journal on this system")
		}
		if !journalAccess() {
			return info("Errors in the last 24h", "no access to the system journal - add yourself to the systemd-journal group or run as root")
		}
		out, err := cmd("journalctl", "-p", "3", "--since", "24 hours ago", "--no-pager", "-q")
		if err != nil && out == "" {
			return probeErr("Errors in the last 24h", err)
		}
		l := lines(out)
		if len(l) == 0 {
			return pass("Errors in the last 24h", "none")
		}
		txt := fmt.Sprintf("%d error message(s); top sources: %s", len(l), strings.Join(topSources(l, 4), ", "))
		if len(l) > 30 {
			return warn("Errors in the last 24h", txt, "Many errors. The top sources point at the failing service or driver; the boot error list shows the messages.", "show-boot-errors")
		}
		return info("Errors in the last 24h", txt)
	}}
}

var reSegv = regexp.MustCompile(`(\S+)\[\d+\]: segfault`)

func lxCrashes() checkDef {
	return checkDef{"Crashes and out-of-memory kills (7d)", func() Check {
		name := "Crashes and out-of-memory kills (7d)"
		out, ok := kernelLog("7 days ago")
		if !ok {
			return info(name, "kernel log not readable (needs the systemd-journal group or root)")
		}
		oom, _ := countLines(out, "Out of memory", "oom-kill", "Killed process")
		apps := map[string]int{}
		seg := 0
		for _, l := range lines(out) {
			if m := reSegv.FindStringSubmatch(l); m != nil {
				apps[m[1]]++
				seg++
			}
		}
		var top []string
		for a, n := range apps {
			top = append(top, strconv.Itoa(n)+"x "+a)
		}
		if oom > 0 {
			return warn(name, fmt.Sprintf("%d out-of-memory kill(s), %d segfault(s)", oom, seg),
				"The kernel ran out of memory and killed programs. Close memory hogs, add swap/zram or more RAM.", "show-top-processes")
		}
		if seg > 0 {
			return warn(name, fmt.Sprintf("%d segfault(s): %s", seg, trimList(top, 4)),
				"These programs crashed. Repeated crashes of one app point to a bad update or plugin; of many apps, to failing RAM or a driver.", "show-kernel-errors")
		}
		return pass(name, "none")
	}}
}

func lxUptime() checkDef {
	return checkDef{"Uptime", func() Check {
		f := strings.Fields(readStr("/proc/uptime"))
		if len(f) == 0 {
			return na("Uptime")
		}
		secs, _ := strconv.ParseFloat(f[0], 64)
		d := int(secs / 86400)
		txt := fmt.Sprintf("%d day(s) since the last restart", d)
		if d > 30 {
			return warn("Uptime", txt, "Kernel and library updates only apply after a restart, and long uptimes pile up leaks. Restart when convenient.", "")
		}
		return pass("Uptime", txt)
	}}
}

func lxReboot() checkDef {
	return checkDef{"Pending reboot", func() Check {
		if why := rebootReasons(); len(why) > 0 {
			return warn("Pending reboot", "restart required: "+strings.Join(why, ", "),
				"An update replaced something that is still running old code. Restart soon; it also clears many odd problems.", "")
		}
		return pass("Pending reboot", "none")
	}}
}

func lxOSInfo() checkDef {
	return checkDef{"Operating system", func() Check {
		os := parseOSRelease(readStr("/etc/os-release"))
		name := os["PRETTY_NAME"]
		if name == "" {
			name = "Linux"
		}
		return info("Operating system", name+", kernel "+readStr("/proc/sys/kernel/osrelease")+", "+runtime.GOARCH)
	}}
}

func lxZombies() checkDef {
	return checkDef{"Processes", func() Check {
		out, err := cmd("ps", "-eo", "stat=")
		if err != nil && out == "" {
			return probeErr("Processes", err)
		}
		all := lines(out)
		z := 0
		for _, l := range all {
			if strings.HasPrefix(l, "Z") {
				z++
			}
		}
		txt := fmt.Sprintf("%d running, %d zombie", len(all), z)
		if z > 20 {
			return warn("Processes", txt, "Many zombie processes: a parent program is not collecting its finished children. Restarting that program clears them.", "show-top-processes")
		}
		return pass("Processes", txt)
	}}
}

func pcToolLx() tool {
	defs := []checkDef{lxOSInfo(), lxCPU(), lxMem(), lxSwap()}
	defs = append(defs, lxDiskChecks()...)
	defs = append(defs, lxInodes(), lxReadOnly(), lxFailedUnits(), lxJournalErrors(), lxCrashes(), lxUptime(), lxReboot(), lxZombies())
	return tool{Title: "System troubleshooter", Blurb: "general health: CPU, memory, disks, services, errors", Defs: defs}
}

// ---------- performance ----------

var reBoot = regexp.MustCompile(`=\s*(?:(\d+)min\s*)?([\d.]+)s`)

// parseBootSeconds reads the "Startup finished in ... = 38.4s" line of systemd-analyze.
func parseBootSeconds(s string) (float64, bool) {
	for _, l := range lines(s) {
		if !strings.Contains(l, "Startup finished") {
			continue
		}
		if m := reBoot.FindStringSubmatch(l); m != nil {
			sec, _ := strconv.ParseFloat(m[2], 64)
			min, _ := strconv.Atoi(m[1])
			return float64(min*60) + sec, true
		}
	}
	return 0, false
}

func sizeCheck(name, path string, warnAt int64, hint, fixID string) checkDef {
	return checkDef{name, func() Check {
		if !exists(path) {
			return info(name, "not present")
		}
		sz, complete := dirSize(path, 5*time.Second)
		txt := human(sz)
		if !complete {
			txt = "more than " + txt
		}
		if sz > warnAt {
			return warn(name, txt, hint, fixID)
		}
		return pass(name, txt)
	}}
}

func lxPerfCaches() []checkDef {
	home := realHome()
	return []checkDef{
		sizeCheck("User cache (~/.cache)", home+"/.cache", 5<<30,
			"Applications keep downloaded and rendered data here. It is safe to delete and rebuilds itself, but programs start a little slower once.", "clear-cache-old"),
		sizeCheck("Trash", home+"/.local/share/Trash", 1<<30,
			"Deleted files still use disk space until the Trash is emptied.", "empty-trash"),
		sizeCheck("/tmp", "/tmp", 2<<30, "Temporary files from running programs. Old files of yours can be removed safely.", "clear-user-tmp"),
		sizeCheck("Crash dumps", "/var/lib/systemd/coredump", 500<<20, "Core dumps of crashed programs are only useful for debugging.", "clear-coredumps"),
		{"System journal size", func() Check {
			if !haveCmd("journalctl") {
				return na("System journal size")
			}
			out, err := cmd("journalctl", "--disk-usage")
			if err != nil && out == "" {
				return probeErr("System journal size", err)
			}
			sz := parseSizeHuman(out)
			if sz == 0 {
				return info("System journal size", out)
			}
			if sz > 2<<30 {
				return warn("System journal size", human(sz), "The log journal has grown large. Vacuuming keeps the recent logs and frees the rest.", "vacuum-journal")
			}
			return pass("System journal size", human(sz))
		}},
	}
}

func lxPressure() checkDef {
	return checkDef{"Resource pressure (PSI)", func() Check {
		cpu, mem, io := readStr("/proc/pressure/cpu"), readStr("/proc/pressure/memory"), readStr("/proc/pressure/io")
		if cpu == "" && mem == "" && io == "" {
			return info("Resource pressure (PSI)", "the kernel does not expose pressure stall information")
		}
		c, m, i := parsePSI(cpu), parsePSI(mem), parsePSI(io)
		txt := fmt.Sprintf("tasks stalled in the last 10 s: cpu %.0f%%, memory %.0f%%, disk I/O %.0f%%", c, m, i)
		switch {
		case m > 10:
			return warn("Resource pressure (PSI)", txt, "Programs are waiting for memory: the system is short on RAM and swapping. Close heavy apps.", "show-top-processes")
		case i > 30:
			return warn("Resource pressure (PSI)", txt, "Programs are waiting on the disk. Look for a backup, indexer, update or a failing drive.", "show-top-processes")
		case c > 40:
			return warn("Resource pressure (PSI)", txt, "Programs are queueing for CPU time. Find the process responsible.", "show-top-processes")
		}
		return pass("Resource pressure (PSI)", txt)
	}}
}

func lxBootTime() checkDef {
	return checkDef{"Boot time", func() Check {
		if !haveCmd("systemd-analyze") {
			return na("Boot time")
		}
		out, err := cmd("systemd-analyze", "time")
		sec, ok := parseBootSeconds(out)
		if err != nil || !ok {
			return info("Boot time", "unknown")
		}
		txt := fmt.Sprintf("%.0f s to reach the desktop/login", sec)
		if sec > 60 {
			return warn("Boot time", txt, "Slow boot. 'systemd-analyze blame' shows which services take longest.", "show-boot-time")
		}
		return pass("Boot time", txt)
	}}
}

func lxAutostart() checkDef {
	return checkDef{"Autostart apps", func() Check {
		a, _ := globFiles(realHome() + "/.config/autostart/*.desktop")
		b, _ := globFiles("/etc/xdg/autostart/*.desktop")
		n := len(a) + len(b)
		txt := fmt.Sprintf("%d (your %d, system %d)", n, len(a), len(b))
		if n > 25 {
			return warn("Autostart apps", txt, "Many programs start with your session and slow down login. Disable ones you do not need in your desktop's Startup Applications settings.", "list-autostart")
		}
		return pass("Autostart apps", txt)
	}}
}

func lxPowerProfile() checkDef {
	return checkDef{"Power profile", func() Check {
		if haveCmd("powerprofilesctl") {
			out, _ := cmd("powerprofilesctl", "get")
			if out != "" {
				if out == "power-saver" {
					return warn("Power profile", out, "The power-saver profile throttles the CPU. Switch to balanced or performance for more speed.", "profile-balanced")
				}
				return info("Power profile", out)
			}
		}
		if g := readStr("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"); g != "" {
			return info("Power profile", "CPU governor: "+g)
		}
		return na("Power profile")
	}}
}

func lxTop(name, sortKey string) checkDef {
	return checkDef{name, func() Check {
		out, err := cmd("ps", "-eo", "comm=,pcpu=,rss=", "--sort=-"+sortKey)
		if err != nil && out == "" {
			return probeErr(name, err)
		}
		var top []string
		for _, l := range lines(out) {
			f := strings.Fields(l)
			if len(f) < 3 {
				continue
			}
			if sortKey == "pcpu" {
				top = append(top, f[0]+" "+f[1]+"%")
			} else {
				top = append(top, f[0]+" "+strconv.Itoa(atoi(f[2])/1024)+" MB")
			}
			if len(top) == 5 {
				break
			}
		}
		return info(name, strings.Join(top, ", "))
	}}
}

func lxThrottle() checkDef {
	return checkDef{"Thermal throttling", func() Check {
		files, _ := globFiles("/sys/devices/system/cpu/cpu*/thermal_throttle/core_throttle_count")
		if len(files) == 0 {
			return na("Thermal throttling")
		}
		total := 0
		for _, f := range files {
			total += atoi(readStr(f))
		}
		if total > 0 {
			return warn("Thermal throttling", fmt.Sprintf("the CPU slowed itself down %d time(s) since boot", total),
				"The CPU got too hot and reduced its speed. Clean dust from fans and vents, improve airflow, or replace thermal paste.", "show-sensors")
		}
		return pass("Thermal throttling", "never throttled since boot")
	}}
}

func lxDocker() checkDef {
	return checkDef{"Docker disk use", func() Check {
		if !haveCmd("docker") {
			return info("Docker disk use", "docker is not installed")
		}
		out, err := cmd("docker", "system", "df", "--format", "{{.Type}}: {{.Reclaimable}} reclaimable")
		if err != nil || out == "" {
			return info("Docker disk use", "not readable (docker daemon off or no permission)")
		}
		return info("Docker disk use", strings.Join(lines(out), "; "))
	}}
}

func perfToolLx() tool {
	defs := []checkDef{lxCPU(), lxMem(), lxPressure()}
	defs = append(defs, lxDiskChecks()...)
	defs = append(defs, lxUptime(), lxBootTime(), lxAutostart(), lxPowerProfile(), lxThrottle(),
		lxTop("Top CPU processes", "pcpu"), lxTop("Top memory processes", "rss"))
	defs = append(defs, lxPerfCaches()...)
	defs = append(defs, lxDocker())
	return tool{Title: "Performance check", Blurb: "why is my PC slow?", Defs: defs}
}
