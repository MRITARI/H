package main

// Tests for the Linux code. They run on any OS: the Linux checks read /proc, /sys and
// command output only through the variables in lx.go, which these tests replace with fake data.

import (
	"errors"
	"fmt"
	"os/exec"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLinuxParsers(t *testing.T) {
	m := parseMeminfo("MemTotal:       16000000 kB\nMemAvailable:    8000000 kB\nSwapTotal: 0 kB\n")
	if m["MemTotal"] != 16000000 || m["MemAvailable"] != 8000000 {
		t.Errorf("meminfo: %v", m)
	}
	if gw, dev := parseDefaultRoute("default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"); gw != "192.168.1.1" || dev != "wlan0" {
		t.Errorf("route: %s %s", gw, dev)
	}
	if gw, dev := parseDefaultRoute("default dev wg0 scope link"); gw != "" || dev != "wg0" {
		t.Errorf("route without gateway: %q %q", gw, dev)
	}
	if ip := parseIPv4("3: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic"); ip != "192.168.1.23" {
		t.Errorf("ipv4: %q", ip)
	}
	if ok, ms := parsePingAvg("rtt min/avg/max/mdev = 9.123/10.6/11.3/0.5 ms"); !ok || ms != 11 {
		t.Errorf("ping: %v %d", ok, ms)
	}
	if ok, _ := parsePingAvg("2 packets transmitted, 0 received, 100% packet loss"); ok {
		t.Error("ping parsed a failed run as success")
	}
	if l, ok := parsePacketLoss("10 packets transmitted, 8 received, 20% packet loss, time 2000ms"); !ok || l != 20 {
		t.Errorf("loss: %v %v", l, ok)
	}
	if s := parseResolvConf("# c\nnameserver 1.1.1.1\nnameserver 9.9.9.9\nsearch lan\n"); len(s) != 2 || s[1] != "9.9.9.9" {
		t.Errorf("resolv: %v", s)
	}
	if f := parseFailedUnits("● foo.service loaded failed failed Foo\nbar.timer loaded failed failed Bar\n"); len(f) != 2 || f[0] != "foo.service" {
		t.Errorf("failed units: %v", f)
	}
	top := topSources([]string{
		"Nov 17 10:00:01 host kernel: x", "Nov 17 10:00:02 host kernel: y", "Nov 17 10:00:03 host sshd[12]: z",
	}, 2)
	if len(top) != 2 || top[0] != "2x kernel" || top[1] != "1x sshd" {
		t.Errorf("topSources: %v", top)
	}
	if n := parseSizeHuman("Archived and active journals take up 1.5G in the file system."); n != int64(1.5*(1<<30)) {
		t.Errorf("size: %d", n)
	}
	if s, ok := parseBootSeconds("Startup finished in 3.2s (firmware) + 4s (loader) + 1min 12.5s (userspace) = 1min 19.7s"); !ok || s < 79 || s > 80 {
		t.Errorf("boot: %v %v", s, ok)
	}
	if i, tot := parseCPUStat("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 1 1 1 1"); tot != 1000 || i != 800 {
		t.Errorf("cpu stat: idle %d total %d", i, tot)
	}
	if v := parsePSI("some avg10=12.50 avg60=1.00 avg300=0.00 total=1\nfull avg10=3.00"); v != 12.5 {
		t.Errorf("psi: %v", v)
	}
	ls := parseListeners("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nudp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\ntcp LISTEN 0 4096 [::]:631 [::]:*\ntcp LISTEN 0 1 [::1]:631 [::]:*")
	if len(ls) != 4 || !ls[0].exposed() || ls[1].exposed() || !ls[2].exposed() || ls[3].exposed() || ls[2].Port != 631 {
		t.Errorf("listeners: %+v", ls)
	}
	if c := parseSSHD("# x\nPermitRootLogin no\npermitrootlogin yes\nPasswordAuthentication no"); c["permitrootlogin"] != "no" || c["passwordauthentication"] != "no" {
		t.Errorf("sshd (first value wins): %v", c)
	}
	if g := groupMembers("root:x:0:\nsudo:x:27:alice,bob\n", "sudo"); len(g) != 2 || g[1] != "bob" {
		t.Errorf("group: %v", g)
	}
	si := parseSmart("SMART overall-health self-assessment test result: PASSED\nModel Number: Samsung SSD\nTemperature:                        41 Celsius\nPercentage Used: 7%\n")
	if !si.Passed || si.PctUsed != 7 || si.TempC != 41 || si.Model != "Samsung SSD" {
		t.Errorf("smart nvme: %+v", si)
	}
	si = parseSmart("SMART overall-health self-assessment test result: FAILED!\n  5 Reallocated_Sector_Ct   0x0033   100   100   036    Pre-fail  Always       -       12\n197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       3\n194 Temperature_Celsius     0x0022   064   050   000    Old_age   Always       -       36 (Min/Max 20/50)\n")
	if !si.Failed || si.Realloc != 12 || si.Pending != 3 || si.TempC != 36 {
		t.Errorf("smart sata: %+v", si)
	}
	g := parseLspciGPU("00:02.0 VGA compatible controller: Intel Corporation UHD Graphics\n\tSubsystem: x\n\tKernel driver in use: i915\n01:00.0 3D controller: NVIDIA Corp\n\tKernel modules: nouveau\n")
	if len(g) != 2 || g[0].Driver != "i915" || g[1].Driver != "" {
		t.Errorf("lspci: %+v", g)
	}
	all, dis, def := parseLpstat("printer HP is idle.  enabled since Mon\nprinter Brother disabled since Tue -\nsystem default destination: HP\n")
	if len(all) != 2 || len(dis) != 1 || dis[0] != "Brother" || def != "HP" {
		t.Errorf("lpstat: %v %v %q", all, dis, def)
	}
	rk := parseRfkill("0: phy0: Wireless LAN\n\tSoft blocked: yes\n\tHard blocked: no\n1: hci0: Bluetooth\n\tSoft blocked: no\n\tHard blocked: yes\n")
	if len(rk) != 2 || !rk[0].Soft || rk[0].Hard || rk[1].Soft || !rk[1].Hard {
		t.Errorf("rfkill: %+v", rk)
	}
	if ssid, sig, ok := parseNmcliWifi("no:Other:90\nyes:Home\\:5G:63\n"); !ok || ssid != "Home:5G" || sig != 63 {
		t.Errorf("nmcli: %q %d %v", ssid, sig, ok)
	}
	if _, q, ok := parseWirelessQuality("Inter-| sta-|   Quality\n face | tus | link level noise\n wlan0: 0000   58.  -52.  -256 0 0\n"); !ok || q != 58 {
		t.Errorf("wireless: %d %v", q, ok)
	}
	kbd, ptr, _ := parseInputDevices("N: Name=\"AT Translated Set 2 keyboard\"\nH: Handlers=sysrq kbd leds event3\n\nN: Name=\"SynPS/2 Touchpad\"\nH: Handlers=mouse0 event5\n")
	if kbd != 1 || ptr != 1 {
		t.Errorf("input: %d %d", kbd, ptr)
	}
	if tm, ok := parseBIOSDate("01/05/2017"); !ok || tm.Year() != 2017 {
		t.Errorf("bios date: %v", tm)
	}
}

func TestLinuxVerdicts(t *testing.T) {
	cases := []struct {
		path, name string
		dir        bool
		want       string
	}{
		{"/home/a/.cache/mozilla/x", "x", true, "SAFE"},
		{"/home/a/.local/share/Trash/files/x.bin", "x.bin", false, "SAFE"},
		{"/var/cache/apt/archives/foo.deb", "foo.deb", false, "SAFE"},
		{"/var/log/journal/abc/system.journal", "system.journal", false, "SAFE"},
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", "libc.so.6", false, "KEEP"},
		{"/boot/vmlinuz-6.8", "vmlinuz-6.8", false, "KEEP"},
		{"/etc/ssh", "ssh", true, "KEEP"},
		{"/swap.img", "swap.img", false, "KEEP"},
		{"/home/a/Downloads/ubuntu.iso", "ubuntu.iso", false, "CAUTION"},
		{"/home/a/project/tmp/x", "x", true, "UNSURE"}, // only the real /tmp is junk
		{"/home/a/project/node_modules", "node_modules", true, "SAFE"},
		{"/var/lib/docker/overlay2", "overlay2", true, "UNSURE"},
	}
	for _, c := range cases {
		if v, _ := verdictFor(&Node{Name: c.name, Path: c.path, IsDir: c.dir}); v != c.want {
			t.Errorf("%s: got %s want %s", c.path, v, c.want)
		}
	}
}

func TestLinuxFixesExist(t *testing.T) {
	seen := map[string]string{}
	for _, c := range linuxFixCats {
		for _, id := range c.IDs {
			if _, ok := linuxFixes[id]; !ok {
				t.Errorf("category %q references unknown fix %q", c.Name, id)
			}
			if prev, dup := seen[id]; dup {
				t.Errorf("fix %q is in both %q and %q", id, prev, c.Name)
			}
			seen[id] = c.Name
		}
	}
	if len(linuxFixCats) > 9 {
		t.Errorf("menus support the number keys 1-9 only (%d categories)", len(linuxFixCats))
	}
	for id, f := range linuxFixes {
		if seen[id] == "" {
			t.Errorf("fix %q is not in any category", id)
		}
		switch f.Risk {
		case "safe", "disruptive", "heavy":
		default:
			t.Errorf("fix %q has invalid risk %q", id, f.Risk)
		}
		if f.Desc == "" || f.Run == nil {
			t.Errorf("fix %q is incomplete", id)
		}
	}
}

// ---------- fake system ----------

type fakeSys struct {
	files map[string]string
	cmds  map[string]string
	have  map[string]bool
	env   map[string]string
	mu    sync.Mutex
	reads map[string]int
}

func (f *fakeSys) install(t *testing.T) {
	oRead, oGlob, oEnv, oHave, oCmd := readFile, globFiles, getenv, haveCmd, cmdOut
	t.Cleanup(func() { readFile, globFiles, getenv, haveCmd, cmdOut = oRead, oGlob, oEnv, oHave, oCmd })
	f.reads = map[string]int{}
	readFile = func(p string) ([]byte, error) {
		p = path.Clean(strings.ReplaceAll(p, `\`, "/"))
		v, ok := f.files[p]
		if !ok {
			return nil, errors.New("no such file")
		}
		if p == "/proc/stat" { // each read shows more elapsed CPU time
			f.mu.Lock()
			f.reads[p]++
			n := f.reads[p]
			f.mu.Unlock()
			return []byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0 0 0\n", 1000*n, 1000*n)), nil
		}
		return []byte(v), nil
	}
	globFiles = func(pattern string) ([]string, error) {
		pattern = strings.ReplaceAll(pattern, `\`, "/")
		cand := map[string]bool{}
		for p := range f.files {
			for q := p; q != "/" && q != "."; q = path.Dir(q) {
				cand[q] = true
			}
		}
		var out []string
		for c := range cand {
			if ok, _ := path.Match(pattern, c); ok {
				out = append(out, c)
			}
		}
		return out, nil
	}
	getenv = func(k string) string { return f.env[k] }
	haveCmd = func(n string) bool { return f.have[n] }
	cmdOut = func(_ time.Duration, name string, args ...string) (string, error) {
		out, ok := f.cmds[strings.TrimSpace(name+" "+strings.Join(args, " "))]
		if !ok {
			return "", errors.New("command not found or no such fake output")
		}
		return out, nil
	}
}

func journalLines(n int, prog, msg string) string {
	var l []string
	for i := 0; i < n; i++ {
		l = append(l, fmt.Sprintf("Nov 17 10:00:%02d host %s[1]: %s", i%60, prog, msg))
	}
	return strings.Join(l, "\n")
}

func laptop() *fakeSys {
	return &fakeSys{
		files: map[string]string{
			"/proc/meminfo":                                   "MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\nSwapTotal: 2000000 kB\nSwapFree: 1900000 kB\n",
			"/proc/stat":                                      "x",
			"/proc/loadavg":                                   "0.50 0.40 0.30 1/200 123",
			"/proc/uptime":                                    "86400.00 1000.00",
			"/proc/mounts":                                    "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n/dev/sdb1 /data ext4 ro 0 0\n",
			"/etc/os-release":                                 "PRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
			"/proc/sys/kernel/osrelease":                      "6.8.0-45-generic",
			"/proc/sys/kernel/randomize_va_space":             "0",
			"/proc/pressure/memory":                           "some avg10=15.00 avg60=1 avg300=0 total=1\n",
			"/proc/pressure/cpu":                              "some avg10=1.00 avg60=1 avg300=0 total=1\n",
			"/proc/pressure/io":                               "some avg10=1.00 avg60=1 avg300=0 total=1\n",
			"/proc/asound/cards":                              "--- no soundcards ---",
			"/proc/mdstat":                                    "md0 : active raid1 sda1[0] sdb1[1]\n      1000 blocks [2/1] [U_]\n",
			"/proc/bus/input/devices":                         "N: Name=\"AT keyboard\"\nH: Handlers=sysrq kbd leds event3\n",
			"/sys/class/power_supply/BAT0/type":               "Battery",
			"/sys/class/power_supply/BAT0/status":             "Discharging",
			"/sys/class/power_supply/BAT0/capacity":           "12",
			"/sys/class/power_supply/BAT0/energy_full":        "36000000",
			"/sys/class/power_supply/BAT0/energy_full_design": "50000000",
			"/sys/class/power_supply/BAT0/cycle_count":        "512",
			"/sys/class/power_supply/AC/type":                 "Mains",
			"/sys/class/power_supply/AC/online":               "0",
			"/sys/class/hwmon/hwmon1/name":                    "coretemp",
			"/sys/class/hwmon/hwmon1/temp1_input":             "92000",
			"/sys/class/hwmon/hwmon3/name":                    "nvme",
			"/sys/class/hwmon/hwmon3/temp1_input":             "41000",
			"/sys/class/dmi/id/bios_date":                     "01/05/2017",
			"/sys/class/dmi/id/product_name":                  "ThinkPad",
			"/sys/class/net/lo/operstate":                     "unknown",
			"/sys/class/net/wlan0/operstate":                  "up",
			"/sys/class/net/wlan0/wireless/link":              "1",
			"/etc/resolv.conf":                                "nameserver 127.0.0.53\n",
			"/etc/group":                                      "sudo:x:27:alice,bob\ndocker:x:998:alice\n",
			"/etc/ssh/sshd_config":                            "PermitRootLogin yes\nPasswordAuthentication yes\n",
			"/etc/hosts":                                      "127.0.0.1 localhost\n10.0.0.5 nas.lan\n",
			"/var/run/reboot-required":                        "*** System restart required ***",
			"/usr/lib/modules/6.8.0-50-generic/kernel":        "x",
		},
		cmds: map[string]string{
			"systemctl --failed --no-legend --plain":             "● foo.service loaded failed failed Foo\nbar.service loaded failed failed Bar",
			"systemctl is-active ssh":                            "active",
			"systemctl is-active cups":                           "inactive",
			"systemctl is-active bluetooth":                      "active",
			"id -nG":                                             "alice sudo adm",
			"journalctl -p 3 --since 24 hours ago --no-pager -q": journalLines(40, "kernel", "boom"),
			"journalctl -k --no-pager -q -b": "blk_update_request: I/O error, dev sda\nDirect firmware load for iwlwifi-9000.ucode failed with error -2\n" +
				"mce: [Hardware Error]: CPU 0",
			"journalctl -k --no-pager -q --since 7 days ago": "Out of memory: Killed process 99 (chrome)\nfirefox[5]: segfault at 0",
			"journalctl --disk-usage":                        "Archived and active journals take up 3.5G in the file system.",
			"ss -tulnH":                                      "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:3306 0.0.0.0:*\nudp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*",
			"lsblk -rno TYPE":                                "disk\npart\npart",
			"ip -4 route show default":                       "default via 192.168.1.1 dev wlan0 proto dhcp metric 600",
			"ip -4 -o addr show dev wlan0":                   "3: wlan0    inet 169.254.3.4/16 scope link",
			"lpstat -p -d":                                   "printer HP disabled since Tue -\nsystem default destination: HP",
			"lpstat -o":                                      "HP-1 alice 1024 Mon\nHP-2 alice 1024 Mon",
			"apt list --upgradable":                          "Listing...\nopenssl/noble-security 3.0.2 amd64 [upgradable from: 3.0.1]\nvim/noble 9.0 amd64 [upgradable from: 8.9]",
			"ps -eo comm=":                                   "systemd\nsshd\nZ",
			"ps -eo stat=":                                   "Ss\nZ\nR+",
			"ps -eo comm=,pcpu=,rss= --sort=-pcpu":           "chrome 40.0 900000\nfirefox 20.0 800000",
			"ps -eo comm=,pcpu=,rss= --sort=-rss":            "chrome 40.0 900000\nfirefox 20.0 800000",
			"timedatectl show -p NTPSynchronized --value":    "no",
			"rfkill list":                                    "0: phy0: Wireless LAN\n\tSoft blocked: yes\n\tHard blocked: no\n",
			"nmcli -t -f ACTIVE,SSID,SIGNAL dev wifi":        "yes:Home:25",
			"powerprofilesctl get":                           "power-saver",
			"systemd-analyze time":                           "Startup finished in 3s (firmware) + 2min 5.5s (userspace) = 2min 8.5s",
			"dpkg --audit":                                   "The following packages are only half configured",
			"bluetoothctl show":                              "Controller AA:BB\n\tPowered: no",
			"sh -c wpctl get-volume @DEFAULT_AUDIO_SINK@":    "Volume: 0.40 [MUTED]",
			"dpkg-query -W -f ${db:Status-Abbrev} ${Package}\\n linux-image-[0-9]*": "ii linux-image-1\nii linux-image-2\nii linux-image-3\nii linux-image-4",
		},
		have: map[string]bool{"journalctl": true, "systemctl": true, "ss": true, "lsblk": true, "apt-get": true, "lpstat": true, "ufw": true,
			"rfkill": true, "nmcli": true, "powerprofilesctl": true, "systemd-analyze": true, "wpctl": true, "bluetoothctl": true, "ping": false},
		env: map[string]string{},
	}
}

func runAll(t *testing.T, tl tool) map[string]Check {
	t.Helper()
	res := make([]Check, len(tl.Defs))
	var wg sync.WaitGroup
	for i, d := range tl.Defs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeSem <- struct{}{}
			defer func() { <-probeSem }()
			res[i] = d.Run()
		}()
	}
	wg.Wait()
	out := map[string]Check{}
	for _, c := range res {
		out[c.Name] = c
		switch c.Status {
		case "PASS", "WARN", "FAIL", "INFO":
		default:
			t.Errorf("%s: invalid status %q", c.Name, c.Status)
		}
		if c.Fix != "" {
			if _, ok := linuxFixes[c.Fix]; !ok {
				t.Errorf("%s references unknown fix %q", c.Name, c.Fix)
			}
		}
		if (c.Status == "WARN" || c.Status == "FAIL") && c.Hint == "" {
			t.Errorf("%s: %s without an explanation", c.Name, c.Status)
		}
		if c.Detail == "" {
			t.Errorf("%s: empty detail", c.Name)
		}
	}
	return out
}

func expect(t *testing.T, got map[string]Check, name, status string) {
	t.Helper()
	c, ok := got[name]
	if !ok {
		t.Errorf("no check named %q", name)
		return
	}
	if c.Status != status {
		t.Errorf("%s: got %s (%s), want %s", name, c.Status, c.Detail, status)
	}
}

func TestLinuxChecksOnFakeSystem(t *testing.T) {
	f := laptop()
	f.install(t)

	pc := runAll(t, pcToolLx())
	expect(t, pc, "Operating system", "INFO")
	expect(t, pc, "Memory use", "PASS")
	expect(t, pc, "Failed services", "WARN")
	expect(t, pc, "Errors in the last 24h", "WARN")
	expect(t, pc, "Crashes and out-of-memory kills (7d)", "WARN")
	expect(t, pc, "Read-only file systems", "WARN")
	expect(t, pc, "Uptime", "PASS")
	expect(t, pc, "Pending reboot", "WARN")
	expect(t, pc, "Processes", "PASS")
	if !strings.Contains(pc["Failed services"].Detail, "foo.service") {
		t.Errorf("failed units not listed: %q", pc["Failed services"].Detail)
	}
	if !strings.Contains(pc["Errors in the last 24h"].Detail, "40x kernel") {
		t.Errorf("journal sources: %q", pc["Errors in the last 24h"].Detail)
	}

	perf := runAll(t, perfToolLx())
	expect(t, perf, "Resource pressure (PSI)", "WARN")
	expect(t, perf, "Boot time", "WARN")
	expect(t, perf, "Power profile", "WARN")
	expect(t, perf, "System journal size", "WARN")

	upd := runAll(t, updateToolLx())
	expect(t, upd, "Package database consistency", "FAIL")
	expect(t, upd, "Pending updates", "WARN")
	expect(t, upd, "Old kernels installed", "WARN")
	if !strings.Contains(upd["Pending updates"].Detail, "1 security") {
		t.Errorf("security updates not counted: %q", upd["Pending updates"].Detail)
	}

	sec := runAll(t, securityToolLx())
	expect(t, sec, "Firewall", "WARN")
	expect(t, sec, "Network services exposed", "WARN")
	expect(t, sec, "SSH server", "FAIL")
	expect(t, sec, "Disk encryption", "WARN")
	expect(t, sec, "Kernel hardening", "WARN")

	hw := runAll(t, hardwareToolLx())
	expect(t, hw, "Battery", "WARN")
	expect(t, hw, "Battery wear", "WARN")
	expect(t, hw, "CPU temperature", "WARN")
	expect(t, hw, "Disk I/O errors (this boot)", "FAIL")
	expect(t, hw, "Missing device firmware", "WARN")
	expect(t, hw, "Memory errors", "FAIL")
	expect(t, hw, "BIOS / firmware age", "WARN")
	expect(t, hw, "Software RAID", "FAIL")

	per := runAll(t, peripheralsToolLx())
	expect(t, per, "Print service (CUPS)", "WARN")
	expect(t, per, "Printers", "WARN")
	expect(t, per, "Print queue", "INFO")
	expect(t, per, "Sound card", "WARN")
	expect(t, per, "Volume and mute", "WARN")
	expect(t, per, "Bluetooth", "WARN")
	expect(t, per, "Keyboard and mouse", "INFO")
}

// The network screen also talks to the real network (DNS, HTTPS), so only its offline logic is asserted.
func TestLinuxNetworkOnFakeSystem(t *testing.T) {
	if testing.Short() {
		t.Skip("uses the network")
	}
	f := laptop()
	f.install(t)
	n := runAll(t, netToolLx())
	expect(t, n, "Network adapter", "PASS")
	expect(t, n, "IP configuration", "FAIL") // 169.254.x.x self-assigned
	expect(t, n, "Radio kill switches", "WARN")
	expect(t, n, "Wi-Fi signal", "WARN")
	expect(t, n, "Hosts file overrides", "INFO")
}

// A bare system (no tools, no files) must degrade to INFO, never crash or invent verdicts.
func TestLinuxChecksOnEmptySystem(t *testing.T) {
	f := &fakeSys{files: map[string]string{}, cmds: map[string]string{}, have: map[string]bool{}, env: map[string]string{}}
	f.install(t)
	for _, mk := range []func() tool{pcToolLx, perfToolLx, updateToolLx, securityToolLx, hardwareToolLx, peripheralsToolLx} {
		tl := mk()
		got := runAll(t, tl)
		for name, c := range got {
			if c.Status == "FAIL" {
				t.Errorf("%s / %s: FAIL on an empty system: %s", tl.Title, name, c.Detail)
			}
		}
	}
}

// The Linux menus and fix screens must fit the smallest supported terminal, like the Windows ones.
func TestLinuxScreensFit(t *testing.T) {
	oMenu, oCats, oFixes := menuItems, fixCats, fixes
	t.Cleanup(func() { menuItems, fixCats, fixes = oMenu, oCats, oFixes })
	menuItems, fixCats, fixes = linuxMenuItems, linuxFixCats, linuxFixes

	a := newApp("/")
	for _, sz := range [][2]int{{60, 16}, {100, 30}} {
		a.w, a.h = sz[0], sz[1]
		a.sc = scMenu
		checkFits(t, "linux menu", a.View(), a.w, a.h)
		a.sc = scFixCats
		checkFits(t, "linux categories", a.View(), a.w, a.h)
	}
	if len(menuItems) > 9 {
		t.Errorf("menu has %d items, number keys cover 1-9", len(menuItems))
	}
	for _, c := range linuxFixCats {
		name := c.Name
		d := newDiag(func() tool { return fixesTool(name) })
		if len(d.t.Defs) != len(c.IDs) {
			t.Errorf("%s: %d defs for %d ids", name, len(d.t.Defs), len(c.IDs))
		}
		for i, def := range d.t.Defs {
			ck := def.Run()
			d.res[i] = &ck
		}
		d.w, d.h = 70, 18
		checkFits(t, "linux fixes "+name, d.View(), d.w, d.h)
	}
}

// Every shell script in the fix table must at least parse (sh -n). This catches quoting mistakes
// without executing anything.
func TestLinuxFixScriptsParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	oRun, oHave := runFn, haveCmd
	t.Cleanup(func() { runFn, haveCmd = oRun, oHave })
	var current string
	var scripts []string
	runFn = func(_ time.Duration, name string, args ...string) (string, error) {
		if name != "sh" || len(args) != 2 || args[0] != "-c" {
			t.Errorf("%s: unexpected command %s %v", current, name, args)
			return "", nil
		}
		scripts = append(scripts, current+"\x00"+args[1])
		return "", nil
	}
	for _, pm := range []string{"apt-get", "dnf", "pacman", "zypper", "apk"} {
		haveCmd = func(n string) bool { return n == pm }
		for id, f := range linuxFixes {
			current = id + " (" + pm + ")"
			_, _ = f.Run() // pm-less fixes are re-run per package manager; that is harmless
		}
	}
	if len(scripts) < len(linuxFixes) {
		t.Errorf("only %d scripts captured for %d fixes", len(scripts), len(linuxFixes))
	}
	for _, s := range scripts {
		name, script, _ := strings.Cut(s, "\x00")
		out, err := exec.Command(sh, "-n", "-c", script).CombinedOutput()
		if err != nil {
			t.Errorf("%s: shell syntax error: %v\n%s\n%s", name, err, out, script)
		}
	}
}
