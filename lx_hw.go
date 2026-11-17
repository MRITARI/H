package main

// Linux: hardware & battery, printing & peripherals (no build tag, see lx.go).

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- battery ----------

type battery struct {
	Name, Status      string
	Percent           int
	Full, Design      int64 // same unit (µWh or µAh), only the ratio matters
	Cycles            int
	HasWear, HasCycle bool
}

func readBattery(dir string) (battery, bool) {
	if t := readStr(dir + "/type"); t != "" && t != "Battery" {
		return battery{}, false
	}
	b := battery{Name: filepath.Base(dir), Status: readStr(dir + "/status"), Percent: atoi(readStr(dir + "/capacity"))}
	full, design := readStr(dir+"/energy_full"), readStr(dir+"/energy_full_design")
	if full == "" || design == "" {
		full, design = readStr(dir+"/charge_full"), readStr(dir+"/charge_full_design")
	}
	f, _ := strconv.ParseInt(full, 10, 64)
	d, _ := strconv.ParseInt(design, 10, 64)
	if f > 0 && d > 0 {
		b.Full, b.Design, b.HasWear = f, d, true
	}
	if c := readStr(dir + "/cycle_count"); c != "" {
		b.Cycles, b.HasCycle = atoi(c), true
	}
	return b, true
}

func batteries() (out []battery) {
	dirs, _ := globFiles("/sys/class/power_supply/BAT*")
	for _, d := range dirs {
		if b, ok := readBattery(d); ok {
			out = append(out, b)
		}
	}
	return
}

func (b battery) wearPct() int {
	if !b.HasWear {
		return 0
	}
	w := 100 - int(100*b.Full/b.Design)
	return max(0, w)
}

func onAC() (bool, bool) {
	dirs, _ := globFiles("/sys/class/power_supply/*")
	for _, d := range dirs {
		if readStr(d+"/type") == "Mains" {
			return readStr(d+"/online") == "1", true
		}
	}
	return false, false
}

// ---------- SMART ----------

type smartInfo struct {
	Passed, Failed   bool
	TempC, PctUsed   int // -1 when unknown
	Realloc, Pending int
	Model            string
}

var (
	reTempAttr = regexp.MustCompile(`(?m)^\s*19[04]\s+\S+\s+.*?(\d+)(?:\s*\(.*\))?\s*$`)
	reNvmeTemp = regexp.MustCompile(`(?m)^Temperature:\s+(\d+)`)
	reNvmeUsed = regexp.MustCompile(`(?m)^Percentage Used:\s+(\d+)%`)
	reRealloc  = regexp.MustCompile(`(?m)^\s*5\s+Reallocated_Sector_Ct\s+.*?(\d+)\s*$`)
	rePending  = regexp.MustCompile(`(?m)^\s*197\s+Current_Pending_Sector\s+.*?(\d+)\s*$`)
	reModel    = regexp.MustCompile(`(?m)^(?:Device Model|Model Number|Model Family):\s+(.+)$`)
)

// parseSmart reads "smartctl -H -A -i" output.
func parseSmart(s string) smartInfo {
	si := smartInfo{TempC: -1, PctUsed: -1}
	switch {
	case strings.Contains(s, "FAILED") && strings.Contains(s, "overall-health"):
		si.Failed = true
	case strings.Contains(s, "PASSED"), strings.Contains(s, "SMART Health Status: OK"):
		si.Passed = true
	}
	if m := reNvmeTemp.FindStringSubmatch(s); m != nil {
		si.TempC = atoi(m[1])
	} else if m := reTempAttr.FindStringSubmatch(s); m != nil {
		si.TempC = atoi(m[1])
	}
	if m := reNvmeUsed.FindStringSubmatch(s); m != nil {
		si.PctUsed = atoi(m[1])
	}
	if m := reRealloc.FindStringSubmatch(s); m != nil {
		si.Realloc = atoi(m[1])
	}
	if m := rePending.FindStringSubmatch(s); m != nil {
		si.Pending = atoi(m[1])
	}
	if m := reModel.FindStringSubmatch(s); m != nil {
		si.Model = strings.TrimSpace(m[1])
	}
	return si
}

// smartReports runs smartctl once per physical disk and shares the result between checks.
type smartReports struct {
	once sync.Once
	m    map[string]smartInfo
	err  string
}

func (r *smartReports) get() (map[string]smartInfo, string) {
	r.once.Do(func() {
		r.m = map[string]smartInfo{}
		switch {
		case !isAdmin():
			r.err = "needs root to read SMART data (press a on the main menu)"
			return
		case !haveCmd("smartctl"):
			r.err = "install smartmontools to read drive health"
			return
		}
		out, _ := cmd("lsblk", "-dno", "NAME,TYPE")
		for _, l := range lines(out) {
			f := strings.Fields(l)
			if len(f) < 2 || f[1] != "disk" || hasAnyPrefix(f[0], "zram", "loop", "ram", "sr", "fd") {
				continue
			}
			rep, _ := cmdOut(30*time.Second, "smartctl", "-H", "-A", "-i", "/dev/"+f[0])
			r.m[f[0]] = parseSmart(rep)
		}
		if len(r.m) == 0 {
			r.err = "no physical disks found"
		}
	})
	return r.m, r.err
}

func (r *smartReports) names() []string {
	m, _ := r.get()
	var n []string
	for k := range m {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// ---------- temperatures ----------

type sensor struct {
	Chip, Label string
	C           float64
}

func readSensors() (out []sensor) {
	hw, _ := globFiles("/sys/class/hwmon/hwmon*")
	for _, h := range hw {
		chip := readStr(h + "/name")
		files, _ := globFiles(h + "/temp*_input")
		for _, f := range files {
			v := atoi(readStr(f))
			if v <= 0 || v > 200000 {
				continue
			}
			label := readStr(strings.TrimSuffix(f, "_input") + "_label")
			out = append(out, sensor{Chip: chip, Label: label, C: float64(v) / 1000})
		}
	}
	if len(out) == 0 {
		zones, _ := globFiles("/sys/class/thermal/thermal_zone*")
		for _, z := range zones {
			if v := atoi(readStr(z + "/temp")); v > 0 && v < 200000 {
				out = append(out, sensor{Chip: readStr(z + "/type"), C: float64(v) / 1000})
			}
		}
	}
	return
}

var cpuChips = map[string]bool{"coretemp": true, "k10temp": true, "zenpower": true, "cpu_thermal": true, "x86_pkg_temp": true, "cpu-thermal": true}

// ---------- kernel-log patterns ----------

var (
	reIOErr    = regexp.MustCompile(`I/O error|blk_update_request|EXT4-fs error|XFS \(.*\): (?:Metadata|Corruption)|BTRFS (?:error|critical)|nvme\d+:.*(?:timeout|reset|I/O Cq)|ata\d+(?:\.\d+)?: (?:failed|exception|hard resetting)`)
	reFirmware = regexp.MustCompile(`firmware: failed to load (\S+)|Direct firmware load for (\S+) failed`)
	reUSBErr   = regexp.MustCompile(`usb \S+: (?:device descriptor read/\w+, error|device not accepting address|unable to enumerate|Cannot enable|disabled by hub|over-current)`)
	reMCE      = regexp.MustCompile(`Hardware Error|mce: \[Hardware Error\]|EDAC .*(?:UE|CE) `)
)

func hardwareToolLx() tool {
	smart := &smartReports{}
	defs := []checkDef{
		{"Battery", func() Check {
			bs := batteries()
			if len(bs) == 0 {
				return info("Battery", "no battery (desktop or virtual machine)")
			}
			b := bs[0]
			txt := fmt.Sprintf("%d%% (%s)", b.Percent, strings.ToLower(b.Status))
			if ac, ok := onAC(); ok {
				if ac {
					txt += ", on AC power"
				} else {
					txt += ", on battery"
				}
			}
			if b.HasCycle && b.Cycles > 0 {
				txt += fmt.Sprintf(", %d charge cycles", b.Cycles)
			}
			if b.Percent <= 15 && strings.EqualFold(b.Status, "Discharging") {
				return warn("Battery", txt, "The battery is nearly empty. Plug in the charger.", "")
			}
			return pass("Battery", txt)
		}},
		{"Battery wear", func() Check {
			bs := batteries()
			if len(bs) == 0 || !bs[0].HasWear {
				return info("Battery wear", "not available")
			}
			w := bs[0].wearPct()
			txt := fmt.Sprintf("holds %d%% of its original capacity (%d%% worn)", 100-w, w)
			switch {
			case w >= 40:
				return fail("Battery wear", txt, "The battery is badly worn and lasts much shorter than new. Consider replacing it.", "battery-report")
			case w >= 25:
				return warn("Battery wear", txt, "Noticeable wear: runtime is reduced. Avoid heat and keeping it at 100% on the charger; limit charge to 80% if your laptop supports it.", "battery-report")
			}
			return pass("Battery wear", txt)
		}},
		{"Drive health (SMART)", func() Check {
			m, why := smart.get()
			if why != "" {
				return info("Drive health (SMART)", why)
			}
			var bad, ok []string
			for _, n := range smart.names() {
				s := m[n]
				switch {
				case s.Failed:
					bad = append(bad, n+" FAILING")
				case s.Passed:
					ok = append(ok, n)
				}
			}
			if len(bad) > 0 {
				return fail("Drive health (SMART)", strings.Join(bad, ", "), "The drive predicts its own failure. Back up your data now and replace the drive.", "smart-report")
			}
			if len(ok) == 0 {
				return info("Drive health (SMART)", "the drives did not report a verdict (virtual disks do not support SMART)")
			}
			return pass("Drive health (SMART)", strings.Join(ok, ", ")+" report healthy")
		}},
		{"Drive wear and errors", func() Check {
			m, why := smart.get()
			if why != "" {
				return info("Drive wear and errors", why)
			}
			var bad, det []string
			for _, n := range smart.names() {
				s := m[n]
				if s.PctUsed >= 0 {
					det = append(det, fmt.Sprintf("%s %d%% worn", n, s.PctUsed))
					if s.PctUsed >= 80 {
						bad = append(bad, fmt.Sprintf("%s has used %d%% of its write endurance", n, s.PctUsed))
					}
				}
				if s.Realloc > 0 || s.Pending > 0 {
					bad = append(bad, fmt.Sprintf("%s has %d reallocated and %d pending bad sectors", n, s.Realloc, s.Pending))
				}
				if s.TempC >= 60 {
					bad = append(bad, fmt.Sprintf("%s runs at %d°C", n, s.TempC))
				}
			}
			if len(bad) > 0 {
				return warn("Drive wear and errors", strings.Join(bad, "; "), "Bad sectors mean the surface is failing; wear near 100% means a flash drive is at the end of its life; heat shortens drive life. Back up important data.", "smart-report")
			}
			if len(det) == 0 {
				return pass("Drive wear and errors", "no bad sectors reported")
			}
			return pass("Drive wear and errors", strings.Join(det, ", "))
		}},
		{"Disk I/O errors (this boot)", func() Check {
			out, ok := kernelLog("")
			if !ok {
				return info("Disk I/O errors (this boot)", "kernel log not readable (needs the systemd-journal group or root)")
			}
			n := 0
			for _, l := range lines(out) {
				if reIOErr.MatchString(l) {
					n++
				}
			}
			if n > 0 {
				return fail("Disk I/O errors (this boot)", plural(n, "disk error message", "disk error messages"),
					"The kernel could not read or write a disk. That is a failing drive, a bad cable or a corrupted file system. Back up now and run a SMART check.", "smart-report")
			}
			return pass("Disk I/O errors (this boot)", "none")
		}},
		{"CPU temperature", func() Check {
			var top float64
			var chip string
			for _, s := range readSensors() {
				if cpuChips[s.Chip] && s.C > top {
					top, chip = s.C, s.Chip
				}
			}
			if chip == "" {
				return info("CPU temperature", "no CPU sensor exposed (virtual machine or no driver loaded)")
			}
			txt := fmt.Sprintf("%.0f°C (%s)", top, chip)
			switch {
			case top >= 95:
				return fail("CPU temperature", txt, "Dangerously hot: the CPU will throttle or shut down. Clean fans and vents and check the cooler is seated.", "show-sensors")
			case top >= 85:
				return warn("CPU temperature", txt, "Running hot. Clean dust from vents and fans, improve airflow, check the power profile.", "show-sensors")
			}
			return pass("CPU temperature", txt)
		}},
		{"Other temperatures", func() Check {
			var hot, all []string
			for _, s := range readSensors() {
				if cpuChips[s.Chip] || s.Chip == "" {
					continue
				}
				all = append(all, fmt.Sprintf("%s %.0f°C", s.Chip, s.C))
				limit := 90.0
				if s.Chip == "nvme" {
					limit = 70
				}
				if s.C >= limit {
					hot = append(hot, fmt.Sprintf("%s %.0f°C", s.Chip, s.C))
				}
			}
			switch {
			case len(hot) > 0:
				return warn("Other temperatures", strings.Join(hot, ", "), "A drive or graphics chip is hot. Check airflow and heatsinks.", "show-sensors")
			case len(all) == 0:
				return info("Other temperatures", "no other sensors exposed")
			}
			return pass("Other temperatures", trimList(all, 5))
		}},
		{"Memory errors", func() Check {
			ce, ue := 0, 0
			for _, f := range func() []string { g, _ := globFiles("/sys/devices/system/edac/mc/mc*/ce_count"); return g }() {
				ce += atoi(readStr(f))
			}
			for _, f := range func() []string { g, _ := globFiles("/sys/devices/system/edac/mc/mc*/ue_count"); return g }() {
				ue += atoi(readStr(f))
			}
			mce := 0
			if out, ok := kernelLog(""); ok {
				for _, l := range lines(out) {
					if reMCE.MatchString(l) {
						mce++
					}
				}
			}
			switch {
			case ue > 0 || mce > 0:
				return fail("Memory errors", fmt.Sprintf("%d uncorrectable and %d hardware-error log entries", ue, mce),
					"The hardware reported memory or CPU errors. Test the RAM (memtest86+ from the boot menu) and reseat or replace the failing module.", "show-kernel-errors")
			case ce > 0:
				return warn("Memory errors", fmt.Sprintf("%d corrected ECC errors", ce), "ECC RAM is silently correcting errors. A growing count means a module is going bad.", "show-kernel-errors")
			}
			return pass("Memory errors", "none reported")
		}},
		{"Graphics driver", func() Check {
			if !haveCmd("lspci") {
				return info("Graphics driver", "lspci is not installed")
			}
			out, _ := cmd("lspci", "-k")
			gpus := parseLspciGPU(out)
			if len(gpus) == 0 {
				return info("Graphics driver", "no graphics adapter found")
			}
			var d []string
			for _, g := range gpus {
				if g.Driver == "" {
					return warn("Graphics driver", g.Name+": no kernel driver loaded",
						"The graphics card has no driver, so the desktop is software-rendered and slow. Install the vendor driver (nvidia, mesa, amdgpu).", "")
				}
				d = append(d, g.Name+" ("+g.Driver+")")
			}
			return pass("Graphics driver", strings.Join(d, "; "))
		}},
		{"BIOS / firmware age", func() Check {
			product := readStr("/sys/class/dmi/id/product_name")
			if p := strings.ToLower(product); strings.Contains(p, "virtual") || strings.Contains(p, "kvm") || strings.Contains(p, "vmware") || strings.Contains(p, "qemu") {
				return info("BIOS / firmware age", "virtual machine ("+product+")")
			}
			t, ok := parseBIOSDate(readStr("/sys/class/dmi/id/bios_date"))
			if !ok {
				return info("BIOS / firmware age", "not available")
			}
			years := int(time.Since(t).Hours() / 24 / 365)
			txt := fmt.Sprintf("%s %s from %s (%d years old)", readStr("/sys/class/dmi/id/bios_vendor"), readStr("/sys/class/dmi/id/bios_version"), t.Format("2006-01-02"), years)
			if years >= 5 {
				return warn("BIOS / firmware age", txt, "Old firmware misses stability, battery and security fixes. fwupd can offer updates for many laptops.", "fwupd-check")
			}
			return pass("BIOS / firmware age", txt)
		}},
		{"Missing device firmware", func() Check {
			out, ok := kernelLog("")
			if !ok {
				return info("Missing device firmware", "kernel log not readable")
			}
			seen := map[string]bool{}
			var files []string
			for _, l := range lines(out) {
				if m := reFirmware.FindStringSubmatch(l); m != nil {
					f := m[1] + m[2]
					if !seen[f] {
						seen[f] = true
						files = append(files, f)
					}
				}
			}
			if len(files) > 0 {
				return warn("Missing device firmware", plural(len(files), "firmware file is", "firmware files are")+" missing: "+trimList(files, 4),
					"A device (Wi-Fi, GPU, sound or Bluetooth chip) cannot work fully without its firmware. Install linux-firmware (or sof-firmware / your vendor's package).", "")
			}
			return pass("Missing device firmware", "none")
		}},
		{"USB problems (this boot)", func() Check {
			out, ok := kernelLog("")
			if !ok {
				return info("USB problems (this boot)", "kernel log not readable")
			}
			n := 0
			for _, l := range lines(out) {
				if reUSBErr.MatchString(l) {
					n++
				}
			}
			if n > 5 {
				return warn("USB problems (this boot)", plural(n, "USB error message", "USB error messages"),
					"A USB device or port keeps failing to enumerate: bad cable, hub or port, or too little power. Try another cable or port.", "show-kernel-errors")
			}
			return pass("USB problems (this boot)", plural(n, "message", "messages"))
		}},
		{"Software RAID", func() Check {
			md := readStr("/proc/mdstat")
			if !strings.Contains(md, "md") {
				return info("Software RAID", "no md arrays")
			}
			if regexp.MustCompile(`\[[U_]*_[U_]*\]`).MatchString(md) {
				return fail("Software RAID", "an array is degraded", "A RAID member has failed. Replace it and re-add it (mdadm) before a second failure loses data.", "")
			}
			return pass("Software RAID", "all arrays healthy")
		}},
	}
	return tool{Title: "Hardware & battery", Blurb: "battery wear, drive health, temperatures, firmware", Defs: defs}
}

type gpuInfo struct{ Name, Driver string }

// parseLspciGPU reads "lspci -k" and returns display adapters with their kernel driver.
func parseLspciGPU(s string) []gpuInfo {
	var out []gpuInfo
	in := false
	for _, l := range strings.Split(s, "\n") {
		if l != "" && l[0] != ' ' && l[0] != '\t' {
			in = strings.Contains(l, "VGA compatible controller") || strings.Contains(l, "3D controller") || strings.Contains(l, "Display controller")
			if in {
				_, name, _ := strings.Cut(l, ": ")
				out = append(out, gpuInfo{Name: name})
			}
			continue
		}
		if in && len(out) > 0 {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Kernel driver in use:"); ok {
				out[len(out)-1].Driver = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// ---------- printing & peripherals ----------

// parseLpstat reads "lpstat -p -d": all printers, the disabled ones and the default.
func parseLpstat(s string) (all, disabled []string, def string) {
	for _, l := range lines(s) {
		switch {
		case strings.HasPrefix(l, "printer "):
			f := strings.Fields(l)
			if len(f) >= 2 {
				all = append(all, f[1])
				if strings.Contains(l, " disabled") {
					disabled = append(disabled, f[1])
				}
			}
		case strings.HasPrefix(l, "system default destination:"):
			def = strings.TrimSpace(strings.TrimPrefix(l, "system default destination:"))
		}
	}
	return
}

// parseInputDevices reads /proc/bus/input/devices and counts keyboards and pointing devices.
func parseInputDevices(s string) (kbd, ptr int, names []string) {
	var name string
	for _, l := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(l, "N: Name="):
			name = strings.Trim(strings.TrimPrefix(l, "N: Name="), `"`)
		case strings.HasPrefix(l, "H: Handlers="):
			isKbd := strings.Contains(l, "kbd") && strings.Contains(l, "leds")
			isPtr := strings.Contains(l, "mouse")
			if isKbd {
				kbd++
				names = append(names, name)
			} else if isPtr && !strings.Contains(strings.ToLower(name), "power") {
				ptr++
				names = append(names, name)
			}
		}
	}
	return
}

func desktopSession() bool {
	return getenv("DISPLAY") != "" || getenv("WAYLAND_DISPLAY") != "" || getenv("SUDO_USER") != "" && exists("/run/user/*/bus") || getenv("XDG_SESSION_TYPE") == "wayland" || getenv("XDG_SESSION_TYPE") == "x11"
}

func peripheralsToolLx() tool {
	defs := []checkDef{
		{"Print service (CUPS)", func() Check {
			if !haveCmd("lpstat") {
				return info("Print service (CUPS)", "CUPS is not installed")
			}
			if out, _ := cmd("systemctl", "is-active", "cups"); out != "active" {
				return warn("Print service (CUPS)", "the cups service is "+firstNonEmpty(out, "not running"),
					"Printing needs the CUPS service. Restart it.", "restart-cups")
			}
			return pass("Print service (CUPS)", "running")
		}},
		{"Printers", func() Check {
			if !haveCmd("lpstat") {
				return info("Printers", "CUPS is not installed")
			}
			out, _ := cmd("lpstat", "-p", "-d")
			all, dis, def := parseLpstat(out)
			switch {
			case len(all) == 0:
				return info("Printers", "no printers configured")
			case len(dis) > 0:
				return warn("Printers", "disabled: "+strings.Join(dis, ", "),
					"CUPS disables a printer after errors (paper jam, offline, USB hiccup) and then silently holds every job. Re-enabling it releases the queue.", "enable-printers")
			case def == "":
				return info("Printers", plural(len(all), "printer", "printers")+", no default set")
			}
			return pass("Printers", fmt.Sprintf("%s; default %s", plural(len(all), "printer ready", "printers ready"), def))
		}},
		{"Print queue", func() Check {
			if !haveCmd("lpstat") {
				return info("Print queue", "CUPS is not installed")
			}
			out, _ := cmd("lpstat", "-o")
			n := len(lines(out))
			switch {
			case n > 10:
				return warn("Print queue", plural(n, "job waiting", "jobs waiting"), "A big backlog usually means one job is stuck. Clearing the queue cancels everything pending.", "clear-print-queue")
			case n > 0:
				return info("Print queue", plural(n, "job waiting", "jobs waiting"))
			}
			return pass("Print queue", "empty")
		}},
		{"Audio server", func() Check {
			out, _ := cmd("ps", "-eo", "comm=")
			var run []string
			for _, p := range lines(out) {
				switch p {
				case "pipewire", "pipewire-pulse", "wireplumber", "pulseaudio":
					run = append(run, p)
				}
			}
			if len(run) > 0 {
				return pass("Audio server", strings.Join(run, ", ")+" running")
			}
			if desktopSession() {
				return warn("Audio server", "neither PipeWire nor PulseAudio is running", "Without a sound server there is no audio in desktop apps. Restart it.", "restart-audio")
			}
			return info("Audio server", "not running (no desktop session)")
		}},
		{"Sound card", func() Check {
			cards := readStr("/proc/asound/cards")
			if cards == "" || strings.Contains(cards, "no soundcards") {
				return warn("Sound card", "no sound hardware detected",
					"The kernel sees no audio device. On new laptops install sof-firmware (or alsa-firmware); otherwise check the BIOS and whether the codec is supported.", "")
			}
			n := 0
			for _, l := range lines(cards) {
				if len(l) > 0 && l[0] >= '0' && l[0] <= '9' {
					n++
				}
			}
			return pass("Sound card", plural(n, "sound card", "sound cards"))
		}},
		{"Volume and mute", func() Check {
			var out string
			switch {
			case haveCmd("wpctl"):
				out, _ = cmd("sh", "-c", asUser("wpctl get-volume @DEFAULT_AUDIO_SINK@"))
			case haveCmd("pactl"):
				m, _ := cmd("sh", "-c", asUser("pactl get-sink-mute @DEFAULT_SINK@"))
				if strings.Contains(m, "yes") {
					out = "Volume: [MUTED]"
				} else {
					out = "Volume: 1.00"
				}
			default:
				return info("Volume and mute", "wpctl/pactl not installed")
			}
			if out == "" {
				return info("Volume and mute", "the audio server could not be queried")
			}
			switch {
			case strings.Contains(out, "MUTED"):
				return warn("Volume and mute", "the default output is muted", "No sound because the output is muted. Unmuting restores it.", "unmute-audio")
			case strings.Contains(out, "Volume: 0.00"):
				return warn("Volume and mute", "the default output volume is 0%", "No sound because the volume is zero. Raise it.", "unmute-audio")
			}
			return pass("Volume and mute", strings.TrimPrefix(out, "Volume: "))
		}},
		{"Bluetooth", func() Check {
			if !haveCmd("bluetoothctl") {
				return info("Bluetooth", "not installed (no Bluetooth stack)")
			}
			if out, _ := cmd("systemctl", "is-active", "bluetooth"); out != "active" {
				return warn("Bluetooth", "the bluetooth service is "+firstNonEmpty(out, "not running"), "Bluetooth devices cannot connect without the service. Restart it.", "restart-bluetooth")
			}
			out, _ := cmd("bluetoothctl", "show")
			switch {
			case strings.Contains(out, "No default controller"):
				return info("Bluetooth", "no Bluetooth adapter found")
			case strings.Contains(out, "Powered: no"):
				return warn("Bluetooth", "the adapter is powered off", "Turn it on in the desktop settings or with 'bluetoothctl power on'. A blocked radio is fixed by unblocking it.", "rfkill-unblock")
			}
			return pass("Bluetooth", "service running, adapter on")
		}},
		{"Camera", func() Check {
			devs, _ := globFiles("/dev/video*")
			if len(devs) == 0 {
				return info("Camera", "no camera found")
			}
			if f, err := os.Open(devs[0]); err != nil && os.IsPermission(err) {
				return warn("Camera", devs[0]+": permission denied", "Your user may not use the camera. Add yourself to the video group (sudo usermod -aG video $USER) and log in again.", "")
			} else if f != nil {
				f.Close()
			}
			return pass("Camera", plural(len(devs), "video device", "video devices")+" present")
		}},
		{"Keyboard and mouse", func() Check {
			kbd, ptr, names := parseInputDevices(readStr("/proc/bus/input/devices"))
			if kbd+ptr == 0 {
				return info("Keyboard and mouse", "no input devices listed")
			}
			return info("Keyboard and mouse", fmt.Sprintf("%d keyboard(s), %d pointing device(s): %s", kbd, ptr, trimList(names, 4)))
		}},
	}
	return tool{Title: "Printing & peripherals", Blurb: "CUPS printers, audio, Bluetooth, camera, input", Defs: defs}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
