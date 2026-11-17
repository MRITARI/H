package main

// Linux helpers. This file has no build tag on purpose: it only uses portable
// APIs (everything OS specific is in *_linux.go), so the parsers and the
// check logic can be unit tested on any machine with fake /proc, /sys and
// command output (see lx_test.go).

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// System access goes through these variables so tests can replace it.
var (
	readFile  = os.ReadFile
	globFiles = filepath.Glob
	getenv    = os.Getenv
	haveCmd   = func(name string) bool { _, err := exec.LookPath(name); return err == nil }
	cmdOut    = func(timeout time.Duration, name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		return strings.TrimSpace(out.String()), err
	}
)

// readStr returns a trimmed file, or "" when it cannot be read.
func readStr(path string) string {
	b, err := readFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// cmd runs a read-only probe command (stdout only, 15 s limit).
func cmd(name string, args ...string) (string, error) { return cmdOut(15*time.Second, name, args...) }

// ---------- the person behind sudo ----------

// realUser is the desktop user: the sudo caller when running elevated, else the current user.
func realUser() (name, uid, home string) {
	if su := getenv("SUDO_USER"); su != "" && su != "root" {
		if u, err := user.Lookup(su); err == nil {
			return u.Username, u.Uid, u.HomeDir
		}
	}
	if u, err := user.Current(); err == nil {
		return u.Username, u.Uid, u.HomeDir
	}
	return "", "", getenv("HOME")
}

func realHome() string { _, _, h := realUser(); return h }

// asUser wraps a shell snippet so it runs as the desktop user even from a sudo session
// (needed for per-user things: audio, GNOME settings, caches in the home folder).
func asUser(script string) string {
	name, uid, _ := realUser()
	if getenv("SUDO_USER") != "" && name != "" && name != "root" {
		return "runuser -u " + name + " -- env XDG_RUNTIME_DIR=/run/user/" + uid +
			" DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + uid + "/bus sh -c " + shQuote(script)
	}
	return script
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ---------- parsers ----------

// parseMeminfo returns the /proc/meminfo values in kB.
func parseMeminfo(s string) map[string]int64 {
	m := map[string]int64{}
	for _, l := range lines(s) {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) > 0 {
			n, _ := strconv.ParseInt(f[0], 10, 64)
			m[strings.TrimSpace(k)] = n
		}
	}
	return m
}

func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	for _, l := range lines(s) {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

var reRoute = regexp.MustCompile(`^default via (\S+) dev (\S+)`)

// parseDefaultRoute reads "ip -4 route show default" and returns gateway and interface of the first route.
func parseDefaultRoute(s string) (gw, dev string) {
	for _, l := range lines(s) {
		if m := reRoute.FindStringSubmatch(l); m != nil {
			return m[1], m[2]
		}
		// "default dev wg0 scope link" (no gateway)
		if f := strings.Fields(l); len(f) >= 3 && f[0] == "default" && f[1] == "dev" {
			return "", f[2]
		}
	}
	return "", ""
}

var reInet = regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)/`)

// parseIPv4 returns the first IPv4 address in "ip -4 -o addr show" output.
func parseIPv4(s string) string {
	if m := reInet.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

var rePingAvg = regexp.MustCompile(`= [\d.]+/([\d.]+)/`)

// parsePingAvg reads iputils/busybox ping summaries; ok is false when nothing answered.
func parsePingAvg(out string) (ok bool, avgMs int) {
	if m := rePingAvg.FindStringSubmatch(out); m != nil {
		f, _ := strconv.ParseFloat(m[1], 64)
		return true, int(f + 0.5)
	}
	if strings.Contains(out, "bytes from") {
		return true, 0
	}
	return false, 0
}

func parseResolvConf(s string) []string {
	var out []string
	for _, l := range lines(s) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

func parseLoadavg(s string) (l1, l5, l15 float64) {
	f := strings.Fields(s)
	if len(f) >= 3 {
		l1, _ = strconv.ParseFloat(f[0], 64)
		l5, _ = strconv.ParseFloat(f[1], 64)
		l15, _ = strconv.ParseFloat(f[2], 64)
	}
	return
}

// parseCPUStat returns idle(+iowait) and total jiffies from the first line of /proc/stat.
func parseCPUStat(s string) (idle, total uint64) {
	for _, l := range lines(s) {
		f := strings.Fields(l)
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		for i, v := range f[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			if i >= 8 { // guest times are already inside user/nice
				break
			}
			total += n
			if i == 3 || i == 4 {
				idle += n
			}
		}
		return
	}
	return
}

// parsePSI returns avg10 of the "some" line of /proc/pressure/*.
func parsePSI(s string) float64 {
	for _, l := range lines(s) {
		if strings.HasPrefix(l, "some") {
			for _, f := range strings.Fields(l) {
				if v, ok := strings.CutPrefix(f, "avg10="); ok {
					n, _ := strconv.ParseFloat(v, 64)
					return n
				}
			}
		}
	}
	return 0
}

type mountEnt struct{ Dev, Dir, FS, Opts string }

func parseMounts(s string) []mountEnt {
	var out []mountEnt
	for _, l := range lines(s) {
		f := strings.Fields(l)
		if len(f) >= 4 {
			out = append(out, mountEnt{f[0], unescapeMount(f[1]), f[2], f[3]})
		}
	}
	return out
}

func unescapeMount(s string) string { return strings.ReplaceAll(s, `\040`, " ") }

// realFS lists file systems that hold user data (skips tmpfs, proc, squashfs ...).
var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "f2fs": true,
	"vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "zfs": true, "jfs": true, "reiserfs": true}

func hasOpt(opts, o string) bool {
	for _, x := range strings.Split(opts, ",") {
		if x == o {
			return true
		}
	}
	return false
}

// parseFailedUnits reads "systemctl --failed --no-legend --plain".
func parseFailedUnits(s string) []string {
	var out []string
	for _, l := range lines(s) {
		f := strings.Fields(strings.TrimLeft(l, "●* "))
		if len(f) > 0 && strings.Contains(f[0], ".") {
			out = append(out, f[0])
		}
	}
	return out
}

var reLogProg = regexp.MustCompile(`^\S+\s+\d+\s+[\d:]+\s+\S+\s+([^\s:\[]+)`)

// topSources counts the program names in short-format journal lines and returns "Nx name" for the top n.
func topSources(ls []string, n int) []string {
	counts := map[string]int{}
	for _, l := range ls {
		if m := reLogProg.FindStringSubmatch(l); m != nil {
			counts[m[1]]++
		}
	}
	type kv struct {
		k string
		v int
	}
	var all []kv
	for k, v := range counts {
		all = append(all, kv{k, v})
	}
	for i := 0; i < len(all); i++ { // tiny selection sort; n is small
		for j := i + 1; j < len(all); j++ {
			if all[j].v > all[i].v || (all[j].v == all[i].v && all[j].k < all[i].k) {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	var out []string
	for i := 0; i < len(all) && i < n; i++ {
		out = append(out, strconv.Itoa(all[i].v)+"x "+all[i].k)
	}
	return out
}

var reSize = regexp.MustCompile(`([\d.]+)\s*([KMGT])`)

// parseSizeHuman reads "1.2G" / "512.0M" style sizes (journalctl, du -h).
func parseSizeHuman(s string) int64 {
	m := reSize.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	f, _ := strconv.ParseFloat(m[1], 64)
	mul := map[string]float64{"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m[2]]
	return int64(f * mul)
}

// parseBIOSDate reads /sys/class/dmi/id/bios_date (MM/DD/YYYY or YYYY-MM-DD).
func parseBIOSDate(s string) (time.Time, bool) {
	for _, layout := range []string{"01/02/2006", "2006-01-02", "01/02/06"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseWirelessQuality reads /proc/net/wireless and returns the link quality (0-70) of the first interface.
func parseWirelessQuality(s string) (iface string, quality int, ok bool) {
	for _, l := range lines(s) {
		if !strings.Contains(l, ":") || strings.HasPrefix(l, "Inter") || strings.HasPrefix(l, "face") {
			continue
		}
		name, rest, _ := strings.Cut(l, ":")
		f := strings.Fields(rest)
		if len(f) >= 2 {
			q, err := strconv.ParseFloat(strings.TrimSuffix(f[1], "."), 64)
			if err == nil {
				return strings.TrimSpace(name), int(q), true
			}
		}
	}
	return "", 0, false
}

func gbKB(kb int64) string { return gb(uint64(kb) << 10) }

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func trimList(l []string, n int) string {
	if len(l) > n {
		return strings.Join(l[:n], ", ") + ", ..."
	}
	return strings.Join(l, ", ")
}

// activeUnits reports which of the given systemd units are active.
func activeUnits(units ...string) (active []string) {
	for _, u := range units {
		if out, _ := cmd("systemctl", "is-active", u); out == "active" {
			active = append(active, u)
		}
	}
	return
}

// packageManager names the system package manager ("" when none is recognised).
func packageManager() string {
	for _, pm := range []string{"apt-get", "dnf", "pacman", "zypper", "apk"} {
		if haveCmd(pm) {
			return pm
		}
	}
	return ""
}
