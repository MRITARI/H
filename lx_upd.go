package main

// Linux: package manager and update health (no build tag, see lx.go).

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// newestMTime returns the most recent modification time among the files matching the globs.
func newestMTime(globs ...string) (time.Time, bool) {
	var best time.Time
	for _, g := range globs {
		files, _ := globFiles(g)
		for _, f := range files {
			if st, err := os.Stat(f); err == nil && st.ModTime().After(best) {
				best = st.ModTime()
			}
		}
	}
	return best, !best.IsZero()
}

// pendingUpdates counts available package updates from the local metadata (no root, no network where possible).
// security counts the ones from a security pocket (apt only). ok is false when it cannot be determined.
func pendingUpdates(pm string) (total, security int, names []string, ok bool) {
	switch pm {
	case "apt-get":
		out, err := cmd("apt", "list", "--upgradable")
		if err != nil && out == "" {
			return
		}
		for _, l := range lines(out) {
			if !strings.Contains(l, "[upgradable") {
				continue
			}
			total++
			names = append(names, strings.SplitN(l, "/", 2)[0])
			if strings.Contains(l, "-security") {
				security++
			}
		}
		return total, security, names, true
	case "dnf":
		out, err := cmdOut(40*time.Second, "dnf", "-q", "check-update", "-C")
		if err != nil && out == "" && !strings.Contains(fmt.Sprint(err), "100") {
			return
		}
		for _, l := range lines(out) {
			if f := strings.Fields(l); len(f) == 3 && strings.Contains(f[0], ".") && !strings.HasPrefix(l, "Obsoleting") {
				total++
				names = append(names, f[0])
			}
		}
		return total, 0, names, true
	case "pacman":
		if !haveCmd("checkupdates") {
			return
		}
		out, _ := cmdOut(40*time.Second, "checkupdates")
		for _, l := range lines(out) {
			total++
			names = append(names, strings.Fields(l)[0])
		}
		return total, 0, names, true
	case "zypper":
		out, err := cmdOut(40*time.Second, "zypper", "-q", "--no-refresh", "list-updates")
		if err != nil && out == "" {
			return
		}
		for _, l := range lines(out) {
			if strings.HasPrefix(l, "v |") {
				total++
				if f := strings.Split(l, "|"); len(f) > 2 {
					names = append(names, strings.TrimSpace(f[2]))
				}
			}
		}
		return total, 0, names, true
	case "apk":
		out, err := cmd("apk", "version", "-l", "<")
		if err != nil && out == "" {
			return
		}
		for _, l := range lines(out) {
			if !strings.HasPrefix(l, "Installed") {
				total++
			}
		}
		return total, 0, names, true
	}
	return
}

func cacheDirFor(pm string) string {
	switch pm {
	case "apt-get":
		return "/var/cache/apt/archives"
	case "pacman":
		return "/var/cache/pacman/pkg"
	case "dnf":
		return "/var/cache/dnf"
	case "zypper":
		return "/var/cache/zypp"
	case "apk":
		return "/var/cache/apk"
	}
	return ""
}

func updateToolLx() tool {
	pm := packageManager()
	pmName := map[string]string{"apt-get": "apt (Debian/Ubuntu)", "dnf": "dnf (Fedora/RHEL)", "pacman": "pacman (Arch)", "zypper": "zypper (openSUSE)", "apk": "apk (Alpine)"}[pm]

	defs := []checkDef{
		{"Package manager", func() Check {
			if pm == "" {
				return info("Package manager", "none of apt, dnf, pacman, zypper or apk found - package checks are skipped")
			}
			return info("Package manager", pmName)
		}},
		{"Package database consistency", func() Check {
			switch pm {
			case "apt-get":
				audit, _ := cmd("dpkg", "--audit")
				_, chk := cmd("apt-get", "check")
				if audit != "" || chk != nil {
					det := "dpkg reports half-installed or unconfigured packages"
					if audit == "" {
						det = "apt-get check found broken dependencies"
					}
					return fail("Package database consistency", det,
						"An interrupted install or upgrade left packages half-configured, which blocks all further installs and updates. The repair command finishes the job.", "pkg-repair")
				}
				return pass("Package database consistency", "dpkg and apt report no problems")
			case "pacman":
				out, err := cmd("pacman", "-Dk")
				if err != nil && out != "" {
					return warn("Package database consistency", firstLines(out, 2), "pacman's database has dangling dependencies or missing files.", "pkg-repair")
				}
				return pass("Package database consistency", "pacman database is consistent")
			case "":
				return info("Package database consistency", "no package manager")
			}
			return info("Package database consistency", "not checked for "+pmName)
		}},
		{"Another package process", func() Check {
			out, err := cmd("ps", "-eo", "comm=")
			if err != nil && out == "" {
				return probeErr("Another package process", err)
			}
			busy := map[string]bool{}
			for _, p := range lines(out) {
				switch p {
				case "apt", "apt-get", "aptitude", "dpkg", "unattended-upgr", "unattended-upgrade", "dnf", "yum", "rpm", "zypper", "pacman", "apk":
					busy[p] = true
				}
			}
			if len(busy) > 0 {
				var l []string
				for p := range busy {
					l = append(l, p)
				}
				return info("Another package process", "running: "+strings.Join(l, ", ")+" - wait for it before installing; a lock error means this is why")
			}
			return pass("Another package process", "none running")
		}},
		{"Pending updates", func() Check {
			total, sec, names, ok := pendingUpdates(pm)
			if !ok {
				return info("Pending updates", "cannot be determined without refreshing package lists (or the tool is missing)")
			}
			if total == 0 {
				return pass("Pending updates", "everything is up to date (as of the last package list refresh)")
			}
			txt := fmt.Sprintf("%d update(s) available: %s", total, trimList(names, 5))
			switch {
			case sec > 0:
				return warn("Pending updates", fmt.Sprintf("%s (%d security)", txt, sec), "Security updates are waiting. Install them soon.", "pkg-upgrade")
			case total > 50:
				return warn("Pending updates", txt, "Many updates have piled up. Upgrading in one go gets harder the longer you wait.", "pkg-upgrade")
			}
			return info("Pending updates", txt)
		}},
		{"Package lists freshness", func() Check {
			var t time.Time
			var ok bool
			switch pm {
			case "apt-get":
				t, ok = newestMTime("/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/lists/*Packages*", "/var/cache/apt/pkgcache.bin")
			case "pacman":
				t, ok = newestMTime("/var/lib/pacman/sync/*.db")
			case "dnf":
				t, ok = newestMTime("/var/cache/dnf/*/repodata/repomd.xml", "/var/cache/dnf/*.solv")
			default:
				return info("Package lists freshness", "not checked")
			}
			if !ok {
				return info("Package lists freshness", "unknown")
			}
			age := int(time.Since(t).Hours() / 24)
			txt := fmt.Sprintf("refreshed %d day(s) ago", age)
			if age > 30 {
				return warn("Package lists freshness", txt, "The package lists are old, so updates and installs may fail or miss new versions. Refresh them.", "pkg-refresh")
			}
			return pass("Package lists freshness", txt)
		}},
		lxReboot(),
		{"Free space for updates", func() Check {
			var bad []string
			var seen []string
			for _, d := range fixedDrives() {
				var need uint64
				switch d.Root {
				case "/":
					need = 2 << 30
				case "/boot":
					need = 150 << 20
				default:
					continue
				}
				seen = append(seen, fmt.Sprintf("%s %s free", d.Root, gb(d.Free)))
				if d.Free < need {
					bad = append(bad, fmt.Sprintf("%s has only %s free", d.Root, gb(d.Free)))
				}
			}
			switch {
			case len(bad) > 0:
				return warn("Free space for updates", strings.Join(bad, "; "),
					"Upgrades need room to unpack. A full /boot (old kernels) is the classic cause of failed updates: remove unused packages and old kernels.", "pkg-autoremove")
			case len(seen) > 0:
				return pass("Free space for updates", strings.Join(seen, ", "))
			}
			return info("Free space for updates", "system disk not found")
		}},
		{"Old kernels installed", func() Check {
			if pm != "apt-get" {
				return info("Old kernels installed", "only checked on apt systems")
			}
			out, _ := cmd("dpkg-query", "-W", "-f", "${db:Status-Abbrev} ${Package}\\n", "linux-image-[0-9]*")
			n := 0
			for _, l := range lines(out) {
				if strings.HasPrefix(l, "ii") {
					n++
				}
			}
			if n > 3 {
				return warn("Old kernels installed", fmt.Sprintf("%d kernel images", n), "Old kernels fill /boot and the disk. Removing unused packages keeps the current and previous kernel.", "pkg-autoremove")
			}
			return pass("Old kernels installed", fmt.Sprintf("%d kernel image(s)", n))
		}},
		{"Held back packages", func() Check {
			if pm != "apt-get" {
				return info("Held back packages", "only checked on apt systems")
			}
			out, _ := cmd("apt-mark", "showhold")
			if l := lines(out); len(l) > 0 {
				return info("Held back packages", trimList(l, 6)+" - these are never upgraded until you unhold them")
			}
			return pass("Held back packages", "none")
		}},
	}
	if dir := cacheDirFor(pm); dir != "" {
		defs = append(defs, sizeCheck("Package cache", dir, 5<<30, "Downloaded package files kept after installing. Safe to delete; they are re-downloaded if needed.", "pkg-clean-cache"))
	}
	defs = append(defs,
		checkDef{"Automatic updates", func() Check {
			switch pm {
			case "apt-get":
				cfg := readStr("/etc/apt/apt.conf.d/20auto-upgrades")
				if strings.Contains(cfg, `Unattended-Upgrade "1"`) {
					return pass("Automatic updates", "unattended-upgrades is enabled")
				}
				return info("Automatic updates", "unattended security upgrades are not configured")
			case "dnf":
				if len(activeUnits("dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer")) > 0 {
					return pass("Automatic updates", "dnf-automatic is active")
				}
				return info("Automatic updates", "dnf-automatic is not active")
			}
			return info("Automatic updates", "not checked on this distribution")
		}},
		checkDef{"Flatpak and Snap", func() Check {
			var parts []string
			if haveCmd("flatpak") {
				out, _ := cmdOut(20*time.Second, "flatpak", "remote-ls", "--updates", "--columns=application")
				parts = append(parts, plural(len(lines(out)), "Flatpak update", "Flatpak updates"))
			}
			if haveCmd("snap") {
				out, _ := cmdOut(20*time.Second, "snap", "refresh", "--list")
				n := len(lines(out))
				if strings.Contains(out, "All snaps up to date") {
					n = 0
				} else if n > 0 {
					n-- // header row
				}
				parts = append(parts, plural(n, "Snap update", "Snap updates"))
			}
			if len(parts) == 0 {
				return info("Flatpak and Snap", "neither is installed")
			}
			return info("Flatpak and Snap", strings.Join(parts, ", "))
		}},
	)
	return tool{Title: "Updates & packages", Blurb: "broken or stuck package manager, pending updates, reboots", Defs: defs}
}
