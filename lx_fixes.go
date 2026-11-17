package main

// Linux quick fixes (no build tag so the table can be tested anywhere; fixes_linux.go selects it).
// Every fix is a fixed, reviewed command line. Nothing runs until the user presses y,
// and fixes that need root are refused unless H runs as root (press a on the main menu).

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var linuxFixCats = []fixCat{
	{"Network", "DNS, DHCP, Wi-Fi, time, proxy", []string{"flush-dns", "restart-resolved", "restart-networkmanager", "renew-dhcp", "wifi-cycle", "rfkill-unblock", "clear-neighbors", "gnome-proxy-off", "time-sync"}},
	{"Updates & packages", "refresh, upgrade, repair, clean", []string{"pkg-refresh", "pkg-upgrade", "pkg-repair", "pkg-clean-cache", "pkg-autoremove", "flatpak-update", "snap-refresh"}},
	{"System repair", "services, libraries, initramfs, bootloader", []string{"reset-failed", "restart-failed-units", "daemon-reload", "fix-font-cache", "ldconfig", "rebuild-initramfs", "update-grub"}},
	{"Cleanup", "free disk space", []string{"clear-user-tmp", "clear-cache-old", "clear-thumbnails", "empty-trash", "vacuum-journal", "clear-coredumps", "flatpak-unused", "snap-old-revisions", "docker-prune"}},
	{"Performance", "power profile, memory, SSD trim, autostart", []string{"profile-balanced", "profile-performance", "drop-caches", "trim-ssd", "set-swappiness", "list-autostart"}},
	{"Printing & audio", "CUPS, PipeWire/Pulse, Bluetooth", []string{"restart-cups", "enable-printers", "clear-print-queue", "restart-audio", "unmute-audio", "restart-bluetooth"}},
	{"Security", "firewall, kernel hardening, logins", []string{"enable-firewall", "enable-aslr", "enable-auto-updates", "show-failed-logins"}},
	{"Hardware", "battery, SMART, firmware, sensors", []string{"battery-report", "smart-report", "smart-short-test", "fwupd-check", "fwupd-refresh", "show-sensors"}},
	{"Show info", "read-only reports in one line", []string{"show-failed-units", "show-boot-errors", "show-kernel-errors", "show-disk-usage", "show-open-ports", "show-boot-time", "show-top-processes"}},
}

// runFn executes a fix command; tests replace it to syntax-check every script.
var runFn = run

// ---- constructors ----

func shFix(timeout time.Duration, script string) func() (string, error) {
	return func() (string, error) { return runFn(timeout, "sh", "-c", script) }
}

// tailed keeps only the last three lines of a chatty command but preserves its exit status.
func tailed(script string) string {
	return `out=$({ ` + script + `; } 2>&1); rc=$?; printf '%s\n' "$out" | tail -n 3; exit $rc`
}

// userFix runs a script as the desktop user (not root) even from a sudo session.
// {HOME} and {UID} are substituted with the real user's values.
func userFix(timeout time.Duration, tmpl string) func() (string, error) {
	return func() (string, error) {
		_, uid, home := realUser()
		if home == "" || home == "/" {
			return "", errors.New("cannot find your home folder")
		}
		s := strings.NewReplacer("{HOME}", shQuote(home), "{UID}", uid).Replace(tmpl)
		return runFn(timeout, "sh", "-c", asUser(s))
	}
}

// pmFix picks the command for the installed package manager at run time.
func pmFix(timeout time.Duration, apt, dnf, pacman, zypper, apk string) func() (string, error) {
	return func() (string, error) {
		pm := packageManager()
		script := map[string]string{"apt-get": apt, "dnf": dnf, "pacman": pacman, "zypper": zypper, "apk": apk}[pm]
		if pm == "" {
			return "", errors.New("no supported package manager found (apt, dnf, pacman, zypper, apk)")
		}
		if script == "" {
			return "", fmt.Errorf("this action is not available for %s", pm)
		}
		return runFn(timeout, "sh", "-c", tailed(script))
	}
}

const aptEnv = "DEBIAN_FRONTEND=noninteractive "

const disksLoop = `for d in $(lsblk -dno NAME,TYPE | awk '$2=="disk"{print $1}' | grep -Ev '^(zram|loop|ram)'); do `

var linuxFixes = map[string]fix{
	// ---- Network ----
	"flush-dns": {"Flush the DNS cache", true, "safe", shFix(20*time.Second,
		`if command -v resolvectl >/dev/null 2>&1; then resolvectl flush-caches && echo 'systemd-resolved cache flushed'; `+
			`elif command -v systemd-resolve >/dev/null 2>&1; then systemd-resolve --flush-caches && echo 'systemd-resolved cache flushed'; `+
			`elif command -v nscd >/dev/null 2>&1; then nscd -i hosts && echo 'nscd hosts cache cleared'; `+
			`else echo 'No DNS cache service is running - nothing to flush.'; fi`)},
	"restart-resolved": {"Restart the DNS resolver (systemd-resolved)", true, "disruptive",
		shFix(30*time.Second, `systemctl restart systemd-resolved && echo 'systemd-resolved restarted'`)},
	"restart-networkmanager": {"Restart the network service (brief disconnect)", true, "disruptive", shFix(60*time.Second,
		`if systemctl cat NetworkManager >/dev/null 2>&1; then systemctl restart NetworkManager && echo 'NetworkManager restarted'; `+
			`elif systemctl cat systemd-networkd >/dev/null 2>&1; then systemctl restart systemd-networkd && echo 'systemd-networkd restarted'; `+
			`else echo 'No NetworkManager or systemd-networkd found.'; exit 1; fi`)},
	"renew-dhcp": {"Renew the DHCP lease on the active connection (brief disconnect)", true, "disruptive", shFix(90*time.Second,
		`dev=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'); `+
			`[ -n "$dev" ] || dev=$(ip -o link show up | awk -F': ' '$2!="lo"{print $2; exit}'); `+
			`[ -n "$dev" ] || { echo 'No active network interface found.'; exit 1; }; `+
			`if command -v nmcli >/dev/null 2>&1; then nmcli device reapply "$dev" || { nmcli device disconnect "$dev"; nmcli device connect "$dev"; }; `+
			`elif command -v networkctl >/dev/null 2>&1; then networkctl renew "$dev"; `+
			`elif command -v dhclient >/dev/null 2>&1; then dhclient -r "$dev"; dhclient "$dev"; `+
			`else echo 'No DHCP tool (nmcli, networkctl, dhclient) found.'; exit 1; fi; echo "Renewed $dev"`)},
	"wifi-cycle": {"Turn the Wi-Fi radio off and on (brief disconnect)", false, "disruptive",
		shFix(30*time.Second, `nmcli radio wifi off && sleep 2 && nmcli radio wifi on && echo 'Wi-Fi radio cycled'`)},
	"rfkill-unblock": {"Unblock Wi-Fi and Bluetooth (turn off airplane mode)", false, "safe",
		shFix(15*time.Second, `rfkill unblock all && echo 'All radios unblocked' && rfkill list | grep -c 'blocked: yes' | xargs echo 'still blocked (hardware switch):'`)},
	"clear-neighbors": {"Clear the ARP/neighbour cache (forgets known LAN devices)", true, "safe",
		shFix(15*time.Second, `ip neigh flush all && echo 'Neighbour cache cleared'`)},
	"gnome-proxy-off": {"Turn off the desktop proxy setting (GNOME)", false, "disruptive",
		userFix(15*time.Second, `gsettings set org.gnome.system.proxy mode 'none' && echo 'Desktop proxy turned off'`)},
	"time-sync": {"Turn on network time and resync the clock", true, "safe", shFix(40*time.Second,
		`timedatectl set-ntp true; (systemctl restart systemd-timesyncd || systemctl restart chronyd || systemctl restart chrony || systemctl restart ntpd) >/dev/null 2>&1; `+
			`sleep 3; timedatectl | grep -E 'synchronized|Local time' | tr -s ' ' | tr '\n' ';'`)},

	// ---- Updates & packages ----
	"pkg-refresh": {"Refresh the package lists", true, "safe", pmFix(10*time.Minute,
		aptEnv+`apt-get update`, `dnf -y makecache --refresh`,
		`echo "On Arch, refresh and upgrade together with 'Upgrade all packages' - a lone pacman -Sy can break the system."`,
		`zypper -n refresh`, `apk update`)},
	"pkg-upgrade": {"Upgrade all packages (long-running; may need a restart afterwards)", true, "heavy", pmFix(90*time.Minute,
		aptEnv+`apt-get update && `+aptEnv+`apt-get -y upgrade`, `dnf -y upgrade --refresh`, `pacman -Syu --noconfirm`,
		`zypper -n update`, `apk update && apk upgrade`)},
	"pkg-repair": {"Repair an interrupted or broken package installation", true, "disruptive", pmFix(30*time.Minute,
		aptEnv+`dpkg --configure -a && `+aptEnv+`apt-get -f install -y`,
		`rpm --rebuilddb && dnf -y clean expire-cache && echo 'RPM database rebuilt'`,
		`if pgrep -x pacman >/dev/null; then echo 'pacman is running - wait for it to finish'; exit 1; fi; rm -f /var/lib/pacman/db.lck; pacman -Dk && echo 'pacman database is consistent'`,
		`zypper -n verify`, `apk fix`)},
	"pkg-clean-cache": {"Delete downloaded package files from the cache", true, "disruptive", pmFix(10*time.Minute,
		`apt-get clean && echo 'apt cache cleaned'`, `dnf -y clean all`,
		`if command -v paccache >/dev/null 2>&1; then paccache -rk2; else pacman -Sc --noconfirm; fi`,
		`zypper -n clean --all`, `apk cache clean`)},
	"pkg-autoremove": {"Remove unused packages and old kernels (frees /boot)", true, "heavy", pmFix(30*time.Minute,
		aptEnv+`apt-get -y autoremove --purge`, `dnf -y autoremove`,
		`orphans=$(pacman -Qdtq); if [ -n "$orphans" ]; then pacman -Rns --noconfirm $orphans; else echo 'No orphaned packages.'; fi`, "", "")},
	"flatpak-update": {"Update Flatpak apps", false, "safe", shFix(30*time.Minute, tailed(`flatpak update -y --noninteractive`))},
	"snap-refresh":   {"Refresh Snap packages", true, "safe", shFix(30*time.Minute, tailed(`snap refresh`))},

	// ---- System repair ----
	"reset-failed": {"Clear the failed state of all services", true, "safe", shFix(15*time.Second, `systemctl reset-failed && echo 'Failed-service list cleared'`)},
	"restart-failed-units": {"Restart every failed service", true, "disruptive", shFix(90*time.Second,
		`units=$(systemctl --failed --no-legend --plain | awk '{print $1}' | grep '\.'); `+
			`if [ -z "$units" ]; then echo 'No failed units.'; else systemctl restart $units; echo "Restarted: $(echo $units)"; `+
			`echo "Still failed: $(systemctl --failed --no-legend --plain | wc -l)"; fi`)},
	"daemon-reload":  {"Reload systemd unit files", true, "safe", shFix(30*time.Second, `systemctl daemon-reload && echo 'systemd reloaded'`)},
	"fix-font-cache": {"Rebuild the font cache (fixes missing or broken fonts)", false, "safe", userFix(120*time.Second, `fc-cache -f && echo 'Font cache rebuilt'`)},
	"ldconfig":       {"Rebuild the shared-library cache (fixes 'cannot open shared object')", true, "safe", shFix(60*time.Second, `ldconfig && echo 'Library cache rebuilt'`)},
	"rebuild-initramfs": {"Rebuild the boot image (initramfs) for all kernels", true, "heavy", shFix(20*time.Minute, tailed(
		`if command -v update-initramfs >/dev/null 2>&1; then update-initramfs -u -k all; `+
			`elif command -v dracut >/dev/null 2>&1; then dracut -f --regenerate-all; `+
			`elif command -v mkinitcpio >/dev/null 2>&1; then mkinitcpio -P; `+
			`else echo 'No initramfs tool (update-initramfs, dracut, mkinitcpio) found.'; exit 1; fi`))},
	"update-grub": {"Regenerate the GRUB boot menu", true, "heavy", shFix(5*time.Minute, tailed(
		`if command -v update-grub >/dev/null 2>&1; then update-grub; `+
			`elif command -v grub2-mkconfig >/dev/null 2>&1; then grub2-mkconfig -o /boot/grub2/grub.cfg; `+
			`elif command -v grub-mkconfig >/dev/null 2>&1; then grub-mkconfig -o /boot/grub/grub.cfg; `+
			`else echo 'GRUB tools not found.'; exit 1; fi`))},

	// ---- Cleanup ----
	"clear-user-tmp": {"Delete your files in /tmp older than 1 day", false, "disruptive", userFix(2*time.Minute,
		`find /tmp /var/tmp -xdev -user {UID} -type f -mtime +0 -delete 2>/dev/null; echo 'Removed your temp files older than 1 day.'`)},
	"clear-cache-old": {"Delete cache files in ~/.cache not changed for 30 days", false, "disruptive", userFix(5*time.Minute,
		`find {HOME}/.cache -type f -mtime +30 -delete 2>/dev/null; find {HOME}/.cache -type d -empty -delete 2>/dev/null; echo 'Removed cache files older than 30 days.'`)},
	"clear-thumbnails": {"Delete the thumbnail cache (rebuilds itself)", false, "safe", userFix(time.Minute,
		`rm -rf {HOME}/.cache/thumbnails/* {HOME}/.thumbnails/* 2>/dev/null; echo 'Thumbnail cache cleared.'`)},
	"empty-trash": {"Empty the Trash (PERMANENT: trashed files cannot be restored)", false, "heavy", userFix(5*time.Minute,
		`rm -rf {HOME}/.local/share/Trash/files/* {HOME}/.local/share/Trash/info/* 2>/dev/null; echo 'Trash emptied.'`)},
	"vacuum-journal": {"Trim the system journal to 14 days / 500 MB", true, "disruptive", shFix(2*time.Minute,
		tailed(`journalctl --vacuum-time=14d --vacuum-size=500M`))},
	"clear-coredumps": {"Delete crash dumps (/var/lib/systemd/coredump, /var/crash)", true, "disruptive",
		shFix(time.Minute, `rm -f /var/lib/systemd/coredump/* /var/crash/* 2>/dev/null; echo 'Crash dumps removed.'`)},
	"flatpak-unused": {"Remove unused Flatpak runtimes", false, "disruptive", shFix(10*time.Minute, tailed(`flatpak uninstall --unused -y --noninteractive`))},
	"snap-old-revisions": {"Remove old disabled Snap revisions", true, "disruptive", shFix(10*time.Minute,
		`snap list --all | awk '/disabled/{print $1, $3}' | while read n r; do snap remove "$n" --revision="$r"; done; echo 'Old Snap revisions removed.'`)},
	"docker-prune": {"Delete stopped containers, dangling images and unused networks (Docker)", false, "heavy",
		shFix(10*time.Minute, tailed(`docker system prune -f`))},

	// ---- Performance ----
	"profile-balanced":    {"Switch to the balanced power profile", false, "safe", shFix(15*time.Second, `powerprofilesctl set balanced && echo 'Power profile: balanced'`)},
	"profile-performance": {"Switch to the performance power profile (more heat and battery use)", false, "disruptive", shFix(15*time.Second, `powerprofilesctl set performance && echo 'Power profile: performance'`)},
	"drop-caches": {"Drop the page cache (frees RAM held as cache; it refills as needed)", true, "safe",
		shFix(30*time.Second, `sync; echo 3 > /proc/sys/vm/drop_caches && echo 'Page cache dropped'`)},
	"trim-ssd":       {"Trim all mounted SSDs (fstrim)", true, "safe", shFix(10*time.Minute, tailed(`fstrim -av`))},
	"set-swappiness": {"Prefer RAM over swap (vm.swappiness=10, until the next restart)", true, "disruptive", shFix(15*time.Second, `sysctl -w vm.swappiness=10`)},
	"list-autostart": {"List the apps that start with your session", false, "safe", userFix(15*time.Second,
		`l=$(ls -1 {HOME}/.config/autostart 2>/dev/null | sed 's/\.desktop$//' | tr '\n' ' '); echo "Your autostart apps: ${l:-none}"`)},

	// ---- Printing & audio ----
	"restart-cups": {"Restart the print service (CUPS)", true, "disruptive", shFix(30*time.Second, `systemctl restart cups && echo 'CUPS restarted'`)},
	"enable-printers": {"Re-enable disabled printers", true, "safe", shFix(30*time.Second,
		`for p in $(lpstat -p | awk '/disabled/{print $2}'); do cupsenable "$p"; cupsaccept "$p"; echo "Enabled $p"; done; echo 'Printers checked.'`)},
	"clear-print-queue": {"Cancel every pending print job", true, "disruptive", shFix(30*time.Second, `cancel -a && echo 'All print jobs cancelled.'`)},
	"restart-audio": {"Restart the audio server (PipeWire or PulseAudio; sound cuts out briefly)", false, "disruptive", userFix(30*time.Second,
		`(systemctl --user restart pipewire pipewire-pulse wireplumber 2>/dev/null || { pulseaudio -k; pulseaudio --start; }) && echo 'Audio server restarted.'`)},
	"unmute-audio": {"Unmute the default output and set the volume to 50%", false, "safe", userFix(15*time.Second,
		`if command -v wpctl >/dev/null 2>&1; then wpctl set-mute @DEFAULT_AUDIO_SINK@ 0; wpctl set-volume @DEFAULT_AUDIO_SINK@ 0.5; `+
			`else pactl set-sink-mute @DEFAULT_SINK@ 0; pactl set-sink-volume @DEFAULT_SINK@ 50%; fi; echo 'Output unmuted at 50%.'`)},
	"restart-bluetooth": {"Restart the Bluetooth service (devices reconnect)", true, "disruptive", shFix(30*time.Second, `systemctl restart bluetooth && echo 'Bluetooth restarted'`)},

	// ---- Security ----
	"enable-firewall": {"Turn the firewall on: ufw or firewalld (SSH stays allowed when the SSH server runs)", true, "disruptive", shFix(60*time.Second,
		`if command -v ufw >/dev/null 2>&1; then if systemctl is-active --quiet ssh sshd 2>/dev/null; then ufw allow ssh; fi; ufw --force enable; `+
			`elif command -v firewall-cmd >/dev/null 2>&1; then systemctl enable --now firewalld && echo 'firewalld enabled'; `+
			`else echo 'Neither ufw nor firewalld is installed - install one first.'; exit 1; fi`)},
	"enable-aslr": {"Turn on ASLR and SYN cookies (until the next restart)", true, "disruptive",
		shFix(15*time.Second, `sysctl -w kernel.randomize_va_space=2 net.ipv4.tcp_syncookies=1`)},
	"enable-auto-updates": {"Turn on the automatic update timers (the package that does the work must be installed)", true, "disruptive", pmFix(30*time.Second,
		`systemctl enable --now apt-daily.timer apt-daily-upgrade.timer && echo 'Timers enabled - also install unattended-upgrades for security updates.'`,
		`systemctl enable --now dnf-automatic.timer && echo 'dnf-automatic timer enabled'`, "", "", "")},
	"show-failed-logins": {"Show the latest failed logins", true, "safe", shFix(20*time.Second, `lastb -n 3 2>&1 | head -n 3`)},

	// ---- Hardware ----
	"battery-report": {"Show battery charge, wear and cycles", false, "safe", func() (string, error) {
		bs := batteries()
		if len(bs) == 0 {
			return "No battery found.", nil
		}
		var out []string
		for _, b := range bs {
			s := fmt.Sprintf("%s: %d%% %s", b.Name, b.Percent, strings.ToLower(b.Status))
			if b.HasWear {
				s += fmt.Sprintf(", %d%% of design capacity (%d%% worn)", 100-b.wearPct(), b.wearPct())
			}
			if b.HasCycle {
				s += fmt.Sprintf(", %d cycles", b.Cycles)
			}
			out = append(out, s)
		}
		return strings.Join(out, "\n"), nil
	}},
	"smart-report": {"Show the SMART health verdict of every drive (needs smartmontools)", true, "safe", shFix(2*time.Minute,
		`command -v smartctl >/dev/null 2>&1 || { echo 'Install smartmontools first.'; exit 1; }; `+
			disksLoop+`echo "$d: $(smartctl -H /dev/$d 2>&1 | grep -iE 'overall-health|SMART Health Status' | sed 's/.*: *//')"; done`)},
	"smart-short-test": {"Start a short SMART self-test on every drive (about 2 minutes)", true, "safe", shFix(2*time.Minute,
		`command -v smartctl >/dev/null 2>&1 || { echo 'Install smartmontools first.'; exit 1; }; `+
			disksLoop+`smartctl -t short /dev/$d >/dev/null 2>&1 && echo "started on $d"; done; echo 'Read the result later: smartctl -l selftest /dev/<disk>'`)},
	"fwupd-check": {"Check for firmware updates (fwupd)", false, "safe", shFix(2*time.Minute,
		`command -v fwupdmgr >/dev/null 2>&1 || { echo 'fwupd is not installed.'; exit 1; }; fwupdmgr get-updates --no-unreported-check 2>&1 | head -n 6`)},
	"fwupd-refresh": {"Download the latest firmware metadata (fwupd)", true, "safe", shFix(2*time.Minute,
		tailed(`fwupdmgr refresh --force`))},
	"show-sensors": {"Show all temperature sensors", false, "safe", func() (string, error) {
		var out []string
		for _, s := range readSensors() {
			name := s.Chip
			if s.Label != "" {
				name += " " + s.Label
			}
			out = append(out, fmt.Sprintf("%s %.0f°C", name, s.C))
		}
		if len(out) == 0 {
			return "No temperature sensors exposed.", nil
		}
		return trimList(out, 8), nil
	}},

	// ---- Show info (read-only) ----
	"show-failed-units": {"List the failed services", false, "safe", shFix(15*time.Second,
		`l=$(systemctl --failed --no-legend --plain | awk '{print $1}' | head -n 8 | tr '\n' ' '); echo "Failed: ${l:-none}"`)},
	"show-boot-errors": {"Show the latest error messages of this boot", false, "safe", shFix(20*time.Second,
		`journalctl -b -p 3 --no-pager -q 2>&1 | tail -n 3 | cut -c1-160`)},
	"show-kernel-errors": {"Show the latest kernel errors of this boot", false, "safe", shFix(20*time.Second,
		`(journalctl -k -p err -b --no-pager -q 2>/dev/null || dmesg --level=err,crit,alert,emerg 2>&1) | tail -n 3 | cut -c1-160`)},
	"show-disk-usage": {"Show disk usage per mount point", false, "safe", shFix(15*time.Second,
		`df -h --output=target,pcent,avail -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2 | head -n 6 | tr -s ' ' | tr '\n' ';'`)},
	"show-open-ports": {"Show the ports that listen for connections", false, "safe", shFix(15*time.Second,
		`ss -tulnH | awk '{print $1"/"$5}' | head -n 10 | tr '\n' ' '`)},
	"show-boot-time": {"Show the slowest services at boot", false, "safe", shFix(30*time.Second, `systemd-analyze blame | head -n 3`)},
	"show-top-processes": {"Show the processes using most CPU and memory", false, "safe", shFix(15*time.Second,
		`echo "CPU: $(ps -eo comm=,pcpu= --sort=-pcpu | head -n 3 | tr -s ' ' | tr '\n' ',')"; echo "RAM: $(ps -eo comm=,rss= --sort=-rss | head -n 3 | tr -s ' ' | tr '\n' ',')"`)},
}
