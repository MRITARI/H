package main

// Linux: security check (no build tag, see lx.go).

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type listener struct {
	Proto, Addr string
	Port        int
}

func (l listener) exposed() bool {
	return !(strings.HasPrefix(l.Addr, "127.") || l.Addr == "::1" || l.Addr == "[::1]")
}

// parseListeners reads "ss -tulnH".
func parseListeners(s string) []listener {
	var out []listener
	for _, l := range lines(s) {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		addr := strings.Trim(local[:i], "[]")
		if j := strings.Index(addr, "%"); j >= 0 {
			addr = addr[:j]
		}
		out = append(out, listener{Proto: f[0], Addr: addr, Port: port})
	}
	return out
}

var riskyPorts = map[int]string{21: "FTP", 23: "Telnet", 139: "NetBIOS", 445: "SMB file sharing", 3306: "MySQL", 3389: "remote desktop (RDP)",
	5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB", 2375: "Docker API (unencrypted)"}

// parseSSHD returns the effective (first) value of each keyword in sshd_config text.
func parseSSHD(text string) map[string]string {
	m := map[string]string{}
	for _, l := range lines(text) {
		if strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		if len(f) >= 2 {
			k := strings.ToLower(f[0])
			if _, seen := m[k]; !seen {
				m[k] = strings.ToLower(f[1])
			}
		}
	}
	return m
}

// groupMembers returns the members of a group from /etc/group text.
func groupMembers(etcGroup, name string) []string {
	for _, l := range lines(etcGroup) {
		f := strings.Split(l, ":")
		if len(f) >= 4 && f[0] == name {
			var out []string
			for _, m := range strings.Split(f[3], ",") {
				if m != "" {
					out = append(out, m)
				}
			}
			return out
		}
	}
	return nil
}

func securityToolLx() tool {
	defs := []checkDef{
		{"Firewall", func() Check {
			if !haveCmd("systemctl") {
				return info("Firewall", "this system does not use systemd - not checked")
			}
			act := activeUnits("ufw", "firewalld", "nftables", "iptables")
			managed := false
			for _, a := range act {
				if a == "ufw" || a == "firewalld" {
					managed = true
				}
			}
			switch {
			case managed:
				return pass("Firewall", strings.Join(act, ", ")+" active")
			case len(act) > 0:
				return info("Firewall", strings.Join(act, ", ")+" active (custom rules - not inspected)")
			case haveCmd("ufw") || haveCmd("firewall-cmd"):
				return warn("Firewall", "installed but not running",
					"Without a firewall every listening service is reachable from the network. Turn it on (it blocks incoming connections by default).", "enable-firewall")
			}
			return warn("Firewall", "no firewall manager (ufw, firewalld) found",
				"Nothing filters incoming connections. Install ufw or firewalld, especially on laptops that join public networks.", "")
		}},
		{"Network services exposed", func() Check {
			if !haveCmd("ss") {
				return na("Network services exposed")
			}
			out, err := cmd("ss", "-tulnH")
			if err != nil && out == "" {
				return probeErr("Network services exposed", err)
			}
			seen := map[string]bool{}
			var exposed, risky []string
			for _, l := range parseListeners(out) {
				if !l.exposed() {
					continue
				}
				key := fmt.Sprintf("%s/%d", l.Proto, l.Port)
				if seen[key] {
					continue
				}
				seen[key] = true
				exposed = append(exposed, key)
				if n, bad := riskyPorts[l.Port]; bad {
					risky = append(risky, fmt.Sprintf("%s (%s)", key, n))
				}
			}
			sort.Strings(exposed)
			switch {
			case len(risky) > 0:
				return warn("Network services exposed", "sensitive services listen on all interfaces: "+strings.Join(risky, ", "),
					"Databases, file sharing and remote desktop should listen on localhost or sit behind a firewall/VPN. Anyone on the network can try to reach them.", "show-open-ports")
			case len(exposed) > 0:
				return info("Network services exposed", plural(len(exposed), "port listens", "ports listen")+" on the network: "+trimList(exposed, 8))
			}
			return pass("Network services exposed", "nothing listens beyond localhost")
		}},
		{"SSH server", func() Check {
			if !haveCmd("systemctl") || len(activeUnits("sshd", "ssh")) == 0 {
				return pass("SSH server", "not running")
			}
			text := readStr("/etc/ssh/sshd_config")
			if conf, _ := globFiles("/etc/ssh/sshd_config.d/*.conf"); len(conf) > 0 {
				var parts []string
				for _, c := range conf { // drop-ins are read first and win
					parts = append(parts, readStr(c))
				}
				text = strings.Join(parts, "\n") + "\n" + text
			}
			if text == "" {
				return info("SSH server", "running; the configuration is not readable (run as root to check it)")
			}
			cfg := parseSSHD(text)
			var issues []string
			if cfg["permitrootlogin"] == "yes" {
				issues = append(issues, "root may log in over SSH")
			}
			if cfg["passwordauthentication"] != "no" {
				issues = append(issues, "password logins are allowed")
			}
			if cfg["permitemptypasswords"] == "yes" {
				issues = append(issues, "EMPTY passwords are allowed")
			}
			switch {
			case cfg["permitemptypasswords"] == "yes" || cfg["permitrootlogin"] == "yes":
				return fail("SSH server", "running: "+strings.Join(issues, ", "),
					"Root login or empty passwords over SSH is the first thing attackers try. Set PermitRootLogin no and use keys.", "")
			case len(issues) > 0:
				return warn("SSH server", "running: "+strings.Join(issues, ", "),
					"Password logins invite brute-force guessing. Use SSH keys and set PasswordAuthentication no when you can.", "")
			}
			return pass("SSH server", "running with key-only logins")
		}},
		{"Failed SSH logins (24h)", func() Check {
			if !haveCmd("journalctl") || len(activeUnits("sshd", "ssh")) == 0 {
				return info("Failed SSH logins (24h)", "SSH server is not running")
			}
			if !journalAccess() {
				return info("Failed SSH logins (24h)", "no access to the journal - run as root")
			}
			out, _ := cmd("journalctl", "-u", "ssh", "-u", "sshd", "--since", "24 hours ago", "--no-pager", "-q")
			n, _ := countLines(out, "Failed password", "Invalid user", "authentication failure")
			switch {
			case n > 100:
				return warn("Failed SSH logins (24h)", fmt.Sprintf("%d failed attempts", n),
					"Someone is guessing passwords. Use key-only logins, a firewall limit (ufw limit ssh) or fail2ban.", "show-failed-logins")
			case n > 0:
				return info("Failed SSH logins (24h)", fmt.Sprintf("%d failed attempts", n))
			}
			return pass("Failed SSH logins (24h)", "none")
		}},
		{"SELinux / AppArmor", func() Check {
			if e := readStr("/sys/fs/selinux/enforce"); e == "1" {
				return pass("SELinux / AppArmor", "SELinux enforcing")
			} else if e == "0" {
				return info("SELinux / AppArmor", "SELinux is permissive (logs but does not block)")
			}
			if readStr("/sys/module/apparmor/parameters/enabled") == "Y" {
				return pass("SELinux / AppArmor", "AppArmor enabled")
			}
			return info("SELinux / AppArmor", "no mandatory access control active (normal on Arch and some minimal systems)")
		}},
		{"Disk encryption", func() Check {
			out, err := cmd("lsblk", "-rno", "TYPE")
			if err != nil && out == "" {
				return probeErr("Disk encryption", err)
			}
			if strings.Contains(out, "crypt") {
				return pass("Disk encryption", "an encrypted (LUKS) volume is in use")
			}
			if b, _ := globFiles("/sys/class/power_supply/BAT*"); len(b) > 0 {
				return warn("Disk encryption", "this laptop's disks are not encrypted",
					"Anyone who finds a lost or stolen laptop can read every file by plugging the disk into another PC. Encrypt at install time (LUKS) or move to an encrypted home.", "")
			}
			return info("Disk encryption", "no encrypted volume (acceptable for a desktop or server in a secure place)")
		}},
		{"Secure Boot", func() Check {
			if !exists("/sys/firmware/efi") {
				return info("Secure Boot", "legacy BIOS boot - Secure Boot is not available")
			}
			files, _ := globFiles("/sys/firmware/efi/efivars/SecureBoot-*")
			if len(files) == 0 {
				return info("Secure Boot", "state not readable")
			}
			b, err := readFile(files[0])
			if err != nil || len(b) == 0 {
				return info("Secure Boot", "state not readable")
			}
			if b[len(b)-1] == 1 {
				return pass("Secure Boot", "enabled")
			}
			return info("Secure Boot", "disabled in the firmware - boot-time malware protection is off")
		}},
		{"Administrator accounts", func() Check {
			grp := readStr("/etc/group")
			seen := map[string]bool{}
			for _, g := range []string{"sudo", "wheel", "admin"} {
				for _, m := range groupMembers(grp, g) {
					seen[m] = true
				}
			}
			var admins []string
			for m := range seen {
				admins = append(admins, m)
			}
			sort.Strings(admins)
			var extra []string
			for _, g := range []string{"docker", "disk", "lxd"} {
				if m := groupMembers(grp, g); len(m) > 0 {
					extra = append(extra, g+": "+strings.Join(m, ","))
				}
			}
			txt := fmt.Sprintf("%d with sudo: %s", len(admins), trimList(admins, 6))
			if len(extra) > 0 {
				txt += "; root-equivalent groups " + strings.Join(extra, " ")
			}
			if len(admins) > 4 {
				return warn("Administrator accounts", txt, "Every sudo account is a way to take over the machine. Remove people who do not need it.", "")
			}
			return info("Administrator accounts", txt)
		}},
		{"Accounts without a password", func() Check {
			if c := adminOnly("Accounts without a password"); c != nil {
				return *c
			}
			var open []string
			for _, l := range lines(readStr("/etc/shadow")) {
				f := strings.Split(l, ":")
				if len(f) > 1 && f[1] == "" {
					open = append(open, f[0])
				}
			}
			if len(open) > 0 {
				return fail("Accounts without a password", strings.Join(open, ", "),
					"These accounts can log in without any password. Set one (passwd) or lock the account (passwd -l).", "")
			}
			return pass("Accounts without a password", "none")
		}},
		{"Automatic login", func() Check {
			for _, f := range []string{"/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"} {
				if strings.Contains(strings.ReplaceAll(readStr(f), " ", ""), "\nAutomaticLoginEnable=true") {
					return info("Automatic login", "enabled in "+f+" - anyone who powers on the PC gets in")
				}
			}
			if conf, _ := globFiles("/etc/lightdm/lightdm.conf*"); len(conf) > 0 {
				for _, f := range conf {
					for _, l := range lines(readStr(f)) {
						if strings.HasPrefix(strings.ReplaceAll(l, " ", ""), "autologin-user=") {
							return info("Automatic login", "enabled in "+f)
						}
					}
				}
			}
			if exists("/etc/sddm.conf") && strings.Contains(readStr("/etc/sddm.conf"), "[Autologin]") {
				return info("Automatic login", "enabled in /etc/sddm.conf")
			}
			return pass("Automatic login", "off")
		}},
		{"Sudo without password", func() Check {
			if c := adminOnly("Sudo without password"); c != nil {
				return *c
			}
			files, _ := globFiles("/etc/sudoers.d/*")
			files = append(files, "/etc/sudoers")
			n := 0
			for _, f := range files {
				for _, l := range lines(readStr(f)) {
					if !strings.HasPrefix(l, "#") && strings.Contains(l, "NOPASSWD") {
						n++
					}
				}
			}
			if n > 0 {
				return info("Sudo without password", plural(n, "rule lets", "rules let")+" commands run as root without a password")
			}
			return pass("Sudo without password", "no NOPASSWD rules")
		}},
		{"Kernel hardening", func() Check {
			var issues []string
			aslr := readStr("/proc/sys/kernel/randomize_va_space")
			if aslr != "" && aslr != "2" {
				issues = append(issues, "address-space randomisation (ASLR) is not fully on")
			}
			if readStr("/proc/sys/net/ipv4/tcp_syncookies") == "0" {
				issues = append(issues, "SYN cookies are off")
			}
			if aslr == "" {
				return na("Kernel hardening")
			}
			if len(issues) > 0 {
				return warn("Kernel hardening", strings.Join(issues, "; "), "These kernel settings make exploits and flood attacks easier. Re-enable them.", "enable-aslr")
			}
			return pass("Kernel hardening", "ASLR on, SYN cookies on")
		}},
		{"Home folder permissions", func() Check {
			home := realHome()
			st, err := os.Stat(home)
			if err != nil || runtime.GOOS != "linux" { // permission bits mean nothing elsewhere
				return na("Home folder permissions")
			}
			mode := st.Mode().Perm()
			switch {
			case mode&0o002 != 0:
				return fail("Home folder permissions", fmt.Sprintf("%s is world-writable (%o)", home, mode), "Any user on this machine can change your files. Run chmod 750 on the folder.", "")
			case mode&0o005 != 0:
				return info("Home folder permissions", fmt.Sprintf("%s is readable by other users (%o)", home, mode))
			}
			return pass("Home folder permissions", fmt.Sprintf("%s is private (%o)", home, mode))
		}},
	}
	return tool{Title: "Security check", Blurb: "firewall, SSH, SELinux/AppArmor, encryption, open ports", Defs: defs}
}
