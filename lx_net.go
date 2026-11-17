package main

// Linux: network diagnostics (no build tag, see lx.go).

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rfkillDev struct {
	Name       string
	Soft, Hard bool
}

// parseRfkill reads "rfkill list" output.
func parseRfkill(s string) []rfkillDev {
	var out []rfkillDev
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case l != "" && l[0] != ' ' && l[0] != '\t' && strings.Contains(t, ":"):
			_, name, _ := strings.Cut(t, ": ")
			out = append(out, rfkillDev{Name: name})
		case strings.HasPrefix(t, "Soft blocked:") && len(out) > 0:
			out[len(out)-1].Soft = strings.HasSuffix(t, "yes")
		case strings.HasPrefix(t, "Hard blocked:") && len(out) > 0:
			out[len(out)-1].Hard = strings.HasSuffix(t, "yes")
		}
	}
	return out
}

var rePacketLoss = regexp.MustCompile(`([\d.]+)% packet loss`)

func parsePacketLoss(s string) (float64, bool) {
	if m := rePacketLoss.FindStringSubmatch(s); m != nil {
		f, _ := strconv.ParseFloat(m[1], 64)
		return f, true
	}
	return 0, false
}

// parseNmcliWifi reads "nmcli -t -f ACTIVE,SSID,SIGNAL dev wifi" and returns the active network.
func parseNmcliWifi(s string) (ssid string, signal int, ok bool) {
	for _, l := range lines(s) {
		rest, found := strings.CutPrefix(l, "yes:")
		if !found {
			continue
		}
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			continue
		}
		sig, err := strconv.Atoi(strings.TrimSpace(rest[i+1:]))
		if err != nil {
			continue
		}
		return strings.ReplaceAll(rest[:i], `\:`, ":"), sig, true
	}
	return "", 0, false
}

// netIfaces lists interfaces that are up, without loopback and container plumbing.
func netIfaces() (names []string) {
	dirs, _ := globFiles("/sys/class/net/*")
	for _, d := range dirs {
		n := filepath.Base(d)
		if n == "lo" || hasAnyPrefix(n, "docker", "veth", "br-", "virbr", "vboxnet", "vmnet", "podman", "cni", "flannel", "kube") {
			continue
		}
		if readStr(d+"/operstate") == "up" {
			names = append(names, n)
		}
	}
	return
}

func hasAnyPrefix(s string, p ...string) bool {
	for _, x := range p {
		if strings.HasPrefix(s, x) {
			return true
		}
	}
	return false
}

func isWireless(iface string) bool {
	return exists("/sys/class/net/"+iface+"/wireless") || exists("/sys/class/net/"+iface+"/phy80211")
}

// webProbe fetches a tiny page once; the body detects captive portals and the Date header measures clock skew.
type webProbe struct {
	once sync.Once
	body string
	date time.Time
	err  error
}

func (w *webProbe) get() (string, time.Time, error) {
	w.once.Do(func() {
		c := &http.Client{Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		r, err := c.Get("http://detectportal.firefox.com/success.txt")
		if err != nil {
			w.err = err
			return
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(r.Body, 512))
		w.body = strings.TrimSpace(string(b))
		w.date, _ = http.ParseTime(r.Header.Get("Date"))
	})
	return w.body, w.date, w.err
}

func lxDNSServerOK(srv string) bool {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		return d.DialContext(ctx, "udp", net.JoinHostPort(srv, "53"))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, "example.com")
	return err == nil && len(addrs) > 0
}

func netToolLx() tool {
	route := &lazy{f: func() (string, error) { return cmd("ip", "-4", "route", "show", "default") }}
	parts := func() (ip, gw, dev string) {
		out, _ := route.get()
		gw, dev = parseDefaultRoute(out)
		if dev != "" {
			a, _ := cmd("ip", "-4", "-o", "addr", "show", "dev", dev)
			ip = parseIPv4(a)
		}
		return
	}
	web := &webProbe{}

	defs := []checkDef{
		{"Network adapter", func() Check {
			up := netIfaces()
			if len(up) == 0 {
				return fail("Network adapter", "no network interface is up",
					"Cable unplugged, Wi-Fi off or blocked, or the network service is stopped. Check those first, then restart the network service.", "restart-networkmanager")
			}
			var desc []string
			for _, n := range up {
				switch {
				case isWireless(n):
					desc = append(desc, n+" (Wi-Fi)")
				case atoi(readStr("/sys/class/net/"+n+"/speed")) > 0:
					desc = append(desc, fmt.Sprintf("%s (%s Mb/s)", n, readStr("/sys/class/net/"+n+"/speed")))
				default:
					desc = append(desc, n)
				}
			}
			return pass("Network adapter", strings.Join(desc, ", "))
		}},
		{"Radio kill switches", func() Check {
			if !haveCmd("rfkill") {
				return info("Radio kill switches", "rfkill is not installed")
			}
			out, err := cmd("rfkill", "list")
			if err != nil && out == "" {
				return probeErr("Radio kill switches", err)
			}
			var soft, hard []string
			for _, d := range parseRfkill(out) {
				switch {
				case d.Hard:
					hard = append(hard, d.Name)
				case d.Soft:
					soft = append(soft, d.Name)
				}
			}
			switch {
			case len(hard) > 0:
				return fail("Radio kill switches", "hardware-blocked: "+strings.Join(hard, ", "),
					"A physical switch or Fn key has turned the radio off. Software cannot undo that; flip the switch or press the airplane-mode key.", "")
			case len(soft) > 0:
				return warn("Radio kill switches", "software-blocked: "+strings.Join(soft, ", "),
					"Airplane mode or a software toggle disabled these radios. Unblocking turns Wi-Fi/Bluetooth back on.", "rfkill-unblock")
			}
			return pass("Radio kill switches", "nothing blocked")
		}},
		{"Network service", func() Check {
			if !haveCmd("systemctl") {
				return info("Network service", "this system does not use systemd")
			}
			act := activeUnits("NetworkManager", "systemd-networkd", "connman", "wicd", "dhcpcd", "netctl")
			if len(act) > 0 {
				return pass("Network service", strings.Join(act, ", ")+" running")
			}
			if haveCmd("nmcli") {
				return warn("Network service", "NetworkManager is installed but not running",
					"Without a network manager nothing configures Wi-Fi or DHCP. Start it.", "restart-networkmanager")
			}
			return info("Network service", "no known network manager is running (fine if you configure the network by hand)")
		}},
		{"IP configuration", func() Check {
			ip, gw, dev := parts()
			switch {
			case dev == "" || ip == "":
				return fail("IP configuration", "no IPv4 address with a default route",
					"The PC did not get an address from the router (DHCP). Renewing the lease or restarting the network service often fixes this.", "renew-dhcp")
			case strings.HasPrefix(ip, "169.254."):
				return fail("IP configuration", "self-assigned address "+ip+" on "+dev,
					"DHCP failed, so the PC gave itself a 169.254.x.x address. Renew the lease or check the router.", "renew-dhcp")
			}
			return pass("IP configuration", fmt.Sprintf("ip %s on %s, gateway %s", ip, dev, gw))
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
				"The router is unreachable: weak Wi-Fi, bad cable or router problem. Restarting the network service or the router can help.", "restart-networkmanager")
		}},
		{"Packet loss to the router", func() Check {
			_, gw, _ := parts()
			if gw == "" || !haveCmd("ping") {
				return info("Packet loss to the router", "needs ping and a known gateway")
			}
			out, _ := cmdOut(20*time.Second, "ping", "-c", "10", "-i", "0.3", "-W", "2", gw)
			loss, ok := parsePacketLoss(out)
			if !ok {
				return info("Packet loss to the router", "could not be measured")
			}
			txt := fmt.Sprintf("%.0f%% of 10 pings lost", loss)
			switch {
			case loss >= 30:
				return fail("Packet loss to the router", txt, "Heavy loss on the local link: very weak Wi-Fi, a bad cable or a faulty router/port.", "")
			case loss > 0:
				return warn("Packet loss to the router", txt, "Some loss on the local link causes stutter and slow pages. Move closer to the router, change the Wi-Fi channel or swap the cable.", "")
			}
			return pass("Packet loss to the router", "none")
		}},
		{"Internet ping", func() Check {
			for _, h := range []string{"1.1.1.1", "8.8.8.8"} {
				if ok, ms := pingHost(h); ok {
					if ms > 150 {
						return warn("Internet ping", fmt.Sprintf("%s answers slowly (%d ms)", h, ms), "High latency: Wi-Fi interference, a VPN or a congested connection.", "")
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
			addrs, err := net.DefaultResolver.LookupHost(ctx, "example.com")
			if err != nil || len(addrs) == 0 {
				return fail("DNS lookup", "cannot resolve example.com",
					"Names do not resolve, so sites will not open even if the connection works. Flush the DNS cache; if it persists, restart the resolver or the DNS server is down.", "flush-dns")
			}
			return pass("DNS lookup", "example.com -> "+addrs[0])
		}},
		{"DNS servers", func() Check {
			servers := parseResolvConf(readStr("/etc/resolv.conf"))
			if len(servers) == 0 {
				return fail("DNS servers", "/etc/resolv.conf lists no nameserver",
					"The system has no DNS server configured. Restarting the network manager or resolver normally rewrites it.", "restart-resolved")
			}
			var bad []string
			for _, s := range servers {
				if !lxDNSServerOK(s) {
					bad = append(bad, s)
				}
			}
			txt := strings.Join(servers, ", ")
			switch {
			case len(bad) == len(servers):
				return fail("DNS servers", "none of "+txt+" answers", "Every configured DNS server is unreachable or broken. Restart the resolver, or switch to another DNS server.", "restart-resolved")
			case len(bad) > 0:
				return warn("DNS servers", "no answer from "+strings.Join(bad, ", ")+" (of "+txt+")", "One DNS server is down; lookups slow down while the system waits for it.", "restart-resolved")
			}
			return pass("DNS servers", txt)
		}},
		{"HTTPS (port 443)", func() Check {
			c, err := net.DialTimeout("tcp", "example.com:443", 5*time.Second)
			if err != nil {
				return fail("HTTPS (port 443)", "cannot connect to example.com:443",
					"Web traffic is blocked or broken: firewall, proxy, DNS or no internet.", "")
			}
			c.Close()
			return pass("HTTPS (port 443)", "example.com:443 reachable")
		}},
		{"Captive portal", func() Check {
			body, _, err := web.get()
			if err != nil {
				return info("Captive portal", "could not be checked (no HTTP connection)")
			}
			if body != "success" {
				return warn("Captive portal", "the test page was replaced",
					"A login page (hotel, airport, school Wi-Fi) or a filtering proxy intercepts web traffic. Open a browser and sign in to the network.", "")
			}
			return pass("Captive portal", "none - open internet")
		}},
		{"Clock", func() Check {
			ntp := ""
			if haveCmd("timedatectl") {
				ntp, _ = cmd("timedatectl", "show", "-p", "NTPSynchronized", "--value")
			}
			_, date, _ := web.get()
			var skew time.Duration
			if !date.IsZero() {
				skew = time.Since(date)
				if skew < 0 {
					skew = -skew
				}
			}
			switch {
			case skew > 2*time.Minute:
				return warn("Clock", fmt.Sprintf("off by about %s", skew.Round(time.Second)),
					"A wrong clock makes HTTPS certificates fail and breaks logins and package signatures. Sync the time.", "time-sync")
			case ntp == "no":
				return warn("Clock", "time synchronisation is off", "The clock is not being corrected automatically and will drift. Turn on network time.", "time-sync")
			}
			return pass("Clock", "accurate"+map[bool]string{true: ", network time on"}[ntp == "yes"])
		}},
		{"Proxy settings", func() Check {
			var set []string
			for _, k := range []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
				if v := getenv(k); v != "" {
					set = append(set, k+"="+v)
				}
			}
			mode := ""
			if haveCmd("gsettings") {
				mode, _ = cmd("gsettings", "get", "org.gnome.system.proxy", "mode")
			}
			switch {
			case strings.Contains(mode, "manual"):
				return warn("Proxy settings", "the desktop uses a manual proxy", "Traffic goes through a proxy. If the internet is broken, a dead proxy is a common cause.", "gnome-proxy-off")
			case len(set) > 0:
				return warn("Proxy settings", strings.Join(set, ", "), "Proxy variables are set in this shell, so command-line tools use a proxy. Unset them (unset http_proxy https_proxy) if it is dead.", "")
			}
			return pass("Proxy settings", "none")
		}},
		{"Wi-Fi signal", func() Check {
			if haveCmd("nmcli") {
				out, _ := cmd("nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL", "dev", "wifi")
				if ssid, sig, ok := parseNmcliWifi(out); ok {
					if sig < 40 {
						return warn("Wi-Fi signal", fmt.Sprintf("%d%% on '%s'", sig, ssid), "Weak signal causes drops and slow speeds. Move closer to the router, use 5 GHz or a cable.", "wifi-cycle")
					}
					return pass("Wi-Fi signal", fmt.Sprintf("%d%% on '%s'", sig, ssid))
				}
			}
			if iface, q, ok := parseWirelessQuality(readStr("/proc/net/wireless")); ok {
				pct := q * 100 / 70
				if pct < 40 {
					return warn("Wi-Fi signal", fmt.Sprintf("%d%% on %s", pct, iface), "Weak signal causes drops and slow speeds. Move closer to the router or use a cable.", "wifi-cycle")
				}
				return pass("Wi-Fi signal", fmt.Sprintf("%d%% on %s", pct, iface))
			}
			return info("Wi-Fi signal", "no Wi-Fi connection")
		}},
		{"Link speed", func() Check {
			var slow []string
			var seen []string
			for _, n := range netIfaces() {
				if isWireless(n) {
					continue
				}
				if sp := atoi(readStr("/sys/class/net/" + n + "/speed")); sp > 0 {
					seen = append(seen, fmt.Sprintf("%s %d Mb/s", n, sp))
					if sp <= 100 {
						slow = append(slow, fmt.Sprintf("%s %d Mb/s", n, sp))
					}
				}
			}
			switch {
			case len(slow) > 0:
				return warn("Link speed", strings.Join(slow, ", "), "A gigabit port negotiated only 10/100 Mb/s: a damaged cable, bad port or old switch. Try another cable.", "")
			case len(seen) > 0:
				return pass("Link speed", strings.Join(seen, ", "))
			}
			return info("Link speed", "no wired link")
		}},
		{"VPN and virtual adapters", func() Check {
			var v []string
			for _, n := range netIfaces() {
				if hasAnyPrefix(n, "tun", "tap", "wg", "tailscale", "ppp", "zt", "proton", "mullvad", "nordlynx", "ipsec") {
					v = append(v, n)
				}
			}
			if len(v) > 0 {
				return info("VPN and virtual adapters", "active: "+strings.Join(v, ", ")+" - traffic may route through a tunnel")
			}
			return pass("VPN and virtual adapters", "none active")
		}},
		{"Hosts file overrides", func() Check {
			n := 0
			for _, l := range lines(readStr("/etc/hosts")) {
				if strings.HasPrefix(l, "#") {
					continue
				}
				f := strings.Fields(l)
				if len(f) < 2 {
					continue
				}
				switch f[0] {
				case "127.0.0.1", "127.0.1.1", "::1", "fe00::0", "ff00::0", "ff02::1", "ff02::2", "ff02::3":
					if f[1] == "localhost" || f[1] == "ip6-localhost" || f[1] == "ip6-loopback" || strings.HasPrefix(f[1], "ip6-") || f[0] == "127.0.1.1" || f[0] == "ff02::1" || f[0] == "ff02::2" {
						continue
					}
				}
				n++
			}
			if n > 0 {
				return info("Hosts file overrides", fmt.Sprintf("%d custom entries in /etc/hosts", n))
			}
			return pass("Hosts file overrides", "none")
		}},
	}
	return tool{Title: "Network diagnostics", Blurb: "no internet, slow Wi-Fi, DNS problems", Defs: defs}
}
