package main

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/doctor"
	"github.com/Troglobitten/sgc/internal/firewall"
)

const adguardLog = "Its log: sudo journalctl -u sgc-adguard --no-pager -n 30"

func checkDNS(ctx context.Context) []doctor.Result {
	paths := adguard.DefaultPaths()
	const switchOn = "to switch it on: SGC's System page, or sudo sgc dns on"
	if !adguard.Installed(paths) {
		return one(doctor.Good("DNS is off: AdGuard Home is not on this device (" + switchOn + ")"))
	}
	version := adguard.InstalledVersion(paths)
	if state, _ := ask(ctx, "/usr/bin/systemctl", "is-active", adguard.ServiceUnit); state != "active" {
		// Switched off by the owner is no problem. Switched on and not
		// running is one.
		if enabled, _ := ask(ctx, "/usr/bin/systemctl", "is-enabled", adguard.ServiceUnit); enabled != "enabled" {
			return one(doctor.Good("DNS is switched off; AdGuard Home " + version + " and its settings stay on this device (" + switchOn + ")"))
		}
		return one(doctor.Bad("AdGuard Home "+version+" is installed but not running ("+state+")",
			"Start it: sudo systemctl start sgc-adguard\n"+adguardLog))
	}
	// The real thing: a question, asked the way a device in the network would.
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", adguard.DNSPort))
	}}
	asked, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if _, err := resolver.LookupHost(asked, "debian.org"); err != nil {
		return one(doctor.Bad("AdGuard Home runs but did not answer a DNS question: "+err.Error(),
			"Does the device reach the internet? AdGuard Home asks Quad9 unless you changed that in its page.\n"+adguardLog))
	}
	results := one(doctor.Good("AdGuard Home " + version + " runs and answers DNS questions"))
	// The device asks other servers than AdGuard Home for its own lookups, so
	// that updates and certificates do not depend on it. They must work too.
	if _, err := ask(ctx, "/usr/bin/getent", "ahosts", "deb.debian.org"); err != nil {
		results = append(results, doctor.Bad("The device itself cannot look up names",
			"Which servers it asks: cat /etc/resolv.conf\nIf systemd-resolved is in use: sudo systemctl restart systemd-resolved"))
	}

	// With the firewall on, DNS has to be let in, or only this device is served.
	if state, err := firewall.ReadState(firewall.DefaultPaths()); err == nil && state.Confirmed != nil && state.Confirmed.Enabled && !state.Confirmed.DNS {
		results = append(results, doctor.Warn("The firewall does not let DNS in yet, so only this device itself is answered",
			"On SGC's System page, under DNS: \"Let DNS in\"."))
	}
	return results
}

// The ports SGC's parts listen on, now or in a later version. Something else
// sitting on one of them is better known before than found out at setup.
var neededPorts = []struct {
	port int
	what string
}{
	{53, "DNS (AdGuard Home)"},
	{80, "the proxy"},
	{443, "the proxy"},
	{51820, "the VPN"},
}

// ownPart tells SGC's own parts on their ports from other programs:
// AdGuard Home, Traefik, and WireGuard, which is part of the kernel, so its
// socket has no program. systemd-resolved steps aside by itself when
// AdGuard Home is installed.
func ownPart(port int, protocol, program string, hasProgram bool) bool {
	switch {
	case program == "AdGuardHome" || program == "systemd-resolve":
		return true
	case program == "traefik" && (port == 80 || port == 443):
		return true
	case port == 51820 && protocol == "udp" && !hasProgram:
		return true
	}
	return false
}

func checkPorts(ctx context.Context) []doctor.Result {
	output, err := ask(ctx, "/usr/bin/ss", "-H", "-lntup")
	if err != nil {
		return one(doctor.Warn("Which ports are in use could not be found out: "+err.Error(), ""))
	}
	taken := takenPorts(output)
	if len(taken) == 0 {
		return one(doctor.Good("The ports SGC needs, now or later, are free (53, 80, 443, 51820)"))
	}
	return one(doctor.Warn("In use by another program: port "+strings.Join(taken, "; port "),
		"SGC's part for that port cannot start while it is taken. Which program: sudo ss -lntup"))
}

// takenPorts reads `ss -H -lntup` and says which of the ports SGC needs
// another program holds, as "80 (the proxy) by nginx".
func takenPorts(output string) []string {
	var taken []string
	for line := range strings.Lines(output) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		address := fields[4]
		port := address[strings.LastIndex(address, ":")+1:]
		program := "a program"
		_, rest, hasProgram := strings.Cut(line, `users:(("`)
		if hasProgram {
			program, _, _ = strings.Cut(rest, `"`)
		}
		for _, needed := range neededPorts {
			if port != fmt.Sprint(needed.port) || ownPart(needed.port, fields[0], program, hasProgram) {
				continue
			}
			entry := fmt.Sprintf("%d (%s) by %s", needed.port, needed.what, program)
			if !slices.Contains(taken, entry) {
				taken = append(taken, entry)
			}
		}
	}
	return taken
}
