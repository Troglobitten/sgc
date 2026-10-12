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
	if !adguard.Installed(paths) {
		return one(doctor.Good("AdGuard Home (DNS) is not installed"))
	}
	version := adguard.InstalledVersion(paths)
	if state, _ := ask(ctx, "/usr/bin/systemctl", "is-active", adguard.ServiceUnit); state != "active" {
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

func checkPorts(ctx context.Context) []doctor.Result {
	output, err := ask(ctx, "/usr/bin/ss", "-H", "-lntup")
	if err != nil {
		return one(doctor.Warn("Which ports are in use could not be found out: "+err.Error(), ""))
	}
	var taken []string
	for line := range strings.Lines(output) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		address := fields[4]
		port := address[strings.LastIndex(address, ":")+1:]
		program := "a program"
		if _, rest, ok := strings.Cut(line, `users:(("`); ok {
			program, _, _ = strings.Cut(rest, `"`)
		}
		for _, needed := range neededPorts {
			// SGC's own parts are where they belong. And systemd-resolved
			// steps aside by itself when AdGuard Home is installed.
			if port != fmt.Sprint(needed.port) || program == "AdGuardHome" || program == "systemd-resolve" {
				continue
			}
			entry := fmt.Sprintf("%d (%s) by %s", needed.port, needed.what, program)
			if !slices.Contains(taken, entry) {
				taken = append(taken, entry)
			}
		}
	}
	if len(taken) == 0 {
		return one(doctor.Good("The ports SGC needs, now or later, are free (53, 80, 443, 51820)"))
	}
	return one(doctor.Warn("In use by another program: port "+strings.Join(taken, "; port "),
		"SGC's part for that port cannot start while it is taken. Which program: sudo ss -lntup"))
}
