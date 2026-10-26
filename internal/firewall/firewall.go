// Package firewall describes SGC's firewall: which rules there are, how they
// are written down for nftables, and how a change is tried out and either
// confirmed or undone.
//
// SGC does not filter packets itself. It writes a ruleset for nftables, the
// Linux kernel's firewall, into a table of its own ("inet sgc") and leaves
// every other table on the machine alone.
//
// The rules in one sentence: connections the gateway did not ask for are
// refused, except to SGC's page and SSH from "inside".
//
// "Inside" is any private address (the owner's decision, docs/design.md
// §2.1). Traffic from the internet always arrives with a public source
// address, so it never matches; and because nothing has to be detected, the
// rules stay right when the home network's range changes, for example with a
// new router. A rule that named today's range would refuse the owner
// themselves on that day.
//
// This package is used by the root helper and must stay lean: standard
// library only, no database, no network.
package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// The table SGC owns in nftables. "inet" covers IPv4 and IPv6 together.
const tableName = "sgc"

// VPNInterface is the WireGuard interface SGC's VPN uses (internal/wireguard).
// Traffic through it is let past this table; which device may reach what is
// decided in the VPN's own table.
const VPNInterface = "sgc-wg"

// maxProxyPorts bounds the ports proxied services can have.
const maxProxyPorts = 500

// PublicMark is the mark SGC's table for traffic from the internet
// (internal/public, "inet sgc_public") puts on a packet it let through: one
// for a service the owner made public, from a visitor who got past the
// filters. This table accepts such packets while internet access is on
// (Config.Door). Marks are the kernel's own; nothing on the wire sets them.
const PublicMark = 0x53474301

// DoorPort is Traefik's public entry point (internal/public.DoorPort, which
// this package cannot import).
const DoorPort = 8446

// maxSSHPorts bounds a list that comes from this machine's SSH configuration.
const maxSSHPorts = 8

// Inside: the private ranges of IPv4 (RFC 1918), plus the addresses devices
// give themselves when there is no router to hand one out (169.254/16), so a
// cable straight into the gateway still gets in.
var insideV4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
}

// The same for IPv6: unique local addresses and link-local ones. A home
// device's public IPv6 address is deliberately not inside: IPv6 has no
// address translation, so "public" there really can mean "from anywhere".
var insideV6 = []netip.Prefix{
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// InsideV4 returns the IPv4 ranges that count as inside.
func InsideV4() []netip.Prefix { return slices.Clone(insideV4) }

// IsInside reports whether a connection from this address is let in by the
// rules. The machine talking to itself always is.
func IsInside(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if addr.IsLoopback() {
		return true
	}
	ranges := insideV6
	if addr.Is4() {
		ranges = insideV4
	}
	for _, r := range ranges {
		if r.Contains(addr) {
			return true
		}
	}
	return false
}

// Request is what the web process may ask for. Everything else that goes
// into the rules is worked out by the root side itself.
type Request struct {
	Enabled bool `json:"enabled"`
}

// Config is everything that determines the ruleset.
type Config struct {
	Enabled bool `json:"enabled"`
	// SSHPorts are the ports this machine's SSH server listens on, read from
	// its configuration when the rules were made. Opening a fixed port 22
	// would cut off an owner who moved SSH elsewhere.
	SSHPorts []int `json:"sshPorts"`
	// WebPort is where SGC's own page listens.
	WebPort int `json:"webPort"`
	// DNS lets DNS questions in from inside. Set by the root side when
	// AdGuard Home is installed: without something to answer, the port
	// stays shut.
	DNS bool `json:"dns,omitempty"`
	// Proxy lets the proxy's web ports (80, 443) in from inside, and the
	// ports of proxied services ("25565/tcp"). Set by the root side while
	// the proxy is switched on.
	Proxy      bool     `json:"proxy,omitempty"`
	ProxyPorts []string `json:"proxyPorts,omitempty"`
	// VPNPort is the VPN's UDP port, let in from anywhere: the one port that
	// faces the internet. 0 while the VPN is off.
	VPNPort int `json:"vpnPort,omitempty"`
	// Door: internet access is on (docs/design.md §14). What the table for
	// the internet marked is let in, and the public door from inside too
	// (a router that sends the home's own requests for a public name back
	// in). Set by the root side from what the proxy has in place.
	Door bool `json:"door,omitempty"`
}

// Equal reports whether two configurations lead to the same rules.
func (c Config) Equal(other Config) bool {
	a, b := c.normalised(), other.normalised()
	return a.Enabled == b.Enabled && a.WebPort == b.WebPort && a.DNS == b.DNS &&
		a.Proxy == b.Proxy && a.VPNPort == b.VPNPort && a.Door == b.Door &&
		slices.Equal(a.SSHPorts, b.SSHPorts) && slices.Equal(a.ProxyPorts, b.ProxyPorts)
}

func (c Config) normalised() Config {
	ports := slices.Clone(c.SSHPorts)
	slices.Sort(ports)
	c.SSHPorts = slices.Compact(ports)
	proxied := slices.Clone(c.ProxyPorts)
	slices.Sort(proxied)
	c.ProxyPorts = slices.Compact(proxied)
	if len(c.ProxyPorts) == 0 {
		c.ProxyPorts = nil
	}
	return c
}

// splitProxyPort reads "25565/tcp".
func splitProxyPort(s string) (int, string, bool) {
	number, protocol, found := strings.Cut(s, "/")
	port, err := strconv.Atoi(number)
	if !found || err != nil || !validPort(port) || (protocol != "tcp" && protocol != "udp") {
		return 0, "", false
	}
	return port, protocol, true
}

func (c Config) validate() error {
	if !validPort(c.WebPort) {
		return fmt.Errorf("port %d for SGC's page is not a valid port", c.WebPort)
	}
	if len(c.SSHPorts) > maxSSHPorts {
		return fmt.Errorf("more than %d SSH ports", maxSSHPorts)
	}
	for _, port := range c.SSHPorts {
		if !validPort(port) {
			return fmt.Errorf("SSH port %d is not a valid port", port)
		}
	}
	if len(c.ProxyPorts) > maxProxyPorts {
		return fmt.Errorf("more than %d ports for proxied services", maxProxyPorts)
	}
	for _, p := range c.ProxyPorts {
		if _, _, ok := splitProxyPort(p); !ok {
			return fmt.Errorf("%q is not a port for a proxied service", p)
		}
	}
	if c.VPNPort != 0 && !validPort(c.VPNPort) {
		return fmt.Errorf("port %d for the VPN is not a valid port", c.VPNPort)
	}
	return nil
}

func validPort(port int) bool { return port >= 1 && port <= 65535 }

// configMarker starts the line of a ruleset file that says what the rules
// were made from. Keeping it inside the file means there is one file to
// replace when a change is confirmed, and it can never disagree with itself.
const configMarker = "# sgc-config: "

// Render writes the ruleset for nftables. Loading the result always leaves
// the firewall in exactly the described state, whatever was loaded before:
// it removes SGC's table and, if the firewall is on, creates it again, as
// one step that either happens completely or not at all.
//
// Every value that ends up in the text is a number checked here or a
// constant of this package; nothing is copied in from outside.
func Render(cfg Config) (string, error) {
	if err := cfg.validate(); err != nil {
		return "", err
	}
	cfg = cfg.normalised()
	description, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Written by SGC. Do not edit: SGC replaces this file.\n")
	b.WriteString(configMarker + string(description) + "\n\n")
	// "destroy" rather than "delete": it is not an error if the table is not there.
	fmt.Fprintf(&b, "destroy table inet %s\n", tableName)
	if !cfg.Enabled {
		return b.String(), nil
	}

	ports := slices.Clone(cfg.SSHPorts)
	ports = append(ports, cfg.WebPort)
	slices.Sort(ports)
	ports = slices.Compact(ports)

	fmt.Fprintf(&b, "table inet %s {\n", tableName)
	fmt.Fprintf(&b, "\tset inside4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n", joinPrefixes(insideV4))
	fmt.Fprintf(&b, "\tset inside6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n", joinPrefixes(insideV6))
	b.WriteString(`	counter refused {
	}
	chain input {
		type filter hook input priority filter; policy drop;
		# Answers to what this machine itself asked for.
		ct state established,related accept
		ct state invalid drop
		# The machine talking to itself.
		iif "lo" accept
		# IPv6 does not work without these; they never cross a router.
		icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query } accept
		# Getting and keeping an address from the router (DHCP).
		udp sport 67 udp dport 68 accept
		ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
`)
	if cfg.VPNPort != 0 {
		fmt.Fprintf(&b, "\t\t# The VPN, from anywhere: the one port that faces the internet.\n\t\tudp dport %d accept\n", cfg.VPNPort)
	}
	b.WriteString(`		ip saddr @inside4 jump inside
		ip6 saddr @inside6 jump inside
`)
	if cfg.Door {
		fmt.Fprintf(&b, "\t\t# From the internet: what SGC's table for public services let through.\n\t\tmeta mark 0x%08x accept\n", PublicMark)
	}
	b.WriteString(`		counter name refused drop
	}
	chain inside {
`)
	fmt.Fprintf(&b, "\t\ttcp dport { %s } accept\n", joinPorts(ports))
	if cfg.DNS {
		b.WriteString("\t\t# DNS, answered by AdGuard Home.\n\t\tmeta l4proto { tcp, udp } th dport 53 accept\n")
	}
	if cfg.Proxy {
		b.WriteString("\t\t# The proxy (Traefik): the names of the home network.\n\t\ttcp dport { 80, 443 } accept\n")
		var tcpPorts, udpPorts []int
		for _, p := range cfg.ProxyPorts {
			port, protocol, _ := splitProxyPort(p)
			if protocol == "tcp" {
				tcpPorts = append(tcpPorts, port)
			} else {
				udpPorts = append(udpPorts, port)
			}
		}
		if len(tcpPorts) > 0 || len(udpPorts) > 0 {
			b.WriteString("\t\t# Services passed on by the proxy at a port of their own.\n")
		}
		if len(tcpPorts) > 0 {
			slices.Sort(tcpPorts)
			fmt.Fprintf(&b, "\t\ttcp dport { %s } accept\n", joinPorts(slices.Compact(tcpPorts)))
		}
		if len(udpPorts) > 0 {
			slices.Sort(udpPorts)
			fmt.Fprintf(&b, "\t\tudp dport { %s } accept\n", joinPorts(slices.Compact(udpPorts)))
		}
	}
	if cfg.Door {
		fmt.Fprintf(&b, "\t\t# The public door, from inside too.\n\t\ttcp dport %d accept\n", DoorPort)
	}
	b.WriteString(`		icmp type echo-request accept
		icmpv6 type echo-request accept
	}
`)
	if cfg.VPNPort == 0 {
		b.WriteString(`	# The gateway does not pass traffic on between networks yet.
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
`)
		return b.String(), nil
	}
	fmt.Fprintf(&b, `	# Only the VPN's traffic passes the gateway. Which device may reach what
	# is decided in the VPN's own table (inet sgc_vpn), which also has to
	# let it through.
	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state invalid drop
		iifname "%[1]s" accept
		oifname "%[1]s" ct state established,related accept
	}
}
`, VPNInterface)
	return b.String(), nil
}

func joinPrefixes(prefixes []netip.Prefix) string {
	parts := make([]string, len(prefixes))
	for i, p := range prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ", ")
}

// ParseConfig reads back what a ruleset written by Render was made from.
func ParseConfig(ruleset []byte) (Config, error) {
	for line := range bytes.Lines(ruleset) {
		rest, found := bytes.CutPrefix(line, []byte(configMarker))
		if !found {
			continue
		}
		var cfg Config
		decoder := json.NewDecoder(bytes.NewReader(rest))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("read the firewall description: %w", err)
		}
		return cfg, nil
	}
	return Config{}, errors.New("not a ruleset written by SGC")
}
