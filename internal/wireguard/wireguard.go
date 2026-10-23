// Package wireguard is the root side of SGC's VPN: what its configuration
// may contain, the WireGuard settings and the VPN's own nftables table that
// are made from it, and the small program (sgc-wireguard.service) that puts
// them in place, keeps them in place across restarts, and reads the counters
// (docs/design.md §4.9 and §10).
//
// The web process sends the whole configuration, typed: the server's key and
// port, and per device its public key, its address in the tunnel and what it
// may reach. Everything is checked here again. The files and the ruleset are
// written from constants and those checked values only.
//
// The VPN keeps running when SGC does not: the interface lives in the
// kernel, and this program sets it up again at every start of the device
// from the last state that worked.
//
// Used by the root helper: standard library only.
package wireguard

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	// Interface is the WireGuard interface (internal/firewall knows it too).
	Interface = "sgc-wg"
	// TableName is the VPN's own nftables table.
	TableName = "sgc_vpn"

	maxPeers   = 250
	maxAllowed = 500
)

// Access is what a device reaches.
const (
	// AccessFull: the whole home network, SGC's page and SSH included.
	AccessFull = "full"
	// AccessServices: the gateway's DNS and proxy, and what is listed.
	AccessServices = "services"
)

// Endpoint is a port on a device in the home network ("direct" services).
type Endpoint struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// Peer is one device.
type Peer struct {
	PublicKey    string `json:"publicKey"`
	PresharedKey string `json:"presharedKey"`
	// Address is the device's address in the tunnel (one address).
	Address string `json:"address"`
	Access  string `json:"access"`
	// For AccessServices: the direct services it may reach, and the
	// gateway's own ports of proxied services ("25565/tcp").
	Direct       []Endpoint `json:"direct,omitempty"`
	GatewayPorts []string   `json:"gatewayPorts,omitempty"`
}

// Config is the VPN as a whole.
type Config struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
	// Network is the tunnel's range; the gateway has its first address.
	Network    string `json:"network"`
	PrivateKey string `json:"privateKey"`
	Peers      []Peer `json:"peers"`
}

func validKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// privateRanges are where a tunnel and the home network may be.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

func private(p netip.Prefix) bool {
	for _, r := range privateRanges {
		if r.Contains(p.Addr()) && p.Bits() >= r.Bits() {
			return true
		}
	}
	return false
}

// GatewayAddress is the gateway's own address in a tunnel range.
func GatewayAddress(network netip.Prefix) netip.Addr { return network.Masked().Addr().Next() }

// Validate checks everything.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !validPort(c.Port) {
		return errors.New("the VPN's port is not a valid port")
	}
	network, err := netip.ParsePrefix(c.Network)
	if err != nil || !network.Addr().Is4() || network.Masked() != network || network.Bits() < 16 || network.Bits() > 28 || !private(network) {
		return errors.New("the tunnel's range must be a private IPv4 range from /16 to /28")
	}
	if !validKey(c.PrivateKey) {
		return errors.New("the server's key is not a WireGuard key")
	}
	if len(c.Peers) > maxPeers {
		return fmt.Errorf("more than %d devices", maxPeers)
	}
	keys, addresses := map[string]bool{}, map[string]bool{}
	gateway := GatewayAddress(network)
	for i, p := range c.Peers {
		if !validKey(p.PublicKey) || !validKey(p.PresharedKey) {
			return fmt.Errorf("device %d: a key is not a WireGuard key", i+1)
		}
		if keys[p.PublicKey] {
			return fmt.Errorf("device %d: the same key twice", i+1)
		}
		keys[p.PublicKey] = true
		addr, err := netip.ParseAddr(p.Address)
		if err != nil || !addr.Is4() || !network.Contains(addr) || addr == gateway || addr == network.Addr() ||
			addr == lastAddress(network) {
			return fmt.Errorf("device %d: %q is not an address for a device in the tunnel", i+1, p.Address)
		}
		if addresses[p.Address] {
			return fmt.Errorf("device %d: the address %s twice", i+1, p.Address)
		}
		addresses[p.Address] = true
		switch p.Access {
		case AccessFull:
			if len(p.Direct) > 0 || len(p.GatewayPorts) > 0 {
				return fmt.Errorf("device %d: a full-network device has no list", i+1)
			}
		case AccessServices:
			if len(p.Direct)+len(p.GatewayPorts) > maxAllowed {
				return fmt.Errorf("device %d: too many allowed services", i+1)
			}
			for _, e := range p.Direct {
				ip, err := netip.ParseAddr(e.IP)
				if err != nil || !ip.Is4() || !private(netip.PrefixFrom(ip, 32)) || network.Contains(ip) || !validPort(e.Port) ||
					(e.Protocol != "tcp" && e.Protocol != "udp") {
					return fmt.Errorf("device %d: %v is not a service in the home network", i+1, e)
				}
			}
			for _, gp := range p.GatewayPorts {
				if _, _, ok := splitPort(gp); !ok {
					return fmt.Errorf("device %d: %q is not a port of the gateway", i+1, gp)
				}
			}
		default:
			return fmt.Errorf("device %d: unknown access %q", i+1, p.Access)
		}
	}
	return nil
}

func lastAddress(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func splitPort(s string) (int, string, bool) {
	number, protocol, found := strings.Cut(s, "/")
	port, err := strconv.Atoi(number)
	if !found || err != nil || !validPort(port) || (protocol != "tcp" && protocol != "udp") {
		return 0, "", false
	}
	return port, protocol, true
}

// RenderWireGuard writes the settings for `wg setconf`/`wg syncconf`: the
// interface's key and port, and the peers. (The address of the interface is
// set with ip; it is not part of this format.)
func RenderWireGuard(c Config) string {
	var b strings.Builder
	b.WriteString("# Written by SGC. Do not edit: SGC replaces this file.\n[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\nListenPort = %d\n", c.PrivateKey, c.Port)
	peers := slices.Clone(c.Peers)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Address < peers[j].Address })
	for _, p := range peers {
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", p.PublicKey, p.PresharedKey, p.Address)
	}
	return b.String()
}

// RenderRules writes the VPN's own nftables table: which device may reach
// what, and address translation of the VPN's traffic into the home network
// (the devices there do not know the tunnel's range). Loading it replaces
// the table as one step. Off, it only removes the table.
//
// Every packet has to pass this table and SGC's firewall table (when that
// is on): the firewall lets the VPN's traffic past, and this table decides.
func RenderRules(c Config) string {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n# Written by SGC. Do not edit: SGC replaces this file.\n\n")
	fmt.Fprintf(&b, "destroy table inet %s\n", TableName)
	if !c.Enabled {
		return b.String()
	}
	network := netip.MustParsePrefix(c.Network)
	var full, services []string
	var direct []string
	var gatewayPorts []string
	peers := slices.Clone(c.Peers)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Address < peers[j].Address })
	for _, p := range peers {
		if p.Access == AccessFull {
			full = append(full, p.Address)
			continue
		}
		services = append(services, p.Address)
		for _, e := range p.Direct {
			direct = append(direct, fmt.Sprintf("%s . %s . %s . %d", p.Address, e.IP, e.Protocol, e.Port))
		}
		for _, gp := range p.GatewayPorts {
			port, protocol, _ := splitPort(gp)
			gatewayPorts = append(gatewayPorts, fmt.Sprintf("%s . %s . %d", p.Address, protocol, port))
		}
	}
	slices.Sort(direct)
	direct = slices.Compact(direct)
	slices.Sort(gatewayPorts)
	gatewayPorts = slices.Compact(gatewayPorts)

	set := func(name, typ string, elements []string, interval bool) {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n", name, typ)
		if interval {
			b.WriteString("\t\tflags interval\n")
		}
		if len(elements) > 0 {
			fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(elements, ", "))
		}
		b.WriteString("\t}\n")
	}
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	set("full", "ipv4_addr", full, false)
	set("services", "ipv4_addr", services, false)
	set("direct", "ipv4_addr . ipv4_addr . inet_proto . inet_service", direct, false)
	set("gateway_ports", "ipv4_addr . inet_proto . inet_service", gatewayPorts, false)

	fmt.Fprintf(&b, `	# What a device in the tunnel may ask of the gateway itself. A device
	# whose person reaches services only gets DNS and the proxy, and the
	# gateway's ports of the proxied services on its list: not SGC's page,
	# not SSH.
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "%[1]s" ip saddr @full accept
		iifname "%[1]s" ip saddr @services jump services_only
		iifname "%[1]s" drop
	}
	chain services_only {
		ct state established,related accept
		meta l4proto { tcp, udp } th dport 53 accept
		tcp dport { 80, 443 } accept
		ip saddr . meta l4proto . th dport @gateway_ports accept
		icmp type echo-request accept
		drop
	}
`, Interface)
	fmt.Fprintf(&b, `	# What passes through the gateway: full-network devices to anywhere, the
	# others only to the services on their list; and the answers back.
	chain forward {
		type filter hook forward priority filter; policy accept;
		ct state invalid drop
		iifname "%[1]s" ip saddr @full accept
		iifname "%[1]s" ip saddr . ip daddr . meta l4proto . th dport @direct accept
		iifname "%[1]s" drop
		oifname "%[1]s" ct state established,related accept
		oifname "%[1]s" drop
	}
	# The home network does not know the tunnel's range: what leaves the
	# tunnel goes on with the gateway's address. Traffic to the internet
	# (devices that send everything through home) the same.
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr %[2]s oifname != "%[1]s" masquerade
	}
}
`, Interface, network.String())
	return b.String()
}
