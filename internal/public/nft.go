package public

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Troglobitten/sgc/internal/firewall"
)

// Table is everything the table for traffic from the internet is made of.
// Settings come from the owner (checked); the ports from what Traefik has in
// place; the ranges from the lists, read and merged by the job.
type Table struct {
	Settings Settings
	// Public are the ports reachable from the internet (the door, while a
	// website is public; the own port of each other public service).
	Public []Port
	// Closed are Traefik's other ports: never from the internet.
	Closed []Port
	// Reserved are the device's own ports, which can never be in Public or
	// Closed (SSH, SGC's page, DNS, the VPN's).
	Reserved []Port
	// Blocked are the ranges of the FireHOL levels switched on, merged.
	Blocked []Range
	// Countries are the ranges of the chosen countries, merged.
	Countries []Range
}

// The device's own ports, which no rule here may name.
var ownPorts = []Port{{22, "tcp"}, {53, "tcp"}, {53, "udp"}, {80, "tcp"}, {443, "tcp"}, {3000, "tcp"},
	{8082, "tcp"}, {8443, "tcp"}, {8444, "tcp"}, {8445, "tcp"}}

// maxRanges bounds a set: the four levels together are about 210,000 ranges.
const maxRanges = 1_000_000

func (t Table) validate() error {
	if err := t.Settings.Validate(); err != nil {
		return err
	}
	reserved := slices.Concat(ownPorts, t.Reserved)
	seen := map[Port]bool{}
	for _, p := range slices.Concat(t.Public, t.Closed) {
		if p.Number < 1 || p.Number > 65535 || (p.Protocol != "tcp" && p.Protocol != "udp") {
			return fmt.Errorf("%v is not a port", p)
		}
		if slices.Contains(reserved, p) {
			return fmt.Errorf("port %v is the device's own and is not for a service", p)
		}
		if seen[p] {
			return fmt.Errorf("port %v is both public and not", p)
		}
		seen[p] = true
	}
	if len(t.Blocked) > maxRanges || len(t.Countries) > maxRanges {
		return errors.New("a list is larger than any list of addresses SGC uses")
	}
	for _, r := range slices.Concat(t.Blocked, t.Countries) {
		if !r.From.Is4() || !r.To.Is4() || r.To.Less(r.From) {
			return fmt.Errorf("%v is not a range of IPv4 addresses", r)
		}
	}
	return nil
}

// Render writes the table for nftables. Loading it replaces SGC's rules
// for traffic from the internet in one step, and keeps the addresses
// fail2ban has banned: they are in a set of their own that is made if it
// is missing and otherwise left as it is.
func Render(t Table) (string, error) {
	if err := t.validate(); err != nil {
		return "", err
	}
	s := t.Settings
	var allow []netip.Prefix
	for _, entry := range s.Allow {
		p, _ := ParseAllow(entry)
		allow = append(allow, p)
	}
	mark := fmt.Sprintf("0x%08x", firewall.PublicMark)

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Written by SGC. Do not edit: SGC replaces this file.\n")
	b.WriteString("# Traffic from the internet to services the owner made public (docs/design.md §14).\n\n")
	fmt.Fprintf(&b, "add table inet %s\n", TableName)
	fmt.Fprintf(&b, "# fail2ban's bans (it adds them through /etc/fail2ban/action.d/sgc.conf); kept when the rest is replaced.\n")
	fmt.Fprintf(&b, "add set inet %s banned4 { type ipv4_addr; flags timeout; }\n", TableName)
	for _, chain := range []string{"input", "visitors"} {
		fmt.Fprintf(&b, "destroy chain inet %s %s\n", TableName, chain)
	}
	for _, set := range []string{"inside4", "allow4", "blocked4", "countries4", "public_tcp", "public_udp", "closed_tcp", "closed_udp", "new4"} {
		fmt.Fprintf(&b, "destroy set inet %s %s\n", TableName, set)
	}

	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	writeSet(&b, "inside4", "ipv4_addr", true, prefixElements(firewall.InsideV4()))
	writeSet(&b, "allow4", "ipv4_addr", true, prefixElements(allow))
	writeSet(&b, "blocked4", "ipv4_addr", true, rangeElements(t.Blocked))
	writeSet(&b, "countries4", "ipv4_addr", true, rangeElements(t.Countries))
	writeSet(&b, "public_tcp", "inet_service", false, portElements(t.Public, "tcp"))
	writeSet(&b, "public_udp", "inet_service", false, portElements(t.Public, "udp"))
	writeSet(&b, "closed_tcp", "inet_service", false, portElements(t.Closed, "tcp"))
	writeSet(&b, "closed_udp", "inet_service", false, portElements(t.Closed, "udp"))
	// Visitors seen lately, for the limit on new connections.
	b.WriteString("\tset new4 {\n\t\ttype ipv4_addr\n\t\tsize 65535\n\t\tflags dynamic,timeout\n\t\ttimeout 5m\n\t}\n")

	b.WriteString("\t# What a visitor from the internet must get past.\n")
	b.WriteString("\tchain visitors {\n")
	fmt.Fprintf(&b, "\t\tip saddr @allow4 meta mark set %s accept\n", mark)
	b.WriteString("\t\tip saddr @banned4 counter drop\n")
	b.WriteString("\t\tip saddr @blocked4 counter drop\n")
	switch s.CountryMode {
	case CountryAllow:
		b.WriteString("\t\tip saddr != @countries4 counter drop\n")
	case CountryBlock:
		b.WriteString("\t\tip saddr @countries4 counter drop\n")
	}
	fmt.Fprintf(&b, "\t\tct state new add @new4 { ip saddr limit rate over %d/minute burst %d packets } counter drop\n",
		s.ConnectionsPerMinute, s.ConnectionsPerMinute)
	fmt.Fprintf(&b, "\t\tmeta mark set %s\n", mark)
	b.WriteString("\t}\n")

	// Before SGC's own table (priority filter), which accepts the marked.
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter - 10; policy accept;\n")
	b.WriteString("\t\t# IPv4 only, from outside only: nothing below can touch the device itself, the home\n")
	b.WriteString("\t\t# network or the VPN. (FireHOL's level 1 lists 127.0.0.0/8 among its bogons.)\n")
	b.WriteString("\t\tiif \"lo\" return\n")
	b.WriteString("\t\tmeta nfproto != ipv4 return\n")
	b.WriteString("\t\tip saddr @inside4 return\n")
	b.WriteString("\t\t# Answers to what the device itself asked for.\n")
	b.WriteString("\t\tct direction reply return\n")
	b.WriteString("\t\ttcp dport @public_tcp jump visitors\n")
	b.WriteString("\t\tudp dport @public_udp jump visitors\n")
	b.WriteString("\t\t# Traefik's other ports, connections already open included: a service just closed stops here.\n")
	b.WriteString("\t\ttcp dport @closed_tcp counter drop\n")
	b.WriteString("\t\tudp dport @closed_udp counter drop\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}

// RenderOff removes the table: nothing from the internet is let in.
func RenderOff() string {
	return "#!/usr/sbin/nft -f\n# Written by SGC: no services are reachable from the internet.\ndestroy table inet " + TableName + "\n"
}

func writeSet(b *strings.Builder, name, kind string, interval bool, elements []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n", name, kind)
	if interval {
		b.WriteString("\t\tflags interval\n")
	}
	if len(elements) > 0 {
		b.WriteString("\t\telements = {\n")
		for i := 0; i < len(elements); i += 8 {
			end := min(i+8, len(elements))
			fmt.Fprintf(b, "\t\t\t%s,\n", strings.Join(elements[i:end], ", "))
		}
		b.WriteString("\t\t}\n")
	}
	b.WriteString("\t}\n")
}

func prefixElements(prefixes []netip.Prefix) []string {
	ranges := make([]Range, 0, len(prefixes))
	for _, p := range prefixes {
		ranges = append(ranges, prefixRange(p))
	}
	return rangeElements(Merge(ranges))
}

func rangeElements(ranges []Range) []string {
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, r.String())
	}
	return out
}

func portElements(ports []Port, protocol string) []string {
	var numbers []int
	for _, p := range ports {
		if p.Protocol == protocol {
			numbers = append(numbers, p.Number)
		}
	}
	slices.Sort(numbers)
	numbers = slices.Compact(numbers)
	out := make([]string, len(numbers))
	for i, n := range numbers {
		out[i] = strconv.Itoa(n)
	}
	return out
}
