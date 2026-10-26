// Package public is the root side of services reachable from the internet
// (docs/design.md §14): the firewall table for traffic from the internet
// ("inet sgc_public"), the lists it filters with, and fail2ban's settings.
//
// The shape, in one paragraph. The router forwards the internet's port 443
// to Traefik's public entry point on the device (DoorPort), and each public
// non-web service's port to the same port on the device. SGC's own firewall table
// (internal/firewall) refuses everything from outside, except packets this
// table has marked (PublicMark). This table looks at traffic from outside
// addresses only, to the door and to Traefik's ports: what goes to a public
// port and passes the filters (allow list, bans, FireHOL's lists, the
// country filter, a limit on new connections per visitor) is marked; what
// goes to one of Traefik's other ports is dropped, connections already open
// included, which is how closing a service cuts them. Home addresses and the
// VPN never reach a rule here that could drop them.
//
// Changing this table needs no confirmation (docs/design.md §4.2): it cannot
// touch the way in from home. Every drop in it is behind a check that the
// sender is outside, and the ports it knows are Traefik's.
//
// Used by the root helper's jobs: standard library only, no database, no
// network.
package public

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// DoorPort is Traefik's public entry point: the router forwards the
// internet's port 443 here. Next to SGC's own ports (8443 to 8445).
const DoorPort = 8446

// TableName is the nftables table this package owns.
const TableName = "sgc_public"

// The names of the lists. FireHOL's levels are separate lists, not a
// ladder (checked 2026-10-25: each is made from other sources), so each is
// fetched and switched on its own.
const (
	ListLevel1  = "firehol_level1"
	ListLevel2  = "firehol_level2"
	ListLevel3  = "firehol_level3"
	ListLevel4  = "firehol_level4"
	ListCountry = "dbip-country"
)

// FireHOLLevels are the four lists in order.
var FireHOLLevels = []string{ListLevel1, ListLevel2, ListLevel3, ListLevel4}

// Country filter modes.
const (
	CountryOff   = ""
	CountryAllow = "allow" // only visitors from these countries
	CountryBlock = "block" // visitors from anywhere but these countries
)

// Bounds on what the owner can set, here and in the page.
const (
	MinRequestsPerMinute    = 10
	MaxRequestsPerMinute    = 100000
	MinConnectionsPerMinute = 1
	MaxConnectionsPerMinute = 10000
	maxAllow                = 256
	maxCountries            = 250
	// The shortest range the allow list takes: /8. Anything wider would
	// switch the filters off for a large part of the internet by mistake.
	minAllowBits = 8
)

// List names a downloaded list and the SHA-256 of the file, so that the
// job uses exactly the file the web process meant.
type List struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Fail2ban is the owner's settings for banning repeat offenders.
type Fail2ban struct {
	Enabled bool `json:"enabled"`
	// SignIns: failed sign-ins at SGC's login on a public service before a
	// ban. Refused: refused requests at the public door (401, 403, 404, 429)
	// before a ban.
	SignIns     int `json:"signIns"`
	Refused     int `json:"refused"`
	FindMinutes int `json:"findMinutes"`
	BanMinutes  int `json:"banMinutes"`
}

// Settings are the owner's choices for visitors from the internet. The web
// process sends them with the proxy's configuration; they are checked here
// again.
type Settings struct {
	// RequestsPerMinute is per visitor, for websites (Traefik's limit).
	RequestsPerMinute int `json:"requestsPerMinute"`
	// ConnectionsPerMinute is per visitor: new connections to any public
	// port, the door included (the firewall's limit).
	ConnectionsPerMinute int `json:"connectionsPerMinute"`
	// Allow are addresses or ranges every filter lets through.
	Allow []string `json:"allow"`
	// FireHOL are the levels switched on whose file is there.
	FireHOL     []List   `json:"firehol"`
	CountryMode string   `json:"countryMode"`
	Countries   []string `json:"countries"`
	// CountryList is DB-IP's file, needed when the country filter is on.
	CountryList *List    `json:"countryList,omitempty"`
	Fail2ban    Fail2ban `json:"fail2ban"`
}

var (
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)
)

// ParseAllow reads one entry of the allow list: an IPv4 address or range.
func ParseAllow(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is4() {
			return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 address", s)
		}
		return netip.PrefixFrom(addr, 32), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 range", s)
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("%q is not the start of its range (%s)", s, p.Masked())
	}
	if p.Bits() < minAllowBits {
		return netip.Prefix{}, fmt.Errorf("%q is wider than a /%d", s, minAllowBits)
	}
	return p, nil
}

// Validate checks the settings. The web process checked them before
// sending; this is the check that counts.
func (s Settings) Validate() error {
	if s.RequestsPerMinute < MinRequestsPerMinute || s.RequestsPerMinute > MaxRequestsPerMinute {
		return fmt.Errorf("the limit of requests per minute is %d to %d", MinRequestsPerMinute, MaxRequestsPerMinute)
	}
	if s.ConnectionsPerMinute < MinConnectionsPerMinute || s.ConnectionsPerMinute > MaxConnectionsPerMinute {
		return fmt.Errorf("the limit of new connections per minute is %d to %d", MinConnectionsPerMinute, MaxConnectionsPerMinute)
	}
	if len(s.Allow) > maxAllow {
		return fmt.Errorf("more than %d entries on the allow list", maxAllow)
	}
	for _, entry := range s.Allow {
		if _, err := ParseAllow(entry); err != nil {
			return fmt.Errorf("the allow list: %w", err)
		}
	}
	seen := map[string]bool{}
	for _, l := range s.FireHOL {
		if !slices.Contains(FireHOLLevels, l.Name) || seen[l.Name] {
			return fmt.Errorf("%q is not one of FireHOL's levels, or comes twice", l.Name)
		}
		seen[l.Name] = true
		if !sha256Pattern.MatchString(l.SHA256) {
			return fmt.Errorf("the list %s has no checksum", l.Name)
		}
	}
	switch s.CountryMode {
	case CountryOff:
		if len(s.Countries) > 0 || s.CountryList != nil {
			return errors.New("countries without a country filter")
		}
	case CountryAllow, CountryBlock:
		if len(s.Countries) == 0 || len(s.Countries) > maxCountries {
			return fmt.Errorf("the country filter needs 1 to %d countries", maxCountries)
		}
		for _, c := range s.Countries {
			if !countryPattern.MatchString(c) {
				return fmt.Errorf("%q is not a country code", c)
			}
		}
		if s.CountryList == nil || s.CountryList.Name != ListCountry || !sha256Pattern.MatchString(s.CountryList.SHA256) {
			return errors.New("the country filter needs DB-IP's list")
		}
	default:
		return fmt.Errorf("unknown country filter %q", s.CountryMode)
	}
	f := s.Fail2ban
	if f.SignIns < 1 || f.SignIns > 100 || f.Refused < 1 || f.Refused > 10000 ||
		f.FindMinutes < 1 || f.FindMinutes > 1440 || f.BanMinutes < 1 || f.BanMinutes > 525600 {
		return errors.New("fail2ban's numbers are out of bounds")
	}
	return nil
}

// Defaults are the settings until the owner changes them.
func Defaults() Settings {
	return Settings{
		RequestsPerMinute:    600,
		ConnectionsPerMinute: 120,
		Allow:                []string{},
		FireHOL:              []List{},
		Countries:            []string{},
		Fail2ban:             Fail2ban{SignIns: 5, Refused: 40, FindMinutes: 10, BanMinutes: 60},
	}
}

// Port is a public port: a number and "tcp" or "udp".
type Port struct {
	Number   int
	Protocol string
}

func (p Port) String() string { return fmt.Sprintf("%d/%s", p.Number, p.Protocol) }

// ParsePort reads "25565/tcp".
func ParsePort(s string) (Port, bool) {
	number, protocol, found := strings.Cut(s, "/")
	var n int
	if _, err := fmt.Sscanf(number, "%d", &n); !found || err != nil || fmt.Sprint(n) != number || n < 1 || n > 65535 ||
		(protocol != "tcp" && protocol != "udp") {
		return Port{}, false
	}
	return Port{n, protocol}, true
}
