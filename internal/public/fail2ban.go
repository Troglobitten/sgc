package public

import (
	"bufio"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/firewall"
)

// fail2ban (Debian's package) bans an address that fails too often: at SGC's
// login on a public service, or with requests the public door refuses. SGC
// writes four files for it and leaves the rest of its settings alone:
//
//   - a jail file, which also switches off the SSH jail Debian's package
//     switches on: SSH is reachable from home only (SGC's firewall), and a
//     ban there could lock the owner out of their own device;
//   - two filters, for SGC's log line and for Traefik's access log;
//   - an action that puts a ban into SGC's table for the internet
//     (banned4), so that a ban applies to public ports only and the allow
//     list still comes first.
//
// The jail file's name sorts after Debian's own (defaults-debian.conf), and
// ".local" is read after ".conf", so SGC's settings are the ones in effect.

// Fail2banFiles are fail2ban's files that SGC writes, relative to its folder
// (/etc/fail2ban).
const (
	Fail2banJail         = "jail.d/zz-sgc.local"
	Fail2banSignInFilter = "filter.d/sgc-signin.conf"
	Fail2banDoorFilter   = "filter.d/sgc-door.conf"
	Fail2banAction       = "action.d/sgc.conf"
)

// The jails.
const (
	JailSignIn = "sgc-signin"
	JailDoor   = "sgc-door"
)

// SignInFailedMessage is the log line SGC writes for a failed sign-in at its
// login on a public service (internal/web), and the filter's pattern. The
// visitor's address is the first value after it; SGC writes no text a
// visitor chose before it.
const SignInFailedMessage = "gate sign-in failed"

const header = "# Written by SGC. Do not edit: SGC replaces this file (docs/design.md §14).\n"

// Fail2banFileSet renders the four files. off writes them with SGC's jails
// switched off (and Debian's SSH jail off all the same).
func Fail2banFileSet(f Fail2ban, allow []string) (map[string]string, error) {
	if f.SignIns < 1 || f.Refused < 1 || f.FindMinutes < 1 || f.BanMinutes < 1 {
		return nil, fmt.Errorf("fail2ban's numbers are out of bounds")
	}
	ignore := []string{"127.0.0.0/8"}
	for _, p := range firewall.InsideV4() {
		ignore = append(ignore, p.String())
	}
	for _, entry := range allow {
		p, err := ParseAllow(entry)
		if err != nil {
			return nil, err
		}
		ignore = append(ignore, p.String())
	}
	enabled := "false"
	if f.Enabled {
		enabled = "true"
	}
	jail := func(name, unit, filter string, maxRetry int) string {
		return fmt.Sprintf("[%s]\nenabled = %s\nbackend = systemd\njournalmatch = _SYSTEMD_UNIT=%s\nfilter = %s\naction = sgc\n"+
			"maxretry = %d\nfindtime = %d\nbantime = %d\nignoreip = %s\n\n",
			name, enabled, unit, filter, maxRetry, f.FindMinutes*60, f.BanMinutes*60, strings.Join(ignore, " "))
	}
	var j strings.Builder
	j.WriteString(header)
	j.WriteString("\n# Debian switches this on. SSH is reachable from home only (SGC's firewall),\n# and a ban there could lock the owner out of the device.\n[sshd]\nenabled = false\n\n")
	j.WriteString("# Failed sign-ins at SGC's login on a public service.\n")
	j.WriteString(jail(JailSignIn, "sgc.service", JailSignIn, f.SignIns))
	j.WriteString("# Requests the public door refuses (401, 403, 404, 405, 429): someone trying addresses.\n")
	j.WriteString(jail(JailDoor, "sgc-traefik.service", JailDoor, f.Refused))

	return map[string]string{
		Fail2banJail: j.String(),
		// The visitor's address follows the message directly; what a visitor
		// typed is never written before it (internal/web).
		Fail2banSignInFilter: header + "\n[Definition]\nfailregex = msg=\"" + SignInFailedMessage + "\" visitor=<HOST>(?: |$)\nignoreregex =\n",
		// Traefik's access log, one JSON object per line with its keys in
		// order (seen with Traefik 3.7.16): the visitor (ClientHost), then the
		// answer (DownstreamStatus), then the entry point.
		Fail2banDoorFilter: header + "\n[Definition]\nfailregex = \"ClientHost\":\"<HOST>\",.*\"DownstreamStatus\":(?:401|403|404|405|429),.*\"entryPointName\":\"public\"\nignoreregex =\n",
		Fail2banAction: header + "\n[Definition]\n" +
			"actionstart = /usr/sbin/nft add table inet " + TableName + "\n" +
			"              /usr/sbin/nft 'add set inet " + TableName + " banned4 { type ipv4_addr; flags timeout; }'\n" +
			"actionstop =\nactioncheck =\n" +
			"actionban = /usr/sbin/nft 'add element inet " + TableName + " banned4 { <ip> timeout <bantime>s }'\n" +
			"actionunban = /usr/sbin/nft 'delete element inet " + TableName + " banned4 { <ip> }'\n",
	}, nil
}

// Ban is one banned address, as the page lists it.
type Ban struct {
	Address string    `json:"address"`
	Jail    string    `json:"jail"`
	Until   time.Time `json:"until"`
}

// fail2ban-client get <jail> banip --with-time prints one line per address:
// "203.0.113.5 \t2026-10-25 12:00:00 + 3600 = 2026-10-25 13:00:00".
var banLine = regexp.MustCompile(`^(\S+)\s+\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \+ -?\d+ = (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s*$`)

// ParseBans reads fail2ban-client's list of a jail's bans. Times are the
// device's local time.
func ParseBans(jail, output string, location *time.Location) []Ban {
	var out []Ban
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		m := banLine.FindStringSubmatch(strings.TrimSpace(scanner.Text()))
		if m == nil {
			continue
		}
		addr, err := netip.ParseAddr(m[1])
		if err != nil {
			continue
		}
		until, err := time.ParseInLocation(time.DateTime, m[2], location)
		if err != nil {
			continue
		}
		out = append(out, Ban{Address: addr.String(), Jail: jail, Until: until.UTC()})
	}
	slices.SortFunc(out, func(a, b Ban) int { return a.Until.Compare(b.Until) })
	return out
}
