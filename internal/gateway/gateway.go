// Package gateway holds what SGC calls itself under the owner's domain, and
// the rules every name SGC hands out has to follow.
//
// Names are one label under the domain ("sgc" in sgc.domain.tld): that is
// what one wildcard certificate covers (*.domain.tld covers exactly one
// label), and it keeps every name short to type.
package gateway

import (
	"context"
	"database/sql"
	"strings"

	"github.com/Troglobitten/sgc/internal/store"
)

const (
	// SettingName is the gateway's own label (exported).
	SettingName = "gateway.name"
	// DefaultName is the label until the owner picks another (docs/design.md §10).
	DefaultName = "sgc"
	// AdGuardName is where AdGuard Home's own page is found, behind SGC's
	// sign-in.
	AdGuardName = "adguard"
)

// ValidLabel reports whether s can be one label of a host name: 1 to 63
// lower-case letters, digits and hyphens, not starting or ending with a
// hyphen. Upper case is not accepted rather than folded, so that what the
// owner typed is what is used.
func ValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	// Two hyphens in the third and fourth place are reserved for encoded
	// international names ("xn--"); a name that only looks like one would be
	// shown by browsers as something else.
	return len(s) < 4 || s[2:4] != "--"
}

// FQDN is a label under the domain.
func FQDN(label, domain string) string {
	if label == "" || domain == "" {
		return ""
	}
	return label + "." + domain
}

// Name returns the gateway's label.
func Name(ctx context.Context, db *sql.DB) (string, error) {
	name, found, err := store.Setting(ctx, db, SettingName)
	if err != nil {
		return "", err
	}
	if !found || !ValidLabel(name) {
		return DefaultName, nil
	}
	return name, nil
}

// SetName keeps a new label for the gateway. The caller checks that no
// service has it.
func SetName(ctx context.Context, db *sql.DB, name string) error {
	return store.SetSetting(ctx, db, SettingName, name)
}

// UnderDomain reports whether host is exactly one label under domain, and
// returns that label. Both are compared without regard to case and a
// trailing dot.
func UnderDomain(host, domain string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" {
		return "", false
	}
	label, found := strings.CutSuffix(host, "."+domain)
	if !found || !ValidLabel(label) {
		return "", false
	}
	return label, true
}
