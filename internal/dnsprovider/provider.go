// Package dnsprovider is SGC's side of the company that holds the owner's
// DNS (docs/design.md §11): one interface for the little SGC asks of it
// (check the account, publish and remove a TXT record for the certificate's
// proof, keep the VPN's A record), and a list of the providers SGC knows.
//
// Adding a provider is one file: a type that implements Provider, and a
// Register call in that file's init with its Kind (what the page asks the
// owner for, and what the owner has to do at the provider first). Its
// stand-in in the tests passes the same checks as every other provider's
// (provider_test.go).
//
// Two rules for every provider, because the credentials open the owner's
// DNS, and with most providers their whole account:
//   - a credential never appears in an error, a log line or an answer to the
//     page (errors of the HTTP client are stripped of the address they name,
//     since some APIs want the key in it);
//   - a record SGC did not make is never changed or removed, except the
//     VPN's when the owner says so (vpncontrol).
//
// Web process only.
package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Provider is what SGC needs from a DNS host. Names are fully qualified,
// without the final dot ("_acme-challenge.domain.tld"); domain is the zone
// ("domain.tld").
type Provider interface {
	// Check says whether the account may manage the domain's records: nil
	// if it may, else one of the errors below or a *Refusal.
	Check(ctx context.Context, domain string) error
	AddTXT(ctx context.Context, domain, name, value string) (Record, error)
	DeleteTXT(ctx context.Context, domain, id string) error
	ARecords(ctx context.Context, domain string) ([]Record, error)
	AddA(ctx context.Context, domain, name, address string) (Record, error)
	UpdateA(ctx context.Context, domain, id, name, address string) error
}

// Record is a record as SGC keeps track of it. ID is whatever the provider
// needs to change or remove it again; SGC stores it and hands it back.
type Record struct {
	ID    string
	Name  string
	Value string // a TXT record's text, an A record's address
}

// What can go wrong, in a form the callers turn into sentences with the
// provider's name.
var (
	ErrCredentials = errors.New("the credentials are not accepted")
	ErrNotFound    = errors.New("the domain is not in this account")
	ErrNotActive   = errors.New("the domain's DNS is not active")
	ErrRateLimited = errors.New("too many requests")
	ErrUnreachable = errors.New("could not be reached")
)

// Refusal is a refusal in the provider's own terms, said as it is
// ("API access is not switched on for domain.tld").
type Refusal struct{ Message string }

func (r *Refusal) Error() string { return r.Message }

// Field is one thing the page asks the owner for.
type Field struct {
	// Key is how the value is kept; never renamed once shipped.
	Key   string `json:"key"`
	Label string `json:"label"`
	Help  string `json:"help"`
	// Secret: kept, never shown again.
	Secret bool `json:"secret"`
	// Max is the longest value taken.
	Max int `json:"max"`
}

// Kind is a provider SGC knows.
type Kind struct {
	// ID is how the choice is kept ("zone"); never renamed once shipped.
	ID   string `json:"id"`
	Name string `json:"name"`
	// Credentials are the fields in a sentence: "<Name> does not accept the
	// username and API key".
	Credentials string `json:"-"`
	// Fields are what the owner enters.
	Fields []Field `json:"fields"`
	// Before is what the owner has to do at the provider first, in words.
	Before string `json:"before"`
	// Propagation is how long a new record may take to show at the
	// provider's own name servers.
	Propagation time.Duration `json:"-"`
	// open makes a Provider from the owner's values (already checked to be
	// there and plain).
	open func(values map[string]string, opt Options) (Provider, error)
}

// Options is what opening a provider needs besides the owner's values.
type Options struct {
	HTTP      *http.Client
	UserAgent string
	// ZoneEndpoint is the address of Zone.eu's API; StandIn says that it is
	// a stand-in (the tests). With a stand-in, every other provider is
	// refused: a test set-up must never reach a real provider's API.
	ZoneEndpoint string
	StandIn      bool
	// PublicIP returns the home's public address, for providers that want
	// it with every request (Namecheap).
	PublicIP func(ctx context.Context) (netip.Addr, error)
	// Endpoint replaces the API's address of the provider being opened;
	// for the tests of this package only.
	Endpoint string
}

// Account is the owner's choice: the domain, the provider, the values.
type Account struct {
	Domain   string
	Provider string
	Values   map[string]string
}

// Shown are an account's values that are not secret (a username), for the
// page.
func Shown(a Account) map[string]string {
	out := map[string]string{}
	if k, ok := Lookup(a.Provider); ok {
		for _, f := range k.Fields {
			if !f.Secret && a.Values[f.Key] != "" {
				out[f.Key] = a.Values[f.Key]
			}
		}
	}
	return out
}

var (
	mu    sync.Mutex
	kinds = map[string]Kind{}
)

// Register adds a provider; called from the provider's own file.
func Register(k Kind) {
	mu.Lock()
	defer mu.Unlock()
	if _, taken := kinds[k.ID]; taken || k.open == nil {
		panic("dnsprovider: registered twice or without an open: " + k.ID)
	}
	kinds[k.ID] = k
}

// Kinds lists the providers, Zone.eu first (SGC's first), the rest by name.
func Kinds() []Kind {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Kind, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b Kind) int {
		switch {
		case a.ID == ZoneID:
			return -1
		case b.ID == ZoneID:
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// Lookup finds a provider by its ID.
func Lookup(id string) (Kind, bool) {
	mu.Lock()
	defer mu.Unlock()
	k, ok := kinds[id]
	return k, ok
}

// Name is a provider's name for sentences ("Zone.eu"); its ID if unknown.
func Name(id string) string {
	if k, ok := Lookup(id); ok {
		return k.Name
	}
	return id
}

// CheckValues checks the owner's values for a provider: every field there,
// plain text within its length. The message is for the page.
func CheckValues(id string, values map[string]string) (map[string]string, error) {
	k, ok := Lookup(id)
	if !ok {
		return nil, &Refusal{Message: "SGC does not know that DNS provider"}
	}
	clean := map[string]string{}
	for _, f := range k.Fields {
		v := strings.TrimSpace(values[f.Key])
		if v == "" || len(v) > f.Max || !plain(v) {
			article := "a"
			if strings.ContainsRune("AEIOUaeiou", rune(f.Label[0])) {
				article = "an"
			}
			return nil, &Refusal{Message: fmt.Sprintf("That is not %s %s: copy it as %s shows it, without spaces", article, f.Label, k.Name)}
		}
		clean[f.Key] = v
	}
	for key := range values {
		if _, known := clean[key]; !known {
			return nil, &Refusal{Message: fmt.Sprintf("%s does not use %q", k.Name, key)}
		}
	}
	return clean, nil
}

func plain(s string) bool {
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// Open makes the Provider for an account.
func Open(a Account, opt Options) (Provider, error) {
	k, ok := Lookup(a.Provider)
	if !ok {
		return nil, fmt.Errorf("SGC does not know the DNS provider %q", a.Provider)
	}
	if opt.StandIn && a.Provider != ZoneID {
		return nil, &Refusal{Message: "This SGC talks to a stand-in for Zone.eu (a test set-up), so it uses no other DNS provider"}
	}
	values, err := CheckValues(a.Provider, a.Values)
	if err != nil {
		return nil, err
	}
	if opt.HTTP == nil {
		opt.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if opt.UserAgent == "" {
		opt.UserAgent = "sgc"
	}
	return k.open(values, opt)
}

// relative is a name below the domain ("vpn" for vpn.domain.tld, "" for the
// domain itself), or false if it is not below it.
func relative(name, domain string) (string, bool) {
	name, domain = strings.ToLower(strings.TrimSuffix(name, ".")), strings.ToLower(domain)
	if name == domain {
		return "", true
	}
	sub, ok := strings.CutSuffix(name, "."+domain)
	return sub, ok && sub != ""
}

// transportError is an HTTP client's error without the address it names:
// some APIs want the key in the address.
func transportError(provider string, err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		err = u.Err
	}
	return fmt.Errorf("%w: %s: %v", ErrUnreachable, provider, err)
}

// maxAnswer is the most of an answer that is read. SGC's questions are
// answered with a list of records; more than this is not an answer.
const maxAnswer = 4 << 20

// send makes one request and reads the answer. A failure to get one is
// ErrUnreachable, without the address.
func send(opt Options, provider string, req *http.Request) (int, []byte, error) {
	req.Header.Set("User-Agent", opt.UserAgent)
	resp, err := opt.HTTP.Do(req)
	if err != nil {
		return 0, nil, transportError(provider, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if err != nil {
		return 0, nil, transportError(provider, err)
	}
	return resp.StatusCode, data, nil
}

// plainText makes words from outside fit to show: printable, one line, short.
func plainText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if runes := []rune(s); len(runes) > 200 {
		s = string(runes[:200]) + "…"
	}
	return strings.TrimSpace(s)
}
