// Package domaincontrol keeps the owner's domain and the account at the
// company that holds its DNS (internal/dnsprovider: Zone.eu, Cloudflare,
// Porkbun, Namecheap), and watches whether that account still works.
//
// The domain is what every name SGC hands out ends in; the account is how
// SGC proves to Let's Encrypt that the domain is the owner's, and keeps the
// VPN's name pointing at the house. Both of those stop working, quietly, the
// day the key is withdrawn or the domain moves away. So SGC asks the
// provider every few hours, and says so when the answer is no.
//
// The credentials open the owner's DNS, with most providers the whole
// account (accepted risk R4). They are stored in SGC's database, carried by
// an export, sent to the provider and to nobody else, and never handed back
// to the page.
//
// All of this runs in the web process. The root side has no part in it.
package domaincontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/dnsprovider"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/zone"
)

const (
	// The owner's domain, the provider its DNS is at, and what that provider
	// needs (a JSON object of the provider's fields). An export carries all
	// three.
	SettingDomain      = "domain.name"
	SettingProvider    = "dns.provider"
	SettingCredentials = "dns.credentials"
	// Before 0.18.0 the provider was always Zone.eu, and its two values had
	// settings of their own. An account kept that way (or restored from an
	// export of then) is read as a Zone.eu account; saving the domain again
	// moves it to the settings above.
	legacyUsername = "zone.username"
	legacyAPIKey   = "zone.api_key"
	// SettingCheck is how the last question to the provider ended.
	// Bookkeeping of one installation; an export does not carry it. (Its
	// name is from the days of Zone.eu alone, and stays.)
	SettingCheck = "zone.check"

	// The provider is asked this often while it says yes, and this often
	// while it does not: sooner, so that the warning goes away soon after
	// the owner has put things right, but not so often that it is a nuisance
	// (Zone.eu allows 60 requests a minute, Namecheap 50).
	checkEvery = 6 * time.Hour
	retryEvery = time.Hour
	// Not in the first minutes after start-up: the device may still be
	// finding its way to the internet.
	startDelay = 2 * time.Minute
)

// ChangeError is a failed request with a message fit for the owner.
type ChangeError struct{ Message string }

func (e *ChangeError) Error() string { return e.Message }

type Config struct {
	DB    *sql.DB
	Audit *audit.Log
	Log   *slog.Logger
	// DNS is what opening a provider needs: where Zone.eu is (a stand-in in
	// the tests, which then refuses every other provider), the HTTP client
	// whose timeout bounds each request, the home's public address.
	DNS dnsprovider.Options
	Now func() time.Time
}

type Service struct {
	cfg Config
	// One change or check at a time.
	mu sync.Mutex
	// When this process started, for startDelay.
	started time.Time
}

func New(cfg Config) *Service { return &Service{cfg: cfg, started: cfg.Now()} }

// Status is what the page shows. No secret is in it.
type Status struct {
	// Configured: a domain and an account are saved.
	Configured bool   `json:"configured"`
	Domain     string `json:"domain"`
	// Provider is the provider's ID ("zone"), ProviderName its name;
	// Shown are the account's values that are not secret (a username).
	Provider     string            `json:"provider"`
	ProviderName string            `json:"providerName"`
	Shown        map[string]string `json:"shown"`
	// CheckedAt is when the provider was last asked; nil if it was not yet.
	// OK is its answer; Problem says in words what was wrong, FailingSince
	// since when.
	CheckedAt    *time.Time `json:"checkedAt"`
	OK           bool       `json:"ok"`
	Problem      string     `json:"problem"`
	FailingSince *time.Time `json:"failingSince"`
}

// check is how a question to the provider ended, as kept in the database.
type check struct {
	At           time.Time  `json:"at"`
	OK           bool       `json:"ok"`
	Problem      string     `json:"problem,omitempty"`
	FailingSince *time.Time `json:"failingSince,omitempty"`
}

func (s *Service) setting(ctx context.Context, key string) (string, error) {
	value, _, err := store.Setting(ctx, s.cfg.DB, key)
	return value, err
}

// account reads what is saved, in either form.
func (s *Service) account(ctx context.Context) (dnsprovider.Account, bool, error) {
	var a dnsprovider.Account
	var err error
	if a.Domain, err = s.setting(ctx, SettingDomain); err != nil {
		return a, false, err
	}
	if a.Provider, err = s.setting(ctx, SettingProvider); err != nil {
		return a, false, err
	}
	if a.Provider != "" {
		raw, err := s.setting(ctx, SettingCredentials)
		if err != nil {
			return a, false, err
		}
		if raw != "" {
			if err := json.Unmarshal([]byte(raw), &a.Values); err != nil {
				// Not readable: as if nothing were saved, so that the page
				// asks for it again instead of SGC failing at every turn.
				s.cfg.Log.Error("the saved DNS account cannot be read", "error", err)
				return dnsprovider.Account{}, false, nil
			}
		}
	} else {
		username, err := s.setting(ctx, legacyUsername)
		if err != nil {
			return a, false, err
		}
		apiKey, err := s.setting(ctx, legacyAPIKey)
		if err != nil {
			return a, false, err
		}
		if username != "" && apiKey != "" {
			a.Provider, a.Values = dnsprovider.ZoneID, map[string]string{"username": username, "apiKey": apiKey}
		}
	}
	return a, a.Domain != "" && a.Provider != "" && len(a.Values) > 0, nil
}

// Account returns the domain and the account that are saved, credentials
// included, and whether any are. It is for the parts of SGC that publish
// DNS records (the certificate, the VPN's name), and for nothing that
// answers the page.
func (s *Service) Account(ctx context.Context) (dnsprovider.Account, bool, error) {
	return s.account(ctx)
}

// Open returns the provider of the saved account, opened, with the domain.
func (s *Service) Open(ctx context.Context) (dnsprovider.Provider, dnsprovider.Account, bool, error) {
	a, configured, err := s.account(ctx)
	if err != nil || !configured {
		return nil, a, false, err
	}
	p, err := dnsprovider.Open(a, s.cfg.DNS)
	return p, a, err == nil, err
}

func (s *Service) lastCheck(ctx context.Context) (*check, error) {
	raw, err := s.setting(ctx, SettingCheck)
	if err != nil || raw == "" {
		return nil, err
	}
	var last check
	if err := json.Unmarshal([]byte(raw), &last); err != nil {
		// Unreadable bookkeeping is no reason to fail: it is as if the
		// provider had not been asked yet.
		return nil, nil
	}
	return &last, nil
}

func statusOf(a dnsprovider.Account) Status {
	return Status{Configured: true, Domain: a.Domain, Provider: a.Provider, ProviderName: dnsprovider.Name(a.Provider), Shown: dnsprovider.Shown(a)}
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	a, configured, err := s.account(ctx)
	if err != nil || !configured {
		return Status{Shown: map[string]string{}}, err
	}
	status := statusOf(a)
	last, err := s.lastCheck(ctx)
	if err != nil || last == nil {
		return status, err
	}
	status.CheckedAt, status.OK, status.Problem, status.FailingSince = &last.At, last.OK, last.Problem, last.FailingSince
	return status, nil
}

// Save takes a domain and an account at a provider, asks the provider
// whether they belong together, and keeps them only if the answer is yes.
// An error means nothing was changed.
func (s *Service) Save(ctx context.Context, actor, remote, domain, provider string, values map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain, err := zone.NormalizeDomain(domain)
	if err != nil {
		return &ChangeError{capitalised(err.Error()) + "."}
	}
	clean, err := dnsprovider.CheckValues(provider, values)
	if err != nil {
		return &ChangeError{capitalised(err.Error()) + "."}
	}
	a := dnsprovider.Account{Domain: domain, Provider: provider, Values: clean}
	if problem := s.ask(ctx, a); problem != "" {
		return &ChangeError{problem + " Nothing was saved."}
	}

	data, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	ctx = context.WithoutCancel(ctx)
	tx, err := s.cfg.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range map[string]string{SettingDomain: domain, SettingProvider: provider, SettingCredentials: string(data)} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO setting (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM setting WHERE key IN (?, ?)`, legacyUsername, legacyAPIKey); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.keep(ctx, check{At: s.cfg.Now(), OK: true}); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionDomainSaved, describe(a), remote)
	return nil
}

// describe names an account for the history: never a secret.
func describe(a dnsprovider.Account) string {
	name := dnsprovider.Name(a.Provider)
	if username := dnsprovider.Shown(a)["username"]; username != "" {
		return a.Domain + ", with the " + name + " account " + username
	}
	return a.Domain + ", at " + name
}

// Remove forgets the domain and the account.
func (s *Service) Remove(ctx context.Context, actor, remote string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, configured, err := s.account(ctx)
	if err != nil || !configured {
		return err
	}
	ctx = context.WithoutCancel(ctx)
	if _, err := s.cfg.DB.ExecContext(ctx, `DELETE FROM setting WHERE key IN (?, ?, ?, ?, ?, ?)`,
		SettingDomain, SettingProvider, SettingCredentials, legacyUsername, legacyAPIKey, SettingCheck); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionDomainRemoved, a.Domain, remote)
	return nil
}

// CheckNow asks the provider whether it still accepts the account for the
// domain, and keeps the answer. Without a saved account it does nothing.
func (s *Service) CheckNow(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, configured, err := s.account(ctx)
	if err != nil || !configured {
		return Status{Shown: map[string]string{}}, err
	}
	previous, err := s.lastCheck(ctx)
	if err != nil {
		return Status{}, err
	}
	now := s.cfg.Now()
	result := check{At: now, OK: true}
	if problem := s.ask(ctx, a); problem != "" {
		result.OK, result.Problem, result.FailingSince = false, problem, &now
		if previous != nil && !previous.OK && previous.FailingSince != nil {
			result.FailingSince = previous.FailingSince
		}
	}
	ctx = context.WithoutCancel(ctx)
	if err := s.keep(ctx, result); err != nil {
		return Status{}, err
	}
	// The history gets the turns, not every answer. (The action names are
	// from the days of Zone.eu alone, and stay.)
	wasOK := previous == nil || previous.OK
	switch {
	case wasOK && !result.OK:
		s.record(ctx, audit.ActorSystem, audit.ActionZoneCheckFailed, result.Problem, "")
	case !wasOK && result.OK:
		s.record(ctx, audit.ActorSystem, audit.ActionZoneCheckRecovered, a.Domain, "")
	}
	status := statusOf(a)
	status.CheckedAt, status.OK, status.Problem, status.FailingSince = &result.At, result.OK, result.Problem, result.FailingSince
	return status, nil
}

// Run asks the provider from time to time until ctx ends.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.due(ctx) {
				if _, err := s.CheckNow(ctx); err != nil && ctx.Err() == nil {
					s.cfg.Log.Error("ask the DNS provider about the domain", "error", err)
				}
			}
		}
	}
}

// due says whether it is time to ask the provider again.
func (s *Service) due(ctx context.Context) bool {
	now := s.cfg.Now()
	// (A clock that was set back since start-up makes this negative, which
	// must not be read as "just started" for as long as it was set back.)
	if running := now.Sub(s.started); running >= 0 && running < startDelay {
		return false
	}
	if _, configured, err := s.account(ctx); err != nil || !configured {
		return false
	}
	last, err := s.lastCheck(ctx)
	if err != nil {
		return false
	}
	switch {
	case last == nil:
		return true
	case last.At.After(now):
		// The clock went back: do not wait for it to catch up.
		return true
	case last.OK:
		return now.Sub(last.At) >= checkEvery
	default:
		return now.Sub(last.At) >= retryEvery
	}
}

// ask puts the question to the provider and returns what is wrong, in words
// for the owner, or "" if nothing is.
func (s *Service) ask(ctx context.Context, a dnsprovider.Account) string {
	p, err := dnsprovider.Open(a, s.cfg.DNS)
	if err == nil {
		err = p.Check(ctx, a.Domain)
	}
	if err == nil {
		return ""
	}
	return Words(a, err)
}

// Words says what a provider's error means, for the owner. The errors of
// internal/dnsprovider name no credential.
func Words(a dnsprovider.Account, err error) string {
	kind, _ := dnsprovider.Lookup(a.Provider)
	name := dnsprovider.Name(a.Provider)
	var refusal *dnsprovider.Refusal
	switch {
	case errors.Is(err, dnsprovider.ErrCredentials):
		return name + " does not accept the " + kind.Credentials + "."
	case errors.Is(err, dnsprovider.ErrNotFound):
		return name + " has no DNS zone for " + a.Domain + " in this account."
	case errors.Is(err, dnsprovider.ErrNotActive):
		return "The DNS zone of " + a.Domain + " is not active at " + name + "."
	case errors.Is(err, dnsprovider.ErrRateLimited):
		return name + " answered that too many requests were made. SGC asks again later."
	case errors.As(err, &refusal):
		return capitalised(refusal.Message) + "."
	case errors.Is(err, dnsprovider.ErrUnreachable):
		return name + " could not be reached. Does this device reach the internet?"
	default:
		return capitalised(strings.TrimSuffix(err.Error(), ".")) + "."
	}
}

func (s *Service) keep(ctx context.Context, result check) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return store.SetSetting(ctx, s.cfg.DB, SettingCheck, string(data))
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

func capitalised(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}
