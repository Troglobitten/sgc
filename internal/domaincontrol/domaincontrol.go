// Package domaincontrol keeps the owner's domain and the Zone.eu account
// that holds its DNS, and watches whether Zone.eu still accepts the key.
//
// The domain is what every name SGC hands out ends in; the Zone.eu account
// is how SGC will prove to Let's Encrypt that the domain is the owner's, and
// keep the VPN's name pointing at the house. Both of those stop working,
// quietly, the day the key is withdrawn or the domain moves away. So SGC
// asks Zone.eu every few hours, and says so when the answer is no.
//
// The API key opens the whole Zone.eu account (accepted risk R4). It is
// stored in SGC's database, carried by an export, sent to Zone.eu and to
// nobody else, and never handed back to the page.
//
// All of this runs in the web process. The root side has no part in it.
package domaincontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/zone"
)

const (
	// The owner's domain, and the Zone.eu account its DNS is in. An export
	// carries all three.
	SettingDomain   = "domain.name"
	SettingUsername = "zone.username"
	SettingAPIKey   = "zone.api_key"
	// SettingCheck is how the last question to Zone.eu ended. Bookkeeping of
	// one installation; an export does not carry it.
	SettingCheck = "zone.check"

	// Zone.eu is asked this often while it says yes, and this often while it
	// does not: sooner, so that the warning goes away soon after the owner
	// has put things right, but not so often that it is a nuisance to
	// Zone.eu (which allows 60 requests a minute).
	checkEvery = 6 * time.Hour
	retryEvery = time.Hour
	// Not in the first minutes after start-up: the device may still be
	// finding its way to the internet.
	startDelay = 2 * time.Minute

	maxUsername = 100
	maxAPIKey   = 200
)

// ChangeError is a failed request with a message fit for the owner.
type ChangeError struct{ Message string }

func (e *ChangeError) Error() string { return e.Message }

type Config struct {
	DB    *sql.DB
	Audit *audit.Log
	Log   *slog.Logger
	// Endpoint is Zone.eu's API (zone.DefaultEndpoint, except in tests).
	Endpoint string
	// HTTP makes the requests. Its timeout bounds each of them.
	HTTP      *http.Client
	UserAgent string
	Now       func() time.Time
}

type Service struct {
	cfg Config
	// One change or check at a time.
	mu sync.Mutex
	// When this process started, for startDelay.
	started time.Time
}

func New(cfg Config) *Service { return &Service{cfg: cfg, started: cfg.Now()} }

// Status is what the page shows. The API key is not in it.
type Status struct {
	// Configured: a domain and a Zone.eu account are saved.
	Configured bool   `json:"configured"`
	Domain     string `json:"domain"`
	Username   string `json:"username"`
	// CheckedAt is when Zone.eu was last asked; nil if it was not yet. OK is
	// its answer; Problem says in words what was wrong, FailingSince since
	// when.
	CheckedAt    *time.Time `json:"checkedAt"`
	OK           bool       `json:"ok"`
	Problem      string     `json:"problem"`
	FailingSince *time.Time `json:"failingSince"`
}

// check is how a question to Zone.eu ended, as kept in the database.
type check struct {
	At           time.Time  `json:"at"`
	OK           bool       `json:"ok"`
	Problem      string     `json:"problem,omitempty"`
	FailingSince *time.Time `json:"failingSince,omitempty"`
}

type account struct {
	domain, username, apiKey string
}

func (s *Service) account(ctx context.Context) (account, bool, error) {
	var a account
	for key, into := range map[string]*string{SettingDomain: &a.domain, SettingUsername: &a.username, SettingAPIKey: &a.apiKey} {
		value, _, err := store.Setting(ctx, s.cfg.DB, key)
		if err != nil {
			return a, false, err
		}
		*into = value
	}
	return a, a.domain != "" && a.username != "" && a.apiKey != "", nil
}

// Account returns the domain and the Zone.eu account that are saved, key
// included, and whether any are. It is for the part of SGC that publishes
// DNS records for a certificate, and for nothing that answers the page.
func (s *Service) Account(ctx context.Context) (domain, username, apiKey string, configured bool, err error) {
	a, configured, err := s.account(ctx)
	return a.domain, a.username, a.apiKey, configured, err
}

func (s *Service) lastCheck(ctx context.Context) (*check, error) {
	raw, _, err := store.Setting(ctx, s.cfg.DB, SettingCheck)
	if err != nil || raw == "" {
		return nil, err
	}
	var last check
	if err := json.Unmarshal([]byte(raw), &last); err != nil {
		// Unreadable bookkeeping is no reason to fail: it is as if Zone.eu
		// had not been asked yet.
		return nil, nil
	}
	return &last, nil
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	a, configured, err := s.account(ctx)
	if err != nil || !configured {
		return Status{}, err
	}
	status := Status{Configured: true, Domain: a.domain, Username: a.username}
	last, err := s.lastCheck(ctx)
	if err != nil || last == nil {
		return status, err
	}
	status.CheckedAt, status.OK, status.Problem, status.FailingSince = &last.At, last.OK, last.Problem, last.FailingSince
	return status, nil
}

// Save takes a domain and a Zone.eu account, asks Zone.eu whether they
// belong together, and keeps them only if the answer is yes. An error means
// nothing was changed.
func (s *Service) Save(ctx context.Context, actor, remote, domain, username, apiKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain, err := zone.NormalizeDomain(domain)
	if err != nil {
		return &ChangeError{capitalised(err.Error()) + "."}
	}
	username, apiKey = strings.TrimSpace(username), strings.TrimSpace(apiKey)
	switch {
	case username == "" || len(username) > maxUsername || !plainText(username) || strings.Contains(username, ":"):
		return &ChangeError{"That is not a ZoneID username: it is the name you sign in with at Zone.eu."}
	case apiKey == "" || len(apiKey) > maxAPIKey || !plainText(apiKey):
		return &ChangeError{"That is not an API key: copy it as Zone.eu shows it, without spaces."}
	}

	if problem := s.ask(ctx, account{domain, username, apiKey}); problem != "" {
		return &ChangeError{problem + " Nothing was saved."}
	}

	ctx = context.WithoutCancel(ctx)
	for key, value := range map[string]string{SettingDomain: domain, SettingUsername: username, SettingAPIKey: apiKey} {
		if err := store.SetSetting(ctx, s.cfg.DB, key, value); err != nil {
			return err
		}
	}
	if err := s.keep(ctx, check{At: s.cfg.Now(), OK: true}); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionDomainSaved, domain+", with the Zone.eu account "+username, remote)
	return nil
}

// Remove forgets the domain and the Zone.eu account.
func (s *Service) Remove(ctx context.Context, actor, remote string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, configured, err := s.account(ctx)
	if err != nil || !configured {
		return err
	}
	ctx = context.WithoutCancel(ctx)
	if _, err := s.cfg.DB.ExecContext(ctx, `DELETE FROM setting WHERE key IN (?, ?, ?, ?)`,
		SettingDomain, SettingUsername, SettingAPIKey, SettingCheck); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionDomainRemoved, a.domain, remote)
	return nil
}

// CheckNow asks Zone.eu whether it still accepts the account for the domain,
// and keeps the answer. Without a saved account it does nothing.
func (s *Service) CheckNow(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, configured, err := s.account(ctx)
	if err != nil || !configured {
		return Status{}, err
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
	// The history gets the turns, not every answer.
	wasOK := previous == nil || previous.OK
	switch {
	case wasOK && !result.OK:
		s.record(ctx, audit.ActorSystem, audit.ActionZoneCheckFailed, result.Problem, "")
	case !wasOK && result.OK:
		s.record(ctx, audit.ActorSystem, audit.ActionZoneCheckRecovered, a.domain, "")
	}
	return Status{Configured: true, Domain: a.domain, Username: a.username,
		CheckedAt: &result.At, OK: result.OK, Problem: result.Problem, FailingSince: result.FailingSince}, nil
}

// Run asks Zone.eu from time to time until ctx ends.
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
					s.cfg.Log.Error("ask Zone.eu about the domain", "error", err)
				}
			}
		}
	}
}

// due says whether it is time to ask Zone.eu again.
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

// ask puts the question to Zone.eu and returns what is wrong, in words for
// the owner, or "" if nothing is.
func (s *Service) ask(ctx context.Context, a account) string {
	client, err := zone.NewClient(s.cfg.Endpoint, a.username, a.apiKey, s.cfg.UserAgent, s.cfg.HTTP)
	if err != nil {
		s.cfg.Log.Error("set up the client for Zone.eu", "error", err)
		return "SGC is set to an address for Zone.eu that is not one."
	}
	found, err := client.Zone(ctx, a.domain)
	var refusal *zone.StatusError
	switch {
	case err == nil && found.Active:
		return ""
	case err == nil:
		return "The DNS zone of " + a.domain + " is not active at Zone.eu."
	case errors.Is(err, zone.ErrCredentials):
		return "Zone.eu does not accept the username and API key."
	case errors.Is(err, zone.ErrNotFound):
		return "Zone.eu has no DNS zone for " + a.domain + " in this account."
	case errors.Is(err, zone.ErrRateLimited):
		return "Zone.eu answered that too many requests were made in the last minute."
	case errors.As(err, &refusal):
		return capitalised(refusal.Error()) + "."
	default:
		// The client's errors name the address, never the key.
		s.cfg.Log.Warn("ask Zone.eu about the domain", "error", err)
		return "Zone.eu could not be reached. Does this device reach the internet?"
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

// plainText: visible characters only, none of them a space.
func plainText(text string) bool {
	for _, r := range text {
		if r > unicode.MaxASCII || !unicode.IsGraphic(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func capitalised(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}
