// Package dnsnames keeps the names SGC hands out in AdGuard Home: the
// gateway's own name, the services', the VPN's. Each is a "rewrite" in
// AdGuard Home (a name it answers itself), made through AdGuard Home's API
// on 127.0.0.1, which has no login there (internal/adguard).
//
// SGC's database says which names there should be; AdGuard Home's settings
// file is the owner's (docs/design.md §4.4). So SGC removes only rewrites it
// made itself, and keeps the list of those (SettingPublished, exported, so
// that a restored device knows them too). A rewrite the owner made for a
// name SGC wants is left alone and reported. The names are brought in line
// at start-up, every minute, and right after anything changes.
//
// Web process only; no privileges needed.
package dnsnames

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/store"
)

// SettingPublished is the list of rewrites SGC made.
const SettingPublished = "dns.names"

// Name is a name SGC wants AdGuard Home to answer, and with what.
type Name struct {
	Domain string `json:"domain"`
	// Answer is an IPv4 address.
	Answer string `json:"answer"`
	// For says what the name is, for the page ("SGC's page", a service's name).
	For string `json:"for"`
}

// Rewrite is one of AdGuard Home's rewrites, as its API has it
// (openapi.yaml of 0.107.79: RewriteEntry).
type Rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
	// Enabled is a pointer: AdGuard Home leaves it out in older settings,
	// which means "on".
	Enabled *bool `json:"enabled,omitempty"`
}

func (r Rewrite) on() bool { return r.Enabled == nil || *r.Enabled }

func (r Rewrite) key() string { return strings.ToLower(r.Domain) + " " + r.Answer }

// Client talks to AdGuard Home's API.
type Client struct {
	// Base is http://host:port of AdGuard Home's page.
	Base string
	HTTP *http.Client
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+"/control"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return ErrUnreachable
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrLoginRequired
	case resp.StatusCode != http.StatusOK:
		text, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("AdGuard Home answered %d: %s", resp.StatusCode, strings.TrimSpace(string(text)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

var (
	ErrUnreachable   = errors.New("AdGuard Home does not answer (is DNS switched on?)")
	ErrLoginRequired = errors.New("AdGuard Home asks for a login. SGC's settings give its page none, because SGC's own sign-in is in front of it; remove the user in AdGuard Home's settings file")
)

func (c *Client) List(ctx context.Context) ([]Rewrite, error) {
	var list []Rewrite
	err := c.do(ctx, http.MethodGet, "/rewrite/list", nil, &list)
	return list, err
}

func (c *Client) Add(ctx context.Context, r Rewrite) error {
	return c.do(ctx, http.MethodPost, "/rewrite/add", Rewrite{Domain: r.Domain, Answer: r.Answer}, nil)
}

func (c *Client) Delete(ctx context.Context, r Rewrite) error {
	return c.do(ctx, http.MethodPost, "/rewrite/delete", Rewrite{Domain: r.Domain, Answer: r.Answer}, nil)
}

// RewritesOn reports whether AdGuard Home applies rewrites at all (its own
// switch, /control/rewrite/settings).
func (c *Client) RewritesOn(ctx context.Context) (bool, error) {
	var settings struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.do(ctx, http.MethodGet, "/rewrite/settings", nil, &settings); err != nil {
		return false, err
	}
	return settings.Enabled == nil || *settings.Enabled, nil
}

// Config is what the service needs.
type Config struct {
	DB      *sql.DB
	AdGuard *Client
	// Desired lists the names there should be. An error leaves AdGuard
	// Home as it is.
	Desired func(ctx context.Context) ([]Name, error)
	Log     *slog.Logger
	Now     func() time.Time
}

// NameStatus is one wanted name and how it stands.
type NameStatus struct {
	Name
	InPlace bool `json:"inPlace"`
	// Conflict says why it is not in place, "" if it is or will be.
	Conflict string `json:"conflict,omitempty"`
}

// Status is how the last round went.
type Status struct {
	Names []NameStatus `json:"names"`
	// Problem says why AdGuard Home could not be brought in line, "" if it was.
	Problem string `json:"problem"`
	// RewritesOff: AdGuard Home's own switch for rewrites is off, so none of
	// SGC's names work.
	RewritesOff bool       `json:"rewritesOff"`
	SyncedAt    *time.Time `json:"syncedAt"`
}

type Service struct {
	cfg  Config
	kick chan struct{}
	// One round at a time.
	round  sync.Mutex
	mu     sync.Mutex
	status Status
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{cfg: cfg, kick: make(chan struct{}, 1), status: Status{Names: []NameStatus{}}}
}

// Status returns how the last round went.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.status
	out.Names = slices.Clone(out.Names)
	return out
}

// Kick asks for a round soon, after something changed.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run brings the names in line at start-up, every minute, and soon after
// each Kick, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Sync(ctx)
		case <-timer.C:
			s.Sync(ctx)
		case <-s.kick:
			// Changes often come in a burst (several services at once).
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			s.Sync(ctx)
		}
	}
}

func (s *Service) published(ctx context.Context) ([]Rewrite, error) {
	raw, found, err := store.Setting(ctx, s.cfg.DB, SettingPublished)
	if err != nil || !found || raw == "" {
		return nil, err
	}
	var list []Rewrite
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, fmt.Errorf("the list of SGC's names cannot be read: %w", err)
	}
	return list, nil
}

func (s *Service) savePublished(ctx context.Context, list []Rewrite) error {
	sort.Slice(list, func(i, j int) bool { return list[i].key() < list[j].key() })
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingPublished, string(data))
}

// Sync brings AdGuard Home in line with the wanted names, once.
func (s *Service) Sync(ctx context.Context) Status {
	s.round.Lock()
	defer s.round.Unlock()
	status := s.sync(ctx)
	now := s.cfg.Now().UTC()
	status.SyncedAt = &now
	s.mu.Lock()
	s.status = status
	s.mu.Unlock()
	return status
}

func (s *Service) sync(ctx context.Context) Status {
	status := Status{Names: []NameStatus{}}
	wanted, err := s.cfg.Desired(ctx)
	if err != nil {
		status.Problem = "SGC could not work out its names: " + err.Error()
		return status
	}
	wanted = normalise(wanted)
	for _, w := range wanted {
		status.Names = append(status.Names, NameStatus{Name: w})
	}
	mine, err := s.published(ctx)
	if err != nil {
		status.Problem = err.Error()
		return status
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	current, err := s.cfg.AdGuard.List(ctx)
	if err != nil {
		status.Problem = err.Error()
		return status
	}
	if on, err := s.cfg.AdGuard.RewritesOn(ctx); err == nil && !on {
		status.RewritesOff = true
	}

	have := map[string]Rewrite{}
	byDomain := map[string][]Rewrite{}
	for _, r := range current {
		have[r.key()] = r
		byDomain[strings.ToLower(r.Domain)] = append(byDomain[strings.ToLower(r.Domain)], r)
	}
	want := map[string]bool{}
	for _, w := range wanted {
		want[Rewrite{Domain: w.Domain, Answer: w.Answer}.key()] = true
	}
	madeByMe := map[string]bool{}
	for _, r := range mine {
		madeByMe[r.key()] = true
	}

	var problems []string
	var kept []Rewrite
	// What SGC made and no longer wants goes; what it made and still
	// wants stays on its list.
	for _, r := range mine {
		if want[r.key()] {
			if _, ok := have[r.key()]; ok {
				kept = append(kept, r)
			}
			continue
		}
		if _, ok := have[r.key()]; ok {
			if err := s.cfg.AdGuard.Delete(ctx, r); err != nil {
				problems = append(problems, "could not remove "+r.Domain+": "+err.Error())
				kept = append(kept, r) // tried again next round
				continue
			}
			s.cfg.Log.Info("name removed from AdGuard Home", "name", r.Domain, "answer", r.Answer)
		}
	}
	isKept := func(r Rewrite) bool {
		return slices.ContainsFunc(kept, func(k Rewrite) bool { return k.key() == r.key() })
	}
	for i, w := range status.Names {
		r := Rewrite{Domain: w.Domain, Answer: w.Answer}
		if existing, ok := have[r.key()]; ok {
			// There already: SGC's own, or the owner's with the same answer.
			status.Names[i].InPlace = existing.on()
			if !existing.on() {
				status.Names[i].Conflict = "switched off in AdGuard Home"
			}
			continue
		}
		// Another answer for the same name that SGC did not make is the
		// owner's: it is not replaced.
		var others []string
		for _, other := range byDomain[strings.ToLower(w.Domain)] {
			if !madeByMe[other.key()] {
				others = append(others, other.Answer)
			}
		}
		if len(others) > 0 {
			status.Names[i].Conflict = "AdGuard Home already has a rewrite of its own for this name (to " + strings.Join(others, ", ") + "); remove it there and SGC adds its own"
			continue
		}
		if err := s.cfg.AdGuard.Add(ctx, r); err != nil {
			problems = append(problems, "could not add "+w.Domain+": "+err.Error())
			continue
		}
		s.cfg.Log.Info("name added to AdGuard Home", "name", w.Domain, "answer", w.Answer)
		status.Names[i].InPlace = true
		if !isKept(r) {
			kept = append(kept, r)
		}
	}
	if err := s.savePublished(ctx, kept); err != nil {
		problems = append(problems, err.Error())
	}
	status.Problem = strings.Join(problems, "; ")
	return status
}

// normalise drops names that cannot be rewrites (empty, or an answer that
// is not an IPv4 address) and duplicates, and lower-cases the rest.
func normalise(names []Name) []Name {
	seen := map[string]bool{}
	var out []Name
	for _, n := range names {
		n.Domain = strings.TrimSuffix(strings.ToLower(n.Domain), ".")
		addr, err := netip.ParseAddr(n.Answer)
		if n.Domain == "" || err != nil || !addr.Is4() {
			continue
		}
		key := n.Domain + " " + n.Answer
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}
