// Package announce is how servers register their services with SGC: a
// token per server, and the request the stock curl container makes when the
// server's compose file comes up (docs/design.md §4.6).
//
// A token is shown once and only its hash is kept. It is pinned to the
// address it is first used from: an announcement from anywhere else is
// refused until the owner moves it in the page. Failed attempts are limited
// per address like sign-ins, recorded, and reported.
package announce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/services"
)

const (
	tokenPrefix = "sgc_"
	maxLabel    = 60
	maxTokens   = 200
	// One call may announce this many services.
	maxPerCall = 32
)

// Token is a server's token as the page shows it: never the token itself.
type Token struct {
	ID         int64      `json:"id"`
	Label      string     `json:"label"`
	Hint       string     `json:"hint"`
	PinnedIP   string     `json:"pinnedIp"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	Services   []string   `json:"services"`
}

type Config struct {
	DB       *sql.DB
	Audit    *audit.Log
	Services *services.Catalog
	// Alert reports something the owner should know at once: a token SGC
	// does not know, a name another server already has.
	Alert func(ctx context.Context, title, body string)
	Now   func() time.Time
	Log   *slog.Logger
}

type Service struct {
	cfg     Config
	limiter *auth.Limiter
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Alert == nil {
		cfg.Alert = func(context.Context, string, string) {}
	}
	return &Service{cfg: cfg, limiter: auth.NewLimiter()}
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

// List returns the tokens, newest first.
func (s *Service) List(ctx context.Context) ([]Token, error) {
	used, err := s.cfg.Services.TokenServices(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.cfg.DB.QueryContext(ctx, "SELECT id, label, hint, pinned_ip, created_at, last_used_at FROM announce_token ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var t Token
		var created, lastUsed int64
		if err := rows.Scan(&t.ID, &t.Label, &t.Hint, &t.PinnedIP, &created, &lastUsed); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(created, 0).UTC()
		if lastUsed > 0 {
			at := time.Unix(lastUsed, 0).UTC()
			t.LastUsedAt = &at
		}
		t.Services = used[t.ID]
		if t.Services == nil {
			t.Services = []string{}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Create makes a token for a server and returns it: the one time it is
// shown.
func (s *Service) Create(ctx context.Context, actor, remote, label string) (Token, string, error) {
	label = strings.TrimSpace(label)
	if label == "" || len([]rune(label)) > maxLabel {
		return Token{}, "", problem.Newf("Give the server a name of 1 to %d characters, so you know which token is whose.", maxLabel)
	}
	var count int
	if err := s.cfg.DB.QueryRowContext(ctx, "SELECT count(*) FROM announce_token").Scan(&count); err != nil {
		return Token{}, "", err
	}
	if count >= maxTokens {
		return Token{}, "", problem.Newf("There are already %d tokens; remove one you no longer use.", maxTokens)
	}
	raw, _, err := auth.NewToken()
	if err != nil {
		return Token{}, "", err
	}
	token := tokenPrefix + raw
	now := s.cfg.Now().Unix()
	result, err := s.cfg.DB.ExecContext(ctx, "INSERT INTO announce_token (label, token_hash, hint, created_at) VALUES (?, ?, ?, ?)",
		label, auth.HashToken(token), token[:len(tokenPrefix)+6], now)
	if err != nil {
		return Token{}, "", err
	}
	id, _ := result.LastInsertId()
	s.record(ctx, actor, audit.ActionTokenCreated, label, remote)
	return Token{ID: id, Label: label, Hint: token[:len(tokenPrefix)+6], CreatedAt: time.Unix(now, 0).UTC(), Services: []string{}}, token, nil
}

// Remove takes a token away. Its services are switched off at once, or
// kept as services of the page's own (keep).
func (s *Service) Remove(ctx context.Context, actor, remote string, id int64, keep bool) error {
	var label string
	if err := s.cfg.DB.QueryRowContext(ctx, "SELECT label FROM announce_token WHERE id = ?", id).Scan(&label); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return problem.New("That token does not exist (any more).")
		}
		return err
	}
	if err := s.cfg.Services.ReleaseToken(ctx, id, keep); err != nil {
		return err
	}
	if _, err := s.cfg.DB.ExecContext(ctx, "DELETE FROM announce_token WHERE id = ?", id); err != nil {
		return err
	}
	what := "its services switched off"
	if keep {
		what = "its services kept"
	}
	s.record(ctx, actor, audit.ActionTokenRemoved, label+" ("+what+")", remote)
	return nil
}

// Repin lets a token be used from a new address: the next announcement pins
// it again.
func (s *Service) Repin(ctx context.Context, actor, remote string, id int64) error {
	result, err := s.cfg.DB.ExecContext(ctx, "UPDATE announce_token SET pinned_ip = '' WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return problem.New("That token does not exist (any more).")
	}
	var label string
	s.cfg.DB.QueryRowContext(ctx, "SELECT label FROM announce_token WHERE id = ?", id).Scan(&label)
	s.record(ctx, actor, audit.ActionTokenRepinned, label+": the next announcement pins it to its address", remote)
	// Whatever announces next with this token is not known yet: its public
	// services stay closed until the owner opens them again.
	s.cfg.Services.CloseToken(ctx, actor, remote, id, "its server was marked as moved")
	return nil
}

// Refusal is an announcement that was refused as a whole, with the HTTP
// status to answer and the words for the server's log.
type Refusal struct {
	Status  int
	Message string
}

func (r *Refusal) Error() string { return r.Message }

// Handle checks a server's request and takes up its services. ip is the
// address the request came from. form is the request's fields.
func (s *Service) Handle(ctx context.Context, bearer, ip string, form url.Values) ([]services.AnnounceResult, error) {
	if wait := s.limiter.RetryAfter(ip); wait > 0 {
		return nil, &Refusal{Status: 429, Message: fmt.Sprintf("too many failed attempts from %s; try again in %d seconds", ip, int(wait.Seconds())+1)}
	}
	if !strings.HasPrefix(bearer, tokenPrefix) || len(bearer) > 200 {
		s.fail(ctx, ip, "an announcement without a valid token")
		return nil, &Refusal{Status: 401, Message: "no valid token (Authorization: Bearer <the server's token>)"}
	}
	var id int64
	var label, pinned string
	err := s.cfg.DB.QueryRowContext(ctx, "SELECT id, label, pinned_ip FROM announce_token WHERE token_hash = ?", auth.HashToken(bearer)).Scan(&id, &label, &pinned)
	if errors.Is(err, sql.ErrNoRows) {
		s.fail(ctx, ip, "an announcement with a token SGC does not know")
		return nil, &Refusal{Status: 401, Message: "SGC does not know this token (was it removed?)"}
	}
	if err != nil {
		return nil, err
	}
	if pinned != "" && pinned != ip {
		s.record(ctx, "token:"+label, audit.ActionTokenRefused, "used from "+ip+", pinned to "+pinned, ip)
		s.cfg.Alert(ctx, "A token was used from another address",
			fmt.Sprintf("The token of %q is pinned to %s and was used from %s. If the server moved, allow the new address in SGC's page (Services, Tokens).", label, pinned, ip))
		return nil, &Refusal{Status: 403, Message: "this token belongs to the server at " + pinned + "; if the server moved, allow its new address in SGC's page"}
	}
	s.limiter.Succeed(ip)

	items, err := parse(form)
	if err != nil {
		return nil, &Refusal{Status: 400, Message: err.Error()}
	}
	now := s.cfg.Now().Unix()
	if pinned == "" {
		s.cfg.DB.ExecContext(ctx, "UPDATE announce_token SET pinned_ip = ? WHERE id = ?", ip, id)
	}
	s.cfg.DB.ExecContext(ctx, "UPDATE announce_token SET last_used_at = ? WHERE id = ?", now, id)

	results, err := s.cfg.Services.Announce(ctx, id, label, ip, items)
	if err != nil {
		return nil, err
	}
	for _, r := range results {
		switch {
		case r.Conflict:
			s.cfg.Alert(ctx, "An announcement claimed a name that is taken", fmt.Sprintf("%q (the server at %s, token %q): %s.", r.Name, ip, label, r.Refused))
		case r.New && r.Pending:
			s.cfg.Alert(ctx, "A new service waits for your approval", fmt.Sprintf("%q, announced by %q (%s).", r.Name, label, ip))
		case r.New:
			s.cfg.Alert(ctx, "A new service was announced", fmt.Sprintf("%q, announced by %q (%s): %s", r.Name, label, ip, r.URL))
		}
	}
	return results, nil
}

func (s *Service) fail(ctx context.Context, ip, what string) {
	s.limiter.Fail(ip)
	s.record(ctx, "-", audit.ActionTokenRefused, what, ip)
	s.cfg.Alert(ctx, "An announcement was refused", what+", from "+ip+".")
}

// parse reads the fields of an announcement: service=name:port (repeated),
// and optionally category, scheme, type and mode for all of them.
func parse(form url.Values) ([]services.Announcement, error) {
	list := form["service"]
	if len(list) == 0 {
		return nil, errors.New("nothing to announce (-d service=name:port)")
	}
	if len(list) > maxPerCall {
		return nil, fmt.Errorf("at most %d services in one announcement", maxPerCall)
	}
	kind := strings.ToLower(form.Get("type"))
	switch kind {
	case "", "http", "tcp", "udp":
	default:
		return nil, errors.New(`type is "http", "tcp" or "udp"`)
	}
	scheme := strings.ToLower(form.Get("scheme"))
	if scheme != "" && scheme != "http" && scheme != "https" {
		return nil, errors.New(`scheme is "http" or "https"`)
	}
	mode := strings.ToLower(form.Get("mode"))
	if mode != "" && mode != services.ModeDirect && mode != services.ModeProxied {
		return nil, errors.New(`mode is "direct" or "proxied"`)
	}
	category := strings.TrimSpace(form.Get("category"))
	if len([]rune(category)) > 40 {
		return nil, errors.New("category is at most 40 characters")
	}
	var out []services.Announcement
	for _, entry := range list {
		name, port, ok := services.ParseService(strings.TrimSpace(entry))
		if !ok {
			return nil, fmt.Errorf("%q is not name:port", entry)
		}
		out = append(out, services.Announcement{Name: strings.ToLower(name), Port: port, Kind: kind, Scheme: scheme, Mode: mode, Category: category})
	}
	return out, nil
}
