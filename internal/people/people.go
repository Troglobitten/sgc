// Package people is the people the owner lets in: through the VPN with
// their devices, and through SGC's login gate in front of protected
// services. One list of services per person governs both (docs/design.md
// §4.8). A person never gets into SGC's own page.
//
// Web process only.
package people

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/problem"
)

// What a person's VPN devices reach.
const (
	NetworkFull     = "full"
	NetworkServices = "services"
)

const (
	maxName    = 60
	maxPeople  = 200
	sessionFor = 12 * time.Hour
)

// Person is one person, as the page shows it. The password is never in it.
type Person struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Network      string     `json:"network"`
	AllServices  bool       `json:"allServices"`
	ServiceIDs   []int64    `json:"serviceIds"`
	LoginEnabled bool       `json:"loginEnabled"`
	Username     string     `json:"username"`
	HasPassword  bool       `json:"hasPassword"`
	ExpiresAt    *time.Time `json:"expiresAt"`
	Disabled     bool       `json:"disabled"`
	// Active: not switched off and not past their end date.
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"createdAt"`
}

// Input is what the owner sets. An empty password keeps the one there is.
type Input struct {
	Name         string     `json:"name"`
	Network      string     `json:"network"`
	AllServices  bool       `json:"allServices"`
	ServiceIDs   []int64    `json:"serviceIds"`
	LoginEnabled bool       `json:"loginEnabled"`
	Username     string     `json:"username"`
	Password     string     `json:"password"`
	ExpiresAt    *time.Time `json:"expiresAt"`
	Disabled     bool       `json:"disabled"`
}

type Config struct {
	DB    *sql.DB
	Audit *audit.Log
	// Changed is called after anything that changes who reaches what.
	Changed func()
	// AdminUsername returns the admin's name, which no person may take.
	AdminUsername func(ctx context.Context) (string, error)
	Now           func() time.Time
	Log           *slog.Logger
}

type Service struct {
	cfg     Config
	limiter *auth.Limiter
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Changed == nil {
		cfg.Changed = func() {}
	}
	return &Service{cfg: cfg, limiter: auth.NewLimiter()}
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

func (s *Service) scanPerson(row interface{ Scan(...any) error }) (Person, error) {
	var p Person
	var username sql.NullString
	var hash string
	var expires, created int64
	if err := row.Scan(&p.ID, &p.Name, &p.Network, &p.AllServices, &p.LoginEnabled, &username, &hash, &expires, &p.Disabled, &created); err != nil {
		return Person{}, err
	}
	p.Username, p.HasPassword = username.String, hash != ""
	if expires > 0 {
		at := time.Unix(expires, 0).UTC()
		p.ExpiresAt = &at
	}
	p.CreatedAt = time.Unix(created, 0).UTC()
	p.Active = !p.Disabled && (p.ExpiresAt == nil || s.cfg.Now().Before(*p.ExpiresAt))
	p.ServiceIDs = []int64{}
	return p, nil
}

const personColumns = "id, name, network, all_services, login_enabled, username, password_hash, expires_at, disabled, created_at"

// List returns everybody, by name.
func (s *Service) List(ctx context.Context) ([]Person, error) {
	rows, err := s.cfg.DB.QueryContext(ctx, "SELECT "+personColumns+" FROM person ORDER BY name COLLATE NOCASE")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Person{}
	byID := map[int64]int{}
	for rows.Next() {
		p, err := s.scanPerson(rows)
		if err != nil {
			return nil, err
		}
		byID[p.ID] = len(out)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	links, err := s.cfg.DB.QueryContext(ctx, "SELECT person_id, service_id FROM person_service ORDER BY service_id")
	if err != nil {
		return nil, err
	}
	defer links.Close()
	for links.Next() {
		var personID, serviceID int64
		if err := links.Scan(&personID, &serviceID); err != nil {
			return nil, err
		}
		if i, ok := byID[personID]; ok {
			out[i].ServiceIDs = append(out[i].ServiceIDs, serviceID)
		}
	}
	return out, links.Err()
}

var ErrNotFound = problem.New("That person does not exist (any more).")

func (s *Service) Get(ctx context.Context, id int64) (Person, error) {
	all, err := s.List(ctx)
	if err != nil {
		return Person{}, err
	}
	for _, p := range all {
		if p.ID == id {
			return p, nil
		}
	}
	return Person{}, ErrNotFound
}

// validUsername: what a person types to sign in. Letters, digits and a few
// marks, so that it cannot be mistaken for something else in a log.
func validUsername(s string) bool {
	if len(s) < 2 || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (s *Service) check(ctx context.Context, in *Input, exceptID int64, hadPassword bool) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Username = strings.TrimSpace(in.Username)
	if in.Name == "" || len([]rune(in.Name)) > maxName {
		return problem.Newf("A name of 1 to %d characters.", maxName)
	}
	if in.Network != NetworkFull && in.Network != NetworkServices {
		return problem.New("Choose what this person's devices reach: the whole home network, or services only.")
	}
	if in.LoginEnabled {
		if !validUsername(in.Username) {
			return problem.New("A username of 2 to 40 letters, digits, dots, hyphens or underscores.")
		}
		if in.Password == "" && !hadPassword {
			return problem.New("A login needs a password.")
		}
		if admin, err := s.cfg.AdminUsername(ctx); err == nil && strings.EqualFold(admin, in.Username) {
			return problem.New("That is the admin's name; choose another username.")
		}
		var other int64
		err := s.cfg.DB.QueryRowContext(ctx, "SELECT id FROM person WHERE username = ? COLLATE NOCASE AND id != ?", in.Username, exceptID).Scan(&other)
		if err == nil {
			return problem.New("Somebody else already has that username.")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if in.Password != "" && len([]rune(in.Password)) < auth.MinPasswordLength {
		return problem.Newf("A password of at least %d characters.", auth.MinPasswordLength)
	}
	if in.ExpiresAt != nil && in.ExpiresAt.Before(s.cfg.Now().Add(-time.Minute)) && exceptID == 0 {
		return problem.New("The end date is in the past.")
	}
	var other int64
	err := s.cfg.DB.QueryRowContext(ctx, "SELECT id FROM person WHERE name = ? AND id != ?", in.Name, exceptID).Scan(&other)
	if err == nil {
		return problem.New("There is already a person with that name.")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	slices.Sort(in.ServiceIDs)
	in.ServiceIDs = slices.Compact(in.ServiceIDs)
	return nil
}

func expiresValue(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

func (s *Service) writeServices(ctx context.Context, tx *sql.Tx, personID int64, ids []int64) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM person_service WHERE person_id = ?", personID); err != nil {
		return err
	}
	for _, id := range ids {
		// A service removed in the meantime is not an error: it is skipped.
		if _, err := tx.ExecContext(ctx, "INSERT INTO person_service (person_id, service_id) SELECT ?, id FROM service WHERE id = ?", personID, id); err != nil {
			return err
		}
	}
	return nil
}

func describe(in Input) string {
	parts := []string{in.Name}
	if in.Network == NetworkFull {
		parts = append(parts, "whole home network")
	} else if in.AllServices {
		parts = append(parts, "all services")
	} else {
		parts = append(parts, strconv.Itoa(len(in.ServiceIDs))+" services")
	}
	if in.LoginEnabled {
		parts = append(parts, "login "+in.Username)
	}
	if in.ExpiresAt != nil {
		parts = append(parts, "until "+in.ExpiresAt.UTC().Format(time.DateOnly))
	}
	if in.Disabled {
		parts = append(parts, "switched off")
	}
	return strings.Join(parts, ", ")
}

// Add adds a person.
func (s *Service) Add(ctx context.Context, actor, remote string, in Input) (Person, error) {
	var count int
	if err := s.cfg.DB.QueryRowContext(ctx, "SELECT count(*) FROM person").Scan(&count); err != nil {
		return Person{}, err
	}
	if count >= maxPeople {
		return Person{}, problem.Newf("SGC keeps at most %d people.", maxPeople)
	}
	if err := s.check(ctx, &in, 0, false); err != nil {
		return Person{}, err
	}
	hash := ""
	if in.LoginEnabled {
		var err error
		if hash, err = auth.HashPassword(in.Password); err != nil {
			return Person{}, err
		}
	}
	now := s.cfg.Now().Unix()
	tx, err := s.cfg.DB.BeginTx(ctx, nil)
	if err != nil {
		return Person{}, err
	}
	defer tx.Rollback()
	var username any
	if in.LoginEnabled {
		username = in.Username
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO person (name, network, all_services, login_enabled, username, password_hash,
		expires_at, disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Name, in.Network, in.AllServices, in.LoginEnabled, username, hash, expiresValue(in.ExpiresAt), in.Disabled, now, now)
	if err != nil {
		return Person{}, err
	}
	id, _ := result.LastInsertId()
	if err := s.writeServices(ctx, tx, id, in.ServiceIDs); err != nil {
		return Person{}, err
	}
	if err := tx.Commit(); err != nil {
		return Person{}, err
	}
	s.record(ctx, actor, audit.ActionPersonAdded, describe(in), remote)
	s.cfg.Changed()
	return s.Get(ctx, id)
}

// Update changes a person. Switching off the login, or changing the
// password, ends the person's sign-ins at the gate.
func (s *Service) Update(ctx context.Context, actor, remote string, id int64, in Input) (Person, error) {
	before, err := s.Get(ctx, id)
	if err != nil {
		return Person{}, err
	}
	if err := s.check(ctx, &in, id, before.HasPassword && before.LoginEnabled); err != nil {
		return Person{}, err
	}
	tx, err := s.cfg.DB.BeginTx(ctx, nil)
	if err != nil {
		return Person{}, err
	}
	defer tx.Rollback()
	var username any
	if in.LoginEnabled {
		username = in.Username
	}
	if _, err := tx.ExecContext(ctx, `UPDATE person SET name = ?, network = ?, all_services = ?, login_enabled = ?, username = ?,
		expires_at = ?, disabled = ?, updated_at = ? WHERE id = ?`, in.Name, in.Network, in.AllServices, in.LoginEnabled, username,
		expiresValue(in.ExpiresAt), in.Disabled, s.cfg.Now().Unix(), id); err != nil {
		return Person{}, err
	}
	endSessions := !in.LoginEnabled || in.Disabled || in.Password != "" || (before.Username != in.Username)
	if !in.LoginEnabled {
		if _, err := tx.ExecContext(ctx, "UPDATE person SET password_hash = '' WHERE id = ?", id); err != nil {
			return Person{}, err
		}
	} else if in.Password != "" {
		hash, err := auth.HashPassword(in.Password)
		if err != nil {
			return Person{}, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE person SET password_hash = ? WHERE id = ?", hash, id); err != nil {
			return Person{}, err
		}
	}
	if endSessions {
		if _, err := tx.ExecContext(ctx, "DELETE FROM person_session WHERE person_id = ?", id); err != nil {
			return Person{}, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM gate_pass WHERE person_id = ?", id); err != nil {
			return Person{}, err
		}
	}
	if err := s.writeServices(ctx, tx, id, in.ServiceIDs); err != nil {
		return Person{}, err
	}
	if err := tx.Commit(); err != nil {
		return Person{}, err
	}
	s.record(ctx, actor, audit.ActionPersonChanged, describe(in), remote)
	s.cfg.Changed()
	return s.Get(ctx, id)
}

// Remove takes a person away, with their devices and sign-ins.
func (s *Service) Remove(ctx context.Context, actor, remote string, id int64) error {
	p, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.cfg.DB.ExecContext(ctx, "DELETE FROM person WHERE id = ?", id); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionPersonRemoved, p.Name, remote)
	s.cfg.Changed()
	return nil
}

// Reaches reports whether a person may use a service: full network or all
// services, or the service is on their list.
func (p Person) Reaches(serviceID int64) bool {
	return p.Active && (p.Network == NetworkFull || p.AllServices || slices.Contains(p.ServiceIDs, serviceID))
}

// Run notices guests whose time ran out, once a minute, so that their
// devices and login stop.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	notified := map[int64]bool{}
	for {
		if all, err := s.List(ctx); err == nil {
			changed := false
			for _, p := range all {
				expired := p.ExpiresAt != nil && !p.Active && !p.Disabled
				if expired && !notified[p.ID] {
					notified[p.ID] = true
					changed = true
					s.record(ctx, audit.ActorSystem, audit.ActionPersonExpired, p.Name+" (end date "+p.ExpiresAt.Format(time.DateOnly)+")", "")
					s.cfg.DB.ExecContext(ctx, "DELETE FROM person_session WHERE person_id = ?", p.ID)
					s.cfg.DB.ExecContext(ctx, "DELETE FROM gate_pass WHERE person_id = ?", p.ID)
				}
				if !expired {
					delete(notified, p.ID)
				}
			}
			if changed {
				s.cfg.Changed()
			}
		}
		if err := s.DeleteExpiredSessions(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Log.Error("delete expired gate sign-ins", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// --- Signing in at the gate -------------------------------------------------------

// ErrSignIn is a wrong username or password, or a person who may not sign
// in (no login, switched off, past their end date). Which it was is not
// said.
var ErrSignIn = problem.New("That username and password do not match a login.")

// Session is a person signed in at the gate page.
type Session struct {
	Token    string
	PersonID int64
	Name     string
	Expires  time.Time
}

// Login checks a person's username and password.
func (s *Service) Login(ctx context.Context, username, password, remote, userAgent string) (*Session, error) {
	if wait := s.limiter.RetryAfter(remote); wait > 0 {
		return nil, &auth.TooManyAttemptsError{RetryAfter: wait}
	}
	var id int64
	var name, hash string
	var loginEnabled, disabled bool
	var expires int64
	err := s.cfg.DB.QueryRowContext(ctx, `SELECT id, name, password_hash, login_enabled, disabled, expires_at FROM person
		WHERE username = ? COLLATE NOCASE`, strings.TrimSpace(username)).Scan(&id, &name, &hash, &loginEnabled, &disabled, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		hash = auth.DecoyHash()
	} else if err != nil {
		return nil, err
	}
	ok, verifyErr := auth.VerifyPassword(hash, password)
	if verifyErr != nil {
		ok = false
	}
	active := loginEnabled && !disabled && (expires == 0 || s.cfg.Now().Unix() < expires)
	if err != nil || !ok || !active {
		s.limiter.Fail(remote)
		s.record(ctx, "-", audit.ActionGateLoginFailed, "username tried: "+truncate(username, 64), remote)
		return nil, ErrSignIn
	}
	s.limiter.Succeed(remote)
	token, tokenHash, err := auth.NewToken()
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	session := &Session{Token: token, PersonID: id, Name: name, Expires: now.Add(sessionFor)}
	if _, err := s.cfg.DB.ExecContext(ctx, `INSERT INTO person_session (token_hash, person_id, created_at, last_seen_at, expires_at,
		remote_addr, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)`, tokenHash, id, now.Unix(), now.Unix(), session.Expires.Unix(),
		remote, truncate(userAgent, 200)); err != nil {
		return nil, err
	}
	s.record(ctx, name, audit.ActionGateLogin, "", remote)
	return session, nil
}

// Authenticate returns the person a gate sign-in belongs to, or nil. A
// person who may no longer sign in has no session.
func (s *Service) Authenticate(ctx context.Context, token string) (*Person, error) {
	if token == "" {
		return nil, nil
	}
	var personID, expires int64
	err := s.cfg.DB.QueryRowContext(ctx, "SELECT person_id, expires_at FROM person_session WHERE token_hash = ?", auth.HashToken(token)).Scan(&personID, &expires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && s.cfg.Now().Unix() >= expires) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := s.Get(ctx, personID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil || !p.Active || !p.LoginEnabled {
		return nil, err
	}
	return &p, nil
}

// Logout ends a gate sign-in.
func (s *Service) Logout(ctx context.Context, token string) error {
	_, err := s.cfg.DB.ExecContext(ctx, "DELETE FROM person_session WHERE token_hash = ?", auth.HashToken(token))
	return err
}

// ChangePassword lets a signed-in person set a new password, with the old one.
func (s *Service) ChangePassword(ctx context.Context, personID int64, old, next, remote string) error {
	if len([]rune(next)) < auth.MinPasswordLength {
		return problem.Newf("A password of at least %d characters.", auth.MinPasswordLength)
	}
	var hash, name string
	if err := s.cfg.DB.QueryRowContext(ctx, "SELECT password_hash, name FROM person WHERE id = ?", personID).Scan(&hash, &name); err != nil {
		return err
	}
	if ok, err := auth.VerifyPassword(hash, old); err != nil || !ok {
		s.limiter.Fail(remote)
		return problem.New("The current password is not right.")
	}
	newHash, err := auth.HashPassword(next)
	if err != nil {
		return err
	}
	if _, err := s.cfg.DB.ExecContext(ctx, "UPDATE person SET password_hash = ?, updated_at = ? WHERE id = ?", newHash, s.cfg.Now().Unix(), personID); err != nil {
		return err
	}
	s.record(ctx, name, audit.ActionPersonPasswordChanged, "", remote)
	return nil
}

// DeleteExpiredSessions tidies the gate's sign-ins and passes.
func (s *Service) DeleteExpiredSessions(ctx context.Context) error {
	now := s.cfg.Now().Unix()
	if _, err := s.cfg.DB.ExecContext(ctx, "DELETE FROM person_session WHERE expires_at <= ?", now); err != nil {
		return err
	}
	_, err := s.cfg.DB.ExecContext(ctx, "DELETE FROM gate_pass WHERE expires_at <= ?", now)
	return err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
