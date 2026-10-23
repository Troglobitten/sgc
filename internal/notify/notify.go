// Package notify is how SGC tells the owner something: always in the page
// (the bell, and a banner while a problem lasts), and by email and ntfy
// where the owner set those up, per kind of event (docs/design.md §4.11).
//
// Two ways in: Notify for something that happened (a new service was
// announced), Raise and Resolve for a problem that lasts (the certificate
// cannot be renewed) and is reported once, not at every look.
//
// Web process only.
package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/store"
)

// SettingChannels holds the channels and the routing (exported: the email
// password and the ntfy token travel with an export, like the Zone.eu key).
const SettingChannels = "notify.channels"

// Kinds of event, each routed on its own.
const (
	EventCertificate = "certificate"
	EventDomain      = "domain"
	EventPublicIP    = "public_ip"
	EventCoreDown    = "core_down"
	EventServiceDown = "service_down"
	EventAbandoned   = "abandoned"
	EventHealth      = "health"
	EventUpdates     = "updates"
	EventEndOfLife   = "end_of_life"
	EventLogins      = "logins"
	EventAnnounce    = "announce"
	EventBackup      = "backup"
)

// Events lists every kind, with what the page calls it.
var Events = []struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}{
	{EventCertificate, "The certificate fails or runs out"},
	{EventDomain, "Zone.eu refuses the key"},
	{EventPublicIP, "The VPN's public name cannot be kept up to date"},
	{EventCoreDown, "DNS, the proxy or the VPN stops running"},
	{EventServiceDown, "A service stops answering"},
	{EventAbandoned, "A service looks abandoned"},
	{EventHealth, "Disk nearly full, too hot"},
	{EventUpdates, "Updates waiting, a restart needed"},
	{EventEndOfLife, "Software reaches its end of life"},
	{EventLogins, "Failed sign-ins and lock-outs"},
	{EventAnnounce, "New services announced, tokens misused"},
	{EventBackup, "Backups fail or are overdue"},
}

// Severities.
const (
	Info    = "info"
	Warning = "warning"
	Problem = "problem"
)

// Email is the SMTP account messages are sent from.
type Email struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	// Security is "starttls" (port 587), "tls" (465) or "none" (a relay in
	// the home network only).
	Security string `json:"security"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	To       string `json:"to"`
}

// Ntfy is a topic on an ntfy server (ntfy.sh or one's own).
type Ntfy struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Topic   string `json:"topic"`
	Token   string `json:"token,omitempty"`
}

// Channels are the owner's settings.
type Channels struct {
	Email Email `json:"email"`
	Ntfy  Ntfy  `json:"ntfy"`
	// Routes says, per event, which channels besides the page get it. An
	// event that is not listed goes to both if it is a warning or a
	// problem.
	Routes map[string]Route `json:"routes"`
}

type Route struct {
	Email bool `json:"email"`
	Ntfy  bool `json:"ntfy"`
}

// Notification is one entry of the bell.
type Notification struct {
	ID         int64      `json:"id"`
	At         time.Time  `json:"at"`
	Event      string     `json:"event"`
	Severity   string     `json:"severity"`
	Title      string     `json:"title"`
	Body       string     `json:"body"`
	Ongoing    bool       `json:"ongoing"`
	ResolvedAt *time.Time `json:"resolvedAt"`
	Read       bool       `json:"read"`
}

type Config struct {
	DB    *sql.DB
	Audit *audit.Log
	// HTTP sends to ntfy; Mail sends an email (nil: the real SMTP).
	HTTP *http.Client
	Mail func(ctx context.Context, e Email, subject, body string) error
	// Hostname names this device in messages.
	Hostname string
	Now      func() time.Time
	Log      *slog.Logger
}

type Service struct {
	cfg Config
	mu  sync.Mutex
	// sending runs channels in the background; tests wait for it.
	sending sync.WaitGroup
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Mail == nil {
		cfg.Mail = SendMail
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	return &Service{cfg: cfg}
}

// Channels returns the settings, without the secrets (the page shows
// whether they are set).
func (s *Service) Channels(ctx context.Context) (Channels, bool, bool, error) {
	c, err := s.channels(ctx)
	hasPassword, hasToken := c.Email.Password != "", c.Ntfy.Token != ""
	c.Email.Password, c.Ntfy.Token = "", ""
	return c, hasPassword, hasToken, err
}

func (s *Service) channels(ctx context.Context) (Channels, error) {
	var c Channels
	raw, found, err := store.Setting(ctx, s.cfg.DB, SettingChannels)
	if err != nil {
		return c, err
	}
	if found {
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return Channels{}, fmt.Errorf("the notification settings cannot be read: %w", err)
		}
	}
	if c.Routes == nil {
		c.Routes = map[string]Route{}
	}
	if c.Email.Port == 0 {
		c.Email.Port = 587
	}
	if c.Email.Security == "" {
		c.Email.Security = "starttls"
	}
	if c.Ntfy.Server == "" {
		c.Ntfy.Server = "https://ntfy.sh"
	}
	return c, nil
}

var (
	topicPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	hostPattern  = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
)

func validAddress(s string) bool {
	at := strings.LastIndexByte(s, '@')
	return at > 0 && at < len(s)-1 && len(s) <= 254 && !strings.ContainsAny(s, " \r\n<>,;\"")
}

// SetChannels keeps new settings. An empty password or token keeps the one
// there is.
func (s *Service) SetChannels(ctx context.Context, actor, remote string, next Channels) error {
	current, err := s.channels(ctx)
	if err != nil {
		return err
	}
	if next.Email.Password == "" {
		next.Email.Password = current.Email.Password
	}
	if next.Ntfy.Token == "" {
		next.Ntfy.Token = current.Ntfy.Token
	}
	if next.Email.Enabled {
		e := next.Email
		if !hostPattern.MatchString(e.Host) || e.Port < 1 || e.Port > 65535 {
			return problem.New("The mail server is a name like smtp.example.com, with a port (587 for STARTTLS, 465 for TLS).")
		}
		if e.Security != "starttls" && e.Security != "tls" && e.Security != "none" {
			return problem.New("Choose how SGC talks to the mail server: STARTTLS, TLS, or not encrypted.")
		}
		if !validAddress(e.From) || !validAddress(e.To) {
			return problem.New("The sender and the recipient are email addresses.")
		}
		if len(e.Username) > 200 || len(e.Password) > 200 || strings.ContainsAny(e.Username+e.Password, "\r\n") {
			return problem.New("The username or password is not usable.")
		}
	}
	if next.Ntfy.Enabled {
		u, err := url.Parse(next.Ntfy.Server)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
			return problem.New("The ntfy server is an address like https://ntfy.sh.")
		}
		if !topicPattern.MatchString(next.Ntfy.Topic) {
			return problem.New("A topic has letters, digits, hyphens and underscores. On ntfy.sh anyone who knows it can read it: make it long and random, or use a token.")
		}
		if len(next.Ntfy.Token) > 200 || strings.ContainsAny(next.Ntfy.Token, "\r\n ") {
			return problem.New("The ntfy token is not usable.")
		}
		next.Ntfy.Server = strings.TrimSuffix(next.Ntfy.Server, "/")
	}
	for key := range next.Routes {
		if !slices.ContainsFunc(Events, func(e struct {
			Key   string `json:"key"`
			Label string `json:"label"`
		}) bool {
			return e.Key == key
		}) {
			delete(next.Routes, key)
		}
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := store.SetSetting(ctx, s.cfg.DB, SettingChannels, string(data)); err != nil {
		return err
	}
	s.record(ctx, actor, audit.ActionNotifySettingsChanged, fmt.Sprintf("email %t, ntfy %t", next.Email.Enabled, next.Ntfy.Enabled), remote)
	return nil
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

// Notify records something that happened and sends it where it goes.
func (s *Service) Notify(ctx context.Context, event, severity, title, body string) {
	s.insert(ctx, event, severity, title, body, "")
}

// Raise reports a lasting problem, once while it lasts. key names it (one
// per thing: "service:12").
func (s *Service) Raise(ctx context.Context, key, event, severity, title, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id int64
	err := s.cfg.DB.QueryRowContext(ctx, "SELECT id FROM notification WHERE ongoing_key = ? AND resolved_at = 0", key).Scan(&id)
	if err == nil {
		return // reported already
	}
	if !errors.Is(err, sql.ErrNoRows) {
		s.cfg.Log.Error("look up a notification", "error", err)
		return
	}
	s.insert(ctx, event, severity, title, body, key)
}

// Resolve ends a lasting problem; resolved says so in words ("" for no
// message beyond the bell).
func (s *Service) Resolve(ctx context.Context, key, resolved string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id int64
	var event, title string
	err := s.cfg.DB.QueryRowContext(ctx, "SELECT id, event, title FROM notification WHERE ongoing_key = ? AND resolved_at = 0", key).Scan(&id, &event, &title)
	if err != nil {
		return
	}
	s.cfg.DB.ExecContext(context.WithoutCancel(ctx), "UPDATE notification SET resolved_at = ? WHERE id = ?", s.cfg.Now().Unix(), id)
	if resolved != "" {
		s.insert(ctx, event, Info, resolved, "Was: "+title, "")
	}
}

func (s *Service) insert(ctx context.Context, event, severity, title, body, key string) {
	var ongoing any
	if key != "" {
		ongoing = key
	}
	if _, err := s.cfg.DB.ExecContext(context.WithoutCancel(ctx), `INSERT INTO notification (at, event, severity, title, body, ongoing_key)
		VALUES (?, ?, ?, ?, ?, ?)`, s.cfg.Now().Unix(), event, severity, title, body, ongoing); err != nil {
		s.cfg.Log.Error("keep a notification", "error", err)
	}
	// Old entries go: the bell keeps the newest 500.
	s.cfg.DB.ExecContext(context.WithoutCancel(ctx), `DELETE FROM notification WHERE id NOT IN
		(SELECT id FROM notification ORDER BY id DESC LIMIT 500) AND (ongoing_key IS NULL OR resolved_at != 0)`)
	channels, err := s.channels(ctx)
	if err != nil {
		return
	}
	route, routed := channels.Routes[event]
	if !routed {
		route = Route{Email: severity != Info, Ntfy: severity != Info}
	}
	subject := "[" + s.cfg.Hostname + "] " + title
	if route.Email && channels.Email.Enabled {
		s.send(func(ctx context.Context) error { return s.cfg.Mail(ctx, channels.Email, subject, body) }, "email")
	}
	if route.Ntfy && channels.Ntfy.Enabled {
		s.send(func(ctx context.Context) error { return s.sendNtfy(ctx, channels.Ntfy, subject, body, severity) }, "ntfy")
	}
}

func (s *Service) send(do func(ctx context.Context) error, channel string) {
	s.sending.Add(1)
	go func() {
		defer s.sending.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := do(ctx); err != nil {
			s.cfg.Log.Error("send a notification", "channel", channel, "error", err)
		}
	}()
}

// Wait waits for messages being sent (tests).
func (s *Service) Wait() { s.sending.Wait() }

// sendNtfy publishes as JSON, which keeps any language in the title intact.
func (s *Service) sendNtfy(ctx context.Context, n Ntfy, title, body, severity string) error {
	priority := 3
	tags := []string{}
	switch severity {
	case Problem:
		priority, tags = 4, []string{"warning"}
	case Info:
		priority = 2
	}
	payload, err := json.Marshal(map[string]any{"topic": n.Topic, "title": title, "message": body, "priority": priority, "tags": tags})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.Server+"/", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ntfy answered %d", resp.StatusCode)
	}
	return nil
}

// Test sends a test message through one channel, now, and says how it went.
func (s *Service) Test(ctx context.Context, actor, remote, channel string) error {
	channels, err := s.channels(ctx)
	if err != nil {
		return err
	}
	subject := "[" + s.cfg.Hostname + "] A test from SGC"
	body := "If you read this, SGC's notifications reach you here."
	switch channel {
	case "email":
		if !channels.Email.Enabled {
			return problem.New("Switch email on and save first.")
		}
		err = s.cfg.Mail(ctx, channels.Email, subject, body)
	case "ntfy":
		if !channels.Ntfy.Enabled {
			return problem.New("Switch ntfy on and save first.")
		}
		err = s.sendNtfy(ctx, channels.Ntfy, subject, body, Info)
	default:
		return problem.New("Unknown channel.")
	}
	if err != nil {
		return problem.Newf("The test message was not sent: %v", err)
	}
	s.record(ctx, actor, audit.ActionNotifyTestSent, channel, remote)
	return nil
}

// List returns the newest notifications.
func (s *Service) List(ctx context.Context, limit int) ([]Notification, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.cfg.DB.QueryContext(ctx, `SELECT id, at, event, severity, title, body, ongoing_key IS NOT NULL, resolved_at, read_at
		FROM notification ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Notification{}
	for rows.Next() {
		var n Notification
		var at, resolved, read int64
		if err := rows.Scan(&n.ID, &at, &n.Event, &n.Severity, &n.Title, &n.Body, &n.Ongoing, &resolved, &read); err != nil {
			return nil, err
		}
		n.At = time.Unix(at, 0).UTC()
		if resolved > 0 {
			t := time.Unix(resolved, 0).UTC()
			n.ResolvedAt = &t
		}
		n.Read = read > 0
		out = append(out, n)
	}
	return out, rows.Err()
}

// Summary is what the bell shows at a glance.
type Summary struct {
	Unread int `json:"unread"`
	// Banners are the problems that last now.
	Banners []Notification `json:"banners"`
}

func (s *Service) Summary(ctx context.Context) (Summary, error) {
	out := Summary{Banners: []Notification{}}
	if err := s.cfg.DB.QueryRowContext(ctx, "SELECT count(*) FROM notification WHERE read_at = 0").Scan(&out.Unread); err != nil {
		return out, err
	}
	all, err := s.List(ctx, 500)
	if err != nil {
		return out, err
	}
	for _, n := range all {
		if n.Ongoing && n.ResolvedAt == nil && n.Severity != Info {
			out.Banners = append(out.Banners, n)
		}
	}
	return out, nil
}

// MarkRead marks everything as read.
func (s *Service) MarkRead(ctx context.Context) error {
	_, err := s.cfg.DB.ExecContext(ctx, "UPDATE notification SET read_at = ? WHERE read_at = 0", s.cfg.Now().Unix())
	return err
}
