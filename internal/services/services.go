// Package services is the list of services behind SGC's names: those the
// owner adds in the page (for devices that cannot announce themselves) and
// those servers announce (internal/announce). It checks what goes in, says
// which names AdGuard Home should answer, which routes Traefik should have,
// probes every service, and fetches its icon.
//
// Web process only.
package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/dnsnames"
	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/store"
)

// Settings of the services as a whole (exported).
const (
	// SettingApproveNew: an announced service waits for the owner's approval.
	SettingApproveNew = "services.approve_new"
	// SettingIconCatalogue: use the icon collection kept on the device
	// (internal/iconpack; until 0.17.0 the public catalogue on a CDN).
	SettingIconCatalogue = "services.icon_catalogue"
	// SettingAbandonedDays: after how many days down a service "looks abandoned".
	SettingAbandonedDays = "services.abandoned_days"

	defaultAbandonedDays = 14
	maxTitle             = 80
	maxCategory          = 40
)

// Modes for TCP and UDP services.
const (
	ModeProxied = "proxied"
	ModeDirect  = "direct"
)

// Health is how a service answered the probes.
type Health struct {
	// State is "up", "down" or "unknown" (UDP cannot be probed).
	State     string     `json:"state"`
	Since     time.Time  `json:"since"`
	CheckedAt time.Time  `json:"checkedAt"`
	LastUpAt  *time.Time `json:"lastUpAt"`
	// Abandoned: down for longer than the owner's limit.
	Abandoned bool `json:"abandoned"`
}

// Service is one entry, as the page shows it.
type Service struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Title        string `json:"title"`
	Kind         string `json:"kind"`
	Mode         string `json:"mode"`
	UpstreamIP   string `json:"upstreamIp"`
	UpstreamPort int    `json:"upstreamPort"`
	Scheme       string `json:"scheme"`
	VerifyTLS    bool   `json:"verifyTls"`
	ListenPort   int    `json:"listenPort"`
	Category     string `json:"category"`
	Protected    bool   `json:"protected"`
	Enabled      bool   `json:"enabled"`
	Pending      bool   `json:"pending"`
	// TokenID is the token that announced it, nil for one added in the page.
	TokenID     *int64     `json:"tokenId"`
	TokenLabel  string     `json:"tokenLabel"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	AnnouncedAt *time.Time `json:"announcedAt"`
	HasIcon     bool       `json:"hasIcon"`
	Health      Health     `json:"health"`
	// URL is how to open it ("" until a domain is set up).
	URL string `json:"url"`
}

// Input is what the owner sets for a service in the page.
type Input struct {
	Name         string `json:"name"`
	Title        string `json:"title"`
	Kind         string `json:"kind"`
	Mode         string `json:"mode"`
	UpstreamIP   string `json:"upstreamIp"`
	UpstreamPort int    `json:"upstreamPort"`
	Scheme       string `json:"scheme"`
	VerifyTLS    bool   `json:"verifyTls"`
	ListenPort   int    `json:"listenPort"`
	Category     string `json:"category"`
	Protected    bool   `json:"protected"`
	Enabled      bool   `json:"enabled"`
}

// Config is what the catalogue needs.
type Config struct {
	DB    *sql.DB
	Audit *audit.Log
	// Domain returns the owner's domain, if one is set up.
	Domain func(ctx context.Context) (string, bool, error)
	LAN    func() (netinfo.LAN, error)
	// Reserved returns the labels other parts of SGC use, with what uses
	// them ("SGC's page", "the VPN").
	Reserved func(ctx context.Context) (map[string]string, error)
	// ReservedPorts returns the gateway's own ports, which no proxied
	// service may take.
	ReservedPorts func(ctx context.Context) []int
	// Changed is called after anything that changes names or routes.
	Changed func()
	// Probe tries to reach a service; nil means a TCP connection.
	Probe func(ctx context.Context, address string) error
	// Icons fetches icons; nil means none are fetched (tests).
	Icons *IconFetcher
	Now   func() time.Time
	Log   *slog.Logger
}

type Catalog struct {
	cfg Config
}

func New(cfg Config) *Catalog {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Changed == nil {
		cfg.Changed = func() {}
	}
	if cfg.ReservedPorts == nil {
		cfg.ReservedPorts = func(context.Context) []int { return nil }
	}
	return &Catalog{cfg: cfg}
}

const selectColumns = `s.id, s.name, s.title, s.kind, s.mode, s.upstream_ip, s.upstream_port, s.scheme, s.verify_tls,
	s.listen_port, s.category, s.protected, s.enabled, s.pending, s.token_id, COALESCE(t.label, ''),
	s.created_at, s.updated_at, s.announced_at, i.service_id IS NOT NULL,
	h.up, h.since, h.checked_at, h.last_up_at`

const fromTables = ` FROM service s
	LEFT JOIN announce_token t ON t.id = s.token_id
	LEFT JOIN service_icon i ON i.service_id = s.id
	LEFT JOIN service_health h ON h.service_id = s.id`

type scanner interface{ Scan(dest ...any) error }

func (c *Catalog) scan(row scanner, abandonedAfter time.Duration, domain string) (Service, error) {
	var s Service
	var tokenID sql.NullInt64
	var created, updated, announced int64
	var up, since, checked, lastUp sql.NullInt64
	if err := row.Scan(&s.ID, &s.Name, &s.Title, &s.Kind, &s.Mode, &s.UpstreamIP, &s.UpstreamPort, &s.Scheme, &s.VerifyTLS,
		&s.ListenPort, &s.Category, &s.Protected, &s.Enabled, &s.Pending, &tokenID, &s.TokenLabel,
		&created, &updated, &announced, &s.HasIcon, &up, &since, &checked, &lastUp); err != nil {
		return Service{}, err
	}
	if tokenID.Valid {
		id := tokenID.Int64
		s.TokenID = &id
	}
	s.CreatedAt, s.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	if announced > 0 {
		at := time.Unix(announced, 0).UTC()
		s.AnnouncedAt = &at
	}
	s.Health = Health{State: "unknown"}
	if up.Valid {
		s.Health.State = "down"
		if up.Int64 == 1 {
			s.Health.State = "up"
		}
		s.Health.Since = time.Unix(since.Int64, 0).UTC()
		s.Health.CheckedAt = time.Unix(checked.Int64, 0).UTC()
		if lastUp.Int64 > 0 {
			at := time.Unix(lastUp.Int64, 0).UTC()
			s.Health.LastUpAt = &at
		}
		s.Health.Abandoned = s.Health.State == "down" && c.cfg.Now().Sub(s.Health.Since) > abandonedAfter
	}
	s.URL = urlOf(s, domain)
	return s, nil
}

func urlOf(s Service, domain string) string {
	if domain == "" {
		return ""
	}
	host := s.Name + "." + domain
	switch {
	case s.Kind == proxy.KindHTTP:
		return "https://" + host
	case s.Mode == ModeProxied:
		return host + ":" + strconv.Itoa(s.ListenPort)
	default:
		return host + ":" + strconv.Itoa(s.UpstreamPort)
	}
}

func (c *Catalog) abandonedAfter(ctx context.Context) time.Duration {
	days := defaultAbandonedDays
	if raw, found, err := store.Setting(ctx, c.cfg.DB, SettingAbandonedDays); err == nil && found {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 365 {
			days = n
		}
	}
	return time.Duration(days) * 24 * time.Hour
}

func (c *Catalog) domain(ctx context.Context) (string, error) {
	domain, configured, err := c.cfg.Domain(ctx)
	if err != nil || !configured {
		return "", err
	}
	return domain, nil
}

// List returns every service, by category and name.
func (c *Catalog) List(ctx context.Context) ([]Service, error) {
	domain, err := c.domain(ctx)
	if err != nil {
		return nil, err
	}
	after := c.abandonedAfter(ctx)
	rows, err := c.cfg.DB.QueryContext(ctx, "SELECT "+selectColumns+fromTables+" ORDER BY s.category, s.name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Service{}
	for rows.Next() {
		s, err := c.scan(rows, after, domain)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ErrNotFound is a service that does not exist (any more).
var ErrNotFound = problem.New("That service does not exist (any more).")

func (c *Catalog) Get(ctx context.Context, id int64) (Service, error) {
	domain, err := c.domain(ctx)
	if err != nil {
		return Service{}, err
	}
	s, err := c.scan(c.cfg.DB.QueryRowContext(ctx, "SELECT "+selectColumns+fromTables+" WHERE s.id = ?", id), c.abandonedAfter(ctx), domain)
	if errors.Is(err, sql.ErrNoRows) {
		return Service{}, ErrNotFound
	}
	return s, err
}

// normalise fills in defaults and checks an entry. exceptID is the entry
// being changed (0 for a new one), which may keep its own name and port.
func (c *Catalog) normalise(ctx context.Context, in Input, exceptID int64) (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Title = strings.TrimSpace(in.Title)
	in.Category = strings.TrimSpace(in.Category)
	in.UpstreamIP = strings.TrimSpace(in.UpstreamIP)
	if !gateway.ValidLabel(in.Name) {
		return in, problem.New("A name is 1 to 63 lower-case letters, digits and hyphens, and does not start or end with a hyphen. It becomes name.your-domain.")
	}
	if len([]rune(in.Title)) > maxTitle || len([]rune(in.Category)) > maxCategory {
		return in, problem.New("The title or the category is too long.")
	}
	if !proxy.ValidUpstream(in.UpstreamIP) {
		return in, problem.New("The address must be a device in the home network (192.168.x.x, 10.x.x.x or 172.16–31.x.x).")
	}
	if lan, err := c.cfg.LAN(); err == nil && lan.Address.String() == in.UpstreamIP {
		return in, problem.New("That is the address of this device itself. SGC's own page and AdGuard Home's already have names.")
	}
	if in.UpstreamPort < 1 || in.UpstreamPort > 65535 {
		return in, problem.New("The port is a number from 1 to 65535.")
	}
	switch in.Kind {
	case "", proxy.KindHTTP:
		in.Kind, in.Mode, in.ListenPort = proxy.KindHTTP, ModeProxied, 0
		if in.Scheme == "" {
			in.Scheme = "http"
		}
		if in.Scheme != "http" && in.Scheme != "https" {
			return in, problem.New("The device is reached over http or https.")
		}
	case proxy.KindTCP, proxy.KindUDP:
		in.Scheme, in.VerifyTLS = "http", false
		if in.Protected {
			return in, problem.New("Only web services can be behind SGC's login.")
		}
		if in.Mode == "" {
			in.Mode = ModeDirect
		}
		switch in.Mode {
		case ModeDirect:
			in.ListenPort = 0
		case ModeProxied:
			if in.ListenPort == 0 {
				in.ListenPort = in.UpstreamPort
			}
			if in.ListenPort < 1 || in.ListenPort > 65535 {
				return in, problem.New("The port on the gateway is a number from 1 to 65535.")
			}
			if err := c.portFree(ctx, in.Kind, in.ListenPort, exceptID); err != nil {
				return in, err
			}
		default:
			return in, problem.New(`The way through is "direct" or "proxied".`)
		}
	default:
		return in, problem.New("A service is a web service, TCP or UDP.")
	}
	if err := c.nameFree(ctx, in.Name, exceptID); err != nil {
		return in, err
	}
	return in, nil
}

func (c *Catalog) nameFree(ctx context.Context, name string, exceptID int64) error {
	reserved, err := c.cfg.Reserved(ctx)
	if err != nil {
		return err
	}
	if holder, ok := reserved[name]; ok {
		return problem.Newf("%q is already used by %s.", name, holder)
	}
	var id int64
	err = c.cfg.DB.QueryRowContext(ctx, "SELECT id FROM service WHERE name = ?", name).Scan(&id)
	if err == nil && id != exceptID {
		return problem.Newf("There is already a service called %q.", name)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func (c *Catalog) portFree(ctx context.Context, kind string, port int, exceptID int64) error {
	gatewayPorts := []int{22, 53, 80, 443, 3000, 8082, 8443, 8444}
	gatewayPorts = append(gatewayPorts, c.cfg.ReservedPorts(ctx)...)
	if slices.Contains(gatewayPorts, port) {
		return problem.Newf("Port %d is used by the gateway itself. Choose another port on the gateway.", port)
	}
	var id int64
	err := c.cfg.DB.QueryRowContext(ctx,
		"SELECT id FROM service WHERE kind = ? AND mode = 'proxied' AND listen_port = ? AND id != ?", kind, port, exceptID).Scan(&id)
	if err == nil {
		return problem.Newf("Port %d/%s on the gateway is already taken by another service.", port, kind)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func (c *Catalog) record(ctx context.Context, actor, action, detail, remote string) {
	if err := c.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		c.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

func describe(in Input) string {
	where := in.UpstreamIP + ":" + strconv.Itoa(in.UpstreamPort)
	switch {
	case in.Kind == proxy.KindHTTP:
		return in.Name + " → " + in.Scheme + "://" + where
	case in.Mode == ModeProxied:
		return in.Name + " (" + in.Kind + ", gateway port " + strconv.Itoa(in.ListenPort) + ") → " + where
	default:
		return in.Name + " (" + in.Kind + ", direct) → " + where
	}
}

// Add adds a service by hand.
func (c *Catalog) Add(ctx context.Context, actor, remote string, in Input) (Service, error) {
	in, err := c.normalise(ctx, in, 0)
	if err != nil {
		return Service{}, err
	}
	now := c.cfg.Now().Unix()
	result, err := c.cfg.DB.ExecContext(ctx, `INSERT INTO service (name, title, kind, mode, upstream_ip, upstream_port, scheme,
		verify_tls, listen_port, category, protected, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Name, in.Title, in.Kind, in.Mode, in.UpstreamIP, in.UpstreamPort, in.Scheme, in.VerifyTLS, in.ListenPort,
		in.Category, in.Protected, in.Enabled, now, now)
	if err != nil {
		return Service{}, err
	}
	id, _ := result.LastInsertId()
	c.record(ctx, actor, audit.ActionServiceAdded, describe(in), remote)
	c.cfg.Changed()
	c.fetchIconSoon(id)
	return c.Get(ctx, id)
}

// Update changes a service. One that a server announced can be changed
// too; its next announcement then changes back only its port.
func (c *Catalog) Update(ctx context.Context, actor, remote string, id int64, in Input) (Service, error) {
	before, err := c.Get(ctx, id)
	if err != nil {
		return Service{}, err
	}
	if in, err = c.normalise(ctx, in, id); err != nil {
		return Service{}, err
	}
	if _, err := c.cfg.DB.ExecContext(ctx, `UPDATE service SET name = ?, title = ?, kind = ?, mode = ?, upstream_ip = ?,
		upstream_port = ?, scheme = ?, verify_tls = ?, listen_port = ?, category = ?, protected = ?, enabled = ?, updated_at = ?
		WHERE id = ?`, in.Name, in.Title, in.Kind, in.Mode, in.UpstreamIP, in.UpstreamPort, in.Scheme, in.VerifyTLS,
		in.ListenPort, in.Category, in.Protected, in.Enabled, c.cfg.Now().Unix(), id); err != nil {
		return Service{}, err
	}
	detail := describe(in)
	if before.Name != in.Name {
		detail = before.Name + " renamed: " + detail
	}
	if !in.Enabled {
		detail += " (switched off)"
	}
	c.record(ctx, actor, audit.ActionServiceChanged, detail, remote)
	if before.UpstreamIP != in.UpstreamIP || before.UpstreamPort != in.UpstreamPort || before.Scheme != in.Scheme {
		c.cfg.DB.ExecContext(ctx, "DELETE FROM service_health WHERE service_id = ?", id)
		c.fetchIconSoon(id)
	}
	c.cfg.Changed()
	return c.Get(ctx, id)
}

// Remove takes a service away.
func (c *Catalog) Remove(ctx context.Context, actor, remote string, id int64) error {
	s, err := c.Get(ctx, id)
	if err != nil {
		return err
	}
	if _, err := c.cfg.DB.ExecContext(ctx, "DELETE FROM service WHERE id = ?", id); err != nil {
		return err
	}
	c.record(ctx, actor, audit.ActionServiceRemoved, s.Name, remote)
	c.cfg.Changed()
	return nil
}

// Approve lets an announced service that waited for approval go live.
func (c *Catalog) Approve(ctx context.Context, actor, remote string, id int64) error {
	s, err := c.Get(ctx, id)
	if err != nil {
		return err
	}
	if !s.Pending {
		return nil
	}
	if _, err := c.cfg.DB.ExecContext(ctx, "UPDATE service SET pending = 0, updated_at = ? WHERE id = ?", c.cfg.Now().Unix(), id); err != nil {
		return err
	}
	c.record(ctx, actor, audit.ActionServiceApproved, s.Name, remote)
	c.cfg.Changed()
	return nil
}

// live are the services that are in use: switched on and not waiting.
func (c *Catalog) live(ctx context.Context) ([]Service, error) {
	all, err := c.List(ctx)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, s := range all {
		if s.Enabled && !s.Pending {
			out = append(out, s)
		}
	}
	return out, nil
}

// Names are the services' part of the names in AdGuard Home: a web service
// and a proxied one point at the gateway, a direct one at its device.
func (c *Catalog) Names(ctx context.Context, proxyOn bool) ([]dnsnames.Name, error) {
	domain, err := c.domain(ctx)
	if err != nil || domain == "" {
		return nil, err
	}
	lan, err := c.cfg.LAN()
	if err != nil {
		return nil, err
	}
	live, err := c.live(ctx)
	if err != nil {
		return nil, err
	}
	var out []dnsnames.Name
	for _, s := range live {
		answer := lan.Address.String()
		if s.Kind != proxy.KindHTTP && s.Mode == ModeDirect {
			answer = s.UpstreamIP
		} else if !proxyOn {
			// Without the proxy nothing answers for it at the gateway.
			continue
		}
		out = append(out, dnsnames.Name{Domain: s.Name + "." + domain, Answer: answer, For: displayName(s)})
	}
	return out, nil
}

func displayName(s Service) string {
	if s.Title != "" {
		return s.Title
	}
	return s.Name
}

// ProxyServices are the routes Traefik should have. allow returns, for a
// service, who may reach it ("" range list: everyone inside).
func (c *Catalog) ProxyServices(ctx context.Context, allow func(serviceID int64) []string) ([]proxy.Service, error) {
	live, err := c.live(ctx)
	if err != nil {
		return nil, err
	}
	var out []proxy.Service
	for _, s := range live {
		if s.Kind != proxy.KindHTTP && s.Mode != ModeProxied {
			continue
		}
		ps := proxy.Service{Name: s.Name, Kind: s.Kind, Upstream: s.UpstreamIP, Port: s.UpstreamPort, ListenPort: s.ListenPort}
		if s.Kind == proxy.KindHTTP {
			ps.Scheme, ps.VerifyTLS, ps.Protected = s.Scheme, s.VerifyTLS, s.Protected
		}
		if allow != nil {
			ps.AllowFrom = allow(s.ID)
		}
		out = append(out, ps)
	}
	return out, nil
}

// HasName reports what holds a label among the services ("" if none), for
// the other parts' checks.
func (c *Catalog) HasName(ctx context.Context, label string) (string, error) {
	var title string
	err := c.cfg.DB.QueryRowContext(ctx, "SELECT CASE WHEN title = '' THEN name ELSE title END FROM service WHERE name = ?", label).Scan(&title)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return "the service " + title, nil
}

// ApproveNew reports whether announced services wait for approval.
func (c *Catalog) ApproveNew(ctx context.Context) (bool, error) {
	raw, _, err := store.Setting(ctx, c.cfg.DB, SettingApproveNew)
	return raw == "true", err
}

// Settings are the catalogue's settings as the page shows them.
type Settings struct {
	ApproveNew    bool `json:"approveNew"`
	IconCatalogue bool `json:"iconCatalogue"`
	AbandonedDays int  `json:"abandonedDays"`
}

func (c *Catalog) Settings(ctx context.Context) (Settings, error) {
	approve, err := c.ApproveNew(ctx)
	if err != nil {
		return Settings{}, err
	}
	return Settings{ApproveNew: approve, IconCatalogue: c.catalogueOn(ctx), AbandonedDays: int(c.abandonedAfter(ctx) / (24 * time.Hour))}, nil
}

func (c *Catalog) catalogueOn(ctx context.Context) bool {
	raw, found, err := store.Setting(ctx, c.cfg.DB, SettingIconCatalogue)
	return err == nil && (!found || raw == "true")
}

func (c *Catalog) SetSettings(ctx context.Context, actor, remote string, s Settings) error {
	if s.AbandonedDays < 1 || s.AbandonedDays > 365 {
		return problem.New("A service looks abandoned after 1 to 365 days down.")
	}
	for key, value := range map[string]string{
		SettingApproveNew:    strconv.FormatBool(s.ApproveNew),
		SettingIconCatalogue: strconv.FormatBool(s.IconCatalogue),
		SettingAbandonedDays: strconv.Itoa(s.AbandonedDays),
	} {
		if err := store.SetSetting(ctx, c.cfg.DB, key, value); err != nil {
			return err
		}
	}
	c.record(ctx, actor, audit.ActionServiceSettingsChanged,
		fmt.Sprintf("approve new: %t, icon catalogue: %t, abandoned after %d days", s.ApproveNew, s.IconCatalogue, s.AbandonedDays), remote)
	return nil
}
