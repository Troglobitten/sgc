// Package publiccontrol is the web process's side of services reachable
// from the internet (docs/design.md §14): the owner's switch for internet
// access, opening and closing a service, the filters for visitors (limits,
// allow list, FireHOL's lists, the country filter, fail2ban), downloading
// the lists, and the public names at the DNS provider.
//
// What it decides is put in place by the root side with the proxy's
// configuration (internal/proxy, internal/public), which checks it again.
// Only the admin, in SGC's page, opens anything: nothing a server announces
// can (internal/services closes a public service an announcement changes).
package publiccontrol

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/dnsprovider"
	"github.com/Troglobitten/sgc/internal/netinfo"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/public"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/store"
)

// Settings the owner makes (exported), and bookkeeping of this device (not
// exported: internal/backup/tables.go).
const (
	SettingEnabled  = "public.enabled"
	SettingSettings = "public.settings"
	// SettingRecords are the records SGC made at the DNS provider. They
	// travel with an export, so that a restored SGC can remove them.
	SettingRecords = "public.records"
	SettingLists   = "public.lists"
	SettingState   = "public.state"
)

// Settings are the owner's choices for visitors from the internet.
type Settings struct {
	RequestsPerMinute    int      `json:"requestsPerMinute"`
	ConnectionsPerMinute int      `json:"connectionsPerMinute"`
	Allow                []string `json:"allow"`
	// Levels are FireHOL's lists switched on.
	Levels      []string        `json:"levels"`
	CountryMode string          `json:"countryMode"`
	Countries   []string        `json:"countries"`
	Fail2ban    public.Fail2ban `json:"fail2ban"`
}

func defaults() Settings {
	d := public.Defaults()
	return Settings{RequestsPerMinute: d.RequestsPerMinute, ConnectionsPerMinute: d.ConnectionsPerMinute,
		Allow: []string{}, Levels: []string{}, Countries: []string{}, Fail2ban: d.Fail2ban}
}

// Helper is what the root side does for this.
type Helper interface {
	InstallPackages(ctx context.Context, feature string) error
	PublicBans(ctx context.Context) ([]public.Ban, error)
	PublicUnban(ctx context.Context, address string) error
}

// Config is what the service needs.
type Config struct {
	DB      *sql.DB
	Audit   *audit.Log
	Helper  Helper
	Catalog *services.Catalog
	// FirewallOn reports whether SGC's firewall is on: internet access is
	// only switched on behind it.
	FirewallOn func(ctx context.Context) bool
	// ProxyOn reports whether the owner has the proxy on.
	ProxyOn func(ctx context.Context) bool
	// Apply puts the proxy's configuration in place now, and says how it
	// went (proxycontrol.Service.ApplyNow).
	Apply func(ctx context.Context) error
	// DNS returns the owner's DNS provider, opened (domaincontrol.Service.Open).
	DNS func(ctx context.Context) (dnsprovider.Provider, dnsprovider.Account, bool, error)
	// PublicIP asks what the home's address on the internet is.
	PublicIP func(ctx context.Context) (netip.Addr, error)
	LAN      func() (netinfo.LAN, error)
	HTTP     *http.Client
	// ListsDir is where the lists go for the root side (public.DefaultPaths().ListsDir).
	ListsDir string
	// FireHOLBase and DBIPBase are where the lists are fetched from.
	FireHOLBase string
	DBIPBase    string
	// Alert tells the owner at once (the notifications' "internet" kind).
	Alert func(ctx context.Context, title, body string)
	// Window returns the maintenance window's start and end, in minutes
	// after midnight (maintenance.Window).
	Window func(ctx context.Context) (int, int, error)
	Now    func() time.Time
	Log    *slog.Logger
}

// Service is the web side of internet access.
type Service struct {
	cfg  Config
	kick chan struct{}

	// changes keeps the owner's changes one at a time.
	changes sync.Mutex
	// records keeps the work at the DNS provider one at a time.
	records sync.Mutex
	// hashes caches the checksum of each list file by its size and time.
	hashMu sync.Mutex
	hashes map[string]cachedHash
}

type cachedHash struct {
	size    int64
	modTime time.Time
	sum     string
}

// Defaults for where the lists come from.
const (
	DefaultFireHOLBase = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
	DefaultDBIPBase    = "https://download.db-ip.com/free/"
)

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Alert == nil {
		cfg.Alert = func(context.Context, string, string) {}
	}
	if cfg.FireHOLBase == "" {
		cfg.FireHOLBase = DefaultFireHOLBase
	}
	if cfg.DBIPBase == "" {
		cfg.DBIPBase = DefaultDBIPBase
	}
	if cfg.ListsDir == "" {
		cfg.ListsDir = public.DefaultPaths().ListsDir
	}
	return &Service{cfg: cfg, kick: make(chan struct{}, 1), hashes: map[string]cachedHash{}}
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

// Kick asks for the public names to be brought up to date soon.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// On reports whether the owner has internet access switched on.
func (s *Service) On(ctx context.Context) bool {
	raw, _, err := store.Setting(ctx, s.cfg.DB, SettingEnabled)
	return err == nil && raw == "true"
}

// Settings are the owner's settings, the defaults where none were made.
func (s *Service) Settings(ctx context.Context) Settings {
	out := defaults()
	if raw, found, err := store.Setting(ctx, s.cfg.DB, SettingSettings); err == nil && found {
		var saved Settings
		if json.Unmarshal([]byte(raw), &saved) == nil && check(saved) == nil {
			out = saved
		}
	}
	for _, list := range []*[]string{&out.Allow, &out.Levels, &out.Countries} {
		if *list == nil {
			*list = []string{}
		}
	}
	return out
}

// check is the web process's check of the owner's settings; the root side
// checks what it is sent again.
func check(s Settings) error {
	p := public.Defaults()
	p.RequestsPerMinute, p.ConnectionsPerMinute, p.Allow, p.Fail2ban = s.RequestsPerMinute, s.ConnectionsPerMinute, s.Allow, s.Fail2ban
	for _, level := range s.Levels {
		if !slices.Contains(public.FireHOLLevels, level) {
			return problem.Newf("%q is not one of FireHOL's lists.", level)
		}
		p.FireHOL = append(p.FireHOL, public.List{Name: level, SHA256: strings.Repeat("0", 64)})
	}
	p.CountryMode, p.Countries = s.CountryMode, s.Countries
	if s.CountryMode != public.CountryOff {
		p.CountryList = &public.List{Name: public.ListCountry, SHA256: strings.Repeat("0", 64)}
	}
	if err := p.Validate(); err != nil {
		return problem.Newf("Those settings do not work: %v.", err)
	}
	return nil
}

// BuildPublic is how visitors from the internet are filtered, for the
// proxy's configuration: the owner's settings with the lists that are on
// the device. A list switched on that has not been fetched yet is left out
// until it has been (it is fetched as the owner switches it on, so that is
// only after a failed download).
func (s *Service) BuildPublic(ctx context.Context) (*public.Settings, error) {
	settings := s.Settings(ctx)
	out := public.Defaults()
	out.RequestsPerMinute, out.ConnectionsPerMinute = settings.RequestsPerMinute, settings.ConnectionsPerMinute
	out.Allow, out.Fail2ban = append([]string{}, settings.Allow...), settings.Fail2ban
	for _, level := range public.FireHOLLevels {
		if !slices.Contains(settings.Levels, level) {
			continue
		}
		if sum, ok := s.fileHash(level); ok {
			out.FireHOL = append(out.FireHOL, public.List{Name: level, SHA256: sum})
		}
	}
	if settings.CountryMode != public.CountryOff {
		if sum, ok := s.fileHash(public.ListCountry); ok {
			out.CountryMode, out.Countries = settings.CountryMode, append([]string{}, settings.Countries...)
			out.CountryList = &public.List{Name: public.ListCountry, SHA256: sum}
		}
	}
	return &out, out.Validate()
}

// fileHash returns the SHA-256 of a list file that is there.
func (s *Service) fileHash(name string) (string, bool) {
	path := public.ListFile(s.cfg.ListsDir, name)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	s.hashMu.Lock()
	defer s.hashMu.Unlock()
	if cached, ok := s.hashes[name]; ok && cached.size == info.Size() && cached.modTime.Equal(info.ModTime()) {
		return cached.sum, true
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", false
	}
	hash := hex.EncodeToString(sum.Sum(nil))
	s.hashes[name] = cachedHash{size: info.Size(), modTime: info.ModTime(), sum: hash}
	return hash, true
}

// SetEnabled switches internet access on or off. Switching on needs the
// proxy, the firewall and a domain; it gives Traefik its public door and
// the device the table for the internet. The firewall then lags behind
// (the page brings it up to date, with its usual confirmation).
func (s *Service) SetEnabled(ctx context.Context, actor, remote string, on bool) error {
	s.changes.Lock()
	defer s.changes.Unlock()
	if !on {
		if err := store.SetSetting(ctx, s.cfg.DB, SettingEnabled, "false"); err != nil {
			return err
		}
		// Every public service is closed with it, so that switching on again
		// never reopens one by itself: opening is always the owner's own step.
		closed, err := s.cfg.Catalog.CloseAll(ctx, actor, remote, "internet access was switched off")
		if err != nil {
			s.cfg.Log.Error("close the public services", "error", err)
		}
		detail := ""
		if closed > 0 {
			detail = fmt.Sprintf("%d public service(s) closed", closed)
		}
		s.record(ctx, actor, audit.ActionPublicAccessOff, detail, remote)
		s.cfg.Alert(ctx, "Internet access is off", "Nothing on your home network is reachable from the internet through SGC any more. Services you open again are opened one by one, on the Services page.")
		err = s.cfg.Apply(ctx)
		s.Kick()
		return err
	}
	if !s.cfg.ProxyOn(ctx) {
		return problem.New("Internet access goes through the proxy: switch the proxy on first (Services, Settings).")
	}
	if !s.cfg.FirewallOn(ctx) {
		return problem.New("Internet access needs SGC's firewall on first (System, Security), so that only what you make public is reachable.")
	}
	if _, _, configured, err := s.cfg.DNS(ctx); err != nil || !configured {
		return problem.New("Internet access needs your domain and DNS provider (System, Domain and names): public names are made there.")
	}
	if err := store.SetSetting(ctx, s.cfg.DB, SettingEnabled, "true"); err != nil {
		return err
	}
	if err := s.cfg.Apply(ctx); err != nil {
		store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingEnabled, "false")
		s.cfg.Apply(context.WithoutCancel(ctx))
		return problem.Newf("Internet access could not be switched on: %v", err)
	}
	s.record(ctx, actor, audit.ActionPublicAccessOn, fmt.Sprintf("public door on port %d", public.DoorPort), remote)
	s.cfg.Alert(ctx, "Internet access is on", "Services you make public in SGC's page can now be reached from the internet. None is public until you open it.")
	s.Kick()
	return nil
}

// SetSettings saves the owner's settings and puts them in place. A list
// switched on is fetched first, and fail2ban installed where it is
// missing; if that fails, nothing changes.
func (s *Service) SetSettings(ctx context.Context, actor, remote string, next Settings) error {
	s.changes.Lock()
	defer s.changes.Unlock()
	next.Allow = cleanList(next.Allow)
	next.Countries = cleanList(next.Countries)
	for i, c := range next.Countries {
		next.Countries[i] = strings.ToUpper(c)
	}
	slices.Sort(next.Countries)
	next.Countries = slices.Compact(next.Countries)
	next.Levels = cleanList(next.Levels)
	if next.CountryMode == public.CountryOff {
		next.Countries = []string{}
	}
	if err := check(next); err != nil {
		return err
	}
	for _, level := range next.Levels {
		if _, there := s.fileHash(level); !there {
			if err := s.fetchFireHOL(ctx, level); err != nil {
				return problem.Newf("FireHOL's %s could not be fetched, so it is not switched on: %v", levelLabel(level), err)
			}
		}
	}
	if next.CountryMode != public.CountryOff {
		if _, there := s.fileHash(public.ListCountry); !there {
			if err := s.fetchCountries(ctx); err != nil {
				return problem.Newf("DB-IP's country list could not be fetched, so the country filter is not switched on: %v", err)
			}
		}
	}
	if next.Fail2ban.Enabled && !public.Fail2banInstalled() {
		if err := s.cfg.Helper.InstallPackages(ctx, "fail2ban"); err != nil {
			return problem.Newf("fail2ban could not be installed from Debian, so it is not switched on: %v", err)
		}
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	before := s.Settings(ctx)
	if err := store.SetSetting(ctx, s.cfg.DB, SettingSettings, string(data)); err != nil {
		return err
	}
	if s.On(ctx) {
		if err := s.cfg.Apply(ctx); err != nil {
			if old, err := json.Marshal(before); err == nil {
				store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingSettings, string(old))
				s.cfg.Apply(context.WithoutCancel(ctx))
			}
			return problem.Newf("The settings were not put in place: %v", err)
		}
	}
	s.record(ctx, actor, audit.ActionPublicSettingsChanged, describe(next), remote)
	return nil
}

func cleanList(in []string) []string {
	out := []string{}
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func describe(s Settings) string {
	parts := []string{fmt.Sprintf("%d requests and %d new connections a minute per visitor", s.RequestsPerMinute, s.ConnectionsPerMinute)}
	if len(s.Allow) > 0 {
		parts = append(parts, "allowed: "+strings.Join(s.Allow, ", "))
	}
	if len(s.Levels) > 0 {
		parts = append(parts, "FireHOL: "+strings.Join(s.Levels, ", "))
	}
	switch s.CountryMode {
	case public.CountryAllow:
		parts = append(parts, "only from "+strings.Join(s.Countries, ", "))
	case public.CountryBlock:
		parts = append(parts, "not from "+strings.Join(s.Countries, ", "))
	}
	if s.Fail2ban.Enabled {
		parts = append(parts, fmt.Sprintf("fail2ban: %d failed sign-ins or %d refused requests in %d minutes ban for %d minutes",
			s.Fail2ban.SignIns, s.Fail2ban.Refused, s.Fail2ban.FindMinutes, s.Fail2ban.BanMinutes))
	}
	return strings.Join(parts, "; ")
}

// SetServicePublic opens a service to the internet or closes it, and
// returns once the proxy has it so.
func (s *Service) SetServicePublic(ctx context.Context, actor, remote string, id int64, open bool) error {
	s.changes.Lock()
	defer s.changes.Unlock()
	svc, err := s.cfg.Catalog.Get(ctx, id)
	if err != nil {
		return err
	}
	if !open {
		if svc.Exposure != services.ExposurePublic {
			return nil
		}
		if err := s.cfg.Catalog.SetExposure(ctx, id, services.ExposureLAN); err != nil {
			return err
		}
		s.record(ctx, actor, audit.ActionServicePublicClosed, svc.Name, remote)
		s.cfg.Alert(ctx, svc.Name+" is closed to the internet", svc.Name+" is reachable from your home network only again.")
		err := s.cfg.Apply(ctx)
		s.Kick()
		return err
	}
	switch {
	case !s.On(ctx):
		return problem.New("Switch internet access on first (System, Internet).")
	case !svc.Enabled || svc.Pending:
		return problem.New("Only a service that is switched on (and approved) can be made public.")
	case svc.Kind != proxy.KindHTTP && svc.Mode != services.ModeProxied:
		return problem.New("A service that is not a website is made public through the gateway: set its \"Way in\" to \"Through the gateway\" first.")
	case svc.Exposure == services.ExposurePublic:
		return nil
	}
	if foreign := s.foreignRecord(ctx, svc.Name); foreign != "" {
		return problem.New(foreign)
	}
	if err := s.cfg.Catalog.SetExposure(ctx, id, services.ExposurePublic); err != nil {
		return err
	}
	if err := s.cfg.Apply(ctx); err != nil {
		s.cfg.Catalog.SetExposure(context.WithoutCancel(ctx), id, services.ExposureLAN)
		s.cfg.Apply(context.WithoutCancel(ctx))
		return problem.Newf("%s could not be made public: %v", svc.Name, err)
	}
	where := "the public door (port 443 at your router)"
	if svc.Kind != proxy.KindHTTP {
		where = "port " + strconv.Itoa(svc.ListenPort) + "/" + svc.Kind
	}
	s.record(ctx, actor, audit.ActionServicePublicOpened, svc.Name+" through "+where, remote)
	s.cfg.Alert(ctx, svc.Name+" is reachable from the internet",
		svc.Name+" was made public in SGC's page, through "+where+". If that was not you, close it at once (Services) and change the admin password.")
	s.Kick()
	return nil
}

// Bans are the addresses fail2ban has banned now.
func (s *Service) Bans(ctx context.Context) ([]public.Ban, error) {
	bans, err := s.cfg.Helper.PublicBans(ctx)
	if err != nil {
		return nil, problem.Newf("fail2ban could not be asked: %v", err)
	}
	if bans == nil {
		bans = []public.Ban{}
	}
	return bans, nil
}

// Unban lifts a ban.
func (s *Service) Unban(ctx context.Context, actor, remote, address string) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil || !addr.Is4() {
		return problem.New("That is not an IPv4 address.")
	}
	if err := s.cfg.Helper.PublicUnban(ctx, addr.String()); err != nil {
		return problem.Newf("The ban could not be lifted: %v", err)
	}
	s.record(ctx, actor, audit.ActionPublicUnbanned, addr.String(), remote)
	return nil
}

// MarkRestored keeps internet access off on a restored device, and every
// service closed, until the owner switches it on there and opens each one
// again: nothing is opened by itself.
func (s *Service) MarkRestored(ctx context.Context) error {
	closed, err := s.cfg.Catalog.CloseAll(ctx, audit.ActorSystem, "", "the device was restored from an export")
	if err != nil {
		return err
	}
	if !s.On(ctx) && closed == 0 {
		return nil
	}
	if err := store.SetSetting(ctx, s.cfg.DB, SettingEnabled, "false"); err != nil {
		return err
	}
	s.record(ctx, audit.ActorSystem, audit.ActionPublicAccessOff, "restored from an export: internet access stays off until switched on here", "")
	return nil
}

// ErrNoDomain: public names need the owner's domain.
var ErrNoDomain = errors.New("no domain")
