package vpncontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/zone"
)

// PublicIPServices are asked for the home's public address, the second if
// the first does not answer (docs/design.md §10).
var PublicIPServices = []string{"https://api.ipify.org", "https://ipv4.icanhazip.com"}

const endpointEvery = 5 * time.Minute

// EndpointConfig is what keeping the public name needs.
type EndpointConfig struct {
	DB    *sql.DB
	Audit *audit.Log
	// Settings are the VPN's settings now.
	Settings func(ctx context.Context) Settings
	// Zone returns a client for the owner's Zone.eu account and the
	// domain, if one is set up.
	Zone func(ctx context.Context) (*zone.Client, string, bool, error)
	// PublicIP asks what the home's address on the internet is; nil means
	// asking PublicIPServices.
	PublicIP func(ctx context.Context) (netip.Addr, error)
	HTTP     *http.Client
	Alert    func(ctx context.Context, title, body string)
	Now      func() time.Time
	Log      *slog.Logger
}

// EndpointState is how the public name stands.
type EndpointState struct {
	PublicIP  string     `json:"publicIp"`
	CheckedAt *time.Time `json:"checkedAt"`
	// RecordIP is where the public name points at Zone.eu.
	RecordIP  string     `json:"recordIp"`
	UpdatedAt *time.Time `json:"updatedAt"`
	Problem   string     `json:"problem"`
	// Foreign: Zone.eu has a record for the name that SGC did not make.
	Foreign bool `json:"foreign"`
}

// mine is the record SGC made (SettingRecord).
type mine struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	ID     string `json:"id"`
}

// Endpoint keeps the VPN's public name pointing at the home's address.
type Endpoint struct {
	cfg  EndpointConfig
	kick chan struct{}
	mu   sync.Mutex
}

func NewEndpoint(cfg EndpointConfig) *Endpoint {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Alert == nil {
		cfg.Alert = func(context.Context, string, string) {}
	}
	return &Endpoint{cfg: cfg, kick: make(chan struct{}, 1)}
}

func (e *Endpoint) Kick() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

func (e *Endpoint) State(ctx context.Context) EndpointState {
	var state EndpointState
	if raw, found, err := store.Setting(ctx, e.cfg.DB, SettingEndpoint); err == nil && found {
		json.Unmarshal([]byte(raw), &state)
	}
	return state
}

func (e *Endpoint) keep(ctx context.Context, state EndpointState) {
	before := e.State(ctx)
	if data, err := json.Marshal(state); err == nil {
		store.SetSetting(context.WithoutCancel(ctx), e.cfg.DB, SettingEndpoint, string(data))
	}
	if state.Problem != "" && state.Problem != before.Problem {
		e.record(ctx, audit.ActionVPNEndpointFailed, state.Problem)
		e.cfg.Alert(ctx, "The VPN's public name could not be kept up to date", state.Problem)
	}
}

func (e *Endpoint) record(ctx context.Context, action, detail string) {
	if err := e.cfg.Audit.Record(context.WithoutCancel(ctx), audit.ActorSystem, action, detail, ""); err != nil {
		e.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

// Run looks every five minutes, and soon after a Kick, until ctx ends.
func (e *Endpoint) Run(ctx context.Context) {
	ticker := time.NewTicker(endpointEvery)
	defer ticker.Stop()
	first := time.NewTimer(20 * time.Second)
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-ticker.C:
		case <-e.kick:
		}
		e.Check(ctx)
	}
}

func (e *Endpoint) publicIP(ctx context.Context) (netip.Addr, error) {
	if e.cfg.PublicIP != nil {
		return e.cfg.PublicIP(ctx)
	}
	var last error
	for _, url := range PublicIPServices {
		addr, err := AskPublicIP(ctx, e.cfg.HTTP, url)
		if err == nil {
			return addr, nil
		}
		last = err
	}
	return netip.Addr{}, last
}

// AskPublicIP asks one service, which answers with the address as text.
func AskPublicIP(ctx context.Context, client *http.Client, url string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 100))
	if err != nil || resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("%s answered %d", url, resp.StatusCode)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("%s did not answer with an IPv4 address", url)
	}
	return addr, nil
}

// Check looks once: the home's public address, and whether the name points
// at it; it changes the record at Zone.eu when it does not.
func (e *Endpoint) Check(ctx context.Context) EndpointState {
	e.mu.Lock()
	defer e.mu.Unlock()
	settings := e.cfg.Settings(ctx)
	state := e.State(ctx)
	if !settings.Enabled {
		return state
	}
	client, domain, configured, err := e.cfg.Zone(ctx)
	if err != nil || !configured {
		// Without a domain, devices connect to the fixed address directly.
		return state
	}
	now := e.cfg.Now().UTC()
	state.Problem, state.Foreign = "", false
	address, err := e.publicIP(ctx)
	if err != nil {
		state.Problem = "The home's public address could not be found: " + err.Error()
		e.keep(ctx, state)
		return state
	}
	state.PublicIP, state.CheckedAt = address.String(), &now
	if address.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(address) {
		state.Problem = "The internet sees this home at " + address.String() + ", which is not a public address: the provider shares one address between customers (carrier-grade NAT), and a VPN from outside cannot reach the home this way. Ask the provider for a public address."
		e.keep(ctx, state)
		return state
	}
	want := address.String()
	if settings.EndpointMode == ModeStatic {
		want = settings.StaticIP
		if settings.StaticIP != address.String() {
			state.Problem = "The home's public address is now " + address.String() + ", not the fixed " + settings.StaticIP + " the VPN's name points at."
		}
	}
	name := settings.Name + "." + domain
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	records, err := client.ARecords(ctx, domain)
	if err != nil {
		state.Problem = "Zone.eu could not be asked about " + name + ": " + err.Error()
		e.keep(ctx, state)
		return state
	}
	var made mine
	if raw, found, _ := store.Setting(ctx, e.cfg.DB, SettingRecord); found {
		json.Unmarshal([]byte(raw), &made)
	}
	var own *zone.ARecord
	var others []zone.ARecord
	for i, r := range records {
		if !strings.EqualFold(r.Name, name) {
			continue
		}
		if made.Domain == domain && made.Name == name && r.ID == made.ID {
			own = &records[i]
		} else {
			others = append(others, r)
		}
	}
	switch {
	case own != nil:
		state.RecordIP = own.Address
		if own.Address != want {
			if err := client.UpdateA(ctx, domain, own.ID, name, want); err != nil {
				state.Problem = "Zone.eu did not take the new address for " + name + ": " + err.Error()
				break
			}
			state.RecordIP, state.UpdatedAt = want, &now
			e.record(ctx, audit.ActionVPNEndpointUpdated, name+" → "+want)
		}
	case len(others) > 0:
		state.Foreign, state.RecordIP = true, others[0].Address
		state.Problem = "Zone.eu already has an address for " + name + " (" + others[0].Address + ") that SGC did not make. SGC changes it only if you let it (VPN page)."
	default:
		created, err := client.AddA(ctx, domain, name, want)
		if err != nil {
			state.Problem = "Zone.eu did not take the record for " + name + ": " + err.Error()
			break
		}
		data, _ := json.Marshal(mine{Domain: domain, Name: name, ID: created.ID})
		store.SetSetting(context.WithoutCancel(ctx), e.cfg.DB, SettingRecord, string(data))
		state.RecordIP, state.UpdatedAt = want, &now
		e.record(ctx, audit.ActionVPNEndpointUpdated, name+" → "+want+" (new)")
	}
	e.keep(ctx, state)
	return state
}

// TakeOver lets SGC change a record for the VPN's name that it did not
// make (the owner's choice in the page).
func (e *Endpoint) TakeOver(ctx context.Context) error {
	settings := e.cfg.Settings(ctx)
	client, domain, configured, err := e.cfg.Zone(ctx)
	if err != nil {
		return err
	}
	if !configured {
		return problem.New("Set up your domain first.")
	}
	name := settings.Name + "." + domain
	records, err := client.ARecords(ctx, domain)
	if err != nil {
		return problem.Newf("Zone.eu could not be asked: %v", err)
	}
	for _, r := range records {
		if strings.EqualFold(r.Name, name) {
			data, _ := json.Marshal(mine{Domain: domain, Name: name, ID: r.ID})
			if err := store.SetSetting(ctx, e.cfg.DB, SettingRecord, string(data)); err != nil {
				return err
			}
			e.Kick()
			return nil
		}
	}
	return errors.New("there is no record to take over")
}
