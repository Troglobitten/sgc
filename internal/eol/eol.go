// Package eol says when the software SGC stands on stops getting security
// fixes: the device's Debian, and the Traefik SGC pins (docs/design.md
// §4.10 and §10). It asks endoflife.date once a day, and has a table of its
// own for when that cannot be reached. A look that fails is said, never
// passed over in silence.
//
// Web process only.
package eol

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/store"
)

// SettingState holds the last look (not exported).
const SettingState = "eol.state"

// WarnBefore is how long before the end SGC starts to say so.
const WarnBefore = 180 * 24 * time.Hour

// API is endoflife.date's v1 API (read on 2026-10-23).
const API = "https://endoflife.date/api/v1/products/%s/releases/%s"

// Item is one piece of software and its end.
type Item struct {
	Product string `json:"product"`
	Label   string `json:"label"`
	Cycle   string `json:"cycle"`
	// SecurityEnd is when its regular security support ends, End when all
	// support ends (Debian: the end of long-term support). nil: no date yet.
	SecurityEnd *time.Time `json:"securityEnd"`
	End         *time.Time `json:"end"`
	// Source is "online" or "table".
	Source string `json:"source"`
	// Warning is set from WarnBefore before the end, and after it.
	Warning string `json:"warning"`
}

// State is the last look.
type State struct {
	Items []Item `json:"items"`
	// Programs are what SGC installs besides Debian's packages, with their
	// newest releases (upstream.go).
	Programs  []Program  `json:"programs"`
	CheckedAt *time.Time `json:"checkedAt"`
	// Problem says why endoflife.date could not be asked (the table was used).
	Problem string `json:"problem"`
}

// table is what SGC knows without asking (endoflife.date, 2026-10-23).
var table = map[string]map[string][2]string{
	"debian":  {"12": {"2026-07-11", "2028-06-30"}, "13": {"2028-08-09", "2030-06-30"}},
	"traefik": {},
}

type Config struct {
	DB   *sql.DB
	HTTP *http.Client
	// DebianCycle returns the device's Debian version ("13"); nil reads
	// /etc/os-release.
	DebianCycle func() string
	// TraefikCycle is the pinned Traefik's minor version ("3.7").
	TraefikCycle string
	// Programs are looked up for their newest releases (Pinned and Repo
	// set); GitHubAPI is where ("" for GitHub itself).
	Programs  []Program
	GitHubAPI string
	Now       func() time.Time
	Log       *slog.Logger
}

type Service struct{ cfg Config }

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.DebianCycle == nil {
		cfg.DebianCycle = DebianVersion
	}
	return &Service{cfg: cfg}
}

// DebianVersion reads VERSION_ID from /etc/os-release ("13"; Raspberry Pi
// OS gives its Debian's).
func DebianVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "VERSION_ID="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func (s *Service) State(ctx context.Context) State {
	var state State
	if raw, found, err := store.Setting(ctx, s.cfg.DB, SettingState); err == nil && found {
		json.Unmarshal([]byte(raw), &state)
	}
	if state.Items == nil {
		state.Items = []Item{}
	}
	if state.Programs == nil {
		state.Programs = []Program{}
	}
	return state
}

// Run looks once a day (and soon after start), until ctx ends.
func (s *Service) Run(ctx context.Context) {
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.Check(ctx)
		timer.Reset(24 * time.Hour)
	}
}

type release struct {
	Result struct {
		EoasFrom *string `json:"eoasFrom"`
		EolFrom  *string `json:"eolFrom"`
	} `json:"result"`
}

func parseDate(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.DateOnly, *s)
	if err != nil {
		return nil
	}
	return &t
}

func (s *Service) ask(ctx context.Context, product, cycle string) (*time.Time, *time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(API, url.PathEscape(product), url.PathEscape(cycle)), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("endoflife.date answered %d", resp.StatusCode)
	}
	var r release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return nil, nil, err
	}
	return parseDate(r.Result.EoasFrom), parseDate(r.Result.EolFrom), nil
}

// Check looks now.
func (s *Service) Check(ctx context.Context) State {
	now := s.cfg.Now().UTC()
	state := State{Items: []Item{}, CheckedAt: &now}
	products := []struct{ product, label, cycle string }{
		{"debian", "Debian", s.cfg.DebianCycle()},
		{"traefik", "Traefik", s.cfg.TraefikCycle},
	}
	var problems []string
	for _, p := range products {
		if p.cycle == "" {
			continue
		}
		item := Item{Product: p.product, Label: p.label, Cycle: p.cycle, Source: "online"}
		security, end, err := s.ask(ctx, p.product, p.cycle)
		if err != nil {
			problems = append(problems, p.label+": "+err.Error())
			item.Source = "table"
			if dates, ok := table[p.product][p.cycle]; ok {
				security, end = parseDate(&dates[0]), parseDate(&dates[1])
			}
		}
		if security == nil {
			security = end
		}
		item.SecurityEnd, item.End = security, end
		item.Warning = warning(item, now)
		state.Items = append(state.Items, item)
	}
	if len(problems) > 0 {
		state.Problem = "endoflife.date could not be asked (" + strings.Join(problems, "; ") + "); SGC's own table was used."
	}
	state.Programs = s.checkPrograms(ctx)
	if data, err := json.Marshal(state); err == nil {
		store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingState, string(data))
	}
	return state
}

func warning(item Item, now time.Time) string {
	end := item.SecurityEnd
	if end == nil {
		return ""
	}
	days := int(end.Sub(now).Hours() / 24)
	switch {
	case days < 0:
		return fmt.Sprintf("%s %s no longer gets regular security fixes (since %s).%s", item.Label, item.Cycle, end.Format("2 January 2006"), advice(item))
	case end.Sub(now) < WarnBefore:
		return fmt.Sprintf("%s %s stops getting regular security fixes in %d days (%s).%s", item.Label, item.Cycle, days, end.Format("2 January 2006"), advice(item))
	}
	return ""
}

func advice(item Item) string {
	if item.Product == "debian" {
		return " The way to a newer Debian: make an export, install the new Debian and SGC afresh, and restore the export."
	}
	return " A newer SGC brings a newer one."
}
