package publiccontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/public"
	"github.com/Troglobitten/sgc/internal/store"
)

// The lists, as the page describes them. FireHOL's levels are separate
// lists from different sources (checked on 2026-10-25), not a ladder.
var listWords = map[string][2]string{
	public.ListLevel1: {"Level 1", "Addresses that should never reach a home: hijacked and unused networks, known attack sources. Few false alarms."},
	public.ListLevel2: {"Level 2", "Addresses seen attacking in about the last 48 hours."},
	public.ListLevel3: {"Level 3", "Addresses reported for attacks, spyware or viruses in the last 30 days."},
	public.ListLevel4: {"Level 4", "A much longer list of attack sources. In FireHOL's own words it may include a large number of false positives: a friend may be refused (the allow list lets them in)."},
}

func levelLabel(level string) string { return "level " + strings.TrimPrefix(level, "firehol_level") }

// ListState is how a list stands on this device.
type ListState struct {
	Name        string     `json:"name"`
	Label       string     `json:"label"`
	Description string     `json:"description"`
	Enabled     bool       `json:"enabled"`
	Entries     int        `json:"entries"`
	UpdatedAt   *time.Time `json:"updatedAt"`
	// Error is how the last attempt to fetch it failed, "" if it did not.
	Error   string     `json:"error"`
	ErrorAt *time.Time `json:"errorAt"`
}

// listsState is SettingLists: per list, and when the daily round last ran.
type listsState struct {
	Lists   map[string]ListState `json:"lists"`
	LastRun *time.Time           `json:"lastRun"`
}

func (s *Service) listsState(ctx context.Context) listsState {
	state := listsState{Lists: map[string]ListState{}}
	if raw, found, err := store.Setting(ctx, s.cfg.DB, SettingLists); err == nil && found {
		json.Unmarshal([]byte(raw), &state)
	}
	if state.Lists == nil {
		state.Lists = map[string]ListState{}
	}
	return state
}

func (s *Service) keepListsState(ctx context.Context, state listsState) {
	if data, err := json.Marshal(state); err == nil {
		store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingLists, string(data))
	}
}

// noteList writes down how fetching one list went.
func (s *Service) noteList(ctx context.Context, name string, entries int, fetchErr error) {
	state := s.listsState(ctx)
	l := state.Lists[name]
	now := s.cfg.Now().UTC()
	if fetchErr == nil {
		l.Entries, l.UpdatedAt, l.Error, l.ErrorAt = entries, &now, "", nil
	} else {
		l.Error, l.ErrorAt = fetchErr.Error(), &now
	}
	state.Lists[name] = l
	s.keepListsState(ctx, state)
}

// maxDownload bounds a list's download: level 4 is about 4 MB, DB-IP's
// country list about 5 MB.
const maxDownload = 64 << 20

func (s *Service) download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sgc")
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		var u interface{ Unwrap() error }
		if errors.As(err, &u) {
			return nil, fmt.Errorf("could not be reached: %v", u.Unwrap())
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the download answered %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDownload {
		return nil, errors.New("larger than any list SGC uses")
	}
	return data, nil
}

// keepFile puts a checked list where the root side reads it, in one step.
func (s *Service) keepFile(name string, data []byte) error {
	if err := os.MkdirAll(s.cfg.ListsDir, 0o700); err != nil {
		return err
	}
	path := public.ListFile(s.cfg.ListsDir, name)
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return nil
	}
	temporary := filepath.Join(s.cfg.ListsDir, "."+name+".new")
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// fetchFireHOL fetches one of FireHOL's levels, checks it is a list of
// addresses, and keeps it. A list that does not read keeps the last good one.
func (s *Service) fetchFireHOL(ctx context.Context, level string) error {
	data, err := s.download(ctx, s.cfg.FireHOLBase+level+".netset")
	if err == nil {
		var ranges []public.Range
		if ranges, err = public.ParseNetset(bytes.NewReader(data)); err == nil {
			if !bytes.HasPrefix(data, []byte("#")) || !bytes.Contains(data[:min(len(data), 200)], []byte(level)) {
				err = errors.New("the file is not FireHOL's " + levelLabel(level))
			} else if err = s.keepFile(level, data); err == nil {
				s.noteList(ctx, level, len(ranges), nil)
				return nil
			}
		}
	}
	s.noteList(ctx, level, 0, err)
	return err
}

// countryFile is DB-IP's name for its monthly list.
func countryFile(t time.Time) string { return "dbip-country-lite-" + t.Format("2006-01") + ".csv.gz" }

// fetchCountries fetches DB-IP's country list of this month, or of the
// month before when this month's is not out yet.
func (s *Service) fetchCountries(ctx context.Context) error {
	now := s.cfg.Now().UTC()
	var data []byte
	var err error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		if data, err = s.download(ctx, s.cfg.DBIPBase+countryFile(month)); err == nil {
			break
		}
	}
	if err == nil {
		// Read through once with every country, to see it is the list.
		var ranges []public.Range
		if ranges, err = public.ParseCountries(bytes.NewReader(data), []string{"NL"}); err == nil {
			_ = ranges
			if err = s.keepFile(public.ListCountry, data); err == nil {
				s.noteList(ctx, public.ListCountry, 0, nil)
				return nil
			}
		}
	}
	s.noteList(ctx, public.ListCountry, 0, err)
	return err
}

// refreshDue reports whether the daily round is due: once a day, half an
// hour into the maintenance window (or halfway through a shorter one), so
// that SGC's own update and a restart in the window come first. With the
// window switched off, at the same time all the same.
func (s *Service) refreshDue(ctx context.Context) bool {
	start, end, err := s.cfg.Window(ctx)
	if err != nil {
		return false
	}
	length := end - start
	if length <= 0 {
		length += 24 * 60
	}
	offset := min(30, length/2)
	now := s.cfg.Now()
	slot := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Add(time.Duration(start+offset) * time.Minute)
	if now.Before(slot) {
		slot = slot.AddDate(0, 0, -1)
	}
	last := s.listsState(ctx).LastRun
	return last == nil || last.Before(slot)
}

// refresh fetches the lists switched on: FireHOL's every day, DB-IP's
// when this month's is not on the device. The proxy's configuration is
// sent again when one changed (its checksum is in it).
func (s *Service) refresh(ctx context.Context) {
	settings := s.Settings(ctx)
	for _, level := range public.FireHOLLevels {
		if !slices.Contains(settings.Levels, level) {
			continue
		}
		if err := s.fetchFireHOL(ctx, level); err != nil {
			s.cfg.Log.Error("fetch FireHOL's list", "list", level, "error", err)
			s.record(ctx, audit.ActorSystem, audit.ActionPublicListFailed, "FireHOL's "+levelLabel(level)+": "+err.Error(), "")
		}
	}
	if settings.CountryMode != public.CountryOff {
		state := s.listsState(ctx).Lists[public.ListCountry]
		if state.UpdatedAt == nil || state.UpdatedAt.Format("2006-01") != s.cfg.Now().UTC().Format("2006-01") {
			if err := s.fetchCountries(ctx); err != nil {
				s.cfg.Log.Error("fetch DB-IP's country list", "error", err)
				s.record(ctx, audit.ActorSystem, audit.ActionPublicListFailed, "DB-IP's country list: "+err.Error(), "")
			}
		}
	}
	state := s.listsState(ctx)
	now := s.cfg.Now().UTC()
	state.LastRun = &now
	s.keepListsState(ctx, state)
	if s.On(ctx) {
		if err := s.cfg.Apply(ctx); err != nil {
			s.cfg.Log.Error("put the new lists in place", "error", err)
		}
	}
}

// Lists is how the lists stand, for the page.
func (s *Service) Lists(ctx context.Context) []ListState {
	settings := s.Settings(ctx)
	state := s.listsState(ctx)
	var out []ListState
	for _, level := range public.FireHOLLevels {
		l := state.Lists[level]
		l.Name, l.Label, l.Description = level, listWords[level][0], listWords[level][1]
		l.Enabled = slices.Contains(settings.Levels, level)
		out = append(out, l)
	}
	l := state.Lists[public.ListCountry]
	l.Name, l.Label, l.Description = public.ListCountry, "Countries", "DB-IP's free country list (IP to Country Lite, CC BY 4.0), fetched once a month."
	l.Enabled = settings.CountryMode != public.CountryOff
	return append(out, l)
}

// staleAfter: a list switched on that has not been fetched for this long
// is worth the owner's attention.
const staleAfter = 3 * 24 * time.Hour

// StaleLists names the lists switched on that are older than staleAfter.
func (s *Service) StaleLists(ctx context.Context) []string {
	var out []string
	now := s.cfg.Now()
	for _, l := range s.Lists(ctx) {
		limit := staleAfter
		if l.Name == public.ListCountry {
			limit = 45 * 24 * time.Hour
		}
		if l.Enabled && (l.UpdatedAt == nil || now.Sub(*l.UpdatedAt) > limit) {
			out = append(out, l.Label)
		}
	}
	return out
}
