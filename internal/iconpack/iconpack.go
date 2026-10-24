// Package iconpack keeps a collection of service icons on the device, so that
// finding an icon for a service asks nobody outside for its name
// (docs/design.md §11). The pack is built once a week from
// homarr-labs/dashboard-icons by tools/iconpack (run by
// .github/workflows/icons.yml) and published next to SGC's releases; the
// device looks for a new one once a day, and when the owner asks.
//
// The pack is checked by its SHA-256 from the manifest, not signed with the
// release key, which signs SGC only. What could a bad pack do? Its icons are
// decoded and drawn anew by SGC before anything shows them (services.Redraw),
// and nothing but an index, the licence, a notice and PNG files with plain
// names is taken from it; anything else and the pack is refused. So: show
// wrong pictures.
//
// Standard library only. Web process only.
package iconpack

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// Source is the collection the pack is made from.
	Source = "homarr-labs/dashboard-icons"
	// ManifestFile names the pack published beside it; IndexFile is the
	// list of icons inside the pack.
	ManifestFile = "icons.json"
	IndexFile    = "index.json"
	// DefaultManifestURL is where the weekly pack is published: a
	// pre-release of SGC's repository tagged "icons", which is never the
	// "latest" release the updater and the installer use.
	DefaultManifestURL = "https://github.com/Troglobitten/sgc/releases/download/icons/" + ManifestFile

	maxManifest = 64 << 10
	maxPack     = 200 << 20
	maxIcon     = 256 << 10
	maxIndex    = 8 << 20
	maxEntries  = 20000
	// How often a new pack is looked for, and how soon after a start.
	checkEvery = 24 * time.Hour
	firstLook  = 2 * time.Minute
)

// Manifest is what is published beside a pack, and kept beside the one in
// use (current.json).
type Manifest struct {
	Version string    `json:"version"` // "20261024-1a2b3c4": the day it was built and the commit
	Source  string    `json:"source"`
	Commit  string    `json:"commit"`
	Built   time.Time `json:"built"`
	Count   int       `json:"count"`
	File    string    `json:"file"` // "icons-<version>.tar", beside the manifest
	Size    int64     `json:"size"`
	SHA256  string    `json:"sha256"`
}

// Index is the list of icons in a pack, by name, with their aliases.
type Index struct {
	Source string           `json:"source"`
	Commit string           `json:"commit"`
	Icons  map[string]Entry `json:"icons"`
}

type Entry struct {
	Aliases []string `json:"aliases,omitempty"`
}

var (
	nameShape    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,98}[a-z0-9])?$`)
	commitShape  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionShape = regexp.MustCompile(`^[0-9]{8}-[0-9a-f]{7}$`)
	sha256Shape  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidName is the shape of an icon's name: the file names in the pack.
func ValidName(s string) bool { return nameShape.MatchString(s) }

// ValidCommit is a full git commit id.
func ValidCommit(s string) bool { return commitShape.MatchString(s) }

// Slug writes a name the way the collection writes names: "Home Assistant"
// is home-assistant.
func Slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '.':
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	slug := strings.Trim(b.String(), "-")
	if !ValidName(slug) {
		return ""
	}
	return slug
}

func (m Manifest) check() error {
	switch {
	case m.Source != Source:
		return fmt.Errorf("it is not made from %s", Source)
	case !versionShape.MatchString(m.Version), !ValidCommit(m.Commit), m.Version[9:] != m.Commit[:7]:
		return errors.New("its version is not in the expected form")
	case m.File != "icons-"+m.Version+".tar":
		return errors.New("it names an unexpected file")
	case m.Size <= 0 || m.Size > maxPack:
		return errors.New("it is of an unexpected size")
	case !sha256Shape.MatchString(m.SHA256):
		return errors.New("its checksum is not in the expected form")
	case m.Count <= 0 || m.Count > maxEntries:
		return errors.New("it holds an unexpected number of icons")
	}
	return nil
}

// Config is what a Service needs.
type Config struct {
	// Dir holds the pack in use (one folder per version, and current.json).
	Dir         string
	ManifestURL string
	HTTP        *http.Client
	// Wanted says whether a pack is wanted now: the owner's switch is on and
	// there is at least one service to find an icon for.
	Wanted func(ctx context.Context) bool
	// Installed is called when a new pack is in place.
	Installed func()
	Now       func() time.Time
	Log       *slog.Logger
}

// Status is what the page shows.
type Status struct {
	Installed bool       `json:"installed"`
	Version   string     `json:"version"`
	Count     int        `json:"count"`
	Built     *time.Time `json:"built"`
	Size      int64      `json:"size"`
	CheckedAt *time.Time `json:"checkedAt"`
	Problem   string     `json:"problem"`
	Updating  bool       `json:"updating"`
	Source    string     `json:"source"`
}

// Service keeps the pack.
type Service struct {
	cfg  Config
	kick chan struct{}

	mu        sync.Mutex
	pack      *loaded
	checkedAt time.Time
	problem   string
	updating  bool
	// One update at a time: the button and the daily look.
	updates sync.Mutex
}

// loaded is a pack in use; it does not change once made.
type loaded struct {
	manifest Manifest
	dir      string
	byName   map[string]string // a name or an alias: the icon's name
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 5 * time.Minute}
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	s := &Service{cfg: cfg, kick: make(chan struct{}, 1)}
	if pack, err := s.loadCurrent(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			cfg.Log.Warn("the icon pack on this device could not be read; a new one is fetched", "error", err)
		}
	} else {
		s.pack = pack
	}
	return s
}

// Status says what the page shows.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Problem: s.problem, Updating: s.updating, Source: Source}
	if !s.checkedAt.IsZero() {
		t := s.checkedAt
		st.CheckedAt = &t
	}
	if s.pack != nil {
		m := s.pack.manifest
		st.Installed, st.Version, st.Count, st.Size = true, m.Version, m.Count, m.Size
		built := m.Built
		st.Built = &built
	}
	return st
}

// Kick asks for a look now (the page's "Update icons").
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run looks for a new pack a little after the start, then once a day and
// when kicked, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	timer := time.NewTimer(firstLook)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-s.kick:
		}
		if s.cfg.Wanted == nil || s.cfg.Wanted(ctx) {
			if err := s.Update(ctx); err != nil && ctx.Err() == nil {
				s.cfg.Log.Warn("the icon pack could not be brought up to date", "error", err)
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(checkEvery)
	}
}

// Update fetches the newest pack if it is not the one in use.
func (s *Service) Update(ctx context.Context) error {
	s.updates.Lock()
	defer s.updates.Unlock()
	s.setUpdating(true)
	err := s.update(ctx)
	s.mu.Lock()
	s.updating = false
	s.checkedAt = s.cfg.Now()
	s.problem = ""
	if err != nil {
		s.problem = err.Error()
	}
	s.mu.Unlock()
	return err
}

func (s *Service) setUpdating(on bool) {
	s.mu.Lock()
	s.updating = on
	s.mu.Unlock()
}

func (s *Service) update(ctx context.Context) error {
	base, err := url.Parse(s.cfg.ManifestURL)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") {
		return errors.New("SGC does not know where the icon pack is published")
	}
	raw, err := s.get(ctx, base.String(), maxManifest)
	if err != nil {
		return fmt.Errorf("the list of the newest icon pack could not be fetched: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return errors.New("the list of the newest icon pack could not be read")
	}
	if err := m.check(); err != nil {
		return fmt.Errorf("the newest icon pack was refused: %w", err)
	}
	s.mu.Lock()
	current := s.pack
	s.mu.Unlock()
	if current != nil && current.manifest.Version == m.Version {
		return nil
	}

	fileURL, err := base.Parse(m.File)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.cfg.Dir, 0o750); err != nil {
		return err
	}
	data, err := s.get(ctx, fileURL.String(), m.Size)
	if err != nil {
		return fmt.Errorf("the icon pack could not be downloaded: %w", err)
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != m.Size || hex.EncodeToString(sum[:]) != m.SHA256 {
		return errors.New("the downloaded icon pack does not match its checksum, so it was not used")
	}
	pack, err := s.install(m, data)
	if err != nil {
		return fmt.Errorf("the icon pack was refused: %w", err)
	}
	s.mu.Lock()
	s.pack = pack
	s.mu.Unlock()
	s.cfg.Log.Info("icon pack in place", "version", m.Version, "icons", m.Count)
	s.removeOthers(m.Version)
	if s.cfg.Installed != nil {
		s.cfg.Installed()
	}
	return nil
}

func (s *Service) get(ctx context.Context, target string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the server answered %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("it is larger than expected")
	}
	return data, nil
}

// install unpacks a checked pack into a folder of its own, takes only what
// belongs in a pack, and then makes it the one in use.
func (s *Service) install(m Manifest, data []byte) (*loaded, error) {
	final := filepath.Join(s.cfg.Dir, m.Version)
	work := final + ".new"
	os.RemoveAll(work)
	if err := os.MkdirAll(filepath.Join(work, "png"), 0o750); err != nil {
		return nil, err
	}
	fail := func(err error) (*loaded, error) {
		os.RemoveAll(work)
		return nil, err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	entries := 0
	var indexRaw []byte
	pngs := map[string]bool{}
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(errors.New("it is not a readable archive"))
		}
		entries++
		if entries > maxEntries+3 {
			return fail(errors.New("it holds too many files"))
		}
		if header.Typeflag != tar.TypeReg {
			return fail(fmt.Errorf("it holds something other than files (%q)", header.Name))
		}
		limit, target := int64(0), ""
		switch name := header.Name; {
		case name == IndexFile:
			limit, target = maxIndex, IndexFile
		case name == "LICENSE" || name == "NOTICE":
			limit, target = 64<<10, name
		case strings.HasPrefix(name, "png/") && strings.HasSuffix(name, ".png") && ValidName(strings.TrimSuffix(strings.TrimPrefix(name, "png/"), ".png")):
			limit, target = maxIcon, name
		default:
			return fail(fmt.Errorf("it holds a file a pack does not have (%q)", header.Name))
		}
		if header.Size < 0 || header.Size > limit {
			return fail(fmt.Errorf("%s is larger than a pack's files are", header.Name))
		}
		content, err := io.ReadAll(io.LimitReader(tr, limit+1))
		if err != nil || int64(len(content)) != header.Size {
			return fail(errors.New("it is not a readable archive"))
		}
		if strings.HasPrefix(target, "png/") {
			if !bytes.HasPrefix(content, []byte("\x89PNG\r\n\x1a\n")) {
				return fail(fmt.Errorf("%s is not a PNG", header.Name))
			}
			pngs[strings.TrimSuffix(strings.TrimPrefix(target, "png/"), ".png")] = true
		}
		if target == IndexFile {
			indexRaw = content
		}
		if err := os.WriteFile(filepath.Join(work, filepath.FromSlash(target)), content, 0o640); err != nil {
			return fail(err)
		}
	}
	var index Index
	if indexRaw == nil || json.Unmarshal(indexRaw, &index) != nil || index.Commit != m.Commit {
		return fail(errors.New("its list of icons is missing or does not belong to it"))
	}
	if len(pngs) != m.Count {
		return fail(fmt.Errorf("it holds %d icons and says %d", len(pngs), m.Count))
	}
	for name := range index.Icons {
		if !pngs[name] {
			return fail(fmt.Errorf("its list names an icon it does not hold (%q)", name))
		}
	}
	os.RemoveAll(final)
	if err := os.Rename(work, final); err != nil {
		return fail(err)
	}
	manifestJSON, _ := json.Marshal(m)
	temporary := filepath.Join(s.cfg.Dir, "current.json.new")
	if err := os.WriteFile(temporary, manifestJSON, 0o640); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary, filepath.Join(s.cfg.Dir, "current.json")); err != nil {
		return nil, err
	}
	return &loaded{manifest: m, dir: final, byName: lookupTable(index)}, nil
}

func (s *Service) loadCurrent() (*loaded, error) {
	raw, err := os.ReadFile(filepath.Join(s.cfg.Dir, "current.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	dir := filepath.Join(s.cfg.Dir, m.Version)
	indexRaw, err := os.ReadFile(filepath.Join(dir, IndexFile))
	if err != nil {
		return nil, err
	}
	var index Index
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		return nil, err
	}
	return &loaded{manifest: m, dir: dir, byName: lookupTable(index)}, nil
}

// lookupTable: every icon by its name, then by its aliases where no icon has
// that name.
func lookupTable(index Index) map[string]string {
	table := map[string]string{}
	for name := range index.Icons {
		if ValidName(name) {
			table[name] = name
		}
	}
	for name, entry := range index.Icons {
		if !ValidName(name) {
			continue
		}
		for _, alias := range entry.Aliases {
			if _, taken := table[alias]; !taken && ValidName(alias) {
				table[alias] = name
			}
		}
	}
	return table
}

// removeOthers deletes the folders of packs no longer in use, and anything
// left from an interrupted update.
func (s *Service) removeOthers(keep string) {
	entries, err := os.ReadDir(s.cfg.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != keep {
			os.RemoveAll(filepath.Join(s.cfg.Dir, e.Name()))
		}
	}
}

// Lookup returns the icon for the first of the names the pack has (as an
// icon's name or an alias), as it is in the pack; nil if none. The caller
// draws it anew before it is kept or shown.
func (s *Service) Lookup(names ...string) []byte {
	s.mu.Lock()
	pack := s.pack
	s.mu.Unlock()
	if pack == nil {
		return nil
	}
	for _, candidate := range names {
		name, ok := pack.byName[candidate]
		if !ok {
			continue
		}
		f, err := os.Open(filepath.Join(pack.dir, "png", name+".png"))
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxIcon+1))
		f.Close()
		if err == nil && len(data) <= maxIcon {
			return data
		}
	}
	return nil
}
