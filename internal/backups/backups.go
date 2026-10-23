// Package backups makes an export of SGC every day and puts it on another
// device: a share (SMB), a server over SSH (SFTP) or a WebDAV folder
// (docs/design.md §4.13 and §10). The newest ones are kept, older ones go.
//
// A backup is encrypted to a backup key. SGC makes the key once and shows
// its secret half once; SGC keeps only the public half. So the backups on
// the other device are useless to whoever takes them, or SGC itself.
//
// Web process only.
package backups

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/backup"
	"github.com/Troglobitten/sgc/internal/problem"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	// SettingSettings holds the target and the schedule (exported; the
	// target's password travels with an export).
	SettingSettings = "backups.settings"
	// SettingLast is how the last run went (not exported).
	SettingLast = "backups.last"

	DefaultKeep = 10
	// A backup is overdue after this long without a good one.
	overdueAfter = 3 * 24 * time.Hour
	maxBackup    = 512 << 20
)

// Settings are the owner's settings.
type Settings struct {
	Enabled bool   `json:"enabled"`
	Target  Target `json:"target"`
	// Time is the time of day ("03:30", this device's clock).
	Time string `json:"time"`
	Keep int    `json:"keep"`
	// PublicKey is the backup key's public half ("age1…").
	PublicKey string `json:"publicKey"`
	// Since is when backups were switched on (for "overdue").
	Since time.Time `json:"since"`
}

// Run is how one backup went.
type Run struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
	File    string    `json:"file"`
	Size    int64     `json:"size"`
}

type last struct {
	Last        *Run       `json:"last"`
	LastSuccess *time.Time `json:"lastSuccess"`
}

type Config struct {
	DB    *sql.DB
	Audit *audit.Log
	// Export writes an export encrypted to the public key.
	Export   func(ctx context.Context, w io.Writer, publicKey string) (*backup.Manifest, error)
	Hostname string
	// Alert tells the owner when a backup fails or is overdue.
	Alert func(ctx context.Context, title, body string)
	Now   func() time.Time
	Log   *slog.Logger
}

type Service struct {
	cfg Config
	mu  sync.Mutex
}

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Alert == nil {
		cfg.Alert = func(context.Context, string, string) {}
	}
	return &Service{cfg: cfg}
}

func (s *Service) settings(ctx context.Context) (Settings, error) {
	var out Settings
	raw, found, err := store.Setting(ctx, s.cfg.DB, SettingSettings)
	if err != nil {
		return out, err
	}
	if found {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			return Settings{}, fmt.Errorf("the backup settings cannot be read: %w", err)
		}
	}
	if out.Time == "" {
		out.Time = "03:30"
	}
	if out.Keep == 0 {
		out.Keep = DefaultKeep
	}
	if out.Target.Kind == "" {
		out.Target.Kind = KindSMB
	}
	return out, nil
}

func (s *Service) last(ctx context.Context) last {
	var l last
	if raw, found, err := store.Setting(ctx, s.cfg.DB, SettingLast); err == nil && found {
		json.Unmarshal([]byte(raw), &l)
	}
	return l
}

// Status is what the page shows; never the target's password.
type Status struct {
	Settings    Settings   `json:"settings"`
	HasPassword bool       `json:"hasPassword"`
	HasKey      bool       `json:"hasKey"`
	Last        *Run       `json:"last"`
	LastSuccess *time.Time `json:"lastSuccess"`
	Overdue     bool       `json:"overdue"`
	NextAt      *time.Time `json:"nextAt"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	settings, err := s.settings(ctx)
	if err != nil {
		return Status{}, err
	}
	l := s.last(ctx)
	status := Status{Settings: settings, HasPassword: settings.Target.Password != "", HasKey: settings.PublicKey != "",
		Last: l.Last, LastSuccess: l.LastSuccess}
	status.Settings.Target.Password = ""
	status.Overdue = s.overdue(settings, l)
	if settings.Enabled {
		next := s.nextAt(settings, l)
		status.NextAt = &next
	}
	return status, nil
}

func (s *Service) overdue(settings Settings, l last) bool {
	if !settings.Enabled {
		return false
	}
	since := settings.Since
	if l.LastSuccess != nil {
		since = *l.LastSuccess
	}
	return s.cfg.Now().Sub(since) > overdueAfter
}

var timePattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// todayAt is today's run time, on this device's clock.
func (s *Service) todayAt(settings Settings) time.Time {
	now := s.cfg.Now()
	h, _ := strconv.Atoi(settings.Time[:2])
	m, _ := strconv.Atoi(settings.Time[3:])
	return time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
}

func (s *Service) nextAt(settings Settings, l last) time.Time {
	at := s.todayAt(settings)
	if l.Last != nil && !l.Last.At.Before(at) {
		at = at.AddDate(0, 0, 1)
	}
	if at.Before(s.cfg.Now()) {
		return s.cfg.Now()
	}
	return at
}

// SetSettings keeps new settings. An empty password keeps the one there is.
func (s *Service) SetSettings(ctx context.Context, actor, remote string, next Settings) error {
	current, err := s.settings(ctx)
	if err != nil {
		return err
	}
	if next.Target.Password == "" {
		next.Target.Password = current.Target.Password
	}
	next.PublicKey = current.PublicKey
	next.Since = current.Since
	if next.Enabled && !current.Enabled {
		next.Since = s.cfg.Now().UTC()
	}
	if err := validate(&next); err != nil {
		return err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := store.SetSetting(ctx, s.cfg.DB, SettingSettings, string(data)); err != nil {
		return err
	}
	where := next.Target.Kind + " " + next.Target.Host + next.Target.URL
	s.record(ctx, actor, audit.ActionBackupSettingsChanged, fmt.Sprintf("%s, daily at %s, keep %d, on: %t", where, next.Time, next.Keep, next.Enabled), remote)
	return nil
}

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)

func validate(s *Settings) error {
	if !timePattern.MatchString(s.Time) {
		return problem.New("The time of day is written like 03:30.")
	}
	if s.Keep < 1 || s.Keep > 100 {
		return problem.New("Keep 1 to 100 backups.")
	}
	if s.Enabled && s.PublicKey == "" {
		return problem.New("Make the backup key first: without it SGC cannot encrypt the backups.")
	}
	t := &s.Target
	if strings.ContainsAny(t.Username+t.Password+t.Path+t.Share, "\r\n\x00") || len(t.Password) > 200 || len(t.Username) > 200 {
		return problem.New("The username, password or folder is not usable.")
	}
	if strings.Contains(t.Path, "..") {
		return problem.New("The folder cannot climb out of the share (no \"..\").")
	}
	if t.Port < 0 || t.Port > 65535 {
		return problem.New("The port is a number from 1 to 65535 (or empty for the usual one).")
	}
	switch t.Kind {
	case KindSMB:
		if !hostPattern.MatchString(t.Host) || t.Share == "" || strings.ContainsAny(t.Share, `/\`) {
			return problem.New("For a share: the device's name or address, and the share's name (like \"backups\").")
		}
	case KindSFTP:
		if !hostPattern.MatchString(t.Host) {
			return problem.New("For SFTP: the server's name or address.")
		}
		if s.Enabled && t.HostKey == "" {
			return problem.New("Test the connection first, and confirm the server's key it shows.")
		}
	case KindWebDAV:
		u, err := url.Parse(t.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return problem.New("For WebDAV: the folder's address, like https://nas.home/remote.php/dav/files/alex/sgc.")
		}
	default:
		return problem.New("A target is a share (SMB), SFTP or WebDAV.")
	}
	return nil
}

// NewKey makes the backup key and returns its secret half: the one time it
// is shown. Backups made before can only be opened with the old key.
func (s *Service) NewKey(ctx context.Context, actor, remote string) (string, error) {
	secret, public, err := backup.NewBackupKey()
	if err != nil {
		return "", err
	}
	current, err := s.settings(ctx)
	if err != nil {
		return "", err
	}
	current.PublicKey = public
	data, err := json.Marshal(current)
	if err != nil {
		return "", err
	}
	if err := store.SetSetting(ctx, s.cfg.DB, SettingSettings, string(data)); err != nil {
		return "", err
	}
	s.record(ctx, actor, audit.ActionBackupKeyCreated, public, remote)
	return secret, nil
}

// Test connects to the target and lists it. For an SFTP server whose key is
// not confirmed yet, it says the key (ErrUnknownHostKey).
func (s *Service) Test(ctx context.Context, t Target) error {
	current, err := s.settings(ctx)
	if err != nil {
		return err
	}
	if t.Password == "" {
		t.Password = current.Target.Password
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	f, err := open(ctx, t)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.List(ctx)
	return err
}

func (s *Service) record(ctx context.Context, actor, action, detail, remote string) {
	if err := s.cfg.Audit.Record(context.WithoutCancel(ctx), actor, action, detail, remote); err != nil {
		s.cfg.Log.Error("write audit log", "action", action, "error", err)
	}
}

func (s *Service) prefix() string {
	host := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, s.cfg.Hostname)
	return "sgc-backup-" + host + "-"
}

// BackUp makes a backup now and puts it on the target.
func (s *Service) BackUp(ctx context.Context, actor string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	settings, err := s.settings(ctx)
	if err != nil {
		return Run{}, err
	}
	if settings.PublicKey == "" {
		return Run{}, problem.New("Make the backup key first.")
	}
	run := Run{At: s.cfg.Now().UTC()}
	err = s.backUp(ctx, settings, &run)
	run.OK = err == nil
	l := s.last(ctx)
	l.Last = &run
	if err != nil {
		run.Message = err.Error()
		s.record(ctx, actor, audit.ActionBackupFailed, run.Message, "")
		s.cfg.Alert(ctx, "A backup failed", run.Message)
	} else {
		at := run.At
		l.LastSuccess = &at
		s.record(ctx, actor, audit.ActionBackupMade, fmt.Sprintf("%s (%d kB) to %s", run.File, run.Size/1000, settings.Target.Kind), "")
	}
	if data, jsonErr := json.Marshal(l); jsonErr == nil {
		store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingLast, string(data))
	}
	if err != nil {
		var unknown *ErrUnknownHostKey
		if errors.As(err, &unknown) {
			return run, problem.Newf("The SFTP server showed another key (%s) than the one confirmed. If the server was set up anew, test the connection and confirm its new key.", unknown.Fingerprint)
		}
		return run, problem.Newf("The backup failed: %v", err)
	}
	return run, nil
}

func (s *Service) backUp(ctx context.Context, settings Settings, run *Run) error {
	var buf bytes.Buffer
	if _, err := s.cfg.Export(ctx, &buf, settings.PublicKey); err != nil {
		return fmt.Errorf("making the export: %w", err)
	}
	if buf.Len() > maxBackup {
		return errors.New("the export is larger than SGC sends")
	}
	// Looked at before it goes: what leaves the device is an age file.
	if !bytes.HasPrefix(buf.Bytes(), []byte("age-encryption.org/v1\n")) {
		return errors.New("the export is not encrypted")
	}
	run.File = s.prefix() + run.At.Format("20060102-150405") + ".age"
	run.Size = int64(buf.Len())
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	f, err := open(ctx, settings.Target)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Put(ctx, run.File, buf.Bytes()); err != nil {
		return err
	}
	// The newest are kept: older backups of this device go.
	names, err := f.List(ctx)
	if err != nil {
		return nil // the backup is there; tidying is for next time
	}
	var mine []string
	for _, name := range names {
		if strings.HasPrefix(name, s.prefix()) && strings.HasSuffix(name, ".age") {
			mine = append(mine, name)
		}
	}
	sort.Strings(mine)
	for len(mine) > settings.Keep {
		if err := f.Delete(ctx, mine[0]); err != nil {
			s.cfg.Log.Warn("remove an old backup", "file", mine[0], "error", err)
		}
		mine = mine[1:]
	}
	return nil
}

// Run makes the daily backup at the owner's time, and says when backups are
// overdue, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	warned := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		settings, err := s.settings(ctx)
		if err != nil || !settings.Enabled {
			continue
		}
		l := s.last(ctx)
		at := s.todayAt(settings)
		now := s.cfg.Now()
		// Once a day, at or after the time; a device that was off at that
		// time makes up for it when it comes back.
		if !now.Before(at) && (l.Last == nil || l.Last.At.Before(at)) {
			s.BackUp(ctx, audit.ActorSystem)
			l = s.last(ctx)
		}
		if s.overdue(settings, l) && !warned {
			warned = true
			s.cfg.Alert(ctx, "Backups are overdue", "There has been no good backup for more than three days. The System page, Backups, says why.")
		} else if !s.overdue(settings, l) {
			warned = false
		}
	}
}
