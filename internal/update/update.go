// Package update is the unprivileged half of SGC updating itself: finding out
// whether a newer release exists and downloading it.
//
// It runs inside the web process, which may talk to the internet but has no
// rights on the system. The downloaded release is verified here and placed
// in a spool folder; installing it is done by the separate root updater
// (internal/updater), which verifies everything again by itself.
package update

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"github.com/Troglobitten/sgc/internal/layout"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Troglobitten/sgc/internal/release"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	settingAutoCheck = "update.auto_check"

	checkInterval = 24 * time.Hour

	maxChecksumsSize = 64 * 1024
	maxSignatureSize = 1024
	maxArchiveSize   = 256 * 1024 * 1024
)

var (
	ErrNoUpdate = errors.New("there is no newer version to install")
	// ErrNotLatest means the version asked for is not the one SGC last saw
	// as newest. The UI only ever offers that one.
	ErrNotLatest = errors.New("that is not the newest available version; check for updates again")
)

// Status is what SGC knows about newer versions of itself.
type Status struct {
	Current         string     `json:"current"`
	Latest          string     `json:"latest"` // "" until a check has succeeded
	UpdateAvailable bool       `json:"updateAvailable"`
	Notes           string     `json:"notes"`
	PublishedAt     *time.Time `json:"publishedAt"`
	CheckedAt       *time.Time `json:"checkedAt"` // last successful check
	// CheckError says why the most recent check failed, or is empty. A check
	// that keeps failing must be visible: silence would look like "up to date".
	CheckError    string     `json:"checkError"`
	CheckFailedAt *time.Time `json:"checkFailedAt"`
	AutoCheck     bool       `json:"autoCheck"`
}

type Checker struct {
	db       *sql.DB
	source   *Source
	current  release.Version
	arch     string
	keys     []ed25519.PublicKey
	spoolDir string
	now      func() time.Time
	log      *slog.Logger
}

type Config struct {
	DB             *sql.DB
	Source         *Source
	CurrentVersion string
	Arch           string
	TrustedKeys    []ed25519.PublicKey
	StateDir       string
	Log            *slog.Logger
}

func NewChecker(cfg Config) (*Checker, error) {
	current, err := release.ParseVersion(cfg.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("installed version: %w", err)
	}
	return &Checker{
		db:       cfg.DB,
		source:   cfg.Source,
		current:  current,
		arch:     cfg.Arch,
		keys:     cfg.TrustedKeys,
		spoolDir: filepath.Join(cfg.StateDir, layout.SpoolFolder),
		now:      time.Now,
		log:      cfg.Log,
	}, nil
}

// Status returns what the last check found, without contacting anything.
func (c *Checker) Status(ctx context.Context) (Status, error) {
	s := Status{Current: c.current.String()}

	var publishedAt, checkedAt, errorAt int64
	err := c.db.QueryRowContext(ctx,
		"SELECT latest_version, notes, published_at, checked_at, error, error_at FROM update_check WHERE id = 1").
		Scan(&s.Latest, &s.Notes, &publishedAt, &checkedAt, &s.CheckError, &errorAt)
	if err != nil {
		return s, fmt.Errorf("read update status: %w", err)
	}
	s.PublishedAt = timeOrNil(publishedAt)
	s.CheckedAt = timeOrNil(checkedAt)
	s.CheckFailedAt = timeOrNil(errorAt)

	if s.Latest != "" {
		if latest, err := release.ParseVersion(s.Latest); err == nil {
			s.UpdateAvailable = latest.NewerThan(c.current)
		}
	}
	if !s.UpdateAvailable {
		// Notes of a release that is already installed are of no interest.
		s.Notes = ""
	}

	if s.AutoCheck, err = c.autoCheck(ctx); err != nil {
		return s, err
	}
	return s, nil
}

func timeOrNil(unix int64) *time.Time {
	if unix == 0 {
		return nil
	}
	t := time.Unix(unix, 0).UTC()
	return &t
}

// Check asks the source for the newest release and remembers the answer,
// or the reason it could not be had.
func (c *Checker) Check(ctx context.Context) (Status, error) {
	latest, err := c.source.Latest(ctx)
	now := c.now().Unix()
	if err != nil {
		c.log.Warn("check for updates failed", "error", err)
		if _, dbErr := c.db.ExecContext(ctx,
			"UPDATE update_check SET error = ?, error_at = ? WHERE id = 1", err.Error(), now); dbErr != nil {
			return Status{}, fmt.Errorf("store update status: %w", dbErr)
		}
		return c.Status(ctx)
	}
	if _, err := c.db.ExecContext(ctx,
		`UPDATE update_check
		 SET latest_version = ?, notes = ?, published_at = ?, checked_at = ?, error = '', error_at = 0
		 WHERE id = 1`,
		latest.Version, latest.Notes, latest.PublishedAt.Unix(), now); err != nil {
		return Status{}, fmt.Errorf("store update status: %w", err)
	}
	return c.Status(ctx)
}

func (c *Checker) autoCheck(ctx context.Context) (bool, error) {
	value, found, err := store.Setting(ctx, c.db, settingAutoCheck)
	if err != nil {
		return false, err
	}
	return !found || value == "1", nil // on unless switched off
}

// SetAutoCheck switches the daily check on or off.
func (c *Checker) SetAutoCheck(ctx context.Context, enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	return store.SetSetting(ctx, c.db, settingAutoCheck, value)
}

// Run checks once a day, while the daily check is switched on, until ctx is
// cancelled.
func (c *Checker) Run(ctx context.Context) {
	// Not immediately at start: a service that restarts in a loop must not
	// hammer the source, and start-up should not wait on the network.
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if due, err := c.checkDue(ctx); err != nil {
			c.log.Error("check for updates", "error", err)
		} else if due {
			if _, err := c.Check(ctx); err != nil {
				c.log.Error("check for updates", "error", err)
			}
		}
		timer.Reset(time.Hour)
	}
}

// checkDue reports whether the daily check should run now: switched on, and
// the last attempt (successful or not) is a day old.
func (c *Checker) checkDue(ctx context.Context) (bool, error) {
	status, err := c.Status(ctx)
	if err != nil || !status.AutoCheck {
		return false, err
	}
	var last time.Time
	if status.CheckedAt != nil {
		last = *status.CheckedAt
	}
	if status.CheckFailedAt != nil && status.CheckFailedAt.After(last) {
		last = *status.CheckFailedAt
	}
	return c.now().Sub(last) >= checkInterval, nil
}

// Fetch downloads the given version, verifies it and leaves it in the spool
// folder for the root updater. Only the version last seen as newest is
// accepted.
func (c *Checker) Fetch(ctx context.Context, version string) error {
	status, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if !status.UpdateAvailable {
		return ErrNoUpdate
	}
	if version != status.Latest {
		return ErrNotLatest
	}

	checksums, err := c.source.File(ctx, version, release.ChecksumsFile, maxChecksumsSize)
	if err != nil {
		return err
	}
	signature, err := c.source.File(ctx, version, release.SignatureFile, maxSignatureSize)
	if err != nil {
		return err
	}
	// The signature first: no point downloading megabytes that will be refused.
	if err := release.VerifyChecksums(checksums, signature, c.keys); err != nil {
		return err
	}
	archiveName := release.ArchiveName(version, c.arch)
	archive, err := c.source.File(ctx, version, archiveName, maxArchiveSize)
	if err != nil {
		return err
	}
	if err := release.VerifyFile(checksums, archiveName, archive); err != nil {
		return err
	}

	// Earlier downloads are of no use any more; start from an empty spool.
	if err := os.RemoveAll(c.spoolDir); err != nil {
		return fmt.Errorf("clear earlier downloads: %w", err)
	}
	dir := filepath.Join(c.spoolDir, version)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store the download: %w", err)
	}
	for name, data := range map[string][]byte{
		release.ChecksumsFile: checksums,
		release.SignatureFile: signature,
		archiveName:           archive,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return fmt.Errorf("store the download: %w", err)
		}
	}
	return nil
}

// ClearSpool removes downloads left over from an earlier update. Called at
// start: by then any update that used them has finished.
func (c *Checker) ClearSpool() {
	if err := os.RemoveAll(c.spoolDir); err != nil {
		c.log.Warn("remove earlier update downloads", "error", err)
	}
}
