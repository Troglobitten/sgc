// Package updater installs a downloaded SGC release and rolls it back if the
// new version does not come up healthy. It is the part of updating that
// needs root, and it runs as its own short-lived systemd unit.
//
// Division of labour:
//
//   - The unprivileged web process downloads the release into its spool
//     folder. It talks to the internet; this package never does.
//   - This package trusts nothing it finds there. It verifies the signature
//     and checksum itself before using a single byte, and it treats every
//     path inside the service user's folders as possibly hostile (a bug in
//     the web process must not become root through the updater).
//
// Order of work, chosen so that a failure at any point leaves a working SGC:
//
//  1. verify and unpack the new release next to the installed one
//  2. stop SGC, copy its database aside
//  3. point "current" at the new release, install its systemd units, start it
//  4. wait for the new version to answer; if it does not, put everything
//     back (programs, units, database) and start the previous version
package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/layout"

	"github.com/Troglobitten/sgc/internal/release"
)

// States of an update, as written to the status file.
const (
	StateRunning    = "running"
	StateSucceeded  = "succeeded"
	StateRolledBack = "rolled-back"
	// StateFailed with Changed=false: nothing was touched (for example a bad
	// signature). With Changed=true: the rollback itself did not come up,
	// which needs attention over SSH.
	StateFailed = "failed"
)

const (
	statusFile = "status.json"
	lockFile   = "lock"
	backupDir  = "database-backup"

	mainUnit     = "sgc.service"
	helperUnit   = "sgc-helper.service"
	helperSocket = "sgc-helper.socket"

	maxChecksumsSize = 64 * 1024
	maxSignatureSize = 1024
	maxArchiveSize   = 256 * 1024 * 1024
	maxFileSize      = 128 * 1024 * 1024
	maxArchiveFiles  = 32
)

// Files a release may contain: plain names, no folders. The "@" is for
// systemd template units such as sgc-update@.service.
var releaseFileName = regexp.MustCompile(`^[a-z0-9][a-z0-9.@-]{0,63}$`)

// Programs every release must contain; they are the only executable files.
var programs = map[string]bool{"sgc": true, "sgc-helper": true}

// Services is how the updater controls systemd. An interface so tests can
// run without one.
type Services interface {
	Stop(unit string) error
	Start(unit string) error
	Restart(unit string) error
	DaemonReload() error
}

type Config struct {
	CurrentVersion string
	Arch           string
	TrustedKeys    []ed25519.PublicKey

	InstallRoot string // /opt/sgc: root-owned
	UnitDir     string // /etc/systemd/system: root-owned
	WorkDir     string // /var/lib/sgc-update: root-owned; status and database backup
	StateDir    string // /var/lib/sgc: owned by the service user, treated as untrusted
	SpoolDir    string // /var/lib/sgc/updates: where the web process puts downloads

	// The service user, who must own the database again after a rollback.
	OwnerUID, OwnerGID int

	Services Services
	// Healthy returns nil once the running SGC reports the given version.
	Healthy func(ctx context.Context, version string) error
	Now     func() time.Time
	Log     *slog.Logger
}

// Status is the outcome of the most recent update attempt. The web process
// reads it to tell the user what happened.
type Status struct {
	// ID identifies one attempt, so it is reported exactly once. The start
	// time in milliseconds: unique because only one update runs at a time,
	// and small enough for a browser to read exactly.
	ID         int64     `json:"id"`
	State      string    `json:"state"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	Message    string    `json:"message"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
	// Changed reports whether the installation was touched at all.
	Changed bool `json:"changed"`
}

// ReadStatus returns the last recorded status, or nil if no update was ever
// attempted.
func ReadStatus(workDir string) (*Status, error) {
	data, err := os.ReadFile(filepath.Join(workDir, statusFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("read update status: %w", err)
	}
	return &s, nil
}

// Run installs the given version and returns what happened. It always
// records a final status, whatever the outcome.
func Run(ctx context.Context, cfg Config, targetVersion string) Status {
	u := &update{cfg: cfg}
	u.status = Status{
		ID:        cfg.Now().UnixMilli(),
		State:     StateRunning,
		From:      cfg.CurrentVersion,
		To:        targetVersion,
		StartedAt: cfg.Now().UTC(),
	}

	unlock, err := u.lock()
	if err != nil {
		// Another update holds the status file; do not overwrite it.
		u.status.State, u.status.Message = StateFailed, err.Error()
		return u.status
	}
	defer unlock()

	if err := u.prepare(); err != nil {
		return u.finish(StateFailed, fmt.Sprintf("SGC %s was not installed: %v.", targetVersion, err))
	}

	u.status.Changed = true
	u.writeStatus()
	if err := u.switchTo(ctx); err != nil {
		cfg.Log.Error("update failed, rolling back", "to", targetVersion, "error", err)
		if rollbackErr := u.rollback(ctx); rollbackErr != nil {
			cfg.Log.Error("rollback failed", "error", rollbackErr)
			return u.finish(StateFailed, fmt.Sprintf(
				"The update to %s failed (%v), and returning to %s failed too (%v). SGC needs attention over SSH.",
				targetVersion, err, cfg.CurrentVersion, rollbackErr))
		}
		return u.finish(StateRolledBack, fmt.Sprintf(
			"The update to %s did not work (%v), so SGC went back to %s. Nothing was lost.",
			targetVersion, err, cfg.CurrentVersion))
	}

	u.removeOldReleases()
	return u.finish(StateSucceeded, fmt.Sprintf("SGC was updated from %s to %s.", cfg.CurrentVersion, targetVersion))
}

type update struct {
	cfg    Config
	status Status

	target      string            // validated version string
	releaseDir  string            // InstallRoot/releases/<target>
	previous    string            // what "current" pointed at before
	oldUnits    map[string][]byte // unit files as they were; nil content = did not exist
	hadDatabase map[string]bool   // which database files existed and were backed up
}

func (u *update) finish(state, message string) Status {
	u.status.State = state
	u.status.Message = message
	u.status.FinishedAt = u.cfg.Now().UTC()
	u.writeStatus()
	return u.status
}

func (u *update) writeStatus() {
	data, err := json.MarshalIndent(u.status, "", "  ")
	if err == nil {
		// World-readable on purpose: the unprivileged web process reads it.
		// It lives in a root-owned folder, so that process cannot alter it.
		err = writeFileAtomic(filepath.Join(u.cfg.WorkDir, statusFile), data, 0o644)
	}
	if err != nil {
		u.cfg.Log.Error("write update status", "error", err)
	}
}

// lock makes sure only one update runs at a time.
func (u *update) lock() (unlock func(), err error) {
	if err := os.MkdirAll(u.cfg.WorkDir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(u.cfg.WorkDir, lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another update is already running")
	}
	return func() { f.Close() }, nil
}

// prepare verifies the download and unpacks it next to the installed
// release. Nothing that SGC is using is touched yet.
func (u *update) prepare() error {
	target, err := release.ParseVersion(u.status.To)
	if err != nil {
		return err
	}
	current, err := release.ParseVersion(u.cfg.CurrentVersion)
	if err != nil {
		return fmt.Errorf("installed version: %w", err)
	}
	// Also what stops an old, genuinely signed release from being installed
	// over a newer one.
	if !target.NewerThan(current) {
		return fmt.Errorf("it is not newer than the installed %s", current)
	}
	u.target = target.String()

	spool := filepath.Join(u.cfg.SpoolDir, u.target)
	checksums, err := readRegularFile(filepath.Join(spool, release.ChecksumsFile), maxChecksumsSize)
	if err != nil {
		return fmt.Errorf("read the downloaded checksum list: %w", err)
	}
	signature, err := readRegularFile(filepath.Join(spool, release.SignatureFile), maxSignatureSize)
	if err != nil {
		return fmt.Errorf("read the downloaded signature: %w", err)
	}
	archiveName := release.ArchiveName(u.target, u.cfg.Arch)
	archive, err := readRegularFile(filepath.Join(spool, archiveName), maxArchiveSize)
	if err != nil {
		return fmt.Errorf("read the downloaded archive: %w", err)
	}

	// Verified here, by root, on the exact bytes that will be unpacked. The
	// web process checked too, but it is not trusted with this decision.
	if err := release.VerifyChecksums(checksums, signature, u.cfg.TrustedKeys); err != nil {
		return err
	}
	if err := release.VerifyFile(checksums, archiveName, archive); err != nil {
		return err
	}

	files, err := unpack(archive)
	if err != nil {
		return fmt.Errorf("unpack the release: %w", err)
	}
	for name := range programs {
		if _, ok := files[name]; !ok {
			return fmt.Errorf("the release does not contain %s", name)
		}
	}

	releases := filepath.Join(u.cfg.InstallRoot, "releases")
	u.releaseDir = filepath.Join(releases, u.target)
	staging := u.releaseDir + ".new"
	if err := os.RemoveAll(staging); err != nil {
		return err
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return err
	}
	for name, data := range files {
		mode := os.FileMode(0o644)
		if programs[name] {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(staging, name), data, mode); err != nil {
			os.RemoveAll(staging)
			return err
		}
	}
	if err := os.RemoveAll(u.releaseDir); err != nil {
		return err
	}
	return os.Rename(staging, u.releaseDir)
}

// switchTo stops SGC, moves it to the new release and waits for it to
// answer. Any error here is followed by rollback.
func (u *update) switchTo(ctx context.Context) error {
	var err error
	if u.previous, err = os.Readlink(u.currentLink()); err != nil {
		return fmt.Errorf("find the installed release: %w", err)
	}

	if err := u.cfg.Services.Stop(mainUnit); err != nil {
		return fmt.Errorf("stop SGC: %w", err)
	}
	if err := u.backupDatabase(); err != nil {
		return fmt.Errorf("copy the database aside: %w", err)
	}
	if err := u.setCurrent(filepath.Join("releases", u.target)); err != nil {
		return fmt.Errorf("switch to the new release: %w", err)
	}
	if err := u.installUnits(); err != nil {
		return fmt.Errorf("install the service definitions: %w", err)
	}
	if err := u.startServices(); err != nil {
		return err
	}
	if err := u.cfg.Healthy(ctx, u.target); err != nil {
		return fmt.Errorf("the new version did not start correctly: %w", err)
	}
	return nil
}

func (u *update) rollback(ctx context.Context) error {
	// Best effort: SGC may or may not be running at this point.
	u.cfg.Services.Stop(mainUnit)

	var problems []string
	note := func(what string, err error) {
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", what, err))
		}
	}
	note("switch back to the previous release", u.setCurrent(u.previous))
	note("restore the service definitions", u.restoreUnits())
	note("restore the database", u.restoreDatabase())
	note("start SGC", u.startServices())
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	if err := u.cfg.Healthy(ctx, u.cfg.CurrentVersion); err != nil {
		return fmt.Errorf("the previous version did not start correctly: %w", err)
	}
	return nil
}

// startServices reloads systemd and starts SGC. The helper is stopped so
// that the next request starts the program from the release now in place.
func (u *update) startServices() error {
	if err := u.cfg.Services.DaemonReload(); err != nil {
		return fmt.Errorf("reload systemd: %w", err)
	}
	u.cfg.Services.Stop(helperUnit) // not running is fine
	if err := u.cfg.Services.Restart(helperSocket); err != nil {
		return fmt.Errorf("restart the helper socket: %w", err)
	}
	if err := u.cfg.Services.Start(mainUnit); err != nil {
		return fmt.Errorf("start SGC: %w", err)
	}
	return nil
}

func (u *update) currentLink() string { return filepath.Join(u.cfg.InstallRoot, "current") }

// setCurrent repoints the "current" link. Creating a new link and renaming
// it over the old one means there is never a moment without a valid link.
func (u *update) setCurrent(target string) error {
	if target == "" {
		return errors.New("no release to point at")
	}
	temporary := u.currentLink() + ".new"
	os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	return os.Rename(temporary, u.currentLink())
}

func isUnitFile(name string) bool {
	return strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".socket")
}

// installUnits copies the new release's systemd units into place,
// remembering what was there before.
func (u *update) installUnits() error {
	entries, err := os.ReadDir(u.releaseDir)
	if err != nil {
		return err
	}
	u.oldUnits = make(map[string][]byte)
	for _, entry := range entries {
		name := entry.Name()
		if !isUnitFile(name) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(u.releaseDir, name))
		if err != nil {
			return err
		}
		destination := filepath.Join(u.cfg.UnitDir, name)
		previous, err := os.ReadFile(destination)
		switch {
		case err == nil:
			u.oldUnits[name] = previous
		case errors.Is(err, os.ErrNotExist):
			u.oldUnits[name] = nil
		default:
			return err
		}
		if err := writeFileAtomic(destination, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (u *update) restoreUnits() error {
	for name, previous := range u.oldUnits {
		destination := filepath.Join(u.cfg.UnitDir, name)
		var err error
		if previous == nil {
			// The update introduced this unit; the previous version has no use for it.
			err = os.Remove(destination)
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		} else {
			err = writeFileAtomic(destination, previous, 0o644)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// databaseFiles are the database and the two side files SQLite may keep
// next to it. After a clean stop only the first exists.
func databaseFiles() []string {
	return []string{layout.DatabaseFile, layout.DatabaseFile + "-wal", layout.DatabaseFile + "-shm"}
}

// backupDatabase copies the database into the root-owned work folder. A new
// version may change the database's layout on first start; if it then fails,
// the previous version needs the database as it was.
func (u *update) backupDatabase() error {
	backup := filepath.Join(u.cfg.WorkDir, backupDir)
	if err := os.RemoveAll(backup); err != nil {
		return err
	}
	if err := os.MkdirAll(backup, 0o700); err != nil {
		return err
	}
	u.hadDatabase = make(map[string]bool)
	for _, name := range databaseFiles() {
		err := copyRegularFile(filepath.Join(u.cfg.StateDir, name), filepath.Join(backup, name), 0o600, -1, -1)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		u.hadDatabase[name] = true
	}
	return nil
}

func (u *update) restoreDatabase() error {
	if u.hadDatabase == nil {
		return nil // the failure came before the backup; the database was never at risk
	}
	backup := filepath.Join(u.cfg.WorkDir, backupDir)
	for _, name := range databaseFiles() {
		destination := filepath.Join(u.cfg.StateDir, name)
		// Remove whatever the failed version left, including side files the
		// backup does not have: stale ones would corrupt the restored database.
		if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if !u.hadDatabase[name] {
			continue
		}
		if err := copyRegularFile(filepath.Join(backup, name), destination, 0o600, u.cfg.OwnerUID, u.cfg.OwnerGID); err != nil {
			return err
		}
	}
	return nil
}

// removeOldReleases keeps the new release and the one before it (for a
// manual rollback) and deletes the rest.
func (u *update) removeOldReleases() {
	releases := filepath.Join(u.cfg.InstallRoot, "releases")
	entries, err := os.ReadDir(releases)
	if err != nil {
		return
	}
	keep := map[string]bool{u.target: true, filepath.Base(u.previous): true}
	for _, entry := range entries {
		if !keep[entry.Name()] {
			os.RemoveAll(filepath.Join(releases, entry.Name()))
		}
	}
}

// --- Careful file handling ---------------------------------------------------

// readRegularFile reads a file that an unprivileged process may have put
// there. It refuses anything that is not a plain file, in particular a
// symbolic link pointing at something root can read and that user cannot.
func readRegularFile(path string, maxSize int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > maxSize {
		return nil, errors.New("larger than expected")
	}
	// The limit again while reading: the size could have changed since Stat.
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, errors.New("larger than expected")
	}
	return data, nil
}

// copyRegularFile copies source to a newly created destination without
// following symbolic links at either end, then (if uid is not -1) hands the
// copy to that owner. Used across the boundary between root's folders and
// the service user's.
func copyRegularFile(source, destination string, mode os.FileMode, uid, gid int) error {
	in, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	if info, err := in.Stat(); err != nil {
		return err
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", filepath.Base(source))
	}

	// O_EXCL: the destination must not exist. If something appeared there
	// in the meantime, fail rather than write through it.
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if uid != -1 {
		// Through the open file, not the path, so it applies to the file
		// just written and nothing else.
		if err := out.Chown(uid, gid); err != nil {
			out.Close()
			return err
		}
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// writeFileAtomic replaces a file in a root-owned folder so that readers see
// either the old content or the new, never half of it.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	// WriteFile's mode is subject to the umask; make it exact.
	if err := os.Chmod(temporary, mode); err != nil {
		os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, path)
}

// unpack reads a release archive that has already been verified. It still
// accepts only what a release is supposed to contain: a handful of plain
// files with simple names. No folders, links or devices.
func unpack(archive []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	files := make(map[string][]byte)
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("unexpected entry %q: only plain files are allowed", header.Name)
		}
		if !releaseFileName.MatchString(header.Name) {
			return nil, fmt.Errorf("unexpected file name %q", header.Name)
		}
		if _, duplicate := files[header.Name]; duplicate {
			return nil, fmt.Errorf("file %q appears twice", header.Name)
		}
		if len(files) >= maxArchiveFiles {
			return nil, errors.New("more files than a release contains")
		}
		if header.Size > maxFileSize {
			return nil, fmt.Errorf("file %q is larger than expected", header.Name)
		}
		data, err := io.ReadAll(io.LimitReader(reader, maxFileSize+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxFileSize {
			return nil, fmt.Errorf("file %q is larger than expected", header.Name)
		}
		files[header.Name] = data
	}
	return files, nil
}
