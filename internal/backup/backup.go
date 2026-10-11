// Package backup writes and reads SGC's export file: everything needed to
// bring up an identical SGC on a fresh machine, in one encrypted file.
//
// The file is an age-encrypted tar archive (https://age-encryption.org),
// protected by a passphrase the owner chooses. Inside:
//
//	manifest.json     what this is: format version, SGC version, when, where
//	database.sqlite   a cleaned copy of SGC's database
//
// It can be opened without SGC:  age -d export.age | tar -x
//
// "Cleaned" means: everything that is configuration or history is kept;
// things that only make sense on the running machine (sign-in sessions, the
// one-time setup link, cached answers) are removed. Which table is which is
// decided in tables.go, and a test fails when a table is added to the
// database without being classified there. That is how the rule "every new
// setting must be covered by export/import" is enforced.
package backup

import (
	"archive/tar"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

const (
	// FormatVersion is raised when the file's contents change in a way an
	// older SGC cannot read.
	FormatVersion = 1

	manifestName = "manifest.json"
	databaseName = "database.sqlite"

	MinPassphraseLength = 12
	maxPassphraseLength = 256

	// The cost of turning the passphrase into a key (scrypt, 2^18). This is
	// age's own default, set explicitly so that memory use is known: about
	// 256 MB for a few seconds, on export and on import. Files asking for
	// more are refused, so a crafted file cannot exhaust the gateway.
	scryptWorkFactor = 18

	maxManifestSize = 64 * 1024
	maxDatabaseSize = 512 * 1024 * 1024
)

var (
	ErrWeakPassphrase   = fmt.Errorf("a passphrase must be at least %d characters", MinPassphraseLength)
	ErrPassphraseLength = fmt.Errorf("a passphrase can be at most %d characters", maxPassphraseLength)
	ErrWrongPassphrase  = errors.New("the passphrase does not open this file")
	ErrNotAnExport      = errors.New("this is not an SGC export file")
	ErrDamaged          = errors.New("the export file is damaged or incomplete")
	// ErrNewerExport means the file was made by an SGC newer than this one.
	ErrNewerExport = errors.New("this export was made by a newer SGC; update SGC first, then restore")
)

// Manifest describes an export. It is stored inside the file and shown as
// the preview before a restore.
type Manifest struct {
	FormatVersion int       `json:"formatVersion"`
	SGCVersion    string    `json:"sgcVersion"`
	SchemaVersion int       `json:"schemaVersion"`
	CreatedAt     time.Time `json:"createdAt"`
	Hostname      string    `json:"hostname"`
	AdminUsername string    `json:"adminUsername"`
}

func checkPassphrase(passphrase string) error {
	if len(passphrase) > maxPassphraseLength {
		return ErrPassphraseLength
	}
	if len([]rune(passphrase)) < MinPassphraseLength {
		return ErrWeakPassphrase
	}
	return nil
}

// Source says where an export comes from; it ends up in the manifest.
type Source struct {
	SGCVersion string
	Hostname   string
}

// Export writes an export of the database to w, encrypted with passphrase.
// workDir is a private folder for the temporary copy of the database.
func Export(ctx context.Context, db *sql.DB, w io.Writer, passphrase string, source Source, workDir string) (*Manifest, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare export: %w", err)
	}
	snapshot, err := os.CreateTemp(workDir, "export-*.sqlite")
	if err != nil {
		return nil, fmt.Errorf("prepare export: %w", err)
	}
	snapshotPath := snapshot.Name()
	snapshot.Close()
	// VACUUM INTO refuses to overwrite, so the placeholder goes first.
	os.Remove(snapshotPath)
	defer os.Remove(snapshotPath)

	// A consistent copy of the whole database, taken while SGC keeps running.
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", snapshotPath); err != nil {
		return nil, fmt.Errorf("copy the database: %w", err)
	}
	manifest, err := cleanSnapshot(ctx, snapshotPath, source)
	if err != nil {
		return nil, err
	}

	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("prepare encryption: %w", err)
	}
	recipient.SetWorkFactor(scryptWorkFactor)
	encrypted, err := age.Encrypt(w, recipient)
	if err != nil {
		return nil, fmt.Errorf("encrypt export: %w", err)
	}

	archive := tar.NewWriter(encrypted)
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeEntry(archive, manifestName, manifestJSON, manifest.CreatedAt); err != nil {
		return nil, err
	}
	if err := writeFileEntry(archive, databaseName, snapshotPath, manifest.CreatedAt); err != nil {
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, fmt.Errorf("write export: %w", err)
	}
	// Closing is what writes the final authenticated chunk; without it the
	// file would be refused when read back.
	if err := encrypted.Close(); err != nil {
		return nil, fmt.Errorf("encrypt export: %w", err)
	}
	return manifest, nil
}

// cleanSnapshot removes from the copy everything that must not travel, and
// collects what the manifest says about it.
func cleanSnapshot(ctx context.Context, path string, source Source) (*Manifest, error) {
	db, err := store.OpenSnapshot(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	for _, statement := range cleanupStatements() {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return nil, fmt.Errorf("clean the database copy: %w", err)
		}
	}
	// Deleting rows only marks their space as free; the old contents (for
	// example session token hashes) would still be in the file. Rebuilding
	// the file leaves nothing of them behind.
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		return nil, fmt.Errorf("clean the database copy: %w", err)
	}

	manifest := &Manifest{
		FormatVersion: FormatVersion,
		SGCVersion:    source.SGCVersion,
		Hostname:      source.Hostname,
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&manifest.SchemaVersion); err != nil {
		return nil, fmt.Errorf("read the database copy: %w", err)
	}
	err = db.QueryRowContext(ctx, "SELECT username FROM admin WHERE id = 1").Scan(&manifest.AdminUsername)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read the database copy: %w", err)
	}
	return manifest, nil
}

func writeEntry(archive *tar.Writer, name string, data []byte, modified time.Time) error {
	header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: modified, Typeflag: tar.TypeReg}
	if err := archive.WriteHeader(header); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	if _, err := archive.Write(data); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	return nil
}

func writeFileEntry(archive *tar.Writer, name, path string, modified time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	header := &tar.Header{Name: name, Mode: 0o600, Size: info.Size(), ModTime: modified, Typeflag: tar.TypeReg}
	if err := archive.WriteHeader(header); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	if _, err := io.Copy(archive, f); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	return nil
}

// --- Restoring ---------------------------------------------------------------

// Restoring happens in two steps, because the web process cannot swap its
// own database while using it:
//
//  1. Stage: decrypt the file, check it, and leave the database it contains
//     in a staging folder. This is also the preview shown to the owner.
//  2. Confirm writes a marker. At its next start SGC finds the marker and
//     puts the staged database in place before opening it (ApplyStaged).

const (
	stagingFolder = "restore"
	confirmedName = "confirmed.json"
)

func stagingDir(stateDir string) string { return filepath.Join(stateDir, stagingFolder) }

// Stage decrypts the export read from r and, if it is a usable SGC export,
// leaves its database staged under stateDir. It returns the manifest for the
// preview. Any earlier staged restore is replaced.
func Stage(ctx context.Context, r io.Reader, passphrase, stateDir string) (*Manifest, error) {
	dir := stagingDir(stateDir)
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("prepare restore: %w", err)
	}
	if len(passphrase) > maxPassphraseLength {
		return nil, ErrWrongPassphrase
	}

	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	identity.SetMaxWorkFactor(scryptWorkFactor)
	decrypted, err := age.Decrypt(r, identity)
	if err != nil {
		var wrong *age.NoIdentityMatchError
		if errors.As(err, &wrong) {
			return nil, ErrWrongPassphrase
		}
		return nil, ErrNotAnExport
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare restore: %w", err)
	}
	// age checks every chunk of the file as it is read. When it finds one
	// altered or missing, whatever was being read at that moment fails in
	// its own way; remembering age's verdict lets the message say what
	// really happened: the file is damaged, not "this is something else".
	checked := &decryptedReader{r: decrypted}
	manifest, err := unpackInto(checked, dir)
	if checked.damaged {
		err = ErrDamaged
	}
	if err == nil {
		err = checkStaged(ctx, dir, manifest)
	}
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return manifest, nil
}

// decryptedReader notes whether decrypting failed anywhere along the way.
type decryptedReader struct {
	r       io.Reader
	damaged bool
}

func (d *decryptedReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		d.damaged = true
	}
	return n, err
}

// unpackInto reads the decrypted archive: exactly the manifest, then the
// database, nothing else.
func unpackInto(r io.Reader, dir string) (*Manifest, error) {
	archive := tar.NewReader(r)

	header, err := archive.Next()
	if err != nil || header.Name != manifestName || header.Typeflag != tar.TypeReg || header.Size > maxManifestSize {
		return nil, ErrNotAnExport
	}
	manifestJSON, err := io.ReadAll(io.LimitReader(archive, maxManifestSize))
	if err != nil {
		return nil, ErrNotAnExport
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil || manifest.FormatVersion < 1 {
		return nil, ErrNotAnExport
	}
	// Checked before reading on: a newer file may contain things this SGC
	// does not know how to restore, and half a restore is worse than none.
	if manifest.FormatVersion > FormatVersion || manifest.SchemaVersion > store.SchemaVersion() {
		return nil, ErrNewerExport
	}

	header, err = archive.Next()
	if err != nil || header.Name != databaseName || header.Typeflag != tar.TypeReg {
		return nil, ErrNotAnExport
	}
	if header.Size > maxDatabaseSize {
		return nil, errors.New("the database in this export is larger than SGC accepts")
	}
	out, err := os.OpenFile(filepath.Join(dir, layout.DatabaseFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("prepare restore: %w", err)
	}
	_, copyErr := io.Copy(out, io.LimitReader(archive, maxDatabaseSize+1))
	if err := out.Close(); copyErr == nil {
		copyErr = err
	}
	if copyErr != nil {
		// Includes a file cut short or altered: age authenticates every
		// chunk and reports the damage here.
		return nil, ErrDamaged
	}

	if _, err := archive.Next(); err == nil {
		return nil, ErrNotAnExport // more entries than an export has
	} else if !errors.Is(err, io.EOF) {
		return nil, ErrDamaged
	}
	// The archive reader stops at the archive's end marker. Reading on to the
	// real end makes age verify its final chunk, which is what proves that
	// the file was not cut short.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return nil, ErrDamaged
	}
	return &manifest, nil
}

// checkStaged makes sure the staged database really is an SGC database that
// this version can run on, bringing its layout up to date in the process.
func checkStaged(ctx context.Context, dir string, manifest *Manifest) error {
	db, err := store.Open(ctx, filepath.Join(dir, layout.DatabaseFile))
	if err != nil {
		return fmt.Errorf("the database in this export cannot be used: %w", err)
	}
	defer db.Close()

	var result string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil || result != "ok" {
		return errors.New("the database in this export is damaged")
	}
	// What the preview shows comes from the database itself, not from the
	// manifest's claim about it.
	var username string
	err = db.QueryRowContext(ctx, "SELECT username FROM admin WHERE id = 1").Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("this export contains no admin account; there is nothing to restore")
	}
	if err != nil {
		return fmt.Errorf("the database in this export cannot be used: %w", err)
	}
	manifest.AdminUsername = username

	// Leave a single file behind, without write-ahead log side files.
	if _, err := db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("prepare restore: %w", err)
	}
	return nil
}

// Confirm marks the staged restore to be applied at SGC's next start.
func Confirm(stateDir string, manifest *Manifest) error {
	dir := stagingDir(stateDir)
	if _, err := os.Stat(filepath.Join(dir, layout.DatabaseFile)); err != nil {
		return errors.New("there is no restore waiting to be confirmed; upload the export again")
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, confirmedName), data, 0o600)
}

// DiscardStaged removes a staged restore that was not confirmed.
func DiscardStaged(stateDir string) {
	os.RemoveAll(stagingDir(stateDir))
}

// ApplyStaged puts a confirmed staged database in place of the current one.
// It must be called while the database is not open. It returns the restored
// export's manifest, or nil if there was nothing to apply. A staged restore
// that was never confirmed is thrown away.
func ApplyStaged(stateDir string) (*Manifest, error) {
	dir := stagingDir(stateDir)
	data, err := os.ReadFile(filepath.Join(dir, confirmedName))
	if errors.Is(err, os.ErrNotExist) {
		os.RemoveAll(dir)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read confirmed restore: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("read confirmed restore: %w", err)
	}

	current := filepath.Join(stateDir, layout.DatabaseFile)
	// The side files belong to the database being replaced; left behind,
	// SQLite would apply them to the restored one.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(current + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("replace the database: %w", err)
		}
	}
	// A rename within one folder: the database is either the old one or the
	// restored one, never something in between.
	if err := os.Rename(filepath.Join(dir, layout.DatabaseFile), current); err != nil {
		return nil, fmt.Errorf("replace the database: %w", err)
	}
	os.RemoveAll(dir)
	return &manifest, nil
}
