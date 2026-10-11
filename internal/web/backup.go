package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/backup"
)

// Backups is what the web process can do with export files.
type Backups interface {
	// Export writes an encrypted export of everything SGC holds to w.
	Export(ctx context.Context, w io.Writer, passphrase string) (*backup.Manifest, error)
	// Stage decrypts and checks an uploaded export and keeps it ready.
	Stage(ctx context.Context, r io.Reader, passphrase string) (*backup.Manifest, error)
	// Confirm marks the staged export to replace the database at the next start.
	Confirm(manifest *backup.Manifest) error
}

const (
	// An upload larger than this is not an SGC export.
	maxUploadSize = 600 * 1024 * 1024
	// Exporting and restoring turn a passphrase into a key, which is slow on
	// purpose, and may move a large file over a slow line.
	longRequest = 15 * time.Minute
)

// Characters of a host name that are safe inside a file name.
var unsafeInFileName = regexp.MustCompile(`[^a-zA-Z0-9-]+`)

type exportRequest struct {
	Password   string `json:"password"`
	Passphrase string `json:"passphrase"`
}

// handleExport sends the browser an encrypted export. The file contains
// everything, including the admin's login, so the admin's password is asked
// for again even though they are signed in: an unattended browser must not
// be enough to walk away with it.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	var req exportRequest
	if !readJSON(w, r, &req) {
		return
	}
	extendDeadlines(w)
	username := sessionFrom(r).Username

	if err := s.Auth.VerifyAdminPassword(r.Context(), req.Password, remoteIP(r)); err != nil {
		var locked *auth.TooManyAttemptsError
		switch {
		case errors.As(err, &locked):
			s.authError(w, r, err)
		case errors.Is(err, auth.ErrWrongPassword):
			// Not 401: that would tell the interface the session has ended.
			writeError(w, http.StatusForbidden, sentence(err))
		default:
			s.internalError(w, r, err)
		}
		return
	}

	// Written to a temporary file first, so that a failure can still be
	// reported properly instead of leaving the browser with half a download.
	file, err := os.CreateTemp("", "sgc-export-*")
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer os.Remove(file.Name())
	defer file.Close()

	manifest, err := s.Backups.Export(r.Context(), file, req.Passphrase)
	if err != nil {
		if errors.Is(err, backup.ErrWeakPassphrase) || errors.Is(err, backup.ErrPassphraseLength) {
			writeError(w, http.StatusBadRequest, sentence(err))
			return
		}
		s.internalError(w, r, err)
		return
	}
	size, err := file.Seek(0, io.SeekCurrent)
	if err == nil {
		_, err = file.Seek(0, io.SeekStart)
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.record(r, username, audit.ActionExportCreated, "")

	name := fmt.Sprintf("sgc-export-%s-%s.age",
		unsafeInFileName.ReplaceAllString(manifest.Hostname, "-"), manifest.CreatedAt.Format(time.DateOnly))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.Header().Set("Cache-Control", "no-store")
	io.Copy(w, file)
}

// --- Restoring on a fresh install --------------------------------------------
//
// Guarded by the one-time setup link, like creating the admin account: on a
// fresh install there is nobody to sign in as yet. Two steps, so the owner
// sees what the file contains before anything is replaced.

// handleRestorePreview takes the uploaded export (a form with the fields
// "token", "passphrase" and "file", in that order), decrypts and checks it,
// and answers with what it contains. Nothing is replaced yet.
func (s *Server) handleRestorePreview(w http.ResponseWriter, r *http.Request) {
	extendDeadlines(w)
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	form, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "the upload could not be read")
		return
	}
	token, ok := formField(w, form, "token")
	if !ok {
		return
	}
	passphrase, ok := formField(w, form, "passphrase")
	if !ok {
		return
	}
	// Checked before the file is even looked at.
	if err := s.Auth.CheckSetupToken(r.Context(), token, remoteIP(r)); err != nil {
		s.authError(w, r, err)
		return
	}
	file, err := form.NextPart()
	if err != nil || file.FormName() != "file" {
		writeError(w, http.StatusBadRequest, "the upload could not be read")
		return
	}

	manifest, err := s.Backups.Stage(r.Context(), file, passphrase)
	if err != nil {
		s.setPendingRestore(nil)
		switch {
		case errors.Is(err, backup.ErrWrongPassphrase):
			writeError(w, http.StatusForbidden, sentence(err))
		case errors.Is(err, backup.ErrNotAnExport), errors.Is(err, backup.ErrDamaged), errors.Is(err, backup.ErrNewerExport):
			writeError(w, http.StatusBadRequest, sentence(err))
		default:
			s.Log.Error("check uploaded export", "error", err)
			writeError(w, http.StatusBadRequest, "This file cannot be restored. Details are in the SGC log.")
		}
		return
	}
	s.setPendingRestore(manifest)
	writeJSON(w, http.StatusOK, manifest)
}

// formField reads the next part of an upload, which must be the small text
// field called name. On failure the error response has been written.
func formField(w http.ResponseWriter, form *multipart.Reader, name string) (string, bool) {
	part, err := form.NextPart()
	if err != nil || part.FormName() != name {
		writeError(w, http.StatusBadRequest, "the upload could not be read")
		return "", false
	}
	const maxFieldSize = 1024
	value, err := io.ReadAll(io.LimitReader(part, maxFieldSize+1))
	if err != nil || len(value) > maxFieldSize {
		writeError(w, http.StatusBadRequest, "the upload could not be read")
		return "", false
	}
	return string(value), true
}

type restoreConfirmRequest struct {
	Token string `json:"token"`
}

// handleRestoreConfirm makes the previewed export take over. SGC starts
// over on the restored database; the browser then finds the sign-in screen
// of the restored account.
func (s *Server) handleRestoreConfirm(w http.ResponseWriter, r *http.Request) {
	var req restoreConfirmRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Auth.CheckSetupToken(r.Context(), req.Token, remoteIP(r)); err != nil {
		s.authError(w, r, err)
		return
	}
	manifest := s.takePendingRestore()
	if manifest == nil {
		writeError(w, http.StatusConflict, "There is no restore waiting to be confirmed. Upload the export again.")
		return
	}
	if err := s.Backups.Confirm(manifest); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, struct{}{})
	// After the answer is on its way: starting over closes this connection.
	s.StartOver()
}

func (s *Server) setPendingRestore(manifest *backup.Manifest) {
	s.restoreMu.Lock()
	defer s.restoreMu.Unlock()
	s.pendingRestore = manifest
}

func (s *Server) takePendingRestore() *backup.Manifest {
	s.restoreMu.Lock()
	defer s.restoreMu.Unlock()
	manifest := s.pendingRestore
	s.pendingRestore = nil
	return manifest
}

func extendDeadlines(w http.ResponseWriter) {
	deadline := time.Now().Add(longRequest)
	controller := http.NewResponseController(w)
	controller.SetReadDeadline(deadline)
	controller.SetWriteDeadline(deadline)
}
