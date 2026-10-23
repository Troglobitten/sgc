package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/Troglobitten/sgc/internal/backups"
	"github.com/Troglobitten/sgc/internal/eol"
)

// ScheduledBackups are the daily backups to another device (internal/backups).
type ScheduledBackups interface {
	Status(ctx context.Context) (backups.Status, error)
	SetSettings(ctx context.Context, actor, remote string, next backups.Settings) error
	NewKey(ctx context.Context, actor, remote string) (string, error)
	Test(ctx context.Context, t backups.Target) error
	BackUp(ctx context.Context, actor string) (backups.Run, error)
}

// EndOfLife says when the software SGC stands on runs out (internal/eol).
type EndOfLife interface {
	State(ctx context.Context) eol.State
	Check(ctx context.Context) eol.State
}

func (s *Server) handleBackupsStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.ScheduledBackups.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleBackupsSettings(w http.ResponseWriter, r *http.Request) {
	var req backups.Settings
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.ScheduledBackups.SetSettings(r.Context(), sessionFrom(r).Username, remoteIP(r), req); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleBackupsStatus(w, r)
}

type backupKeyResponse struct {
	Secret string `json:"secret"`
}

type passwordRequest struct {
	Password string `json:"password"`
}

// handleBackupsKey makes the backup key, after the admin's password, and
// shows its secret half this once.
func (s *Server) handleBackupsKey(w http.ResponseWriter, r *http.Request) {
	var req passwordRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Auth.VerifyAdminPassword(r.Context(), req.Password, remoteIP(r)); err != nil {
		s.authError(w, r, err)
		return
	}
	secret, err := s.ScheduledBackups.NewKey(r.Context(), sessionFrom(r).Username, remoteIP(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, backupKeyResponse{Secret: secret})
}

type backupTestResponse struct {
	OK bool `json:"ok"`
	// HostKey is the key an SFTP server showed that is not confirmed yet.
	HostKey string `json:"hostKey,omitempty"`
	Message string `json:"message,omitempty"`
}

func (s *Server) handleBackupsTest(w http.ResponseWriter, r *http.Request) {
	var req backups.Target
	if !readJSON(w, r, &req) {
		return
	}
	err := s.ScheduledBackups.Test(r.Context(), req)
	var unknown *backups.ErrUnknownHostKey
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, backupTestResponse{OK: true})
	case errors.As(err, &unknown):
		writeJSON(w, http.StatusOK, backupTestResponse{HostKey: unknown.Fingerprint,
			Message: "The server's key is " + unknown.Fingerprint + ". Compare it with the server's own (ssh-keygen -lf on it); if they are the same, confirm it."})
	default:
		writeJSON(w, http.StatusOK, backupTestResponse{Message: err.Error()})
	}
}

func (s *Server) handleBackupsRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.ScheduledBackups.BackUp(r.Context(), sessionFrom(r).Username)
	if err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleEOL(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.EndOfLife.State(r.Context()))
}

func (s *Server) handleEOLCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.EndOfLife.Check(r.Context()))
}

// ProxyUpdater installs the Traefik this SGC pins, where an older one is.
type ProxyUpdater interface {
	EnsureInstalled(ctx context.Context) error
}

func (s *Server) handleProxyUpdate(w http.ResponseWriter, r *http.Request) {
	updater, ok := s.Proxy.(ProxyUpdater)
	if !ok {
		writeError(w, http.StatusNotFound, "not available")
		return
	}
	if err := updater.EnsureInstalled(r.Context()); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleProxyStatus(w, r)
}
