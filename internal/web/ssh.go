package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/sshcontrol"
)

// SSH is what the interface can do with SSH keys and "keys only"
// (internal/sshcontrol).
type SSH interface {
	Status(ctx context.Context) (sshcontrol.Status, error)
	AddKey(ctx context.Context, actor, remote, label, pasted, account string) error
	RemoveKey(ctx context.Context, actor, remote string, id int64) error
	SetKeysOnly(ctx context.Context, actor, remote string, enabled bool) error
	Install(ctx context.Context, actor, remote, account string) error
	Undo(ctx context.Context, actor, remote string) error
}

// passwordAgain checks the admin's password although they are signed in. It
// is asked for before anything that an unattended browser must not be enough
// for: taking the export, and handing out a way to log in to the device. On
// failure it has written the answer and returns false.
func (s *Server) passwordAgain(w http.ResponseWriter, r *http.Request, password string) bool {
	err := s.Auth.VerifyAdminPassword(r.Context(), password, remoteIP(r))
	if err == nil {
		return true
	}
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
	return false
}

func (s *Server) writeSSHStatus(w http.ResponseWriter, r *http.Request, code int) {
	status, err := s.SSH.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, code, status)
}

func (s *Server) handleSSHStatus(w http.ResponseWriter, r *http.Request) {
	s.writeSSHStatus(w, r, http.StatusOK)
}

// sshResult answers a request that changed something about SSH, or explains
// why it did not.
func (s *Server) sshResult(w http.ResponseWriter, r *http.Request, err error) {
	var input *sshcontrol.InputError
	var failure *sshcontrol.ChangeError
	switch {
	case err == nil:
		s.writeSSHStatus(w, r, http.StatusOK)
	case errors.As(err, &input):
		writeError(w, http.StatusBadRequest, input.Message)
	case errors.Is(err, sshcontrol.ErrNoSuchKey):
		writeError(w, http.StatusNotFound, sentence(err))
	case errors.Is(err, sshcontrol.ErrDuplicate), errors.Is(err, sshcontrol.ErrNoChange),
		errors.Is(err, sshcontrol.ErrChangePending), errors.Is(err, sshcontrol.ErrNeedAccount),
		errors.Is(err, sshcontrol.ErrNoKeyLogin):
		writeError(w, http.StatusConflict, sentence(err))
	case errors.As(err, &failure):
		writeError(w, http.StatusBadGateway, failure.Message)
	default:
		s.internalError(w, r, err)
	}
}

type sshAddKeyRequest struct {
	Password string `json:"password"`
	Label    string `json:"label"`
	Key      string `json:"key"`
	Account  string `json:"account"`
}

// handleSSHAddKey installs a pasted public key. A key is a way to log in to
// the device itself, so the admin's password is asked for again.
func (s *Server) handleSSHAddKey(w http.ResponseWriter, r *http.Request) {
	var req sshAddKeyRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !s.passwordAgain(w, r, req.Password) {
		return
	}
	// The SSH server is asked to check and take up its configuration.
	extendDeadlines(w)
	s.sshResult(w, r, s.SSH.AddKey(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Label, req.Key, req.Account))
}

type sshInstallRequest struct {
	Password string `json:"password"`
	Account  string `json:"account"`
}

// handleSSHInstall puts the keys known from an export onto this device.
func (s *Server) handleSSHInstall(w http.ResponseWriter, r *http.Request) {
	var req sshInstallRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !s.passwordAgain(w, r, req.Password) {
		return
	}
	extendDeadlines(w)
	s.sshResult(w, r, s.SSH.Install(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Account))
}

type sshRemoveKeyRequest struct {
	ID int64 `json:"id"`
}

func (s *Server) handleSSHRemoveKey(w http.ResponseWriter, r *http.Request) {
	var req sshRemoveKeyRequest
	if !readJSON(w, r, &req) {
		return
	}
	extendDeadlines(w)
	s.sshResult(w, r, s.SSH.RemoveKey(r.Context(), sessionFrom(r).Username, remoteIP(r), req.ID))
}

type sshKeysOnlyRequest struct {
	Enabled bool `json:"enabled"`
}

// handleSSHKeysOnly switches "keys only" on or off. Switching it on takes
// effect at once and stays only if a login with a key is then seen; that is
// decided on the root side, not by anything this page sends.
func (s *Server) handleSSHKeysOnly(w http.ResponseWriter, r *http.Request) {
	var req sshKeysOnlyRequest
	if !readJSON(w, r, &req) {
		return
	}
	extendDeadlines(w)
	s.sshResult(w, r, s.SSH.SetKeysOnly(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Enabled))
}

func (s *Server) handleSSHUndo(w http.ResponseWriter, r *http.Request) {
	if err := s.SSH.Undo(r.Context(), sessionFrom(r).Username, remoteIP(r)); err != nil {
		s.Log.Error("undo SSH change", "error", err)
		writeError(w, http.StatusBadGateway, "The change could not be undone right now. SGC undoes it by itself when the time runs out.")
		return
	}
	s.writeSSHStatus(w, r, http.StatusOK)
}
