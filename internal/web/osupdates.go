package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/Troglobitten/sgc/internal/oscontrol"
)

// OSUpdates is what the interface can do about updates for the device:
// Debian's packages, not SGC itself (internal/oscontrol).
type OSUpdates interface {
	Status(ctx context.Context) (oscontrol.Status, error)
	SetMode(ctx context.Context, actor, remote string, automatic bool) error
	Check(ctx context.Context) error
	Install(ctx context.Context, actor, remote string) error
	// Installing reports whether an installation is at work right now.
	Installing() bool
}

func (s *Server) writeOSUpdatesStatus(w http.ResponseWriter, r *http.Request, code int) {
	status, err := s.OSUpdates.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, code, status)
}

func (s *Server) handleOSUpdatesStatus(w http.ResponseWriter, r *http.Request) {
	s.writeOSUpdatesStatus(w, r, http.StatusOK)
}

// osUpdatesResult answers a request about the device's updates, or explains
// why it was not carried out. started is the status for "it has begun".
func (s *Server) osUpdatesResult(w http.ResponseWriter, r *http.Request, started int, err error) {
	var failure *oscontrol.ChangeError
	switch {
	case err == nil:
		s.writeOSUpdatesStatus(w, r, started)
	case errors.Is(err, oscontrol.ErrBusy), errors.Is(err, oscontrol.ErrNotSetUp):
		writeError(w, http.StatusConflict, sentence(err))
	case errors.As(err, &failure):
		writeError(w, http.StatusBadGateway, failure.Message)
	default:
		s.internalError(w, r, err)
	}
}

type osUpdatesModeRequest struct {
	// A pointer, so that a request without the field is not read as "by hand".
	Automatic *bool `json:"automatic"`
}

// handleOSUpdatesMode sets the device up: updates install by themselves, or
// when the owner starts them here.
func (s *Server) handleOSUpdatesMode(w http.ResponseWriter, r *http.Request) {
	var req osUpdatesModeRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Automatic == nil {
		writeError(w, http.StatusBadRequest, "Say whether updates install by themselves.")
		return
	}
	// The first time, on a device without Debian's update tool, this
	// includes fetching and installing it.
	extendDeadlines(w)
	s.osUpdatesResult(w, r, http.StatusOK, s.OSUpdates.SetMode(r.Context(), sessionFrom(r).Username, remoteIP(r), *req.Automatic))
}

// handleOSUpdatesCheck starts a look for updates. The answer says that it
// has started; the interface then asks for the state until it has ended.
func (s *Server) handleOSUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	s.osUpdatesResult(w, r, http.StatusAccepted, s.OSUpdates.Check(r.Context()))
}

// handleOSUpdatesInstall starts the installation of what is waiting.
func (s *Server) handleOSUpdatesInstall(w http.ResponseWriter, r *http.Request) {
	s.osUpdatesResult(w, r, http.StatusAccepted, s.OSUpdates.Install(r.Context(), sessionFrom(r).Username, remoteIP(r)))
}
