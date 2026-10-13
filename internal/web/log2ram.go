package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/Troglobitten/sgc/internal/logcontrol"
)

// MemoryLogs is what the interface can do about logs in memory, which is
// log2ram (internal/logcontrol).
type MemoryLogs interface {
	Status(ctx context.Context) (logcontrol.Status, error)
	SetEnabled(ctx context.Context, actor, remote string, enabled bool) error
}

func (s *Server) handleLog2ramStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Log2ram.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

type log2ramEnabledRequest struct {
	// A pointer, so that a request without the field is refused, not read as "off".
	Enabled *bool `json:"enabled"`
}

// handleLog2ramEnabled switches logs in memory on or off, which takes effect
// when the device restarts. On a device that does not have log2ram yet,
// switching on installs it from Debian first, which takes a while.
func (s *Server) handleLog2ramEnabled(w http.ResponseWriter, r *http.Request) {
	var req log2ramEnabledRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "the request does not say whether logs in memory is to be on or off")
		return
	}
	extendDeadlines(w)
	err := s.Log2ram.SetEnabled(r.Context(), sessionFrom(r).Username, remoteIP(r), *req.Enabled)
	var failure *logcontrol.ChangeError
	switch {
	case err == nil:
		s.handleLog2ramStatus(w, r)
	case errors.As(err, &failure):
		writeError(w, http.StatusBadGateway, failure.Message)
	default:
		s.internalError(w, r, err)
	}
}
