package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/Troglobitten/sgc/internal/maintenance"
)

// Maintenance is what the interface can do with the maintenance window
// (internal/maintenance).
type Maintenance interface {
	Status(ctx context.Context) (maintenance.Status, error)
	Set(ctx context.Context, actor, remote string, enabled bool, start, end string) error
	SetAutoUpdate(ctx context.Context, actor, remote string, enabled bool) error
}

func (s *Server) handleMaintenanceStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Maintenance.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// maintenanceResult answers a request that changed a setting, or says what
// was wrong with it.
func (s *Server) maintenanceResult(w http.ResponseWriter, r *http.Request, err error) {
	var input *maintenance.InputError
	switch {
	case err == nil:
		s.handleMaintenanceStatus(w, r)
	case errors.As(err, &input):
		writeError(w, http.StatusBadRequest, input.Message)
	default:
		s.internalError(w, r, err)
	}
}

type maintenanceRequest struct {
	// Pointers, so that a request that leaves something out is refused
	// instead of being read as "off" or as midnight.
	Enabled *bool   `json:"enabled"`
	Start   *string `json:"start"`
	End     *string `json:"end"`
}

func (s *Server) handleMaintenanceSet(w http.ResponseWriter, r *http.Request) {
	var req maintenanceRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil || req.Start == nil || req.End == nil {
		writeError(w, http.StatusBadRequest, "Say whether the window is on, and when it begins and ends.")
		return
	}
	s.maintenanceResult(w, r, s.Maintenance.Set(r.Context(), sessionFrom(r).Username, remoteIP(r), *req.Enabled, *req.Start, *req.End))
}

type maintenanceAutoUpdateRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) handleMaintenanceAutoUpdate(w http.ResponseWriter, r *http.Request) {
	var req maintenanceAutoUpdateRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "Say whether SGC's updates install by themselves.")
		return
	}
	s.maintenanceResult(w, r, s.Maintenance.SetAutoUpdate(r.Context(), sessionFrom(r).Username, remoteIP(r), *req.Enabled))
}
