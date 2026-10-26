package web

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Troglobitten/sgc/internal/public"
	"github.com/Troglobitten/sgc/internal/publiccontrol"
)

// Public is internet access (internal/publiccontrol).
type Public interface {
	Status(ctx context.Context) (publiccontrol.Status, error)
	SetEnabled(ctx context.Context, actor, remote string, on bool) error
	SetSettings(ctx context.Context, actor, remote string, s publiccontrol.Settings) error
	SetServicePublic(ctx context.Context, actor, remote string, id int64, open bool) error
	Bans(ctx context.Context) ([]public.Ban, error)
	Unban(ctx context.Context, actor, remote, address string) error
}

func (s *Server) handlePublicStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Public.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

type publicEnabledRequest struct {
	Enabled bool `json:"enabled"`
	// Password: switching on asks for the admin's password again.
	Password string `json:"password"`
}

func (s *Server) handlePublicEnabled(w http.ResponseWriter, r *http.Request) {
	var req publicEnabledRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Enabled && !s.passwordAgain(w, r, req.Password) {
		return
	}
	if err := s.Public.SetEnabled(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Enabled); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handlePublicStatus(w, r)
}

func (s *Server) handlePublicSettings(w http.ResponseWriter, r *http.Request) {
	var req publiccontrol.Settings
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Public.SetSettings(r.Context(), sessionFrom(r).Username, remoteIP(r), req); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handlePublicStatus(w, r)
}

type servicePublicRequest struct {
	Public bool `json:"public"`
	// Password: opening asks for the admin's password again; closing never
	// does, it must always be quick.
	Password string `json:"password"`
}

func (s *Server) handleServicePublic(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "That service does not exist.")
		return
	}
	var req servicePublicRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Public && !s.passwordAgain(w, r, req.Password) {
		return
	}
	if err := s.Public.SetServicePublic(r.Context(), sessionFrom(r).Username, remoteIP(r), id, req.Public); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleServices(w, r)
}

func (s *Server) handlePublicBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.Public.Bans(r.Context())
	if err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, bans)
}

type unbanRequest struct {
	Address string `json:"address"`
}

func (s *Server) handlePublicUnban(w http.ResponseWriter, r *http.Request) {
	var req unbanRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Public.Unban(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Address); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handlePublicBans(w, r)
}
