package web

import (
	"context"
	"net/http"

	"github.com/Troglobitten/sgc/internal/guide"
)

// Guide is the guided setup's state (internal/guide).
type Guide interface {
	State(ctx context.Context) (guide.State, error)
	Save(ctx context.Context, state guide.State) error
	Start(ctx context.Context) error
}

func (s *Server) handleGuide(w http.ResponseWriter, r *http.Request) {
	state := guide.State{Skipped: []string{}}
	if s.Guide != nil {
		var err error
		if state, err = s.Guide.State(r.Context()); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleGuideSave(w http.ResponseWriter, r *http.Request) {
	var req guide.State
	if !readJSON(w, r, &req) {
		return
	}
	if s.Guide == nil {
		writeError(w, http.StatusNotFound, "there is no guided setup here")
		return
	}
	if err := s.Guide.Save(r.Context(), req); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleGuide(w, r)
}
