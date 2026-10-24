package web

import (
	"errors"
	"net/http"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
)

type accountPasswordRequest struct {
	Current string `json:"current"`
	Next    string `json:"next"`
}

// handleAccountPassword is the admin changing their own password: with the
// current one, after which every other sign-in ends (auth.ChangeAdminPassword).
// The browser it is done from stays signed in.
func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	var req accountPasswordRequest
	if !readJSON(w, r, &req) {
		return
	}
	session := sessionFrom(r)
	err := s.Auth.ChangeAdminPassword(r.Context(), req.Current, req.Next, remoteIP(r), session.Token)
	var locked *auth.TooManyAttemptsError
	switch {
	case err == nil:
	case errors.As(err, &locked):
		s.authError(w, r, err)
		return
	case errors.Is(err, auth.ErrWrongPassword):
		// Not 401: that would tell the interface the session has ended.
		writeError(w, http.StatusForbidden, "The current password is not right.")
		return
	case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrPasswordTooLong), errors.Is(err, auth.ErrSamePassword):
		writeError(w, http.StatusBadRequest, sentence(err))
		return
	default:
		s.internalError(w, r, err)
		return
	}
	s.record(r, session.Username, audit.ActionAdminPasswordChanged, "")
	writeJSON(w, http.StatusOK, struct{}{})
}
