package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/Troglobitten/sgc/internal/domaincontrol"
)

// Domain is what the interface can do about the owner's domain and the
// Zone.eu account that holds its DNS (internal/domaincontrol).
type Domain interface {
	Status(ctx context.Context) (domaincontrol.Status, error)
	Save(ctx context.Context, actor, remote, domain, username, apiKey string) error
	Remove(ctx context.Context, actor, remote string) error
	CheckNow(ctx context.Context) (domaincontrol.Status, error)
}

func (s *Server) handleDomainStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Domain.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// domainRequest carries the API key towards SGC. Nothing carries it back.
type domainRequest struct {
	Domain   string `json:"domain"`
	Username string `json:"username"`
	APIKey   string `json:"apiKey"`
}

// handleDomainSave keeps a domain and a Zone.eu account, after Zone.eu has
// said that they belong together.
func (s *Server) handleDomainSave(w http.ResponseWriter, r *http.Request) {
	var req domainRequest
	if !readJSON(w, r, &req) {
		return
	}
	err := s.Domain.Save(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Domain, req.Username, req.APIKey)
	var failure *domaincontrol.ChangeError
	switch {
	case err == nil:
		s.handleDomainStatus(w, r)
	case errors.As(err, &failure):
		writeError(w, http.StatusBadRequest, failure.Message)
	default:
		s.internalError(w, r, err)
	}
}

// handleDomainCheck asks Zone.eu now instead of at the next regular time.
func (s *Server) handleDomainCheck(w http.ResponseWriter, r *http.Request) {
	status, err := s.Domain.CheckNow(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

type domainRemoveRequest struct {
	Confirm bool `json:"confirm"`
}

func (s *Server) handleDomainRemove(w http.ResponseWriter, r *http.Request) {
	var req domainRemoveRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "removing the domain needs confirmation")
		return
	}
	if err := s.Domain.Remove(r.Context(), sessionFrom(r).Username, remoteIP(r)); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.handleDomainStatus(w, r)
}
