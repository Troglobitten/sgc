package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/Troglobitten/sgc/internal/dnsprovider"
	"github.com/Troglobitten/sgc/internal/domaincontrol"
)

// Domain is what the interface can do about the owner's domain and the
// account at the provider that holds its DNS (internal/domaincontrol).
type Domain interface {
	Status(ctx context.Context) (domaincontrol.Status, error)
	Save(ctx context.Context, actor, remote, domain, provider string, values map[string]string) error
	Remove(ctx context.Context, actor, remote string) error
	CheckNow(ctx context.Context) (domaincontrol.Status, error)
}

// domainAnswer is the state with the providers SGC knows, for the form.
type domainAnswer struct {
	domaincontrol.Status
	Kinds []dnsprovider.Kind `json:"kinds"`
}

func (s *Server) writeDomain(w http.ResponseWriter, status domaincontrol.Status) {
	writeJSON(w, http.StatusOK, domainAnswer{Status: status, Kinds: dnsprovider.Kinds()})
}

func (s *Server) handleDomainStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Domain.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.writeDomain(w, status)
}

// domainRequest carries the credentials towards SGC. Nothing carries them
// back. Username and APIKey are the request of a page from before 0.18.0
// (Zone.eu only), which a browser may still have open during an update.
type domainRequest struct {
	Domain   string            `json:"domain"`
	Provider string            `json:"provider"`
	Values   map[string]string `json:"values"`
	Username string            `json:"username"`
	APIKey   string            `json:"apiKey"`
}

// handleDomainSave keeps a domain and an account, after the provider has
// said that they belong together.
func (s *Server) handleDomainSave(w http.ResponseWriter, r *http.Request) {
	var req domainRequest
	if !readJSON(w, r, &req) {
		return
	}
	switch {
	case req.Provider == "" && req.Values == nil && (req.Username != "" || req.APIKey != ""):
		req.Provider, req.Values = dnsprovider.ZoneID, map[string]string{"username": req.Username, "apiKey": req.APIKey}
	case req.Username != "" || req.APIKey != "":
		writeError(w, http.StatusBadRequest, "the request has both kinds of credentials")
		return
	}
	err := s.Domain.Save(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Domain, req.Provider, req.Values)
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

// handleDomainCheck asks the provider now instead of at the next regular
// time.
func (s *Server) handleDomainCheck(w http.ResponseWriter, r *http.Request) {
	status, err := s.Domain.CheckNow(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.writeDomain(w, status)
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
