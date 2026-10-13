package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/Troglobitten/sgc/internal/certcontrol"
)

// Certificates is what the interface can do about the certificate for the
// owner's domain (internal/certcontrol).
type Certificates interface {
	Status(ctx context.Context) (certcontrol.Status, error)
	Request(ctx context.Context, actor, remote string, agree bool) error
}

func (s *Server) handleCertificateStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Certificate.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

type certificateRequest struct {
	// AgreeToTerms is the owner's agreement to the certificate authority's
	// terms. It is theirs to give: the page asks, SGC never assumes it.
	AgreeToTerms bool `json:"agreeToTerms"`
}

// handleCertificateRequest starts getting the first certificate, or a
// renewal ahead of its time. It answers as soon as that has started; the
// state shows how it goes, which takes a few minutes.
func (s *Server) handleCertificateRequest(w http.ResponseWriter, r *http.Request) {
	var req certificateRequest
	if !readJSON(w, r, &req) {
		return
	}
	err := s.Certificate.Request(r.Context(), sessionFrom(r).Username, remoteIP(r), req.AgreeToTerms)
	var refusal *certcontrol.ChangeError
	switch {
	case err == nil:
		status, err := s.Certificate.Status(r.Context())
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		writeJSON(w, http.StatusAccepted, status)
	case errors.As(err, &refusal):
		writeError(w, http.StatusConflict, refusal.Message)
	default:
		s.internalError(w, r, err)
	}
}
