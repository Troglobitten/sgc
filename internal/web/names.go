package web

import (
	"context"
	"net/http"

	"github.com/Troglobitten/sgc/internal/gateway"
	"github.com/Troglobitten/sgc/internal/problem"
)

// Names is the gateway's own name and the state of the names SGC keeps in
// AdGuard Home (internal/gateway, internal/dnsnames).
type Names interface {
	Status(ctx context.Context) (gateway.Status, error)
	SetName(ctx context.Context, actor, remote, name string) error
}

func (s *Server) handleNamesStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.Names.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

type gatewayNameRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleGatewayName(w http.ResponseWriter, r *http.Request) {
	var req gatewayNameRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Names.SetName(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Name); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleNamesStatus(w, r)
}

// problemError answers with the owner's words for a refusal
// (internal/problem), and as an internal error otherwise.
func (s *Server) problemError(w http.ResponseWriter, r *http.Request, err error) {
	if message, ok := problem.Message(err); ok {
		writeError(w, http.StatusBadRequest, message)
		return
	}
	s.internalError(w, r, err)
}
