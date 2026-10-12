package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/fwcontrol"
)

// Firewall is what the interface can do with the firewall (internal/fwcontrol).
type Firewall interface {
	Status(ctx context.Context) (fwcontrol.Status, error)
	Change(ctx context.Context, actor, remoteAddr string, enabled, again bool) error
	Confirm(ctx context.Context, actor, remoteAddr string) error
	Undo(ctx context.Context, actor, remoteAddr string) error
}

// reconnectHeader marks an answer that says: not over this connection, open
// a new one and ask again.
const reconnectHeader = "X-SGC-Reconnect"

type connAcceptedKey struct{}

// ConnContext notes when each connection was accepted. Set it as the
// http.Server's ConnContext.
//
// It is what makes a firewall confirmation mean something. A firewall lets
// connections that already exist carry on, whatever its new rules say. A
// browser that confirms over the connection it had before the change has
// therefore proven nothing: it might be unable to connect ever again. Only a
// connection accepted after the change shows that the owner can still get in.
func ConnContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connAcceptedKey{}, time.Now())
}

// arrivedAfterChange reports whether the request came over a connection that
// was accepted after the last firewall change this process made.
func (s *Server) arrivedAfterChange(r *http.Request) bool {
	s.firewallMu.Lock()
	changedAt := s.firewallChangedAt
	s.firewallMu.Unlock()
	if changedAt.IsZero() {
		// This process has made no change. If one is waiting, it was made
		// before this process started, so every connection it has is newer.
		return true
	}
	acceptedAt, ok := r.Context().Value(connAcceptedKey{}).(time.Time)
	return ok && acceptedAt.After(changedAt)
}

type firewallClient struct {
	Address string `json:"address"`
	// Inside: would the firewall let this browser in?
	Inside bool `json:"inside"`
}

type firewallResponse struct {
	fwcontrol.Status
	Client firewallClient `json:"client"`
}

func clientOf(r *http.Request) firewallClient {
	client := firewallClient{Address: remoteIP(r)}
	if addr, err := netip.ParseAddr(client.Address); err == nil {
		client.Inside = firewall.IsInside(addr)
	}
	return client
}

func (s *Server) writeFirewallStatus(w http.ResponseWriter, r *http.Request, code int) {
	status, err := s.Firewall.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, code, firewallResponse{Status: status, Client: clientOf(r)})
}

func (s *Server) handleFirewallStatus(w http.ResponseWriter, r *http.Request) {
	s.writeFirewallStatus(w, r, http.StatusOK)
}

type firewallChangeRequest struct {
	Enabled bool `json:"enabled"`
	// Again: make the rules afresh although the firewall is on already
	// (after AdGuard Home was installed, so that DNS is let in).
	Again bool `json:"again"`
}

// handleFirewallChange switches the firewall on or off. The change takes
// effect at once and is undone by itself unless it is confirmed.
func (s *Server) handleFirewallChange(w http.ResponseWriter, r *http.Request) {
	var req firewallChangeRequest
	if !readJSON(w, r, &req) {
		return
	}
	client := clientOf(r)
	if req.Enabled && !client.Inside {
		// It would be undone again after a minute, but there is no point in
		// cutting the owner off for that minute when the outcome is known.
		writeError(w, http.StatusConflict, "You are connecting from "+client.Address+
			", which is not a home-network address. With the firewall on, SGC would stop answering you, so it was not switched on. "+
			"Open SGC by its home-network address and try again.")
		return
	}

	// The first time, the firewall software is installed first.
	extendDeadlines(w)
	err := s.Firewall.Change(r.Context(), sessionFrom(r).Username, client.Address, req.Enabled, req.Again)
	var failure *fwcontrol.ChangeError
	switch {
	case err == nil:
	case errors.Is(err, fwcontrol.ErrChangePending), errors.Is(err, fwcontrol.ErrNoChange):
		writeError(w, http.StatusConflict, sentence(err))
		return
	case errors.As(err, &failure):
		writeError(w, http.StatusBadGateway, failure.Message)
		return
	default:
		s.internalError(w, r, err)
		return
	}

	s.firewallMu.Lock()
	s.firewallChangedAt = time.Now()
	s.firewallMu.Unlock()
	// This connection predates the change. Closing it makes the browser
	// open a new one for what it does next, and that one has to get past
	// the new rules.
	w.Header().Set("Connection", "close")
	s.writeFirewallStatus(w, r, http.StatusAccepted)
}

func (s *Server) handleFirewallConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.arrivedAfterChange(r) {
		w.Header().Set("Connection", "close")
		w.Header().Set(reconnectHeader, "1")
		writeError(w, http.StatusConflict, "Confirming needs a new connection to SGC. Try again.")
		return
	}
	err := s.Firewall.Confirm(r.Context(), sessionFrom(r).Username, remoteIP(r))
	switch {
	case err == nil:
		s.writeFirewallStatus(w, r, http.StatusOK)
	case errors.Is(err, fwcontrol.ErrTooLate):
		writeError(w, http.StatusConflict, sentence(err))
	default:
		s.internalError(w, r, err)
	}
}

func (s *Server) handleFirewallUndo(w http.ResponseWriter, r *http.Request) {
	if err := s.Firewall.Undo(r.Context(), sessionFrom(r).Username, remoteIP(r)); err != nil {
		s.Log.Error("undo firewall change", "error", err)
		writeError(w, http.StatusBadGateway, "The change could not be undone right now. SGC undoes it by itself when the time to confirm runs out.")
		return
	}
	s.writeFirewallStatus(w, r, http.StatusOK)
}
