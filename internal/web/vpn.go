package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/people"
	"github.com/Troglobitten/sgc/internal/vpncontrol"
)

// People are the people the owner lets in (internal/people).
type People interface {
	List(ctx context.Context) ([]people.Person, error)
	Add(ctx context.Context, actor, remote string, in people.Input) (people.Person, error)
	Update(ctx context.Context, actor, remote string, id int64, in people.Input) (people.Person, error)
	Remove(ctx context.Context, actor, remote string, id int64) error
	// For the login gate (gate.go).
	Login(ctx context.Context, username, password, remote, userAgent string) (*people.Session, error)
	// For SGC's login on a public service (gate_public.go).
	Verify(ctx context.Context, username, password, remote string) (*people.Person, error)
	Authenticate(ctx context.Context, token string) (*people.Person, error)
	Logout(ctx context.Context, token string) error
	ChangePassword(ctx context.Context, personID int64, old, next, remote, keepToken string) error
}

// VPN is the VPN with people's devices (internal/vpncontrol).
type VPN interface {
	Status(ctx context.Context) (vpncontrol.Status, error)
	SetSettings(ctx context.Context, actor, remote string, in vpncontrol.Settings, taken func(context.Context, string) (string, error)) error
	AddDevice(ctx context.Context, actor, remote string, personID int64, name string, allTraffic bool) (vpncontrol.Device, error)
	UpdateDevice(ctx context.Context, actor, remote string, id int64, name string, allTraffic, enabled bool) (vpncontrol.Device, error)
	RemoveDevice(ctx context.Context, actor, remote string, id int64) error
	DeviceConfig(ctx context.Context, actor, remote string, id int64, password string) (string, string, error)
	Usage(ctx context.Context, id int64, resolution string) ([]vpncontrol.UsagePoint, error)
	Totals(ctx context.Context) (map[int64]vpncontrol.UsagePoint, error)
	AllTrafficDevices(ctx context.Context, personID int64) ([]string, error)
}

// VPNEndpoint keeps the VPN's public name current (internal/vpncontrol).
type VPNEndpoint interface {
	Check(ctx context.Context) vpncontrol.EndpointState
	TakeOver(ctx context.Context) error
}

func (s *Server) handlePeople(w http.ResponseWriter, r *http.Request) {
	list, err := s.People.List(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handlePersonAdd(w http.ResponseWriter, r *http.Request) {
	var in people.Input
	if !readJSON(w, r, &in) {
		return
	}
	added, err := s.People.Add(r.Context(), sessionFrom(r).Username, remoteIP(r), in)
	if err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, added)
}

func (s *Server) handlePersonUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such person")
		return
	}
	var in people.Input
	if !readJSON(w, r, &in) {
		return
	}
	// "Services only" with a device that sends everything through home would
	// leave that device without internet (see vpncontrol.allTrafficRefused).
	if in.Network == people.NetworkServices && s.VPN != nil {
		names, err := s.VPN.AllTrafficDevices(r.Context(), id)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if len(names) > 0 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("These devices send all their traffic through home, which only people who reach the whole home network can: %s. Set them to home only first (each then needs its new settings: its QR code again).", strings.Join(names, ", ")))
			return
		}
	}
	updated, err := s.People.Update(r.Context(), sessionFrom(r).Username, remoteIP(r), id, in)
	if err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handlePersonRemove(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such person")
		return
	}
	if err := s.People.Remove(r.Context(), sessionFrom(r).Username, remoteIP(r), id); err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

type vpnResponse struct {
	vpncontrol.Status
	Totals map[string]vpncontrol.UsagePoint `json:"totals"`
}

func (s *Server) handleVPNStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.VPN.Status(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	totals, err := s.VPN.Totals(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := vpnResponse{Status: status, Totals: map[string]vpncontrol.UsagePoint{}}
	for id, t := range totals {
		out.Totals[strconv.FormatInt(id, 10)] = t
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleVPNSettings(w http.ResponseWriter, r *http.Request) {
	var in vpncontrol.Settings
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.VPN.SetSettings(r.Context(), sessionFrom(r).Username, remoteIP(r), in, s.labelTaken); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleVPNStatus(w, r)
}

// labelTaken says what already uses a label under the domain, for the
// VPN's name: the gateway, AdGuard Home's page, a service.
func (s *Server) labelTaken(ctx context.Context, label string) (string, error) {
	status, err := s.Names.Status(ctx)
	if err != nil {
		return "", err
	}
	if label == status.Name {
		return "SGC's page", nil
	}
	if label == "adguard" {
		return "AdGuard Home's page", nil
	}
	list, err := s.Services.List(ctx)
	if err != nil {
		return "", err
	}
	for _, svc := range list {
		if svc.Name == label {
			return "the service " + svc.Name, nil
		}
	}
	return "", nil
}

type deviceRequest struct {
	PersonID   int64  `json:"personId"`
	Name       string `json:"name"`
	AllTraffic bool   `json:"allTraffic"`
	Enabled    bool   `json:"enabled"`
}

func (s *Server) handleDeviceAdd(w http.ResponseWriter, r *http.Request) {
	var req deviceRequest
	if !readJSON(w, r, &req) {
		return
	}
	device, err := s.VPN.AddDevice(r.Context(), sessionFrom(r).Username, remoteIP(r), req.PersonID, req.Name, req.AllTraffic)
	if err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (s *Server) handleDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	var req deviceRequest
	if !readJSON(w, r, &req) {
		return
	}
	device, err := s.VPN.UpdateDevice(r.Context(), sessionFrom(r).Username, remoteIP(r), id, req.Name, req.AllTraffic, req.Enabled)
	if err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (s *Server) handleDeviceRemove(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	if err := s.VPN.RemoveDevice(r.Context(), sessionFrom(r).Username, remoteIP(r), id); err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

type deviceConfigRequest struct {
	Password string `json:"password"`
}

type deviceConfigResponse struct {
	Config   string `json:"config"`
	Filename string `json:"filename"`
}

// handleDeviceConfig shows a device's settings (with its private key),
// after the admin's password, for its QR code or file.
func (s *Server) handleDeviceConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	var req deviceConfigRequest
	if !readJSON(w, r, &req) {
		return
	}
	text, filename, err := s.VPN.DeviceConfig(r.Context(), sessionFrom(r).Username, remoteIP(r), id, req.Password)
	var locked *auth.TooManyAttemptsError
	switch {
	case errors.Is(err, auth.ErrWrongPassword):
		writeError(w, http.StatusForbidden, "That is not the admin's password.")
		return
	case errors.As(err, &locked):
		s.authError(w, r, err)
		return
	case err != nil:
		s.problemError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, deviceConfigResponse{Config: text, Filename: filename})
}

func (s *Server) handleVPNUsage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("device"), 10, 64)
	points, err := s.VPN.Usage(r.Context(), id, r.URL.Query().Get("resolution"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (s *Server) handleVPNEndpointCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.VPNEndpoint.Check(r.Context()))
}

func (s *Server) handleVPNEndpointTakeOver(w http.ResponseWriter, r *http.Request) {
	if err := s.VPNEndpoint.TakeOver(r.Context()); err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.VPNEndpoint.Check(r.Context()))
}
