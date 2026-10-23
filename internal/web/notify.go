package web

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Troglobitten/sgc/internal/journal"
	"github.com/Troglobitten/sgc/internal/notify"
)

// Notifications are the bell and the channels (internal/notify).
type Notifications interface {
	List(ctx context.Context, limit int) ([]notify.Notification, error)
	Summary(ctx context.Context) (notify.Summary, error)
	MarkRead(ctx context.Context) error
	Channels(ctx context.Context) (notify.Channels, bool, bool, error)
	SetChannels(ctx context.Context, actor, remote string, next notify.Channels) error
	Test(ctx context.Context, actor, remote, channel string) error
}

// Journal reads the logs of SGC's parts, through the helper.
type Journal interface {
	Logs(ctx context.Context, q journal.Query) (journal.Answer, error)
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.Notifications.List(r.Context(), limit)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleNotificationSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.Notifications.Summary(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleNotificationsRead(w http.ResponseWriter, r *http.Request) {
	if err := s.Notifications.MarkRead(r.Context()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.handleNotificationSummary(w, r)
}

type channelsResponse struct {
	Channels    notify.Channels `json:"channels"`
	HasPassword bool            `json:"hasPassword"`
	HasToken    bool            `json:"hasToken"`
	Events      any             `json:"events"`
}

func (s *Server) handleNotificationChannels(w http.ResponseWriter, r *http.Request) {
	channels, hasPassword, hasToken, err := s.Notifications.Channels(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, channelsResponse{Channels: channels, HasPassword: hasPassword, HasToken: hasToken, Events: notify.Events})
}

func (s *Server) handleNotificationChannelsSave(w http.ResponseWriter, r *http.Request) {
	var req notify.Channels
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Notifications.SetChannels(r.Context(), sessionFrom(r).Username, remoteIP(r), req); err != nil {
		s.problemError(w, r, err)
		return
	}
	s.handleNotificationChannels(w, r)
}

type testRequest struct {
	Channel string `json:"channel"`
}

func (s *Server) handleNotificationTest(w http.ResponseWriter, r *http.Request) {
	var req testRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Notifications.Test(r.Context(), sessionFrom(r).Username, remoteIP(r), req.Channel); err != nil {
		s.problemError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	var q journal.Query
	if !readJSON(w, r, &q) {
		return
	}
	if err := q.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "The query is not one SGC asks: "+err.Error()+".")
		return
	}
	answer, err := s.Journal.Logs(r.Context(), q)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, answer)
}
