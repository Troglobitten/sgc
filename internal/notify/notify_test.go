package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/store"
)

type sent struct {
	mu    sync.Mutex
	mails []string
	ntfy  []map[string]any
	auth  []string
}

func setup(t *testing.T) (*Service, *sent, string) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	got := &sent{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		got.mu.Lock()
		got.ntfy = append(got.ntfy, body)
		got.auth = append(got.auth, r.Header.Get("Authorization"))
		got.mu.Unlock()
	}))
	t.Cleanup(server.Close)
	s := New(Config{DB: db, Audit: audit.New(db), Hostname: "old-gateway", HTTP: server.Client(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mail: func(_ context.Context, e Email, subject, body string) error {
			got.mu.Lock()
			got.mails = append(got.mails, e.To+": "+subject)
			got.mu.Unlock()
			return nil
		}})
	return s, got, server.URL
}

func TestWhereNotificationsGo(t *testing.T) {
	s, got, ntfyURL := setup(t)
	ctx := context.Background()
	err := s.SetChannels(ctx, "alex", "", Channels{
		Email:  Email{Enabled: true, Host: "smtp.example.com", Port: 587, Security: "starttls", Username: "alex", Password: "a-made-up-password", From: "sgc@example.com", To: "alex@example.com"},
		Ntfy:   Ntfy{Enabled: true, Server: ntfyURL, Topic: "sgc-made-up-topic", Token: "tk_madeup"},
		Routes: map[string]Route{EventAnnounce: {Email: false, Ntfy: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Notify(ctx, EventServiceDown, Warning, "nas does not answer", "…")
	s.Notify(ctx, EventUpdates, Info, "SGC 9.9.9 is available", "…")
	s.Notify(ctx, EventAnnounce, Warning, "A new service was announced", "…")
	s.Wait()
	if len(got.mails) != 1 || !strings.Contains(got.mails[0], "[old-gateway] nas does not answer") {
		t.Errorf("mails: %v", got.mails)
	}
	if len(got.ntfy) != 2 || got.ntfy[0]["topic"] != "sgc-made-up-topic" || got.auth[0] != "Bearer tk_madeup" {
		t.Errorf("ntfy: %v %v", got.ntfy, got.auth)
	}
	// The secrets never come back.
	c, hasPassword, hasToken, _ := s.Channels(ctx)
	if c.Email.Password != "" || c.Ntfy.Token != "" || !hasPassword || !hasToken {
		t.Errorf("channels shown: %+v", c)
	}
	// Saving without them keeps them.
	c.Ntfy.Topic = "another-made-up-topic"
	if err := s.SetChannels(ctx, "alex", "", c); err != nil {
		t.Fatal(err)
	}
	if kept, _ := s.channels(ctx); kept.Email.Password != "a-made-up-password" || kept.Ntfy.Token != "tk_madeup" {
		t.Error("saving without the secrets lost them")
	}
}

func TestBadChannelsAreRefused(t *testing.T) {
	s, _, _ := setup(t)
	for name, c := range map[string]Channels{
		"no host":      {Email: Email{Enabled: true, Port: 587, Security: "starttls", From: "a@b.c", To: "d@e.f"}},
		"no recipient": {Email: Email{Enabled: true, Host: "smtp.example.com", Port: 587, Security: "starttls", From: "a@b.c"}},
		"a header":     {Email: Email{Enabled: true, Host: "smtp.example.com", Port: 587, Security: "starttls", From: "a@b.c", To: "d@e.f\r\nBcc: x@y.z"}},
		"a bad topic":  {Ntfy: Ntfy{Enabled: true, Server: "https://ntfy.sh", Topic: "a topic/with things"}},
		"a bad server": {Ntfy: Ntfy{Enabled: true, Server: "ftp://ntfy.sh", Topic: "topic"}},
	} {
		if err := s.SetChannels(context.Background(), "alex", "", c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProblemsThatLast(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	present := true
	conditions := map[string]Condition{"core": func(context.Context) ([]Finding, error) {
		if present {
			return []Finding{{Key: "dns", Event: EventCoreDown, Severity: Problem, Title: "DNS is not running"}}, nil
		}
		return nil, nil
	}}
	for range 3 {
		s.look(ctx, "core", conditions["core"])
	}
	summary, _ := s.Summary(ctx)
	if len(summary.Banners) != 1 || summary.Unread != 1 {
		t.Fatalf("raised more than once, or not at all: %+v", summary)
	}
	present = false
	s.look(ctx, "core", conditions["core"])
	summary, _ = s.Summary(ctx)
	if len(summary.Banners) != 0 {
		t.Errorf("not resolved: %+v", summary)
	}
	list, _ := s.List(ctx, 10)
	if len(list) != 2 || list[0].Title != "Resolved" || list[1].ResolvedAt == nil {
		t.Errorf("history: %+v", list)
	}
	s.MarkRead(ctx)
	if summary, _ := s.Summary(ctx); summary.Unread != 0 {
		t.Error("still unread")
	}
}

func TestAMessage(t *testing.T) {
	m := Message("sgc@example.com", "alex@example.com", "Ä certificate\r\nBcc: evil@example.com", "line one\n.\nline three", time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	if strings.Contains(m, "\r\nBcc:") {
		t.Errorf("a header got into the subject:\n%s", m)
	}
	if !strings.Contains(m, "Subject: =?utf-8?q?") || !strings.Contains(m, "Date: Fri, 23 Oct 2026") {
		t.Errorf("headers:\n%s", m)
	}
}
