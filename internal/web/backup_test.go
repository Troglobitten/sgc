package web

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/backup"
)

const testPassphrase = "a passphrase for tests"

func TestExport(t *testing.T) {
	e := newTestEnv(t)

	t.Run("needs a session", func(t *testing.T) {
		body := exportRequest{Password: testPassword, Passphrase: testPassphrase}
		e.expectStatus(e.call("POST", "/api/export", body, nil), http.StatusUnauthorized)
	})

	e.signIn()

	t.Run("asks for the admin password again", func(t *testing.T) {
		var body struct{ Error string }
		wrong := exportRequest{Password: "not my password!", Passphrase: testPassphrase}
		resp := e.call("POST", "/api/export", wrong, &body)
		// Not 401: the interface would take that as "signed out".
		e.expectStatus(resp, http.StatusForbidden)
		if len(e.backups.exports) != 0 {
			t.Error("an export was made without the right password")
		}
		e.expectStatus(e.call("GET", "/api/health", nil, nil), http.StatusOK)
	})

	t.Run("refuses a weak passphrase", func(t *testing.T) {
		weak := exportRequest{Password: testPassword, Passphrase: "short"}
		e.expectStatus(e.call("POST", "/api/export", weak, nil), http.StatusBadRequest)
	})

	t.Run("sends the file as a download and records it", func(t *testing.T) {
		good := exportRequest{Password: testPassword, Passphrase: testPassphrase}
		data, _ := json.Marshal(good)
		req, _ := http.NewRequest("POST", e.url+"/api/export", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		content, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK || string(content) != "ENCRYPTED EXPORT" {
			t.Fatalf("status %d, body %q", resp.StatusCode, content)
		}
		disposition := resp.Header.Get("Content-Disposition")
		// The host name in the file name is cleaned: no path tricks, no spaces.
		if disposition != `attachment; filename=sgc-export-star-gate-x-2026-10-11.age` {
			t.Errorf("Content-Disposition = %q", disposition)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("Cache-Control = %q; an export must never be cached", resp.Header.Get("Cache-Control"))
		}
		if len(e.backups.exports) != 1 || e.backups.exports[0] != testPassphrase {
			t.Errorf("exports = %v", e.backups.exports)
		}

		var entries []audit.Entry
		e.call("GET", "/api/audit", nil, &entries)
		if entries[0].Action != audit.ActionExportCreated || entries[0].Actor != testUser {
			t.Errorf("newest audit entry = %+v", entries[0])
		}
		// Neither secret may end up in the log.
		for _, entry := range entries {
			if strings.Contains(entry.Detail, testPassphrase) || strings.Contains(entry.Detail, testPassword) {
				t.Errorf("a secret was written to the audit log: %+v", entry)
			}
		}
	})
}

// upload builds the form the interface sends for a restore preview.
func upload(t *testing.T, fields ...string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for i := 0; i+1 < len(fields); i += 2 {
		name, value := fields[i], fields[i+1]
		if name == "file" {
			part, _ := form.CreateFormFile("file", "export.age")
			part.Write([]byte(value))
		} else {
			form.WriteField(name, value)
		}
	}
	form.Close()
	return &body, form.FormDataContentType()
}

func (e *testEnv) preview(fields ...string) (*http.Response, []byte) {
	e.t.Helper()
	body, contentType := upload(e.t, fields...)
	req, _ := http.NewRequest("POST", e.url+"/api/setup/restore/preview", body)
	req.Header.Set("Content-Type", contentType)
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func TestRestoreOnAFreshInstall(t *testing.T) {
	e := newTestEnv(t)

	t.Run("needs the setup link", func(t *testing.T) {
		resp, _ := e.preview("token", "wrong", "passphrase", testPassphrase, "file", "FILE")
		e.expectStatus(resp, http.StatusForbidden)
		if len(e.backups.staged) != 0 {
			t.Error("a file was looked at without a valid setup link")
		}
		e.expectStatus(e.call("POST", "/api/setup/restore/confirm", restoreConfirmRequest{Token: "wrong"}, nil), http.StatusForbidden)
	})

	t.Run("confirming without a preview is refused", func(t *testing.T) {
		e.expectStatus(e.call("POST", "/api/setup/restore/confirm", restoreConfirmRequest{Token: e.setupToken}, nil), http.StatusConflict)
		if e.backups.startOvers != 0 {
			t.Error("SGC started over with nothing to restore")
		}
	})

	t.Run("a refused file says why and leaves nothing to confirm", func(t *testing.T) {
		for refusal, status := range map[error]int{
			backup.ErrWrongPassphrase: http.StatusForbidden,
			backup.ErrNotAnExport:     http.StatusBadRequest,
			backup.ErrDamaged:         http.StatusBadRequest,
			backup.ErrNewerExport:     http.StatusBadRequest,
		} {
			e.backups.stageErr = refusal
			resp, body := e.preview("token", e.setupToken, "passphrase", testPassphrase, "file", "FILE")
			e.expectStatus(resp, status)
			if !strings.Contains(strings.ToLower(string(body)), strings.ToLower(refusal.Error())) {
				t.Errorf("%v: answer %s does not say why", refusal, body)
			}
			e.expectStatus(e.call("POST", "/api/setup/restore/confirm", restoreConfirmRequest{Token: e.setupToken}, nil), http.StatusConflict)
		}
		e.backups.stageErr = nil
	})

	t.Run("a malformed upload is refused", func(t *testing.T) {
		// Fields in the wrong order: the link must be checked before the file is read.
		resp, _ := e.preview("file", "FILE", "token", e.setupToken, "passphrase", testPassphrase)
		e.expectStatus(resp, http.StatusBadRequest)
		resp, _ = e.preview("token", e.setupToken, "passphrase", testPassphrase)
		e.expectStatus(resp, http.StatusBadRequest)
		resp, _ = e.preview("token", e.setupToken, "passphrase", strings.Repeat("x", 5000), "file", "FILE")
		e.expectStatus(resp, http.StatusBadRequest)
		if len(e.backups.staged) != 0 {
			t.Errorf("a malformed upload was staged: %v", e.backups.staged)
		}
	})

	t.Run("preview, then confirm, then start over", func(t *testing.T) {
		resp, body := e.preview("token", e.setupToken, "passphrase", testPassphrase, "file", "THE FILE")
		e.expectStatus(resp, http.StatusOK)
		if !strings.Contains(string(body), `"adminUsername":"olduser"`) || !strings.Contains(string(body), `"hostname":"oldgate"`) {
			t.Errorf("preview = %s", body)
		}
		if len(e.backups.staged) != 1 || e.backups.staged[0] != "THE FILE|"+testPassphrase {
			t.Errorf("staged = %v", e.backups.staged)
		}
		// The preview must not have used up the link, or started anything.
		if e.backups.startOvers != 0 || len(e.backups.confirmed) != 0 {
			t.Error("the preview already restored something")
		}

		e.expectStatus(e.call("POST", "/api/setup/restore/confirm", restoreConfirmRequest{Token: e.setupToken}, nil), http.StatusAccepted)
		if len(e.backups.confirmed) != 1 || e.backups.confirmed[0].AdminUsername != "olduser" {
			t.Errorf("confirmed = %+v", e.backups.confirmed)
		}
		if e.backups.startOvers != 1 {
			t.Errorf("SGC started over %d times, want 1", e.backups.startOvers)
		}

		// One preview, one confirmation.
		e.expectStatus(e.call("POST", "/api/setup/restore/confirm", restoreConfirmRequest{Token: e.setupToken}, nil), http.StatusConflict)
	})
}

func TestRestoreIsOnlyForAFreshInstall(t *testing.T) {
	e := newTestEnv(t)
	e.signIn() // setup is done: an admin exists

	resp, _ := e.preview("token", e.setupToken, "passphrase", testPassphrase, "file", "FILE")
	e.expectStatus(resp, http.StatusConflict)
	e.expectStatus(e.call("POST", "/api/setup/restore/confirm", restoreConfirmRequest{Token: e.setupToken}, nil), http.StatusConflict)
	if len(e.backups.staged) != 0 || e.backups.startOvers != 0 {
		t.Error("a configured SGC accepted a restore through the setup link")
	}
}
