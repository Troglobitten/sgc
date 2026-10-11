package web

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/release"
	"github.com/Troglobitten/sgc/internal/update"
	"github.com/Troglobitten/sgc/internal/updater"
)

func TestUpdateEndpointsNeedASession(t *testing.T) {
	e := newTestEnv(t)
	install := updateInstallRequest{Version: "10.0.0", Confirm: true}

	e.expectStatus(e.call("GET", "/api/update", nil, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/update/check", struct{}{}, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/update/settings", updateSettingsRequest{}, nil), http.StatusUnauthorized)
	e.expectStatus(e.call("POST", "/api/update/install", install, nil), http.StatusUnauthorized)

	if len(e.updates.fetched) != 0 || len(e.helper.updates) != 0 {
		t.Error("an update was started without a session")
	}
}

func TestUpdateStatusCheckAndSettings(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	e.updates.status.Latest = "10.0.0"
	e.updates.status.UpdateAvailable = true
	e.lastUpdate = &updater.Status{ID: 7, State: updater.StateRolledBack, Message: "went back"}

	var got updateResponse
	e.expectStatus(e.call("GET", "/api/update", nil, &got), http.StatusOK)
	if got.Latest != "10.0.0" || !got.UpdateAvailable {
		t.Errorf("status = %+v", got)
	}
	if got.LastUpdate == nil || got.LastUpdate.State != updater.StateRolledBack {
		t.Errorf("last update outcome missing: %+v", got.LastUpdate)
	}
	if e.updates.checks != 0 {
		t.Error("reading the status contacted the update source")
	}

	e.expectStatus(e.call("POST", "/api/update/check", struct{}{}, &got), http.StatusOK)
	if e.updates.checks != 1 {
		t.Errorf("check ran %d times, want 1", e.updates.checks)
	}

	e.expectStatus(e.call("POST", "/api/update/settings", updateSettingsRequest{AutoCheck: false}, &got), http.StatusOK)
	if got.AutoCheck || e.updates.status.AutoCheck {
		t.Error("the daily check was not switched off")
	}
	var entries []audit.Entry
	e.call("GET", "/api/audit", nil, &entries)
	if entries[0].Action != audit.ActionSettingChanged || entries[0].Actor != testUser {
		t.Errorf("newest audit entry = %+v, want the setting change", entries[0])
	}
}

func TestInstallingAnUpdate(t *testing.T) {
	e := newTestEnv(t)
	e.signIn()
	install := updateInstallRequest{Version: "10.0.0", Confirm: true}
	newestAudit := func() audit.Entry {
		var entries []audit.Entry
		e.call("GET", "/api/audit", nil, &entries)
		return entries[0]
	}

	t.Run("needs confirmation and a real version", func(t *testing.T) {
		unconfirmed := updateInstallRequest{Version: "10.0.0"}
		notAVersion := updateInstallRequest{Version: "10.0.0; reboot", Confirm: true}
		e.expectStatus(e.call("POST", "/api/update/install", unconfirmed, nil), http.StatusBadRequest)
		e.expectStatus(e.call("POST", "/api/update/install", notAVersion, nil), http.StatusBadRequest)
		if len(e.updates.fetched) != 0 || len(e.helper.updates) != 0 {
			t.Error("something was downloaded or started for a refused request")
		}
	})

	t.Run("downloads first, then hands over to the helper", func(t *testing.T) {
		e.expectStatus(e.call("POST", "/api/update/install", install, nil), http.StatusAccepted)
		if len(e.updates.fetched) != 1 || e.updates.fetched[0] != "10.0.0" {
			t.Errorf("fetched = %v", e.updates.fetched)
		}
		if len(e.helper.updates) != 1 || e.helper.updates[0] != "10.0.0" {
			t.Errorf("helper asked to install %v", e.helper.updates)
		}
		if entry := newestAudit(); entry.Action != audit.ActionUpdateStarted || entry.Actor != testUser {
			t.Errorf("newest audit entry = %+v", entry)
		}
	})

	t.Run("a refused download never reaches the helper", func(t *testing.T) {
		before := len(e.helper.updates)
		for _, refusal := range []error{release.ErrBadSignature, release.ErrBadChecksum, errors.New("could not reach example.org")} {
			e.updates.fetchErr = refusal
			var body struct{ Error string }
			e.expectStatus(e.call("POST", "/api/update/install", install, &body), http.StatusBadGateway)
			if !strings.Contains(body.Error, "Nothing was changed") {
				t.Errorf("message does not reassure: %q", body.Error)
			}
			if entry := newestAudit(); entry.Action != audit.ActionUpdateFailed {
				t.Errorf("newest audit entry = %+v, want the failure", entry)
			}
		}
		e.updates.fetchErr = update.ErrNoUpdate
		e.expectStatus(e.call("POST", "/api/update/install", install, nil), http.StatusConflict)
		if len(e.helper.updates) != before {
			t.Error("the helper was asked to install a refused download")
		}
		e.updates.fetchErr = nil
	})

	t.Run("a helper failure is reported without internals", func(t *testing.T) {
		e.helper.updateErr = errors.New("dial unix /run/secret/path: connection refused")
		var body struct{ Error string }
		e.expectStatus(e.call("POST", "/api/update/install", install, &body), http.StatusBadGateway)
		if strings.Contains(body.Error, "/run/secret") {
			t.Errorf("internal detail leaked: %q", body.Error)
		}
	})
}
