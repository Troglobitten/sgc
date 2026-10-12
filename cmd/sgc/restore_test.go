package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/fwcontrol"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

// instance is one running `sgc serve` with its own state folder, driven the
// way a browser would.
type instance struct {
	t        *testing.T
	stateDir string
	out      *syncBuffer
	client   *http.Client
}

func startInstance(t *testing.T) *instance {
	t.Helper()
	stateDir := t.TempDir()
	// What the root side would keep (the updater's outcome, the firewall's
	// state) is pointed inside the test's own folder, so nothing on the
	// machine running the test is read.
	_, out, _ := startServe(t, "--state-dir", stateDir, "--update-work-dir", stateDir+"/update-work",
		"--firewall-file", stateDir+"/firewall/firewall.nft", "--firewall-run-dir", stateDir+"/firewall/run")
	jar, _ := cookiejar.New(nil)
	return &instance{
		t: t, stateDir: stateDir, out: out,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			// SGC's own self-signed certificate, on this machine.
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

// address is where the instance is listening now. After starting over on a
// restored database it listens on a new port, so the newest line counts.
func (i *instance) address() string {
	matches := regexp.MustCompile(`listening on (\S+)`).FindAllStringSubmatch(i.out.String(), -1)
	if len(matches) == 0 {
		i.t.Fatal("the instance never started listening")
	}
	return "https://" + matches[len(matches)-1][1]
}

func (i *instance) setupToken() string {
	i.t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"setup-link", "--state-dir", i.stateDir}, &stdout, &stderr); code != exitOK {
		i.t.Fatalf("setup-link failed: %s%s", stdout.String(), stderr.String())
	}
	m := regexp.MustCompile(`/setup#(\S+)`).FindStringSubmatch(stdout.String())
	if m == nil {
		i.t.Fatalf("no setup link in: %s", stdout.String())
	}
	return m[1]
}

func (i *instance) postJSON(path string, body any) (*http.Response, []byte) {
	i.t.Helper()
	data, _ := json.Marshal(body)
	resp, err := i.client.Post(i.address()+path, "application/json", bytes.NewReader(data))
	if err != nil {
		i.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	content, _ := io.ReadAll(resp.Body)
	return resp, content
}

func (i *instance) getJSON(path string, out any) int {
	i.t.Helper()
	resp, err := i.client.Get(i.address() + path)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

// The promise of this milestone, end to end with the real programs: export
// from one SGC, restore into a fresh one, and the fresh one is the old one.
func TestExportFromOneInstallRestoresIntoAFreshOne(t *testing.T) {
	const (
		username   = "alex"
		password   = "correct horse battery"
		passphrase = "a passphrase for the export"
	)

	// --- The old gateway: set up, change a setting, export. -----------------
	old := startInstance(t)
	if resp, body := old.postJSON("/api/setup", map[string]string{
		"token": old.setupToken(), "username": username, "password": password,
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("setup: %d %s", resp.StatusCode, body)
	}
	if resp, body := old.postJSON("/api/update/settings", map[string]bool{"autoCheck": false}); resp.StatusCode != http.StatusOK {
		t.Fatalf("change setting: %d %s", resp.StatusCode, body)
	}
	// As if the owner had switched the firewall on there. Doing that for
	// real takes root and a firewall; what an export carries of it is the
	// owner's wish, which SGC keeps as a setting.
	oldDB, err := store.Open(context.Background(), filepath.Join(old.stateDir, layout.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), oldDB, fwcontrol.SettingEnabled, "true"); err != nil {
		t.Fatal(err)
	}
	oldDB.Close()

	resp, exportFile := old.postJSON("/api/export", map[string]string{"password": password, "passphrase": passphrase})
	if resp.StatusCode != http.StatusOK || !bytes.HasPrefix(exportFile, []byte("age-encryption.org/v1\n")) {
		t.Fatalf("export: status %d, %d bytes", resp.StatusCode, len(exportFile))
	}
	if bytes.Contains(exportFile, []byte(username)) {
		t.Error("the export contains readable account data")
	}

	// --- A fresh gateway: restore through the setup link. -------------------
	fresh := startInstance(t)
	token := fresh.setupToken()

	preview := func(pass string) (*http.Response, []byte) {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		form.WriteField("token", token)
		form.WriteField("passphrase", pass)
		part, _ := form.CreateFormFile("file", "export.age")
		part.Write(exportFile)
		form.Close()
		resp, err := fresh.client.Post(fresh.address()+"/api/setup/restore/preview", form.FormDataContentType(), &body)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		content, _ := io.ReadAll(resp.Body)
		return resp, content
	}

	if resp, body := preview("not the passphrase at all"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong passphrase: %d %s", resp.StatusCode, body)
	}
	resp, body := preview(passphrase)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"adminUsername":"alex"`) {
		t.Fatalf("preview: %d %s", resp.StatusCode, body)
	}
	// Previewing changes nothing: the fresh gateway still asks for setup.
	var state struct{ SetupRequired bool }
	if fresh.getJSON("/api/state", &state); !state.SetupRequired {
		t.Fatal("the preview alone already ended setup")
	}

	if resp, body := fresh.postJSON("/api/setup/restore/confirm", map[string]string{"token": token}); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("confirm: %d %s", resp.StatusCode, body)
	}

	// SGC starts over on the restored database.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if fresh.getJSON("/api/state", &state) == http.StatusOK && !state.SetupRequired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fresh gateway never came back restored:\n%s", fresh.out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	// --- The fresh gateway is now the old one. ------------------------------
	if resp, body := fresh.postJSON("/api/login", map[string]string{"username": username, "password": password}); resp.StatusCode != http.StatusOK {
		t.Fatalf("signing in with the old account on the restored gateway: %d %s", resp.StatusCode, body)
	}
	var update struct{ AutoCheck bool }
	if fresh.getJSON("/api/update", &update) != http.StatusOK || update.AutoCheck {
		t.Errorf("the changed setting did not survive: autoCheck = %v", update.AutoCheck)
	}
	// The firewall is known to have been on, and is not switched on unasked:
	// this is another machine, and that step needs the owner's confirmation.
	var fw struct {
		State  string
		Wanted bool
	}
	if fresh.getJSON("/api/firewall", &fw) != http.StatusOK || !fw.Wanted || fw.State != "off" {
		t.Errorf("the firewall after the restore: %+v, want it wanted and off", fw)
	}
	var history []struct{ Actor, Action, Detail string }
	fresh.getJSON("/api/audit", &history)
	seen := map[string]bool{}
	for _, entry := range history {
		seen[entry.Action] = true
	}
	for _, action := range []string{"setup.completed", "setting.changed", "restore.completed"} {
		if !seen[action] {
			t.Errorf("the restored history is missing %q: %+v", action, history)
		}
	}
	// The export itself is recorded where it was made. (It cannot be inside
	// the file: the file is a copy taken a moment before the record exists.)
	var oldHistory []struct{ Action string }
	old.getJSON("/api/audit", &oldHistory)
	if len(oldHistory) == 0 || oldHistory[0].Action != "export.created" {
		t.Errorf("the old gateway did not record the export: %+v", oldHistory)
	}

	// The setup link of the fresh install died with its database.
	if resp, _ := fresh.postJSON("/api/setup", map[string]string{"token": token, "username": "mallory", "password": password}); resp.StatusCode != http.StatusConflict {
		t.Errorf("setup after a restore: status %d, want it to be closed", resp.StatusCode)
	}
	// A browser signed in on the old gateway is not signed in on the new one.
	oldCookieOnNew := &http.Client{Jar: old.client.Jar, Transport: old.client.Transport, Timeout: 10 * time.Second}
	if r, err := oldCookieOnNew.Get(fresh.address() + "/api/health"); err == nil {
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("a session from the old gateway works on the restored one (status %d)", r.StatusCode)
		}
	}
}
