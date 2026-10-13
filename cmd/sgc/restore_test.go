package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/components"
	"github.com/Troglobitten/sgc/internal/fwcontrol"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/log2ram"
	"github.com/Troglobitten/sgc/internal/osupdate"
	"github.com/Troglobitten/sgc/internal/sshd"
	"github.com/Troglobitten/sgc/internal/store"
)

// rootSide stands in for the root helper as far as AdGuard Home goes: a
// device that has it, switched on, as the installer leaves one. It keeps the
// settings AdGuard Home "runs on".
type rootSide struct {
	mu       sync.Mutex
	enabled  bool
	settings string
}

func (r *rootSide) state() (enabled bool, settings string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enabled, r.settings
}

func startRootSide(t *testing.T, stateDir, settings string) (socket string, side *rootSide) {
	t.Helper()
	side = &rootSide{enabled: true, settings: settings}
	// Where the web process hands over the settings from an export.
	handedOver := adguard.Paths{SpoolDir: filepath.Join(stateDir, "components")}.RestoredSettings()
	socket = filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	notHere := errors.New("not on this test's device")
	server := &http.Server{
		ConnContext: helper.ConnContext,
		Handler: (&helper.Server{
			AllowedUID: uint32(os.Getuid()),
			AdguardStatus: func() adguard.Status {
				enabled, _ := side.state()
				return adguard.Status{Installed: true, Version: components.AdGuardHome.Version, Running: enabled, Enabled: enabled}
			},
			AdguardSettings: func() ([]byte, error) {
				_, settings := side.state()
				return []byte(settings), nil
			},
			AdguardSetEnabled: func(enabled bool) error {
				side.mu.Lock()
				defer side.mu.Unlock()
				side.enabled = enabled
				return nil
			},
			AdguardApplySettings: func() error {
				data, err := os.ReadFile(handedOver)
				if err != nil {
					return err
				}
				side.mu.Lock()
				defer side.mu.Unlock()
				side.settings = string(data)
				return nil
			},
			// log2ram as the installer leaves it: installed, switched off.
			Log2ramStatus:    func() log2ram.Status { return log2ram.Status{Installed: true, SizeBytes: 128 << 20} },
			SSHStatus:        func() (sshd.Status, error) { return sshd.Status{}, notHere },
			OSUpdateSettings: func() (osupdate.Settings, error) { return osupdate.Settings{}, notHere },
		}).Handler(),
	}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return socket, side
}

// instance is one running `sgc serve` with its own state folder, driven the
// way a browser would.
type instance struct {
	t        *testing.T
	stateDir string
	out      *syncBuffer
	client   *http.Client
	root     *rootSide
}

// startInstance starts an SGC on a device whose AdGuard Home runs on the
// given settings.
func startInstance(t *testing.T, dnsSettings string) *instance {
	t.Helper()
	stateDir := t.TempDir()
	helperSocket, root := startRootSide(t, stateDir, dnsSettings)
	// What the root side would keep (the updater's outcome, the firewall's
	// state) is pointed inside the test's own folder, so nothing on the
	// machine running the test is read.
	_, out, _ := startServe(t, "--state-dir", stateDir, "--update-work-dir", stateDir+"/update-work",
		"--firewall-file", stateDir+"/firewall/firewall.nft", "--firewall-run-dir", stateDir+"/firewall/run",
		"--ssh-state-file", stateDir+"/ssh/state.json", "--ssh-run-dir", stateDir+"/ssh/run",
		"--os-updates-file", stateDir+"/apt/52sgc-updates", "--os-updates-run-dir", stateDir+"/os-updates/run",
		"--helper-socket", helperSocket)
	jar, _ := cookiejar.New(nil)
	return &instance{
		t: t, stateDir: stateDir, out: out, root: root,
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
	// What the owner made of AdGuard Home's settings on the old gateway.
	const dnsSettings = "user_rules:\n  - '||ads.domain.tld^'\n"
	old := startInstance(t, dnsSettings)
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
	// The same for SSH: a key that was added, for an account, and "keys
	// only" confirmed. (A throwaway public key made for the tests.)
	for _, statement := range []string{
		`INSERT INTO ssh_key (label, key_type, key_blob, fingerprint, added_at, added_by) VALUES ('laptop', 'ssh-ed25519',
			'AAAAC3NzaC1lZDI1NTE5AAAAID25i1+d/VGOmeRQ2ZPpnryBGMe/B28pdc623ONJVCV1', 'SHA256:ZcQJrTJFZ1DO2xgEpCKluYro6G3ehPZvDrs/oGfuJG4', 100, 'alex')`,
		`INSERT INTO setting (key, value) VALUES ('ssh.account', 'alex'), ('ssh.keys_only', 'true')`,
		// And updates for the device: set to install by themselves.
		`INSERT INTO setting (key, value) VALUES ('os_updates.mode', 'automatic')`,
		// And DNS: switched on, as the installer leaves it. Its settings are
		// AdGuard Home's own file, which the export fetches from the device.
		`INSERT INTO setting (key, value) VALUES ('adguard.enabled', 'true')`,
		// And logs in memory: switched on, because the old gateway ran from
		// an SD card.
		`INSERT INTO setting (key, value) VALUES ('log2ram.enabled', 'true')`,
	} {
		if _, err := oldDB.ExecContext(context.Background(), statement); err != nil {
			t.Fatal(err)
		}
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
	fresh := startInstance(t, "the settings SGC gives a new AdGuard Home")
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
	// The SSH key is known again, with the account it was for, and that
	// "keys only" was on. None of it is in effect here: installing the key
	// on this device is a step for the owner, with their password.
	var ssh struct {
		Account      string
		NeedsInstall bool
		KeysOnly     bool
		Wanted       bool
		Keys         []struct {
			Label, Fingerprint string
			Installed          bool
		}
	}
	if fresh.getJSON("/api/ssh", &ssh) != http.StatusOK || len(ssh.Keys) != 1 || ssh.Keys[0].Label != "laptop" ||
		ssh.Keys[0].Fingerprint != "SHA256:ZcQJrTJFZ1DO2xgEpCKluYro6G3ehPZvDrs/oGfuJG4" || ssh.Keys[0].Installed ||
		ssh.Account != "alex" || !ssh.NeedsInstall || ssh.KeysOnly || !ssh.Wanted {
		t.Errorf("SSH after the restore: %+v", ssh)
	}
	// How the old device got its updates is known, and this device is not
	// set up that way unasked.
	var osUpdates struct{ Mode, Wanted string }
	if fresh.getJSON("/api/os-updates", &osUpdates) != http.StatusOK || osUpdates.Wanted != "automatic" || osUpdates.Mode != "" {
		t.Errorf("updates for the device after the restore: %+v", osUpdates)
	}
	// DNS needs nobody: the AdGuard Home the installer put on this device
	// gets the settings from the export by itself.
	var dns struct{ Enabled, RestorePending bool }
	deadline = time.Now().Add(10 * time.Second)
	for fresh.getJSON("/api/dns", &dns) != http.StatusOK || dns.RestorePending {
		if time.Now().After(deadline) {
			t.Fatalf("the DNS part of the restore was never finished: %+v\n%s", dns, fresh.out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if enabled, settings := fresh.root.state(); !dns.Enabled || !enabled || settings != dnsSettings {
		t.Errorf("DNS after the restore: %+v, and AdGuard Home runs on %q", dns, settings)
	}
	// Logs in memory was on on the old device. Whether this one runs from an
	// SD card is not something the export knows: shown, not switched on.
	var memoryLogs struct{ Installed, Enabled, Wanted bool }
	if fresh.getJSON("/api/log2ram", &memoryLogs) != http.StatusOK || !memoryLogs.Installed || memoryLogs.Enabled || !memoryLogs.Wanted {
		t.Errorf("logs in memory after the restore: %+v", memoryLogs)
	}
	var history []struct{ Actor, Action, Detail string }
	fresh.getJSON("/api/audit", &history)
	seen := map[string]bool{}
	for _, entry := range history {
		seen[entry.Action] = true
	}
	for _, action := range []string{"setup.completed", "setting.changed", "restore.completed", "dns.restored"} {
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
