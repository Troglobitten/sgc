package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/Troglobitten/sgc/internal/layout"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/release"
	"github.com/Troglobitten/sgc/internal/updater"
)

const (
	// How long a freshly started SGC gets to answer with its version.
	healthTimeout = 60 * time.Second
	// An update that takes longer than this is stuck.
	updateTimeout = 5 * time.Minute
)

// runUpdate installs the given version. This program is the previous
// version's updater: the code deciding whether to trust and how to install a
// release is always code that is already installed and trusted.
func runUpdate(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sgc-helper update <version>")
	}
	keys, err := release.ParsePublicKeys(sgc.ReleasePublicKeyPEM())
	if err != nil {
		return err
	}
	uid, gid, err := lookupUser(layout.ServiceUser)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()

	status := updater.Run(ctx, updater.Config{
		CurrentVersion: sgc.Version(),
		Arch:           runtime.GOARCH,
		TrustedKeys:    keys,
		InstallRoot:    layout.InstallRoot,
		UnitDir:        layout.UnitDir,
		WorkDir:        workDir(),
		StateDir:       layout.StateDir,
		SpoolDir:       filepath.Join(layout.StateDir, layout.SpoolFolder),
		OwnerUID:       uid,
		OwnerGID:       gid,
		Services:       systemd{},
		Healthy:        waitForVersion,
		Now:            time.Now,
		Log:            slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}, args[0])

	fmt.Println(status.Message)
	if status.State != updater.StateSucceeded {
		return fmt.Errorf("update %s", status.State)
	}
	return nil
}

// workDir is the updater's own root-owned folder. systemd prepares it and
// passes its location (StateDirectory= in sgc-update@.service).
func workDir() string {
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return dir
	}
	return layout.UpdateWorkDir
}

type systemd struct{}

func (systemd) Stop(unit string) error    { return runSystemctl("stop", unit) }
func (systemd) Start(unit string) error   { return runSystemctl("start", unit) }
func (systemd) Restart(unit string) error { return runSystemctl("restart", unit) }
func (systemd) DaemonReload() error       { return runSystemctl("daemon-reload") }
func (systemd) Enable(unit string) error  { return runSystemctl("enable", "--quiet", unit) }
func (systemd) Disable(unit string) error { return runSystemctl("disable", "--quiet", unit) }

// waitForVersion returns once the SGC running on this machine reports the
// given version, or an error if it does not within healthTimeout.
func waitForVersion(ctx context.Context, version string) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			// The certificate is SGC's own self-signed one, and the request
			// goes to this machine itself and carries nothing secret.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	address := "https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(layout.WebPort)) + "/api/state"

	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	last := errors.New("no answer")
	for {
		if got, err := reportedVersion(ctx, client, address); err != nil {
			last = err
		} else if got == version {
			return nil
		} else {
			last = fmt.Errorf("it reports version %s", got)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("SGC %s did not answer within %d seconds (%v)", version, int(healthTimeout.Seconds()), last)
		case <-time.After(time.Second):
		}
	}
}

func reportedVersion(ctx context.Context, client *http.Client, address string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("no answer")
	}
	defer resp.Body.Close()
	var state struct {
		Version string `json:"version"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&state) != nil {
		return "", fmt.Errorf("unexpected answer (status %d)", resp.StatusCode)
	}
	return state.Version, nil
}
