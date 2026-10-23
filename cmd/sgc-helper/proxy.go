package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"runtime"
	"time"

	"github.com/Troglobitten/sgc/internal/components"
	"github.com/Troglobitten/sgc/internal/proxy"
)

// The units that install Traefik and put a configuration in place
// (installer/sgc-traefik-install.service, sgc-proxy-apply.service).
const (
	proxyInstallUnit = "sgc-traefik-install.service"
	proxyApplyUnit   = "sgc-proxy-apply.service"
)

func proxySystem() *proxy.System {
	return &proxy.System{
		Paths:     proxy.DefaultPaths(),
		Component: components.Traefik,
		Arch:      runtime.GOARCH,
		Run:       runProgram,
		Group: proxy.GroupID(func(name string) (string, error) {
			account, err := user.Lookup(name)
			if err != nil {
				return "", err
			}
			return account.Gid, nil
		}),
		Sleep: time.Sleep,
		Now:   time.Now,
		Log:   slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// --- The helper service's side ---------------------------------------------------

func proxyStatus() proxy.Status {
	ctx, cancel := context.WithTimeout(context.Background(), programTimeout)
	defer cancel()
	return proxySystem().Status(ctx)
}

func installProxy() error {
	if err := runSystemctl("start", proxyInstallUnit); err != nil {
		runSystemctl("reset-failed", proxyInstallUnit)
		return errors.New(lastJournalLine(proxyInstallUnit))
	}
	return nil
}

// applyProxy hands a configuration to the job that puts it in place, and
// waits for the job. The configuration was checked by internal/helper; the
// job checks it again, as it does not trust this file either.
func applyProxy(cfg proxy.Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	path := proxy.DefaultPaths().RequestFile
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("hand over the request: %w", err)
	}
	defer os.Remove(path)
	if err := runSystemctl("start", proxyApplyUnit); err != nil {
		runSystemctl("reset-failed", proxyApplyUnit)
		return errors.New(lastJournalLine(proxyApplyUnit))
	}
	return nil
}

// --- The units' side -------------------------------------------------------------

// runProxy is "sgc-helper proxy install|apply".
func runProxy(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sgc-helper proxy install|apply")
	}
	if os.Geteuid() != 0 {
		return errors.New("this needs root")
	}
	system := proxySystem()
	ctx := context.Background()
	switch args[0] {
	case "install":
		return system.Install(ctx)
	case "apply":
		cfg, err := system.ReadRequest()
		if err != nil {
			return err
		}
		return system.Apply(ctx, cfg)
	default:
		return fmt.Errorf("unknown job %q", args[0])
	}
}
