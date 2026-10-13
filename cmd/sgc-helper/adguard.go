package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/adguard"
	"github.com/Troglobitten/sgc/internal/components"
)

// The units that install and remove AdGuard Home
// (installer/sgc-adguard-*.service). AdGuard Home itself is
// sgc-adguard.service.
const (
	adguardInstallUnit  = "sgc-adguard-install.service"
	adguardApplyUnit    = "sgc-adguard-apply.service"
	adguardSettingsUnit = "sgc-adguard-settings.service"
)

func adguardSystem() *adguard.System {
	return &adguard.System{
		Paths:     adguard.DefaultPaths(),
		Component: components.AdGuardHome,
		Arch:      runtime.GOARCH,
		Run: func(ctx context.Context, program string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, program, args...)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			return cmd.CombinedOutput()
		},
		Chown: chownToAdguard,
		Sleep: time.Sleep,
		Log:   slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// chownToAdguard gives a path to the account AdGuard Home runs as.
func chownToAdguard(path string) error {
	account, err := user.Lookup(adguard.ServiceUser)
	if err != nil {
		return fmt.Errorf("look up the account for AdGuard Home: %w", err)
	}
	uid, err1 := strconv.Atoi(account.Uid)
	gid, err2 := strconv.Atoi(account.Gid)
	if err1 != nil || err2 != nil {
		return errors.New("the account for AdGuard Home has an unusable ID")
	}
	return os.Lchown(path, uid, gid)
}

// --- The helper service's side -------------------------------------------------

func adguardStatus() adguard.Status {
	ctx, cancel := context.WithTimeout(context.Background(), programTimeout)
	defer cancel()
	return adguardSystem().Status(ctx)
}

// Where the unit below leaves its copy of AdGuard Home's settings file: the
// helper's own folder under /run, which only root can enter.
const adguardSettingsCopy = "/run/sgc-requests/adguard-settings.yaml"

// adguardSettings hands AdGuard Home's settings file to the web process, for
// an export. The helper cannot read that file: it belongs to AdGuard Home's
// account, and the helper is root without any privilege. A unit that has the
// one privilege needed copies it here first.
func adguardSettings() ([]byte, error) {
	os.Remove(adguardSettingsCopy)
	if err := runSystemctl("start", adguardSettingsUnit); err != nil {
		runSystemctl("reset-failed", adguardSettingsUnit)
		return nil, errors.New(lastJournalLine(adguardSettingsUnit))
	}
	defer os.Remove(adguardSettingsCopy)
	return os.ReadFile(adguardSettingsCopy)
}

// installAdguard runs the unit that installs the release the web process
// downloaded, and waits for it. The request carries nothing: which release,
// and what its file must be, is compiled into this program.
func installAdguard() error {
	if err := runSystemctl("start", adguardInstallUnit); err != nil {
		runSystemctl("reset-failed", adguardInstallUnit)
		return errors.New(lastJournalLine(adguardInstallUnit))
	}
	return nil
}

// setAdguardEnabled switches AdGuard Home on or off. The helper does this
// itself: it only asks systemd to start or stop one fixed unit.
func setAdguardEnabled(enabled bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return adguardSystem().SetEnabled(ctx, enabled)
}

// applyAdguardSettings runs the unit that replaces AdGuard Home's settings
// with the ones from a restored export, which the web process has put in the
// spool folder, and waits for it.
func applyAdguardSettings() error {
	if err := runSystemctl("start", adguardApplyUnit); err != nil {
		runSystemctl("reset-failed", adguardApplyUnit)
		return errors.New(lastJournalLine(adguardApplyUnit))
	}
	return nil
}

// lastJournalLine returns what a unit's program said when it gave up: the
// reason, in the words internal/adguard chose for the owner.
func lastJournalLine(unit string) string {
	cmd := exec.Command("/usr/bin/journalctl", "--unit="+unit, "--output=cat", "--no-pager", "-n", "20", "--identifier=sgc-helper")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	output, _ := cmd.Output()
	const prefix = "sgc-helper: "
	reason := "it could not be done (details: journalctl -u " + unit + " --no-pager -n 30)"
	for line := range strings.Lines(string(output)) {
		if text, ok := strings.CutPrefix(strings.TrimSpace(line), prefix); ok && text != "" {
			reason = text
		}
	}
	return reason
}

// --- The units' side -----------------------------------------------------------

// runAdguard is "sgc-helper adguard <job>".
func runAdguard(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sgc-helper adguard install|apply-settings|remove|copy-settings")
	}
	if os.Geteuid() != 0 {
		return errors.New("installing AdGuard Home needs root")
	}
	system := adguardSystem()
	switch args[0] {
	case "install":
		return system.Install(context.Background())
	case "apply-settings":
		return system.ApplySettings(context.Background())
	case "remove":
		return system.Remove(context.Background())
	case "copy-settings":
		settings, err := system.ReadSettings()
		if err != nil {
			return fmt.Errorf("read AdGuard Home's settings: %w", err)
		}
		return os.WriteFile(adguardSettingsCopy, settings, 0o600)
	default:
		return fmt.Errorf("unknown job %q", args[0])
	}
}
