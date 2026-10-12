package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/doctor"
	"github.com/Troglobitten/sgc/internal/osupdate"
	"github.com/Troglobitten/sgc/internal/sshd"
)

// consoleOSUpdates is the device's update settings as seen by a command run
// as root at the device: it can ask apt and systemd directly.
func consoleOSUpdates() *osupdate.System {
	return &osupdate.System{
		Paths: osupdate.DefaultPaths(),
		Run: func(ctx context.Context, limit time.Duration, program string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, limit)
			defer cancel()
			cmd := exec.CommandContext(ctx, program, args...)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			return cmd.CombinedOutput()
		},
		Exists: func(program string) bool { _, err := os.Stat(program); return err == nil },
		Now:    time.Now,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// A device that has been up this long has been through one of Debian's
// daily runs, which start between six and seven in the morning.
const dailyRunDue = 36 * time.Hour

const chooseInPage = "Choose in SGC's page (System) how this device gets its updates."

func checkOSUpdates(ctx context.Context) []doctor.Result {
	paths := osupdate.DefaultPaths()
	settings, err := consoleOSUpdates().Settings(ctx)
	if err != nil {
		return one(doctor.Bad("apt could not be asked about the device's update settings: "+err.Error(),
			"Its own check says more: apt-config dump"))
	}
	mode, setUp, modeErr := osupdate.ReadMode(paths.ConfigFile)

	var results []doctor.Result
	switch {
	case modeErr != nil:
		results = append(results, doctor.Bad("SGC's file among apt's settings cannot be read: "+modeErr.Error(), chooseInPage))
	case !setUp && settings.Daily():
		results = append(results, doctor.Good("Updates for the device install by themselves (the device's own settings; nothing chosen in SGC yet)"))
	case !setUp:
		results = append(results, doctor.Warn("Updates for the device do not install by themselves, and nothing has been chosen in SGC", chooseInPage))
	case !settings.ToolInstalled:
		results = append(results, doctor.Bad("Debian's update tool (unattended-upgrades) is no longer on this device",
			"Choose again in SGC's page (System) how this device gets its updates; that puts it back."))
	case settings.Overridden != "":
		results = append(results, doctor.Bad("Another settings file on this device overrules what SGC set up for updates ("+settings.Overridden+")",
			"Look in /etc/apt/apt.conf.d for a file whose name sorts after 52sgc-updates and take the setting out of it."))
	case mode == osupdate.Automatic && !settings.Timers:
		results = append(results, doctor.Bad("Updates are set to install by themselves, but Debian's daily timers are not running",
			"Start them: sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer"))
	case mode == osupdate.Automatic:
		results = append(results, checkDailyRun(settings))
	default:
		report, err := osupdate.ReadReport(paths)
		switch n := len(report.Waiting); {
		case err != nil:
			results = append(results, doctor.Warn("Updates for the device are started by hand; what is waiting could not be read: "+err.Error(), ""))
		case n > 0:
			results = append(results, doctor.Warn(fmt.Sprintf("Updates for the device are started by hand, and %d %s waiting", n, plural(n, "is", "are")),
				"Install them in SGC's page (System)."))
		default:
			results = append(results, doctor.Good("Updates for the device are started by hand in SGC's page; none are known to be waiting"))
		}
	}

	if needed, packages := osupdate.RestartNeeded(paths); needed {
		summary := "A restart is needed for an installed update to take effect"
		if len(packages) > 0 {
			summary += " (" + strings.Join(packages, ", ") + ")"
		}
		results = append(results, doctor.Warn(summary, "Restart from SGC's page (System), or: sudo systemctl reboot"))
	}
	return results
}

func checkDailyRun(settings osupdate.Settings) doctor.Result {
	const summary = "Updates for the device install by themselves"
	uptime, err := sshd.Uptime()
	longUp := err == nil && time.Duration(uptime)*time.Second > dailyRunDue
	switch {
	case settings.LastRun == nil && longUp, settings.LastRun != nil && longUp && time.Since(*settings.LastRun) > dailyRunDue:
		last := "never"
		if settings.LastRun != nil {
			last = settings.LastRun.Local().Format("2 January 15:04")
		}
		return doctor.Warn("Updates are set to install by themselves, but Debian's daily run last ran: "+last,
			"Why: sudo journalctl -u apt-daily-upgrade --no-pager -n 30")
	case settings.LastRun == nil:
		return doctor.Good(summary + " (Debian's daily run has not run yet since)")
	}
	return doctor.Good(summary + "; Debian's daily run last ran " + settings.LastRun.Local().Format("2 January 15:04"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
