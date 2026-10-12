package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/osupdate"
)

// The units for Debian's updates (installer/sgc-os-updates*.service).
const (
	osUpdatesUnit    = "sgc-os-updates.service"
	osUpdatesSetUnit = "sgc-os-updates-set.service"
)

// stopGrace is how long a program that was asked to stop is waited for
// before it is killed. unattended-upgrade finishes the package it is at
// first, and a kernel on a slow card takes its time. Shorter than the unit's
// TimeoutStopSec, so that this program is still there to write the report.
const stopGrace = 13 * time.Minute

// --- The helper service's side -------------------------------------------------

// osUpdateSettings is answered by the helper itself: it only reads apt's
// settings and asks systemd about Debian's timers.
func osUpdateSettings() (osupdate.Settings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	return osUpdateSystem().Settings(ctx)
}

// setOSUpdateMode hands the choice to the unit that writes the settings and
// returns when they are in place. request has been decoded strictly by
// internal/helper; it holds one yes-or-no value. If the unit refuses, why is
// in its folder under /run (osupdate.ReadModeOutcome).
func setOSUpdateMode(request osupdate.ModeRequest) error {
	if err := handOver(osupdate.DefaultPaths().ModeRequestFile, request); err != nil {
		return err
	}
	if err := runSystemctl("start", osUpdatesSetUnit); err != nil {
		// A refusal is not something wrong with the device (see startChangeUnit).
		runSystemctl("reset-failed", osUpdatesSetUnit)
		return errors.New("the settings were refused or could not be put into effect")
	}
	return nil
}

// startOSUpdateJob starts a look for updates or their installation and
// returns once the job says, in its report, that it is running. job is one
// of the two the unit knows (internal/helper lets nothing else through, and
// the unit looks again).
func startOSUpdateJob(job string) (int64, error) {
	// Starting a unit that is running does nothing, and the caller would
	// wait for a job that was never started.
	if runSystemctl("is-active", "--quiet", osUpdatesUnit) == nil {
		return 0, errors.New("a look for updates or an installation is already running")
	}
	id := time.Now().UnixMilli()
	if err := handOver(osupdate.DefaultPaths().JobRequestFile, osupdate.JobRequest{Job: job, ID: id}); err != nil {
		return 0, err
	}
	if err := runSystemctl("start", osUpdatesUnit); err != nil {
		runSystemctl("reset-failed", osUpdatesUnit)
		return 0, errors.New("the job could not be started (details: journalctl -u sgc-os-updates --no-pager -n 30)")
	}
	return id, nil
}

// --- The units' side -----------------------------------------------------------

func osUpdateSystem() *osupdate.System {
	return &osupdate.System{
		Paths:  osupdate.DefaultPaths(),
		Run:    runPackageProgram,
		Exists: programExists,
		Now:    time.Now,
		Log:    slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// runOSUpdates is "sgc-helper os-updates <job>".
func runOSUpdates(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sgc-helper os-updates set|run|finished")
	}
	if os.Geteuid() != 0 {
		return errors.New("Debian's updates need root")
	}
	system := osUpdateSystem()

	switch args[0] {
	case "set":
		return system.SetMode(context.Background())
	case "run":
		// systemd stops the unit (SIGTERM) when the device shuts down. The
		// update tool is then asked to stop and waited for; see
		// runPackageProgram.
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		return system.RunJob(ctx, notifyReady)
	case "finished":
		// Run by systemd after the "run" process has ended, however it ended
		// (ExecStopPost). Normally there is nothing left to put right.
		return system.Finished()
	default:
		return fmt.Errorf("unknown job %q", args[0])
	}
}

// runPackageProgram runs apt's programs and Debian's update tool.
//
// The two that take long and say a lot (fetching the lists, the update tool)
// write to the unit's log as they go, so that "journalctl -u sgc-os-updates"
// shows an installation as it happens; what is returned is the beginning and
// the end of it.
//
// When ctx is cancelled the program is asked to stop and waited for, not
// killed. For the update tool that means: finish the package you are at,
// then stop. Killing it in the middle would leave a package half installed.
func runPackageProgram(ctx context.Context, limit time.Duration, program string, args ...string) ([]byte, error) {
	limited, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(limited, program, args...)
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		// Never stop to ask a question: there is nobody to answer it.
		"DEBIAN_FRONTEND=noninteractive",
		// The update tool's sentences are read by internal/osupdate, in English.
		"LC_ALL=C",
	}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace

	kept := &headAndTail{limit: 512 * 1024}
	var output io.Writer = kept
	if program == aptGet || program == osupdate.ToolProgram {
		output = io.MultiWriter(os.Stdout, kept)
	}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	return kept.Bytes(), err
}

// headAndTail keeps the first and the last limit bytes of what is written to
// it. What a program says about its plans comes first and what went wrong
// comes last; an installation of many packages prints megabytes in between.
type headAndTail struct {
	limit   int
	head    []byte
	tail    []byte
	dropped bool
}

func (w *headAndTail) Write(p []byte) (int, error) {
	n := len(p)
	if room := w.limit - len(w.head); room > 0 {
		take := min(room, len(p))
		w.head = append(w.head, p[:take]...)
		p = p[take:]
	}
	if len(p) > 0 {
		w.tail = append(w.tail, p...)
		if extra := len(w.tail) - w.limit; extra > 0 {
			w.tail = append(w.tail[:0], w.tail[extra:]...)
			w.dropped = true
		}
	}
	return n, nil
}

func (w *headAndTail) Bytes() []byte {
	out := append([]byte{}, w.head...)
	if w.dropped {
		out = append(out, "\n[...]\n"...)
	}
	return append(out, w.tail...)
}
