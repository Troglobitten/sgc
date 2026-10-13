package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/Troglobitten/sgc/internal/log2ram"
)

const (
	// The unit that switches log2ram on or off (installer/sgc-log2ram-set.service).
	log2ramSetUnit = "sgc-log2ram-set.service"
	// Where the helper says which of the two it is to do.
	log2ramRequestFile = "/run/sgc-requests/log2ram.json"
)

type log2ramRequest struct {
	// A pointer, so that a request without the field is refused, not read as "off".
	Enabled *bool `json:"enabled"`
}

func log2ramSystem() *log2ram.System {
	return &log2ram.System{
		Paths: log2ram.DefaultPaths(),
		Run: func(ctx context.Context, program string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, program, args...)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			return cmd.CombinedOutput()
		},
		Log: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// --- The helper service's side -------------------------------------------------

// log2ramStatus is answered by the helper itself: it asks systemd, reads the
// list of mounts and measures the log folder.
func log2ramStatus() log2ram.Status {
	ctx, cancel := context.WithTimeout(context.Background(), programTimeout)
	defer cancel()
	return log2ramSystem().Status(ctx)
}

// setLog2ram hands the choice to the unit that carries it out and waits for
// it. The request holds one yes-or-no value. If the unit refuses (the logs
// do not fit in memory, for one), its reason comes back in words.
func setLog2ram(enabled bool) error {
	if err := handOver(log2ramRequestFile, log2ramRequest{Enabled: &enabled}); err != nil {
		return err
	}
	if err := runSystemctl("start", log2ramSetUnit); err != nil {
		// A refusal is not something wrong with the device.
		runSystemctl("reset-failed", log2ramSetUnit)
		return errors.New(lastJournalLine(log2ramSetUnit))
	}
	return nil
}

// --- The unit's side -----------------------------------------------------------

// runLog2ram is "sgc-helper log2ram set".
func runLog2ram(args []string) error {
	if len(args) != 1 || args[0] != "set" {
		return errors.New("usage: sgc-helper log2ram set")
	}
	if os.Geteuid() != 0 {
		return errors.New("switching log2ram needs root")
	}
	data, err := os.ReadFile(log2ramRequestFile)
	if err != nil {
		return fmt.Errorf("read the request: %w", err)
	}
	var request log2ramRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Enabled == nil {
		return errors.New("the request could not be read")
	}
	if *request.Enabled {
		return log2ramSystem().Enable(context.Background())
	}
	return log2ramSystem().Disable(context.Background())
}
