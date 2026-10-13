package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/doctor"
	"github.com/Troglobitten/sgc/internal/log2ram"
)

// checkLog2ram says how "logs in memory" is doing. It asks the device
// itself, as the root side does.
func checkLog2ram(ctx context.Context) []doctor.Result {
	system := &log2ram.System{
		Paths: log2ram.DefaultPaths(),
		Run: func(ctx context.Context, program string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, program, args...)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			return cmd.CombinedOutput()
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	status := system.Status(ctx)
	megabytes := func(bytes int64) string { return fmt.Sprintf("%d MB", (bytes+(1<<19))>>20) }
	space := megabytes(status.UsedBytes) + " of " + megabytes(status.SizeBytes) + " used"
	var names []string
	for _, entry := range status.Largest {
		names = append(names, fmt.Sprintf("%s (%s)", entry.Name, megabytes(entry.Bytes)))
	}
	largest := "The largest in /var/log: " + strings.Join(names, ", ")

	switch {
	case !status.Installed:
		return one(doctor.Good("Logs in memory is off: log2ram is not on this device (switching it on, on SGC's System page, installs it)"))
	case status.StartFailed:
		return one(doctor.Bad("Logs in memory is switched on, but at the last start-up the logs did not fit in memory: they take "+megabytes(status.UsedBytes)+", the space is "+megabytes(status.SizeBytes)+". They are on the disk, and nothing is lost",
			largest+"\nMake room there, then restart the device: the logs go into memory again by themselves.\nOr switch \"Logs in memory\" off on SGC's System page."))
	case status.Active && status.UsedBytes*5 >= status.SizeBytes*4:
		return one(doctor.Warn("The logs are in memory, and the space for them is almost full ("+space+")",
			largest+"\nThe device keeps working when it is full, but log entries get lost, and after a restart the logs stay on the disk until there is room again."))
	case status.Active && !status.Enabled:
		return one(doctor.Good("Logs in memory is switched off; the logs stay in memory until the device restarts (" + space + ")"))
	case status.Active:
		return one(doctor.Good("The logs are in memory (" + space + "), and are written to the disk every day and at shutdown"))
	case status.Enabled:
		return one(doctor.Good("Logs in memory is switched on, and takes effect when the device restarts"))
	default:
		return one(doctor.Good("Logs in memory (log2ram) is switched off"))
	}
}
