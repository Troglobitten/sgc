package log2ram

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const megabyte = 1 << 20

// device stands in for the machine: systemd, the journal, the log folder.
// log2ram's space in memory is 4 MB here, so that small files do: the
// journal may take 1 MB of it, and the logs must fit in 2.6 MB to be
// switched on.
type device struct {
	t      *testing.T
	system *System
	calls  []string

	enabled bool
	failed  bool
	// What "journalctl --vacuum-size" leaves of the journal. Zero: what it
	// was asked for.
	vacuumLeaves int64
	// A systemctl verb that fails.
	refuse string
}

func newDevice(t *testing.T) *device {
	t.Helper()
	dir := t.TempDir()
	d := &device{t: t}
	d.system = &System{
		Paths: Paths{
			Program:       filepath.Join(dir, "usr", "log2ram"),
			Conf:          filepath.Join(dir, "etc", "log2ram.conf"),
			LogDir:        filepath.Join(dir, "log"),
			JournalDropIn: filepath.Join(dir, "etc", "journald.conf.d", "60-sgc-log2ram.conf"),
			Mounts:        filepath.Join(dir, "mounts"),
			MemInfo:       filepath.Join(dir, "meminfo"),
		},
		Run: d.run,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	d.write(d.system.Paths.Program, "#!/bin/sh\n")
	d.write(d.system.Paths.Conf, "# the space in memory\nSIZE=4M\nPATH_DISK=\"/var/log\"\n")
	d.write(d.system.Paths.Mounts, "/dev/sda1 / ext4 rw,relatime 0 0\n")
	d.write(d.system.Paths.MemInfo, "MemTotal:        1953792 kB\nMemFree:          812345 kB\n")
	d.log("journal/machine/system.journal", megabyte/2)
	d.log("apt/history.log", megabyte/4)
	return d
}

func (d *device) write(path, content string) {
	d.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		d.t.Fatal(err)
	}
}

// log puts a file of the given size in the log folder.
func (d *device) log(name string, size int64) {
	d.t.Helper()
	d.write(filepath.Join(d.system.Paths.LogDir, name), strings.Repeat("x", int(size)))
}

// inMemory makes the log folder log2ram's space in memory, as after a
// start-up with log2ram switched on.
func (d *device) inMemory(used int64) {
	d.write(d.system.Paths.Mounts, "/dev/sda1 / ext4 rw,relatime 0 0\nlog2ram "+d.system.Paths.LogDir+" tmpfs rw,nosuid,nodev,noexec,noatime,size=4096k,mode=755 0 0\n")
	d.system.SpaceOf = func(string) (int64, int64, error) { return 4 * megabyte, used, nil }
}

func (d *device) run(_ context.Context, program string, args ...string) ([]byte, error) {
	call := filepath.Base(program) + " " + strings.Join(args, " ")
	failure := func() ([]byte, error) { return []byte("Failed: it did not work\n"), errors.New("exit status 1") }
	switch {
	case program == systemctl && args[0] == "is-enabled":
		if d.enabled {
			return nil, nil
		}
		return nil, errors.New("exit status 1")
	case program == systemctl && args[0] == "is-failed":
		if d.failed {
			return nil, nil
		}
		return nil, errors.New("exit status 1")
	case program == systemctl:
		d.calls = append(d.calls, call)
		if args[0] == d.refuse {
			return failure()
		}
		switch args[0] {
		case "enable":
			d.enabled = true
		case "disable":
			d.enabled = false
		}
		return nil, nil
	case program == journalctl && args[0] == "--rotate":
		d.calls = append(d.calls, call)
		return nil, nil
	case program == journalctl && strings.HasPrefix(args[0], "--vacuum-size="):
		d.calls = append(d.calls, call)
		leaves := d.vacuumLeaves
		if leaves == 0 {
			leaves = megabyte / 2
		}
		d.log("journal/machine/system.journal", leaves)
		return nil, nil
	}
	d.t.Errorf("unexpected program: %s", call)
	return nil, errors.New("unexpected")
}

func (d *device) dropIn() string {
	data, _ := os.ReadFile(d.system.Paths.JournalDropIn)
	return string(data)
}

func TestStatus(t *testing.T) {
	ctx := context.Background()
	d := newDevice(t)

	// The package is there, switched off, as the installer leaves it.
	s := d.system.Status(ctx)
	if !s.Installed || s.Enabled || s.Active || s.StartFailed || s.SizeBytes != 4*megabyte {
		t.Errorf("switched off: %+v", s)
	}
	// What the logs take on the disk, and what takes most.
	if s.UsedBytes < megabyte*3/4 || s.UsedBytes > megabyte || len(s.Largest) != 2 || s.Largest[0].Name != "journal" || s.Largest[1].Name != "apt" {
		t.Errorf("the log folder: %d bytes, %+v", s.UsedBytes, s.Largest)
	}

	// Switched on, not restarted yet.
	d.enabled = true
	if s := d.system.Status(ctx); !s.Enabled || s.Active || s.StartFailed {
		t.Errorf("switched on, before the restart: %+v", s)
	}
	// Restarted: the logs are in memory, and "used" is the file system's word.
	d.inMemory(3 * megabyte)
	if s := d.system.Status(ctx); !s.Enabled || !s.Active || s.StartFailed || s.UsedBytes != 3*megabyte || s.SizeBytes != 4*megabyte {
		t.Errorf("in memory: %+v", s)
	}

	// Restarted with logs that did not fit: log2ram left them on the disk.
	d = newDevice(t)
	d.enabled, d.failed = true, true
	if s := d.system.Status(ctx); !s.Enabled || s.Active || !s.StartFailed {
		t.Errorf("logs that did not fit at start-up: %+v", s)
	}
	// A failed unit that is switched off is nobody's problem.
	d.enabled = false
	if s := d.system.Status(ctx); s.StartFailed {
		t.Errorf("switched off, with an old failure: %+v", s)
	}

	// The package is not there.
	os.Remove(d.system.Paths.Program)
	if s := d.system.Status(ctx); s.Installed || s.Enabled || s.SizeBytes != 4*megabyte {
		t.Errorf("not installed: %+v", s)
	}
}

func TestSwitchingOn(t *testing.T) {
	ctx := context.Background()
	d := newDevice(t)
	// A journal as a disk leaves it: larger than log2ram's whole space.
	d.log("journal/machine/system.journal", 5*megabyte)
	if err := d.system.Enable(ctx); err != nil {
		t.Fatal(err)
	}
	want := "systemctl restart systemd-journald.service, journalctl --rotate, journalctl --vacuum-size=1M, systemctl enable log2ram.service log2ram-daily.timer"
	if got := strings.Join(d.calls, ", "); got != want {
		t.Errorf("done on the device:\n got %s\nwant %s", got, want)
	}
	if !strings.Contains(d.dropIn(), "[Journal]\nSystemMaxUse=1M\n") {
		t.Errorf("the journal's limit: %q", d.dropIn())
	}
	if entries, _ := os.ReadDir(filepath.Dir(d.system.Paths.JournalDropIn)); len(entries) != 1 {
		t.Errorf("left next to the journal's limit: %v", entries)
	}
	if s := d.system.Status(ctx); !s.Enabled || s.Active {
		t.Errorf("after switching on: %+v", s)
	}
}

func TestLogsThatDoNotFitAreRefusedBeforeAnythingIsTouched(t *testing.T) {
	ctx := context.Background()
	d := newDevice(t)
	d.log("big-program.log", 3*megabyte)
	err := d.system.Enable(ctx)
	if err == nil || !strings.Contains(err.Error(), "big-program.log (3 MB)") || !strings.Contains(err.Error(), "must fit in 3 MB") {
		t.Fatalf("logs that do not fit: %v", err)
	}
	if len(d.calls) != 0 || d.dropIn() != "" || d.enabled {
		t.Errorf("something was changed all the same: %v, limit %q, enabled %v", d.calls, d.dropIn(), d.enabled)
	}
}

func TestAJournalThatCannotBeCutDownIsNotSwitchedOn(t *testing.T) {
	ctx := context.Background()
	d := newDevice(t)
	d.log("journal/machine/system.journal", 5*megabyte)
	d.vacuumLeaves = 5 * megabyte
	if err := d.system.Enable(ctx); err == nil || !strings.Contains(err.Error(), "journal (5 MB)") {
		t.Fatalf("a journal that stays large: %v", err)
	}
	if d.enabled || d.dropIn() != "" {
		t.Errorf("switched on, or the limit left behind: enabled %v, limit %q", d.enabled, d.dropIn())
	}
	// The journal runs without the limit again.
	if last := d.calls[len(d.calls)-1]; last != "systemctl restart systemd-journald.service" {
		t.Errorf("the last thing done: %s", last)
	}

	// systemd refuses to make it part of start-up: the same.
	d = newDevice(t)
	d.refuse = "enable"
	if err := d.system.Enable(ctx); err == nil || !strings.Contains(err.Error(), "it did not work") {
		t.Fatalf("a refusal by systemd: %v", err)
	}
	if d.dropIn() != "" {
		t.Errorf("the limit was left behind: %q", d.dropIn())
	}
}

func TestADeviceWithLittleMemoryIsRefused(t *testing.T) {
	ctx := context.Background()
	d := newDevice(t)
	// 12 MB of memory, of which log2ram would take 4.
	d.write(d.system.Paths.MemInfo, "MemTotal:          12288 kB\n")
	if err := d.system.Enable(ctx); err == nil || !strings.Contains(err.Error(), "more than a quarter") {
		t.Fatalf("too little memory: %v", err)
	}
	if len(d.calls) != 0 {
		t.Errorf("something was changed all the same: %v", d.calls)
	}
	// Not installed: said, not tried.
	os.Remove(d.system.Paths.Program)
	if err := d.system.Enable(ctx); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("not installed: %v", err)
	}
}

func TestSwitchingOff(t *testing.T) {
	ctx := context.Background()

	// Switched on and never restarted: off again, and the journal gets its
	// room back at once.
	d := newDevice(t)
	if err := d.system.Enable(ctx); err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	if err := d.system.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(d.calls, ", "); got != "systemctl disable log2ram.service log2ram-daily.timer, systemctl restart systemd-journald.service" {
		t.Errorf("done on the device: %s", got)
	}
	if d.enabled || d.dropIn() != "" {
		t.Errorf("still on, or the limit left: enabled %v, limit %q", d.enabled, d.dropIn())
	}

	// With the logs in memory: nothing is stopped (they still have to be
	// written to the disk every day and at shutdown), and the journal keeps
	// its limit until the restart.
	d = newDevice(t)
	if err := d.system.Enable(ctx); err != nil {
		t.Fatal(err)
	}
	d.inMemory(megabyte)
	d.calls = nil
	if err := d.system.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(d.calls, ", "); got != "systemctl disable log2ram.service log2ram-daily.timer" {
		t.Errorf("done on the device: %s", got)
	}
	if s := d.system.Status(ctx); s.Enabled || !s.Active {
		t.Errorf("switched off, before the restart: %+v", s)
	}
	// A second time is harmless.
	if err := d.system.Disable(ctx); err != nil {
		t.Errorf("switching off twice: %v", err)
	}
}

func TestTheSpaceInMemoryIsReadFromLog2ramsOwnSettings(t *testing.T) {
	d := newDevice(t)
	for content, want := range map[string]int64{
		"SIZE=128M\n":                    128 * megabyte,
		"SIZE=\"40M\"\n":                 40 * megabyte,
		"#SIZE=40M\nSIZE=64M\n":          64 * megabyte,
		"SIZE=64M\nSIZE=1G\n":            1 << 30,
		"SIZE=512K\n":                    512 << 10,
		"PATH_DISK=\"/var/log\"\n":       defaultSize,
		"SIZE=lots\n":                    defaultSize,
		"  SIZE = 32M  \nZL2R=false\n":   32 * megabyte,
		"SIZE=0M\n":                      defaultSize,
		"LOG_DISK_SIZE=256M\nSIZE=96M\n": 96 * megabyte,
	} {
		d.write(d.system.Paths.Conf, content)
		if got := d.system.size(); got != want {
			t.Errorf("%q: %d, want %d", content, got, want)
		}
	}
	os.Remove(d.system.Paths.Conf)
	if got := d.system.size(); got != defaultSize {
		t.Errorf("without a settings file: %d", got)
	}
}
