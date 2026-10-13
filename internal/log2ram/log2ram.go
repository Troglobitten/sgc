// Package log2ram is the root side of "logs in memory": Debian's log2ram
// package, which keeps the log folder in memory and writes it to the disk
// once a day and at shutdown. It is for a device that runs from an SD card.
//
// SGC installs the package, switches it on and off, and says how it is doing.
// It does not start or stop log2ram on a running device: log2ram changes
// places with the logs at start-up and at shutdown, when nothing else has
// them open. Switching on or off therefore takes effect at the next restart.
//
// What happens when the logs do not fit is log2ram's own doing, tried on the
// test machine and relied on here:
//
//   - While running: programs that write logs get "no space left". The
//     device keeps working (DNS, SGC's page, SSH, apt and Debian's update
//     tool were tried); log entries get lost. The daily write to the disk
//     still works. One corner was found: Debian's update tool fails once if
//     it has to create its own log file while the space is full, which is
//     its first run ever on a device. The run after that works.
//   - At start-up: log2ram compares the logs on the disk with its space in
//     memory. If they do not fit, it leaves them on the disk, and its unit
//     ends up as "failed". Nothing is lost, and it tries again at every
//     start-up.
//
// SGC adds what keeps a device out of that corner: before switching on it
// checks that the logs fit with room to spare, and while log2ram is switched
// on it limits the system journal, the one thing in the log folder that
// grows by itself.
//
// Standard library only: this is linked into the root helper.
package log2ram

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const (
	// ServiceUnit and TimerUnit are Debian's: the first takes the logs into
	// memory at start-up and back at shutdown, the second writes them to the
	// disk every day.
	ServiceUnit = "log2ram.service"
	TimerUnit   = "log2ram-daily.timer"

	journaldUnit = "systemd-journald.service"
	systemctl    = "/usr/bin/systemctl"
	journalctl   = "/usr/bin/journalctl"

	// defaultSize is the space in memory log2ram takes when its settings do
	// not say. (They do, and say this.)
	defaultSize = 128 << 20
	// What log2ram calls its space in memory, in the list of mounts.
	mountSource = "log2ram"

	// The journal may take a quarter of the space in memory.
	journalShare = 4
	// When switching on, the logs must fit in two thirds of the space.
	fitNumerator, fitDenominator = 2, 3
	// The space in memory may be a quarter of the device's memory at most.
	memoryShare = 4
	// How many of the largest entries in the log folder are named.
	largestCount = 3
)

// Paths are the places this package reads and writes.
type Paths struct {
	// Program shows that Debian's package is installed.
	Program string
	// Conf is log2ram's own settings file. SGC reads the size from it and
	// never writes it.
	Conf string
	// LogDir is the folder log2ram keeps in memory.
	LogDir string
	// JournalDropIn is SGC's one file among the journal's settings. It is
	// there exactly while log2ram is switched on.
	JournalDropIn string
	// Mounts and MemInfo are the kernel's lists of what is mounted and of
	// the device's memory.
	Mounts  string
	MemInfo string
}

func DefaultPaths() Paths {
	return Paths{
		Program:       "/usr/bin/log2ram",
		Conf:          "/etc/log2ram.conf",
		LogDir:        "/var/log",
		JournalDropIn: "/etc/systemd/journald.conf.d/60-sgc-log2ram.conf",
		Mounts:        "/proc/self/mounts",
		MemInfo:       "/proc/meminfo",
	}
}

// Entry is one file or folder directly in the log folder, with what it
// takes on the disk or in memory.
type Entry struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

// Status is what the device says about log2ram.
type Status struct {
	Installed bool `json:"installed"`
	// Enabled: switched on, which is to say that log2ram takes the logs into
	// memory at the next start-up. Active: they are in memory right now.
	// The two differ between a change and the restart that follows it.
	Enabled bool `json:"enabled"`
	Active  bool `json:"active"`
	// StartFailed: switched on, but at this start-up log2ram left the logs
	// on the disk, because they did not fit.
	StartFailed bool `json:"startFailed"`
	// SizeBytes is the space in memory. UsedBytes is what the logs take: in
	// memory when Active, on the disk otherwise.
	SizeBytes int64 `json:"sizeBytes"`
	UsedBytes int64 `json:"usedBytes"`
	// Largest names what takes most in the log folder, largest first.
	Largest []Entry `json:"largest"`
}

// System does the root side's work. The changes run in a unit of their own
// (installer/sgc-log2ram-set.service); Status is answered by the helper.
type System struct {
	Paths Paths
	// Run runs a program and returns what it printed. Injected so that the
	// tests need neither root nor systemd.
	Run func(ctx context.Context, program string, args ...string) ([]byte, error)
	// SpaceOf returns the size of the file system a folder is on and how
	// much of it is used. Injected for the same reason; nil means: ask the
	// kernel.
	SpaceOf func(dir string) (size, used int64, err error)
	Log     *slog.Logger
}

func (s *System) installed() bool {
	info, err := os.Stat(s.Paths.Program)
	return err == nil && info.Mode().IsRegular()
}

func (s *System) Status(ctx context.Context) Status {
	status := Status{Installed: s.installed(), SizeBytes: s.size()}
	if !status.Installed {
		return status
	}
	_, err := s.Run(ctx, systemctl, "is-enabled", "--quiet", ServiceUnit)
	status.Enabled = err == nil
	status.Active = s.active()
	used, _, largest := s.usage()
	status.UsedBytes, status.Largest = used, largest
	if status.Active {
		// The file system's own word on it: this is what "full" means.
		if size, inUse, err := s.spaceOf(s.Paths.LogDir); err == nil {
			status.SizeBytes, status.UsedBytes = size, inUse
		}
		return status
	}
	_, err = s.Run(ctx, systemctl, "is-failed", "--quiet", ServiceUnit)
	status.StartFailed = status.Enabled && err == nil
	return status
}

// Enable switches log2ram on: from the next start-up the logs are in memory.
//
// It first makes sure they will fit, because logs that do not fit are left
// on the disk by log2ram at every start-up, silently. The system journal is
// limited (and stays limited while log2ram is switched on), what is there of
// it is cut down to that limit, and the rest of the log folder is measured.
// An error means nothing was changed, except that a journal that was cut
// down stays cut down.
func (s *System) Enable(ctx context.Context) error {
	if !s.installed() {
		return errors.New("log2ram is not installed on this device")
	}
	size := s.size()
	if memory := s.memory(); memory > 0 && size > memory/memoryShare {
		return fmt.Errorf("log2ram takes up to %s of memory for the logs, and this device has %s. SGC does not switch it on where that is more than a quarter", megabytes(size), megabytes(memory))
	}
	limit := size / journalShare
	budget := size * fitNumerator / fitDenominator

	// Looked at before anything is touched: the journal will shrink to its
	// limit, the rest will not shrink by itself.
	total, journal, largest := s.usage()
	if rest := total - journal; rest+min(journal, limit) > budget {
		return tooBig(rest+min(journal, limit), budget, largest)
	}

	if err := s.writeJournalLimit(limit); err != nil {
		return fmt.Errorf("write the journal's limit: %w", err)
	}
	undo := func() {
		os.Remove(s.Paths.JournalDropIn)
		s.Run(ctx, systemctl, "restart", journaldUnit)
	}
	// The journal reads its settings when it starts. Its service is made to
	// be restarted: what programs write in the meantime is kept for it.
	if output, err := s.Run(ctx, systemctl, "restart", journaldUnit); err != nil {
		undo()
		return fmt.Errorf("the system journal could not be restarted with its limit: %s", lastLine(output, err))
	}
	// Only files that are closed can be removed, so the one being written
	// is closed first.
	if output, err := s.Run(ctx, journalctl, "--rotate"); err != nil {
		s.Log.Warn("close the journal file in use", "error", lastLine(output, err))
	}
	if output, err := s.Run(ctx, journalctl, "--vacuum-size="+strconv.FormatInt(limit>>20, 10)+"M"); err != nil {
		undo()
		return fmt.Errorf("the system journal could not be cut down to its limit: %s", lastLine(output, err))
	}
	if total, _, largest = s.usage(); total > budget {
		undo()
		return tooBig(total, budget, largest)
	}
	if output, err := s.Run(ctx, systemctl, "enable", ServiceUnit, TimerUnit); err != nil {
		undo()
		return fmt.Errorf("log2ram could not be made part of start-up: %s", lastLine(output, err))
	}
	s.Log.Info("log2ram switched on; it takes the logs into memory at the next start-up", "space", megabytes(size), "journal limit", megabytes(limit))
	return nil
}

// Disable switches log2ram off: from the next start-up the logs are on the
// disk again. Until then nothing changes. If they are in memory now, they
// stay there and go on being written to the disk every day and at shutdown,
// which is why nothing is stopped here.
func (s *System) Disable(ctx context.Context) error {
	if s.installed() {
		if output, err := s.Run(ctx, systemctl, "disable", ServiceUnit, TimerUnit); err != nil {
			return fmt.Errorf("log2ram could not be taken out of start-up: %s", lastLine(output, err))
		}
	}
	if err := os.Remove(s.Paths.JournalDropIn); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the journal's limit: %w", err)
	}
	// With the logs on the disk the journal gets its usual room back at
	// once. With the logs in memory it keeps its limit until the restart
	// that ends that.
	if !s.active() {
		if output, err := s.Run(ctx, systemctl, "restart", journaldUnit); err != nil {
			s.Log.Warn("restart the journal without its limit", "error", lastLine(output, err))
		}
	}
	s.Log.Info("log2ram switched off; the logs are on the disk from the next start-up")
	return nil
}

func tooBig(needed, budget int64, largest []Entry) error {
	var names []string
	for _, entry := range largest {
		names = append(names, fmt.Sprintf("%s (%s)", entry.Name, megabytes(entry.Bytes)))
	}
	return fmt.Errorf("the logs of this device would take %s, and must fit in %s to leave room in memory. The largest in the log folder: %s", megabytes(needed), megabytes(budget), strings.Join(names, ", "))
}

const journalLimitText = `# Written by SGC (Server Gateway Control) while "logs in memory" (log2ram) is
# switched on, and removed when it is switched off. It keeps the system
# journal small enough to fit in log2ram's space in memory with room to
# spare. SGC rewrites this file; settings of your own belong in another one.
[Journal]
SystemMaxUse=%dM
`

func (s *System) writeJournalLimit(limit int64) error {
	if err := os.MkdirAll(filepath.Dir(s.Paths.JournalDropIn), 0o755); err != nil {
		return err
	}
	// The journal reads files ending in ".conf" and nothing else, so a
	// half-written file under this name is never read.
	temporary := s.Paths.JournalDropIn + ".new"
	if err := os.WriteFile(temporary, fmt.Appendf(nil, journalLimitText, limit>>20), 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, s.Paths.JournalDropIn)
}

// active reports whether the log folder is log2ram's space in memory now.
func (s *System) active() bool {
	data, err := os.ReadFile(s.Paths.Mounts)
	if err != nil {
		return false
	}
	for line := range strings.Lines(string(data)) {
		// source, mount point, type, ...
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == mountSource && fields[1] == s.Paths.LogDir {
			return true
		}
	}
	return false
}

var sizeLine = regexp.MustCompile(`^\s*SIZE\s*=\s*"?(\d+)([KMG]?)"?\s*$`)

// size is the space in memory log2ram is set to take, from its own settings.
func (s *System) size() int64 {
	file, err := os.Open(s.Paths.Conf)
	if err != nil {
		return defaultSize
	}
	defer file.Close()
	size := int64(defaultSize)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// The settings are a shell script: the last assignment counts.
		match := sizeLine.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		number, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil || number <= 0 {
			continue
		}
		switch match[2] {
		case "K":
			number <<= 10
		case "M":
			number <<= 20
		case "G":
			number <<= 30
		}
		size = number
	}
	return size
}

// memory is the device's memory, or 0 if that cannot be read.
func (s *System) memory() int64 {
	data, err := os.ReadFile(s.Paths.MemInfo)
	if err != nil {
		return 0
	}
	for line := range strings.Lines(string(data)) {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kilobytes, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0
			}
			return kilobytes << 10
		}
	}
	return 0
}

func (s *System) spaceOf(dir string) (size, used int64, err error) {
	if s.SpaceOf != nil {
		return s.SpaceOf(dir)
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, 0, err
	}
	block := int64(stat.Bsize)
	return int64(stat.Blocks) * block, int64(stat.Blocks-stat.Bfree) * block, nil
}

// usage measures the log folder the way log2ram does (what the files take,
// not their length): all of it, the journal's part, and the largest entries.
// What cannot be read is left out: an estimate that is a little low is
// better than none, and log2ram's own check at start-up is the one that
// counts.
func (s *System) usage() (total, journal int64, largest []Entry) {
	entries, err := os.ReadDir(s.Paths.LogDir)
	if err != nil {
		return 0, 0, nil
	}
	for _, entry := range entries {
		size := taken(filepath.Join(s.Paths.LogDir, entry.Name()))
		total += size
		if entry.Name() == "journal" {
			journal = size
		}
		if size > 0 {
			largest = append(largest, Entry{Name: entry.Name(), Bytes: size})
		}
	}
	sort.Slice(largest, func(i, j int) bool { return largest[i].Bytes > largest[j].Bytes })
	if len(largest) > largestCount {
		largest = largest[:largestCount]
	}
	return total, journal, largest
}

// taken is what a file, or a folder with everything in it, takes.
func taken(path string) int64 {
	var total int64
	filepath.WalkDir(path, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			// Not readable: go on with the rest.
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			// Counted in units of 512 bytes, whatever the file system's own.
			total += stat.Blocks * 512
		} else {
			total += info.Size()
		}
		return nil
	})
	return total
}

// megabytes writes a size the way the page does: "97 MB".
func megabytes(bytes int64) string {
	return strconv.FormatInt((bytes+(1<<19))>>20, 10) + " MB"
}

func lastLine(output []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		if runes := []rune(last); len(runes) > 240 {
			last = string(runes[:240]) + "…"
		}
		return last
	}
	return err.Error()
}
