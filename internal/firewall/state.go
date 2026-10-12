package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Paths says where the firewall's files are. All of them belong to root and
// are readable by everyone: the web process reads them to show the state,
// and cannot change them.
type Paths struct {
	// ConfirmedFile is the ruleset the owner confirmed. It is what loads
	// when the machine starts. Missing: SGC never set up a firewall here.
	ConfirmedFile string
	// RunDir holds what only matters until the next restart: a change
	// waiting for confirmation, and how the last change ended. It is in
	// memory (/run), so a restart always comes back with the confirmed rules.
	RunDir string
	// RequestFile is where the root helper puts what the web process asked
	// for, after checking it.
	RequestFile string
}

func DefaultPaths() Paths {
	return Paths{
		ConfirmedFile: "/etc/sgc/firewall.nft",
		RunDir:        "/run/sgc-firewall",
		RequestFile:   "/run/sgc-requests/firewall.json",
	}
}

func (p Paths) pendingFile() string  { return filepath.Join(p.RunDir, "pending.json") }
func (p Paths) pendingRules() string { return filepath.Join(p.RunDir, "pending.nft") }
func (p Paths) outcomeFile() string  { return filepath.Join(p.RunDir, "last.json") }
func (p Paths) lockFile() string     { return filepath.Join(p.RunDir, "lock") }

// Pending is a change that is in effect but not confirmed yet.
type Pending struct {
	// ID tells changes apart: the start time in milliseconds.
	ID        int64     `json:"id"`
	Config    Config    `json:"config"`
	StartedAt time.Time `json:"startedAt"`
	// DeadlineUptime is when the change is undone, in seconds since the
	// machine started. Not a time of day: the clock can jump (a Raspberry Pi
	// has no battery clock and corrects its time after start-up), and a
	// jump must neither cut the confirmation time short nor stretch it.
	DeadlineUptime float64 `json:"deadlineUptime"`
}

// How a change ended.
const (
	ResultConfirmed = "confirmed"
	// ResultExpired: nobody confirmed in time, so it was undone.
	ResultExpired = "expired"
	// ResultUndone: undone on request, or because the waiting was interrupted.
	ResultUndone = "undone"
	// ResultFailed: it could not be put into effect at all.
	ResultFailed = "failed"
)

// Outcome is how the most recent change ended.
type Outcome struct {
	ID      int64     `json:"id"`
	Result  string    `json:"result"`
	Message string    `json:"message,omitempty"`
	At      time.Time `json:"at"`
}

// State is what the firewall's files say.
type State struct {
	Confirmed *Config
	Pending   *Pending
	Last      *Outcome
}

// SecondsLeft is how long a pending change still waits for confirmation.
func (p *Pending) SecondsLeft(uptime float64) int {
	left := p.DeadlineUptime - uptime
	if left <= 0 {
		return 0
	}
	return int(left + 0.999)
}

// ReadState reads the firewall's files. It needs no privileges.
func ReadState(paths Paths) (State, error) {
	var state State

	ruleset, err := os.ReadFile(paths.ConfirmedFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return state, err
	default:
		cfg, err := ParseConfig(ruleset)
		if err != nil {
			return state, fmt.Errorf("%s: %w", paths.ConfirmedFile, err)
		}
		state.Confirmed = &cfg
	}

	var pending Pending
	if found, err := readJSONFile(paths.pendingFile(), &pending); err != nil {
		return state, err
	} else if found {
		state.Pending = &pending
	}
	var last Outcome
	if found, err := readJSONFile(paths.outcomeFile(), &last); err != nil {
		return state, err
	} else if found {
		state.Last = &last
	}
	return state, nil
}

// Uptime returns the seconds since the machine started.
func Uptime() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errors.New("/proc/uptime is empty")
	}
	return strconv.ParseFloat(fields[0], 64)
}

const maxStateFile = 64 * 1024

func readJSONFile(path string, v any) (found bool, err error) {
	data, err := readSmallFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}

// readSmallFile reads a plain file without following a symbolic link.
func readSmallFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStateFile {
		return nil, fmt.Errorf("%s is larger than expected", path)
	}
	return data, nil
}

// writeFileAtomic replaces a file so that a reader, or a power cut, finds
// either the old content or the new, never half of it. With durable set the
// new content is on the disk before this returns, which matters for the
// confirmed rules: they must survive pulling the plug a second later.
func writeFileAtomic(path string, data []byte, durable bool) error {
	temporary := path + ".new"
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(temporary)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	// The mode given at creation is subject to the umask; make it exact.
	if err := f.Chmod(0o644); err != nil {
		return fail(err)
	}
	if durable {
		if err := f.Sync(); err != nil {
			return fail(err)
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return err
	}
	if durable {
		// The rename itself is recorded in the folder.
		if dir, err := os.Open(filepath.Dir(path)); err == nil {
			dir.Sync()
			dir.Close()
		}
	}
	return nil
}

func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), false)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
