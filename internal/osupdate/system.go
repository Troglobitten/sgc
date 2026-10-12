package osupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// How long the programs may take. Looking at apt's settings is immediate;
// fetching lists and packages depends on the line, installing on the device
// (a kernel on a Raspberry Pi with an SD card takes many minutes).
const (
	quick          = 30 * time.Second
	listsTimeout   = 10 * time.Minute
	lookTimeout    = 45 * time.Minute // includes downloading what is waiting
	installTimeout = 150 * time.Minute
)

var ErrNoTool = errors.New("Debian's tool for installing updates (unattended-upgrades) is not on this device")

// System carries out the root side's work. It runs as root, in units of its
// own (installer/sgc-os-updates*.service), except Settings, which only reads.
type System struct {
	Paths Paths

	// Run runs a program for at most limit and returns what it printed.
	// When ctx is cancelled the program is asked to stop and waited for, not
	// killed: a package installation must be allowed to finish its step.
	// Injected so that the tests need neither root nor apt.
	Run    func(ctx context.Context, limit time.Duration, program string, args ...string) ([]byte, error)
	Exists func(program string) bool
	Now    func() time.Time
	Log    *slog.Logger
}

// --- What the device does now ------------------------------------------------------

// Settings is what apt's settings amount to, all its files taken together,
// and whether Debian's daily machinery is running.
type Settings struct {
	// ToolInstalled is false on a device that has never had automatic
	// updates (a fresh Raspberry Pi OS Lite, for one).
	ToolInstalled bool `json:"toolInstalled"`
	// Periodic: apt's settings say "install updates every day".
	Periodic bool `json:"periodic"`
	// Timers: both of Debian's daily timers are running.
	Timers bool `json:"timers"`
	// Overridden names a setting of SGC's that another file overrules, if
	// SGC's file is in place and one is.
	Overridden string `json:"overridden,omitempty"`
	// LastRun is when Debian's own daily run last ran the update tool. Looks
	// and installations started from SGC's page do not count.
	LastRun *time.Time `json:"lastRun,omitempty"`
	// DailyRunning: Debian's own daily run is in progress.
	DailyRunning bool `json:"dailyRunning"`
}

// Daily reports whether updates install by themselves on this device.
func (s Settings) Daily() bool { return s.ToolInstalled && s.Periodic && s.Timers }

func (s *System) Settings(ctx context.Context) (Settings, error) {
	settings := Settings{ToolInstalled: s.Exists(ToolProgram)}
	effective, err := s.effective(ctx, "")
	if err != nil {
		return settings, err
	}
	settings.Periodic = effective.daily()
	settings.Timers = s.unitState(ctx, listsTimer) == "active" && s.unitState(ctx, installTimer) == "active"
	if mode, found, err := ReadMode(s.Paths.ConfigFile); err == nil && found {
		settings.Overridden = effective.differsFrom(mode)
	}
	if info, err := os.Stat(s.Paths.StampFile); err == nil {
		at := info.ModTime().UTC()
		settings.LastRun = &at
	}
	state := s.unitState(ctx, dailyService)
	settings.DailyRunning = state == "active" || state == "activating"
	return settings, nil
}

// unitState is systemd's one word for a unit: active, inactive, activating...
func (s *System) unitState(ctx context.Context, unit string) string {
	// The exit code says "not active" in several ways; the word is what counts.
	output, _ := s.Run(ctx, quick, systemctl, "is-active", unit)
	return strings.TrimSpace(string(output))
}

// aptSettings are the values of apt's configuration, as "apt-config dump"
// prints them: one line per value, lists as several lines with the same name.
type aptSettings map[string][]string

func (a aptSettings) last(name string) string {
	if values := a[name]; len(values) > 0 {
		return values[len(values)-1]
	}
	return ""
}

// on reads a value the way apt's daily script reads its switches: unset and
// "0" are off, anything else (a number of days, "always") is on.
func (a aptSettings) on(name string, unset bool) bool {
	value := a.last(name)
	if value == "" {
		return unset
	}
	return value != "0"
}

func (a aptSettings) daily() bool {
	return a.on("APT::Periodic::Enable", true) && a.on("APT::Periodic::Unattended-Upgrade", false)
}

// differsFrom names the first setting that is not what SGC's file for this
// mode says, or returns "".
func (a aptSettings) differsFrom(mode Mode) string {
	switch {
	case !a.on("APT::Periodic::Enable", true):
		return "APT::Periodic::Enable"
	case !a.on("APT::Periodic::Update-Package-Lists", false):
		return "APT::Periodic::Update-Package-Lists"
	case a.on("APT::Periodic::Unattended-Upgrade", false) != (mode == Automatic):
		return "APT::Periodic::Unattended-Upgrade"
	case a.last("Unattended-Upgrade::Automatic-Reboot") != "false":
		return "Unattended-Upgrade::Automatic-Reboot"
	case !slices.Contains(a["Unattended-Upgrade::Origins-Pattern::"], PiArchive):
		return "Unattended-Upgrade::Origins-Pattern"
	}
	return ""
}

// effective asks apt what its settings amount to. With extra, a file that is
// not among them yet is read as well, after all the others; that is also the
// check that apt can read the file at all.
func (s *System) effective(ctx context.Context, extra string) (aptSettings, error) {
	args := []string{"dump"}
	if extra != "" {
		args = []string{"-c", extra, "dump"}
	}
	output, err := s.Run(ctx, quick, aptConfigProgram, args...)
	if err != nil {
		return nil, fmt.Errorf("apt does not accept its settings: %s", lastLine(output, err))
	}
	settings := aptSettings{}
	for line := range strings.Lines(string(output)) {
		name, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		value = strings.TrimSuffix(strings.TrimSpace(value), ";")
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = value[1 : len(value)-1]
		}
		settings[name] = append(settings[name], value)
	}
	return settings, nil
}

// --- Changing the mode ---------------------------------------------------------------

// ModeOutcome is how the latest change of mode ended.
type ModeOutcome struct {
	Mode  Mode      `json:"mode"`
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
}

func (p Paths) modeOutcomeFile() string { return p.RunDir + "/mode.json" }

// ReadModeOutcome reads how the latest change of mode ended; found is false
// if there has been none since the device started.
func ReadModeOutcome(paths Paths) (outcome ModeOutcome, found bool, err error) {
	found, err = readJSONFile(paths.modeOutcomeFile(), &outcome)
	return outcome, found, err
}

// SetMode writes SGC's settings file for the requested mode and makes sure
// Debian's daily timers run. The file is checked by apt before it is written
// and its effect is checked afterwards; if another file on the device
// overrules it, the previous state is put back.
//
// An error means nothing was changed. Why is in the outcome file.
func (s *System) SetMode(ctx context.Context) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	var request ModeRequest
	if err := readStrict(s.Paths.ModeRequestFile, &request); err != nil {
		return fmt.Errorf("read the request: %w", err)
	}
	mode := request.Mode()
	err = s.setMode(ctx, mode)
	outcome := ModeOutcome{Mode: mode, At: s.Now().UTC()}
	if err != nil {
		outcome.Error = err.Error()
	}
	if writeErr := writeJSONFile(s.Paths.modeOutcomeFile(), outcome); writeErr != nil {
		s.Log.Error("record how the change ended", "error", writeErr)
	}
	if err == nil {
		s.Log.Info("updates for the device set up", "mode", mode)
	}
	return err
}

func (s *System) setMode(ctx context.Context, mode Mode) error {
	if !s.Exists(ToolProgram) {
		return ErrNoTool
	}
	content := []byte(Render(mode))

	// apt's own reading of the file, before it is anywhere apt would find it.
	candidate := filepath.Join(s.Paths.RunDir, "candidate.conf")
	if err := writeFileAtomic(candidate, content); err != nil {
		return err
	}
	defer os.Remove(candidate)
	if _, err := s.effective(ctx, candidate); err != nil {
		return err
	}

	previous, readErr := readSmallFile(s.Paths.ConfigFile)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	putBack := func() {
		var err error
		if readErr != nil {
			err = removeIfExists(s.Paths.ConfigFile)
		} else {
			err = writeFileAtomic(s.Paths.ConfigFile, previous)
		}
		if err != nil {
			s.Log.Error("put the previous settings back", "error", err)
		}
	}

	if err := writeFileAtomic(s.Paths.ConfigFile, content); err != nil {
		return err
	}
	// And what it amounts to with every other file on the device.
	effective, err := s.effective(ctx, "")
	if err != nil {
		putBack()
		return err
	}
	if name := effective.differsFrom(mode); name != "" {
		putBack()
		return fmt.Errorf("another settings file on this device overrules SGC's (%s). "+
			"Look in %s for a file whose name sorts after %s", name, filepath.Dir(s.Paths.ConfigFile), filepath.Base(s.Paths.ConfigFile))
	}

	// The lists are fetched daily in both modes; the installation timer only
	// matters when updates install by themselves, and is otherwise left as
	// it is (it also runs Debian's cleaning up).
	timers := []string{listsTimer}
	if mode == Automatic {
		timers = append(timers, installTimer)
	}
	for _, timer := range timers {
		if s.unitState(ctx, timer) == "active" {
			continue
		}
		if output, err := s.Run(ctx, quick, systemctl, "enable", "--now", timer); err != nil {
			putBack()
			return fmt.Errorf("Debian's daily timer %s could not be started: %s", timer, lastLine(output, err))
		}
	}
	return nil
}

// --- Looking and installing ------------------------------------------------------------

// RunJob carries out the requested job and keeps the report up to date
// while it does. ready is called once the report says the job is running;
// whoever started the job waits for that.
//
// A look or an installation that fails for a reason of the world's (no
// connection, another installation in progress) is recorded in the report
// and is not an error here: the unit has done its work. An error means the
// report could not be kept.
func (s *System) RunJob(ctx context.Context, ready func()) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	var request JobRequest
	if err := readStrict(s.Paths.JobRequestFile, &request); err != nil {
		return fmt.Errorf("read the request: %w", err)
	}
	if (request.Job != JobCheck && request.Job != JobInstall) || request.ID <= 0 {
		return fmt.Errorf("unknown job %q", request.Job)
	}
	report, err := ReadReport(s.Paths)
	if err != nil {
		// A report that cannot be read is replaced, not obeyed.
		s.Log.Warn("the previous report could not be read", "error", err)
		report = Report{Waiting: []string{}}
	}
	started := s.Now().UTC()
	report.Running, report.RunningID, report.RunningSince = request.Job, request.ID, &started
	if err := s.writeReport(report); err != nil {
		return err
	}
	ready()

	if request.Job == JobInstall {
		s.install(ctx, &report, request.ID, started)
	} else {
		s.check(ctx, &report)
	}
	report.Running, report.RunningID, report.RunningSince = "", 0, nil
	return s.writeReport(report)
}

// look fetches Debian's lists and asks the tool what it would install. The
// tool downloads those packages while it is at it, which an installation
// right afterwards then need not do.
func (s *System) look(ctx context.Context) ([]string, error) {
	if !s.Exists(ToolProgram) {
		return nil, ErrNoTool
	}
	// By default apt-get reports lists it could not fetch as warnings, carries
	// on with the old ones and says all is well. A look made without a
	// connection would then present yesterday's state as today's. Asked
	// this way, it fails instead. (Found on the test machine.)
	if output, err := s.Run(ctx, listsTimeout, aptGetProgram, "-q", "-o", "APT::Update::Error-Mode=any", "update"); err != nil {
		return nil, errors.New(explain(output, err))
	}
	return s.wouldInstall(ctx)
}

func (s *System) wouldInstall(ctx context.Context) ([]string, error) {
	output, err := s.Run(ctx, lookTimeout, ToolProgram, "--dry-run", "-v")
	if err != nil {
		return nil, errors.New(explain(output, err))
	}
	return parseWaiting(output)
}

func (s *System) check(ctx context.Context, report *Report) {
	waiting, err := s.look(ctx)
	now := s.Now().UTC()
	if err != nil {
		s.Log.Warn("looking for updates failed", "error", err)
		report.CheckError, report.CheckFailedAt = sentence(err), &now
		return
	}
	s.Log.Info("looked for updates", "waiting", len(waiting))
	report.Waiting, report.CheckedAt = waiting, &now
	report.CheckError, report.CheckFailedAt = "", nil
}

func (s *System) install(ctx context.Context, report *Report, id int64, started time.Time) {
	install := &Install{ID: id, StartedAt: started, Packages: []string{}, Result: ResultOK}
	finish := func() {
		install.FinishedAt = s.Now().UTC()
		report.LastInstall = install
		s.Log.Info("installation of updates ended", "result", install.Result, "packages", len(install.Packages), "message", install.Message)
	}
	fail := func(err error) {
		install.Result, install.Message = ResultFailed, sentence(err)
		finish()
	}

	before, err := s.look(ctx)
	if err != nil {
		fail(err)
		return
	}
	now := s.Now().UTC()
	report.Waiting, report.CheckedAt = before, &now
	report.CheckError, report.CheckFailedAt = "", nil
	if len(before) == 0 {
		install.Message = "Nothing was waiting."
		finish()
		return
	}
	// Seen by anyone who asks while the installation runs.
	if err := s.writeReport(*report); err != nil {
		s.Log.Error("keep the report", "error", err)
	}

	output, runErr := s.Run(ctx, installTimeout, ToolProgram, "-v")
	// What is left afterwards is the truth about what was installed,
	// whatever the tool's exit code says. Looked at even if this job is
	// being stopped: it takes a moment and changes nothing.
	after, lookErr := s.wouldInstall(context.WithoutCancel(ctx))
	if lookErr == nil {
		now := s.Now().UTC()
		report.Waiting, report.CheckedAt = after, &now
		for _, name := range before {
			if !slices.Contains(after, name) {
				install.Packages = append(install.Packages, name)
			}
		}
	}
	switch {
	case ctx.Err() != nil:
		fail(errors.New("the installation was stopped before it had finished, because the device was shutting down. What is left installs with the next one"))
	case runErr != nil:
		fail(errors.New(explain(output, runErr)))
	case lookErr != nil:
		fail(fmt.Errorf("the updates were installed, but what is left could not be worked out: %w", lookErr))
	default:
		finish()
	}
}

// Finished runs after the job's process has ended, however it ended. If the
// report still says a job is running, that process died in the middle; the
// report is put right, so that nobody waits for a job that is gone.
func (s *System) Finished() error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	report, err := ReadReport(s.Paths)
	if err != nil {
		report = Report{Waiting: []string{}}
	}
	if report.Running == "" {
		return nil
	}
	s.Log.Warn("the job ended without finishing its report", "job", report.Running)
	if report.Running == JobInstall && (report.LastInstall == nil || report.LastInstall.ID != report.RunningID) {
		started := s.Now().UTC()
		if report.RunningSince != nil {
			started = *report.RunningSince
		}
		report.LastInstall = &Install{
			ID: report.RunningID, StartedAt: started, FinishedAt: s.Now().UTC(), Packages: []string{},
			Result: ResultFailed, Message: "The installation was interrupted. Look again to see what is left; installing again continues where it stopped.",
		}
	}
	report.Running, report.RunningID, report.RunningSince = "", 0, nil
	return s.writeReport(report)
}

func (s *System) writeReport(report Report) error {
	if report.Waiting == nil {
		report.Waiting = []string{}
	}
	if err := writeJSONFile(s.Paths.reportFile(), report); err != nil {
		return fmt.Errorf("keep the report: %w", err)
	}
	return nil
}

// sentence makes an error message presentable: capital first letter, full stop.
func sentence(err error) string {
	msg := err.Error()
	if msg == "" {
		return msg
	}
	msg = strings.ToUpper(msg[:1]) + msg[1:]
	if !strings.HasSuffix(msg, ".") && !strings.HasSuffix(msg, "?") {
		msg += "."
	}
	return msg
}

// lock makes the jobs take turns.
func (s *System) lock() (unlock func(), err error) {
	if err := os.MkdirAll(s.Paths.RunDir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Paths.RunDir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// --- Careful file handling -------------------------------------------------------

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

// readStrict reads a request: a file that must exist and hold exactly the
// expected fields.
func readStrict(path string, v any) error {
	data, err := readSmallFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// writeFileAtomic replaces a file so that a reader, or a power cut, finds
// either the old content or the new. Mode 0644: apt's settings and the
// report are for everyone to read.
//
// The temporary file's name ends in "~": apt skips such files in its
// settings folder without a word, so one left behind by a power cut neither
// counts as settings nor makes every apt command print a notice.
func writeFileAtomic(path string, data []byte) error {
	temporary := path + "~"
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
	if err := f.Chmod(0o644); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return err
	}
	return nil
}

func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
