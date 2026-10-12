// Package osupdate is the root side of "updates for the device": Debian's
// packages, as opposed to SGC itself (internal/update and internal/updater).
//
// SGC does not install packages. Debian has a tool for installing updates
// without a person, unattended-upgrades, and this package only does two
// things with it:
//
//   - It writes one settings file for it (see Render), which says whether the
//     tool runs by itself once a day and adds Raspberry Pi's archive to what
//     it may install.
//   - It runs the tool on request: once to look at what is waiting, once to
//     install it (see System).
//
// The owner chooses between updates that install by themselves and updates
// started in SGC's page. In both cases the same tool installs the same set,
// so the two can never disagree about what "the updates" are.
//
// Nothing here can lock anybody out, so there is no confirm-or-undo as for
// the firewall. A change of settings is checked before it is written and
// again afterwards, and put back if it does not hold.
package osupdate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Mode is who starts the installation of updates.
type Mode string

const (
	// Automatic: Debian's tool runs by itself once a day.
	Automatic Mode = "automatic"
	// ByHand: the tool runs when the owner presses the button in SGC's page.
	ByHand Mode = "by-hand"
)

// ModeRequest is everything the web process can ask about the settings: one
// yes or no. The file is rendered here, by the root side.
type ModeRequest struct {
	Automatic bool `json:"automatic"`
}

func (r ModeRequest) Mode() Mode {
	if r.Automatic {
		return Automatic
	}
	return ByHand
}

// The jobs that run the update tool.
const (
	JobCheck   = "check"   // refresh Debian's lists and see what is waiting
	JobInstall = "install" // the same, and install it
)

// JobRequest is what the helper hands to the unit that runs the tool. The
// web process chooses the job, from the two above; the helper makes the ID.
type JobRequest struct {
	Job string `json:"job"`
	ID  int64  `json:"id"`
}

// Paths says where everything is.
type Paths struct {
	// ConfigFile is SGC's file among apt's settings. apt reads the files of
	// that folder in the order of their names and the last word counts, so
	// the name puts it after Debian's own (20auto-upgrades,
	// 50unattended-upgrades).
	ConfigFile string
	// RunDir holds the report of the latest look and installation. Readable
	// by everyone; gone after a restart, like the knowledge in it.
	RunDir string
	// Where the helper puts what the web process asked for.
	ModeRequestFile string
	JobRequestFile  string
	// StampFile is touched by Debian's daily script each time it has run the
	// update tool: the sign that updates really do install by themselves.
	// (The tool keeps a stamp of its own, which is no use for that: a look
	// started by SGC touches it as well. Found on the test machine.)
	StampFile string
	// RestartFile exists when an installed update needs a restart to take
	// effect; RestartPackages lists which ones asked for it.
	RestartFile     string
	RestartPackages string
}

func DefaultPaths() Paths {
	return Paths{
		ConfigFile:      "/etc/apt/apt.conf.d/52sgc-updates",
		RunDir:          "/run/sgc-os-updates",
		ModeRequestFile: "/run/sgc-requests/os-updates-mode.json",
		JobRequestFile:  "/run/sgc-requests/os-updates-job.json",
		StampFile:       "/var/lib/apt/periodic/upgrade-stamp",
		RestartFile:     "/run/reboot-required",
		RestartPackages: "/run/reboot-required.pkgs",
	}
}

func (p Paths) reportFile() string { return p.RunDir + "/report.json" }

// The programs this package runs, and the units it looks at.
const (
	ToolProgram      = "/usr/bin/unattended-upgrade"
	aptConfigProgram = "/usr/bin/apt-config"
	aptGetProgram    = "/usr/bin/apt-get"
	systemctl        = "/usr/bin/systemctl"

	// Debian's two daily timers: the first fetches the lists of what exists,
	// the second starts the installation.
	listsTimer   = "apt-daily.timer"
	installTimer = "apt-daily-upgrade.timer"
	// The service the second timer starts.
	dailyService = "apt-daily-upgrade.service"
)

// PiArchive is added to what the update tool may install from. A Raspberry
// Pi's kernel and firmware come from this archive, not from Debian, and it
// has no separate channel for security fixes. The values are those of its
// release file (Origin, Label); on any other machine the line matches
// nothing. ${distro_codename} is filled in by the tool itself.
const PiArchive = "origin=Raspberry Pi Foundation,codename=${distro_codename},label=Raspberry Pi Foundation"

const modeMarker = "// sgc-mode: "

// Render returns SGC's settings file for a mode. It depends on the mode
// alone, so writing it twice gives the same file (the expected files are in
// testdata).
//
// What is not in it stays as Debian has it: which of Debian's own archives
// count (Debian's 50unattended-upgrades: security fixes and point releases),
// at what hour the daily run happens, what is cleaned up afterwards.
func Render(mode Mode) string {
	daily := "0"
	if mode == Automatic {
		daily = "1"
	}
	var b strings.Builder
	b.WriteString("// Written by SGC (Server Gateway Control). Do not edit: SGC writes this file\n")
	b.WriteString("// again from its own settings. Change them on SGC's System page.\n")
	b.WriteString(modeMarker + string(mode) + "\n")
	b.WriteString("\n")
	b.WriteString("// Debian's lists of what exists are fetched every day in both modes.\n")
	b.WriteString("APT::Periodic::Enable \"1\";\n")
	b.WriteString("APT::Periodic::Update-Package-Lists \"1\";\n")
	b.WriteString("// \"1\": updates install by themselves once a day. \"0\": only when the\n")
	b.WriteString("// owner starts them in SGC's page.\n")
	b.WriteString("APT::Periodic::Unattended-Upgrade \"" + daily + "\";\n")
	b.WriteString("\n")
	b.WriteString("// Restarting the device after an update is SGC's business, not the\n")
	b.WriteString("// update tool's.\n")
	b.WriteString("Unattended-Upgrade::Automatic-Reboot \"false\";\n")
	b.WriteString("\n")
	b.WriteString("// In addition to what Debian's own settings allow. A Raspberry Pi's kernel\n")
	b.WriteString("// and firmware come from this archive. Elsewhere the line matches nothing.\n")
	b.WriteString("Unattended-Upgrade::Origins-Pattern {\n")
	b.WriteString("\t\"" + PiArchive + "\";\n")
	b.WriteString("};\n")
	return b.String()
}

// ReadMode reports which mode SGC's settings file was written for. found is
// false if SGC has not written one: the device then does whatever its own
// settings say. It needs no privileges.
func ReadMode(path string) (mode Mode, found bool, err error) {
	data, err := readSmallFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	for line := range strings.Lines(string(data)) {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), strings.TrimSpace(modeMarker))
		if !ok {
			continue
		}
		switch Mode(strings.TrimSpace(value)) {
		case Automatic:
			return Automatic, true, nil
		case ByHand:
			return ByHand, true, nil
		}
	}
	return "", false, fmt.Errorf("%s is not a file SGC wrote", path)
}

// --- What the update tool says -------------------------------------------------

// The tool has no output meant for programs. These are the two sentences it
// prints (with LC_ALL=C, which this package always sets) when it has worked
// out what to do. They are checked against the real tool by the whole-machine
// test, on every run.
const (
	willUpgrade = "Packages that will be upgraded: "
	nothingToDo = "No packages found that can be upgraded unattended and no pending auto-removals"
)

// Debian's rule for package names, with the architecture the tool sometimes
// adds ("libc6:arm64").
var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,127}(:[a-z0-9-]{1,31})?$`)

// maxPackages is far more than a release ever updates at once; a longer list
// means something other than a list was read.
const maxPackages = 5000

// parseWaiting reads from the tool's output which packages it would upgrade.
// Anything that is not a package name is an error, not an entry: the names
// go on to SGC's page and its history.
func parseWaiting(output []byte) ([]string, error) {
	packages := []string{}
	found := false
	for line := range strings.Lines(string(output)) {
		line = strings.TrimSpace(line)
		if line == nothingToDo {
			found = true
			continue
		}
		list, ok := strings.CutPrefix(line+" ", willUpgrade)
		if !ok {
			continue
		}
		found = true
		for _, name := range strings.Fields(list) {
			if !packageName.MatchString(name) {
				return nil, fmt.Errorf("the update tool named a package SGC cannot read: %q", truncate(name, 60))
			}
			packages = append(packages, name)
		}
	}
	if !found {
		return nil, errors.New("the update tool did not say what is waiting")
	}
	if len(packages) > maxPackages {
		return nil, errors.New("the update tool named more packages than can be right")
	}
	return packages, nil
}

// explain turns a failed run of apt or the tool into words for the owner.
func explain(output []byte, err error) string {
	text := string(output)
	switch {
	case strings.Contains(text, "Lock could not be acquired"), strings.Contains(text, "Lock file is already taken"),
		strings.Contains(text, "Could not get lock"):
		return "another installation of packages is running on the device (perhaps the daily one). Try again in a few minutes"
	case strings.Contains(text, "failed to download"), strings.Contains(text, "Failed to fetch"),
		strings.Contains(text, "Temporary failure resolving"), strings.Contains(text, "Could not resolve"),
		strings.Contains(text, "Unable to connect"), strings.Contains(text, "Some index files failed to download"):
		return "Debian's servers could not be reached. Is the device connected to the internet?"
	case strings.Contains(text, "Installing the upgrades failed"), strings.Contains(text, "dpkg returned"):
		return "installing failed. The details are in the device's log (sudo journalctl -u sgc-os-updates --no-pager -n 60)"
	}
	return "the update tool stopped with an error: " + lastLine(output, err) + ". The details are in the device's log (sudo journalctl -u sgc-os-updates --no-pager -n 60)"
}

func lastLine(output []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		return truncate(last, 200)
	}
	if err != nil {
		return err.Error()
	}
	return "no message"
}

func truncate(text string, max int) string {
	if runes := []rune(text); len(runes) > max {
		return string(runes[:max]) + "…"
	}
	return text
}

// --- The report ----------------------------------------------------------------

// How an installation ended.
const (
	ResultOK     = "ok"
	ResultFailed = "failed"
)

// Install is one installation started on request.
type Install struct {
	ID         int64     `json:"id"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	// Packages are the ones that were waiting before and are not any more.
	Packages []string `json:"packages"`
	Result   string   `json:"result"`
	Message  string   `json:"message,omitempty"`
}

// Report is what the root side knows from running the update tool.
type Report struct {
	// Running is the job in progress, JobCheck or JobInstall; empty if none.
	Running      string     `json:"running,omitempty"`
	RunningID    int64      `json:"runningId,omitempty"`
	RunningSince *time.Time `json:"runningSince,omitempty"`

	// Waiting are the packages the latest successful look found waiting, and
	// CheckedAt is when that was. Nil: nobody has looked since the device
	// started.
	CheckedAt *time.Time `json:"checkedAt,omitempty"`
	Waiting   []string   `json:"waiting"`
	// CheckError says why the latest look failed, if it did. Waiting is then
	// what an earlier look found.
	CheckError    string     `json:"checkError,omitempty"`
	CheckFailedAt *time.Time `json:"checkFailedAt,omitempty"`

	// LastInstall is the latest installation started on request.
	LastInstall *Install `json:"lastInstall,omitempty"`
}

// ReadReport reads the report. It needs no privileges. A missing report is
// an empty one.
func ReadReport(paths Paths) (Report, error) {
	report := Report{Waiting: []string{}}
	if _, err := readJSONFile(paths.reportFile(), &report); err != nil {
		return report, err
	}
	if report.Waiting == nil {
		report.Waiting = []string{}
	}
	return report, nil
}

// RestartNeeded reports whether an installed update waits for a restart, and
// which packages asked for one. Debian's packages say so by creating a file
// in /run, which is therefore gone after the restart. It needs no privileges.
func RestartNeeded(paths Paths) (needed bool, packages []string) {
	packages = []string{}
	if _, err := os.Lstat(paths.RestartFile); err != nil {
		return false, packages
	}
	data, err := readSmallFile(paths.RestartPackages)
	if err != nil {
		return true, packages
	}
	for line := range strings.Lines(string(data)) {
		// Written by package scripts; only names are passed on.
		if name := strings.TrimSpace(line); packageName.MatchString(name) && len(packages) < 50 {
			packages = append(packages, name)
		}
	}
	return true, packages
}

// --- Careful file handling -------------------------------------------------------

const maxSmallFile = 256 * 1024

// readSmallFile reads a plain file without following a symbolic link.
func readSmallFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSmallFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSmallFile {
		return nil, fmt.Errorf("%s is larger than expected", path)
	}
	return data, nil
}
