package osupdate

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// go test ./internal/osupdate -update rewrites the expected files. Read the
// difference before committing it: it is a change to what installs by itself.
var update = flag.Bool("update", false, "rewrite the expected files in testdata")

func TestRender(t *testing.T) {
	for _, mode := range []Mode{Automatic, ByHand} {
		t.Run(string(mode), func(t *testing.T) {
			got := Render(mode)
			golden := filepath.Join("testdata", string(mode)+".conf")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("differs from %s:\n%s", golden, got)
			}

			// And the file says which mode it was written for.
			path := filepath.Join(t.TempDir(), "52sgc-updates")
			os.WriteFile(path, []byte(got), 0o644)
			if read, found, err := ReadMode(path); err != nil || !found || read != mode {
				t.Errorf("ReadMode: %q, %v, %v", read, found, err)
			}
		})
	}
}

func TestReadMode(t *testing.T) {
	dir := t.TempDir()
	if _, found, err := ReadMode(filepath.Join(dir, "missing")); found || err != nil {
		t.Errorf("a missing file: found %v, %v", found, err)
	}
	foreign := filepath.Join(dir, "foreign")
	os.WriteFile(foreign, []byte("APT::Periodic::Unattended-Upgrade \"1\";\n"), 0o644)
	if _, found, err := ReadMode(foreign); found || err == nil {
		t.Errorf("a file SGC did not write: found %v, %v", found, err)
	}
	unknown := filepath.Join(dir, "unknown")
	os.WriteFile(unknown, []byte("// sgc-mode: sometimes\n"), 0o644)
	if _, found, err := ReadMode(unknown); found || err == nil {
		t.Errorf("an unknown mode: found %v, %v", found, err)
	}
}

// The outputs in testdata were captured from unattended-upgrades 2.12 on
// Debian 13, with three updates waiting and with none.
func TestParseWaiting(t *testing.T) {
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	got, err := parseWaiting(read("dry-run-three-waiting.txt"))
	if err != nil || strings.Join(got, " ") != "liblzma5 libpng16-16t64 xz-utils" {
		t.Errorf("three waiting: %v, %v", got, err)
	}
	got, err = parseWaiting(read("dry-run-nothing-waiting.txt"))
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("nothing waiting: %v, %v", got, err)
	}

	cases := map[string]struct {
		output string
		want   string // "" means an error is wanted
	}{
		"only removals are pending":      {"Packages that will be upgraded: \n", "[]"},
		"an architecture on the name":    {"Packages that will be upgraded: libc6:arm64 linux-image-6.12.48+deb13-arm64\n", "[libc6:arm64 linux-image-6.12.48+deb13-arm64]"},
		"the tool said nothing":          {"Starting unattended upgrades script\n", ""},
		"no output at all":               {"", ""},
		"something that is not a name":   {"Packages that will be upgraded: bash <script>alert(1)</script>\n", ""},
		"a name with a capital letter":   {"Packages that will be upgraded: Bash\n", ""},
		"a path instead of a name":       {"Packages that will be upgraded: ../../etc/passwd\n", ""},
		"the sentence inside a line":     {"error: Packages that will be upgraded: bash\n", ""},
		"another language's sentence":    {"Pakete, die aktualisiert werden: bash\n", ""},
		"the lock is taken":              {"Lock could not be acquired (another package manager running?)\nCache lock can not be acquired, exiting\n", ""},
		"more names than can be right":   {"Packages that will be upgraded: " + strings.Repeat("pkg ", maxPackages+1) + "\n", ""},
		"a list right at the size limit": {"Packages that will be upgraded: " + strings.Repeat("pkg ", maxPackages) + "\n", "many"},
	}
	for name, c := range cases {
		got, err := parseWaiting([]byte(c.output))
		switch {
		case c.want == "" && err == nil:
			t.Errorf("%s: accepted as %v", name, got)
		case c.want == "many" && (err != nil || len(got) != maxPackages):
			t.Errorf("%s: %d names, %v", name, len(got), err)
		case c.want != "" && c.want != "many" && (err != nil || fmt.Sprint(got) != c.want):
			t.Errorf("%s: %v, %v; want %s", name, got, err, c.want)
		}
	}
}

func TestRestartNeeded(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{RestartFile: filepath.Join(dir, "reboot-required"), RestartPackages: filepath.Join(dir, "reboot-required.pkgs")}
	if needed, _ := RestartNeeded(paths); needed {
		t.Error("needed without the file")
	}
	os.WriteFile(paths.RestartFile, nil, 0o644)
	if needed, packages := RestartNeeded(paths); !needed || len(packages) != 0 {
		t.Errorf("with the file alone: %v %v", needed, packages)
	}
	os.WriteFile(paths.RestartPackages, []byte("linux-image-6.12.48+deb13-amd64\nlibc6\n<b>not a name</b>\n\n"), 0o644)
	if needed, packages := RestartNeeded(paths); !needed || strings.Join(packages, " ") != "linux-image-6.12.48+deb13-amd64 libc6" {
		t.Errorf("with packages: %v %v", needed, packages)
	}
}

// --- A stand-in for the device -------------------------------------------------------

// device stands in for a Debian machine: apt's settings with the rule that
// the last file read wins, Debian's timers, and an update tool that prints
// what the real one prints.
type device struct {
	t      *testing.T
	system *System
	now    time.Time
	calls  []string

	hasTool bool
	// What Debian's own files say (20auto-upgrades, 50unattended-upgrades).
	own map[string]string
	// A file on the device that apt reads after SGC's.
	later  map[string]string
	timers map[string]string // unit -> systemd's word for its state

	// The world.
	offline    bool
	lockTaken  bool
	waiting    []string // what the tool would install
	keptBack   []string // of those, what an installation leaves waiting
	breaksOn   string   // installing this package fails
	installed  []string
	dailyState string
	// Called while the tool installs, to do something in the middle.
	whileInstalling func()
}

func newDevice(t *testing.T) *device {
	t.Helper()
	dir := t.TempDir()
	d := &device{
		t:       t,
		now:     time.Date(2026, 10, 12, 14, 0, 0, 0, time.UTC),
		hasTool: true,
		own: map[string]string{
			"APT::Periodic::Update-Package-Lists": "1",
			"APT::Periodic::Unattended-Upgrade":   "1",
		},
		later:      map[string]string{},
		timers:     map[string]string{listsTimer: "active", installTimer: "active"},
		dailyState: "inactive",
	}
	for _, sub := range []string{"apt.conf.d", "requests", "periodic"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	d.system = &System{
		Paths: Paths{
			ConfigFile:      filepath.Join(dir, "apt.conf.d", "52sgc-updates"),
			RunDir:          filepath.Join(dir, "run"),
			ModeRequestFile: filepath.Join(dir, "requests", "mode.json"),
			JobRequestFile:  filepath.Join(dir, "requests", "job.json"),
			StampFile:       filepath.Join(dir, "periodic", "upgrade-stamp"),
			RestartFile:     filepath.Join(dir, "reboot-required"),
			RestartPackages: filepath.Join(dir, "reboot-required.pkgs"),
		},
		Run:    d.run,
		Exists: func(string) bool { return d.hasTool },
		Now:    func() time.Time { d.now = d.now.Add(time.Second); return d.now },
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return d
}

// settingsOf reads a settings file the way apt would, as far as these tests
// need: plain values and one list.
func settingsOf(content string) (values map[string]string, origins []string, err error) {
	values = map[string]string{}
	inList := false
	for line := range strings.Lines(content) {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "//"):
		case line == "Unattended-Upgrade::Origins-Pattern {":
			inList = true
		case line == "};":
			inList = false
		case inList:
			origins = append(origins, strings.Trim(strings.TrimSuffix(line, ";"), `"`))
		default:
			name, value, ok := strings.Cut(line, " ")
			if !ok || !strings.HasSuffix(value, ";") {
				return nil, nil, fmt.Errorf("Syntax error: %s", line)
			}
			values[name] = strings.Trim(strings.TrimSuffix(value, ";"), `"`)
		}
	}
	return values, origins, nil
}

func (d *device) aptConfig(extra string) ([]byte, error) {
	values := map[string]string{}
	origins := []string{"origin=Debian,codename=${distro_codename},label=Debian-Security"}
	set := func(more map[string]string) {
		for name, value := range more {
			values[name] = value
		}
	}
	file := func(path string) error {
		content, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		fileValues, fileOrigins, err := settingsOf(string(content))
		if err != nil {
			return err
		}
		set(fileValues)
		origins = append(origins, fileOrigins...)
		return nil
	}
	// The order apt reads in: Debian's own files, SGC's, any file that sorts
	// after SGC's, and last a file named with -c.
	set(d.own)
	err := file(d.system.Paths.ConfigFile)
	set(d.later)
	if err == nil && extra != "" {
		err = file(extra)
	}
	if err != nil {
		return []byte("E: " + err.Error() + "\n"), errors.New("exit status 100")
	}
	var b strings.Builder
	for name, value := range values {
		fmt.Fprintf(&b, "%s \"%s\";\n", name, value)
	}
	for _, origin := range origins {
		fmt.Fprintf(&b, "Unattended-Upgrade::Origins-Pattern:: \"%s\";\n", origin)
	}
	return []byte(b.String()), nil
}

func (d *device) run(ctx context.Context, _ time.Duration, program string, args ...string) ([]byte, error) {
	call := filepath.Base(program) + " " + strings.Join(args, " ")
	switch {
	case program == aptConfigProgram && args[0] == "dump":
		return d.aptConfig("")
	case program == aptConfigProgram && args[0] == "-c":
		return d.aptConfig(args[1])
	case program == systemctl && args[0] == "is-active":
		if args[1] == dailyService {
			return []byte(d.dailyState + "\n"), nil
		}
		return []byte(d.timers[args[1]] + "\n"), nil
	case program == systemctl && args[0] == "enable":
		d.calls = append(d.calls, call)
		d.timers[args[2]] = "active"
		return nil, nil
	case program == aptGetProgram:
		d.calls = append(d.calls, call)
		if d.offline {
			return []byte("W: Failed to fetch https://deb.debian.org/debian/dists/trixie/InRelease  Temporary failure resolving 'deb.debian.org'\n"), errors.New("exit status 100")
		}
		return []byte("Reading package lists...\n"), nil
	case program == ToolProgram:
		d.calls = append(d.calls, call)
		return d.tool(ctx, slices.Contains(args, "--dry-run"))
	}
	d.t.Errorf("unexpected program: %s", call)
	return nil, errors.New("unexpected")
}

// tool prints what unattended-upgrade prints.
func (d *device) tool(ctx context.Context, dryRun bool) ([]byte, error) {
	var b strings.Builder
	b.WriteString("Starting unattended upgrades script\n")
	b.WriteString("Allowed origins are: origin=Debian,codename=trixie,label=Debian\n")
	if d.lockTaken {
		b.WriteString("Lock could not be acquired (another package manager running?)\nCache lock can not be acquired, exiting\n")
		return []byte(b.String()), errors.New("exit status 1")
	}
	if len(d.waiting) == 0 {
		b.WriteString(nothingToDo + "\n")
		return []byte(b.String()), nil
	}
	if dryRun {
		b.WriteString("Option --dry-run given, *not* performing real actions\n")
	}
	b.WriteString(willUpgrade + strings.Join(d.waiting, " ") + "\n")
	if dryRun {
		b.WriteString("All upgrades installed\n")
		return []byte(b.String()), nil
	}
	if d.whileInstalling != nil {
		d.whileInstalling()
	}
	var left []string
	var failed error
	for _, name := range d.waiting {
		switch {
		case ctx.Err() != nil, failed != nil, slices.Contains(d.keptBack, name):
			left = append(left, name)
		case name == d.breaksOn:
			left = append(left, name)
			b.WriteString("Installing the upgrades failed!\nerror message: installArchives() failed\ndpkg returned a error! See /var/log/unattended-upgrades/unattended-upgrades-dpkg.log for details\n")
			failed = errors.New("exit status 1")
		default:
			d.installed = append(d.installed, name)
		}
	}
	d.waiting = left
	if failed == nil {
		b.WriteString("All upgrades installed\n")
	}
	return []byte(b.String()), failed
}

// dailyRun is Debian's own daily script having run the update tool.
func (d *device) dailyRun() {
	d.t.Helper()
	if err := os.WriteFile(d.system.Paths.StampFile, nil, 0o644); err != nil {
		d.t.Fatal(err)
	}
}

func (d *device) requestMode(automatic bool) error {
	d.t.Helper()
	data, _ := json.Marshal(ModeRequest{Automatic: automatic})
	if err := os.WriteFile(d.system.Paths.ModeRequestFile, data, 0o600); err != nil {
		d.t.Fatal(err)
	}
	return d.system.SetMode(context.Background())
}

func (d *device) job(ctx context.Context, job string, id int64) Report {
	d.t.Helper()
	data, _ := json.Marshal(JobRequest{Job: job, ID: id})
	if err := os.WriteFile(d.system.Paths.JobRequestFile, data, 0o600); err != nil {
		d.t.Fatal(err)
	}
	announced := false
	err := d.system.RunJob(ctx, func() {
		announced = true
		if report := d.report(); report.Running != job || report.RunningID != id || report.RunningSince == nil {
			d.t.Errorf("when the job said it was ready, the report said: %+v", report)
		}
	})
	if err != nil {
		d.t.Fatal(err)
	}
	if !announced {
		d.t.Fatal("the job never said it was running")
	}
	report := d.report()
	if report.Running != "" || report.RunningID != 0 || report.RunningSince != nil {
		d.t.Errorf("the finished job is still reported as running: %+v", report)
	}
	return report
}

func (d *device) report() Report {
	d.t.Helper()
	report, err := ReadReport(d.system.Paths)
	if err != nil {
		d.t.Fatal(err)
	}
	return report
}

func (d *device) settings() Settings {
	d.t.Helper()
	settings, err := d.system.Settings(context.Background())
	if err != nil {
		d.t.Fatal(err)
	}
	return settings
}

func (d *device) configFile() string {
	data, _ := os.ReadFile(d.system.Paths.ConfigFile)
	return string(data)
}

// --- The mode ----------------------------------------------------------------------

func TestSettingTheMode(t *testing.T) {
	d := newDevice(t)
	// A Debian that installs updates by itself, as its cloud images do.
	if s := d.settings(); !s.Daily() || s.Overridden != "" {
		t.Fatalf("to begin with: %+v", s)
	}

	if err := d.requestMode(false); err != nil {
		t.Fatal(err)
	}
	if d.configFile() != Render(ByHand) {
		t.Errorf("the file written:\n%s", d.configFile())
	}
	if s := d.settings(); s.Daily() || s.Periodic || s.Overridden != "" {
		t.Errorf("by hand: %+v", s)
	}
	if outcome, found, err := ReadModeOutcome(d.system.Paths); err != nil || !found || outcome.Mode != ByHand || outcome.Error != "" {
		t.Errorf("outcome: %+v, %v, %v", outcome, found, err)
	}
	if len(d.calls) != 0 {
		t.Errorf("timers that were running were touched: %v", d.calls)
	}

	// On a device whose owner switched Debian's timers off.
	d.timers[listsTimer], d.timers[installTimer] = "inactive", "inactive"
	if err := d.requestMode(true); err != nil {
		t.Fatal(err)
	}
	if d.configFile() != Render(Automatic) {
		t.Errorf("the file written:\n%s", d.configFile())
	}
	if s := d.settings(); !s.Daily() {
		t.Errorf("automatic: %+v", s)
	}
	want := "systemctl enable --now " + listsTimer + ",systemctl enable --now " + installTimer
	if got := strings.Join(d.calls, ","); got != want {
		t.Errorf("timers: %s", got)
	}

	// By hand, the lists are still fetched daily; the other timer is left alone.
	d.calls = nil
	d.timers[listsTimer], d.timers[installTimer] = "inactive", "inactive"
	if err := d.requestMode(false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(d.calls, ","); got != "systemctl enable --now "+listsTimer {
		t.Errorf("timers by hand: %s", got)
	}
	// No temporary file is left where apt reads its settings.
	entries, _ := os.ReadDir(filepath.Dir(d.system.Paths.ConfigFile))
	if len(entries) != 1 {
		t.Errorf("files in apt's folder: %v", entries)
	}
}

func TestOnADeviceThatNeverHadAutomaticUpdates(t *testing.T) {
	d := newDevice(t)
	d.own = map[string]string{} // no 20auto-upgrades
	if s := d.settings(); s.Daily() {
		t.Fatalf("to begin with: %+v", s)
	}
	if err := d.requestMode(true); err != nil {
		t.Fatal(err)
	}
	if s := d.settings(); !s.Daily() || s.Overridden != "" {
		t.Errorf("automatic: %+v", s)
	}

	d.hasTool = false
	if err := d.requestMode(true); !errors.Is(err, ErrNoTool) {
		t.Errorf("without the tool: %v", err)
	}
	if s := d.settings(); s.Daily() || s.ToolInstalled {
		t.Errorf("without the tool: %+v", s)
	}
}

// Another file on the device, read after SGC's, says otherwise. SGC's file
// would then be a claim that is not true, so it is not left there.
func TestAModeThatWouldNotHoldIsNotKept(t *testing.T) {
	d := newDevice(t)
	d.later["APT::Periodic::Unattended-Upgrade"] = "0"

	err := d.requestMode(true)
	if err == nil || !strings.Contains(err.Error(), "APT::Periodic::Unattended-Upgrade") || !strings.Contains(err.Error(), "52sgc-updates") {
		t.Fatalf("an overruled setting: %v", err)
	}
	if _, statErr := os.Stat(d.system.Paths.ConfigFile); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("the file that does not hold was left in place")
	}
	if outcome, _, _ := ReadModeOutcome(d.system.Paths); outcome.Error == "" {
		t.Error("the reason was not recorded")
	}

	// With a file of SGC's already there, that one comes back.
	d.later = map[string]string{}
	if err := d.requestMode(false); err != nil {
		t.Fatal(err)
	}
	d.later["Unattended-Upgrade::Automatic-Reboot"] = "true"
	if err := d.requestMode(true); err == nil || !strings.Contains(err.Error(), "Automatic-Reboot") {
		t.Fatalf("an overruled restart setting: %v", err)
	}
	if d.configFile() != Render(ByHand) {
		t.Errorf("the previous file was not put back:\n%s", d.configFile())
	}
	// And Settings says so when the other file appears later.
	d.later = map[string]string{"APT::Periodic::Enable": "0"}
	if s := d.settings(); s.Overridden != "APT::Periodic::Enable" || s.Daily() {
		t.Errorf("settings with a later file: %+v", s)
	}
}

func TestARequestWithAnythingElseInItIsRefused(t *testing.T) {
	d := newDevice(t)
	os.WriteFile(d.system.Paths.ModeRequestFile, []byte(`{"automatic":true,"origins":["origin=*"]}`), 0o600)
	if err := d.system.SetMode(context.Background()); err == nil {
		t.Error("a request with an extra field was accepted")
	}
	if d.configFile() != "" {
		t.Error("something was written")
	}
	os.WriteFile(d.system.Paths.JobRequestFile, []byte(`{"job":"install","id":1,"packages":["bash"]}`), 0o600)
	if err := d.system.RunJob(context.Background(), func() {}); err == nil {
		t.Error("a job with an extra field was accepted")
	}
	os.WriteFile(d.system.Paths.JobRequestFile, []byte(`{"job":"remove","id":1}`), 0o600)
	if err := d.system.RunJob(context.Background(), func() {}); err == nil {
		t.Error("an unknown job was accepted")
	}
	if len(d.calls) != 0 {
		t.Errorf("programs were run: %v", d.calls)
	}
}

// --- Looking and installing ----------------------------------------------------------

func TestLooking(t *testing.T) {
	d := newDevice(t)
	d.waiting = []string{"liblzma5", "xz-utils"}
	report := d.job(context.Background(), JobCheck, 1)
	if strings.Join(report.Waiting, " ") != "liblzma5 xz-utils" || report.CheckedAt == nil || report.CheckError != "" {
		t.Fatalf("report: %+v", report)
	}
	// The lists are fetched in the way that makes a missing connection a
	// failure and not a warning.
	if got := strings.Join(d.calls, ","); got != "apt-get -q -o APT::Update::Error-Mode=any update,unattended-upgrade --dry-run -v" {
		t.Errorf("programs run: %s", got)
	}
	if len(d.installed) != 0 {
		t.Error("looking installed something")
	}
	checked := *report.CheckedAt

	// No connection: said so, and what was known before stays.
	d.offline = true
	report = d.job(context.Background(), JobCheck, 2)
	if !strings.Contains(report.CheckError, "connected to the internet") || report.CheckFailedAt == nil {
		t.Errorf("offline: %+v", report)
	}
	if strings.Join(report.Waiting, " ") != "liblzma5 xz-utils" || !report.CheckedAt.Equal(checked) {
		t.Errorf("offline, what was known before: %+v", report)
	}

	// Debian's own daily run has the lock.
	d.offline, d.lockTaken = false, true
	report = d.job(context.Background(), JobCheck, 3)
	if !strings.Contains(report.CheckError, "Another installation of packages is running") {
		t.Errorf("lock taken: %+v", report)
	}

	// A look that works again clears the complaint.
	d.lockTaken, d.waiting = false, nil
	report = d.job(context.Background(), JobCheck, 4)
	if report.CheckError != "" || report.CheckFailedAt != nil || len(report.Waiting) != 0 || !report.CheckedAt.After(checked) {
		t.Errorf("afterwards: %+v", report)
	}

	// Without the tool there is nothing to ask.
	d.hasTool = false
	report = d.job(context.Background(), JobCheck, 5)
	if !strings.Contains(report.CheckError, "unattended-upgrades") {
		t.Errorf("without the tool: %+v", report)
	}
}

func TestInstalling(t *testing.T) {
	d := newDevice(t)
	d.waiting = []string{"liblzma5", "libpng16-16t64", "xz-utils"}
	d.whileInstalling = func() {
		// Somebody asking in the middle sees what is being installed.
		if report := d.report(); report.Running != JobInstall || len(report.Waiting) != 3 {
			t.Errorf("in the middle: %+v", report)
		}
	}
	report := d.job(context.Background(), JobInstall, 7)
	last := report.LastInstall
	if last == nil || last.ID != 7 || last.Result != ResultOK || strings.Join(last.Packages, " ") != "liblzma5 libpng16-16t64 xz-utils" {
		t.Fatalf("installation: %+v", last)
	}
	if !last.FinishedAt.After(last.StartedAt) || len(report.Waiting) != 0 || report.CheckedAt == nil {
		t.Errorf("report: %+v, installation %+v", report, last)
	}
	want := "apt-get -q -o APT::Update::Error-Mode=any update,unattended-upgrade --dry-run -v,unattended-upgrade -v,unattended-upgrade --dry-run -v"
	if got := strings.Join(d.calls, ","); got != want {
		t.Errorf("programs run: %s", got)
	}
	// What SGC starts is not taken for Debian's own daily run. That one
	// leaves a mark of its own.
	if s := d.settings(); s.LastRun != nil {
		t.Error("an installation started by SGC is shown as Debian's daily run")
	}
	d.dailyRun()
	if s := d.settings(); s.LastRun == nil {
		t.Error("Debian's daily run is not shown")
	}

	// Nothing waiting: nothing is installed, and that is not a failure.
	d.calls, d.whileInstalling = nil, nil
	report = d.job(context.Background(), JobInstall, 8)
	if last := report.LastInstall; last.ID != 8 || last.Result != ResultOK || len(last.Packages) != 0 || last.Message == "" {
		t.Errorf("nothing waiting: %+v", last)
	}
	if got := strings.Join(d.calls, ","); got != "apt-get -q -o APT::Update::Error-Mode=any update,unattended-upgrade --dry-run -v" {
		t.Errorf("programs run with nothing waiting: %s", got)
	}

	// The tool leaves a package for a person (a changed settings file, say).
	d.waiting, d.keptBack = []string{"openssh-server", "tzdata"}, []string{"openssh-server"}
	report = d.job(context.Background(), JobInstall, 9)
	if last := report.LastInstall; last.Result != ResultOK || strings.Join(last.Packages, " ") != "tzdata" {
		t.Errorf("one kept back: %+v", last)
	}
	if strings.Join(report.Waiting, " ") != "openssh-server" {
		t.Errorf("still waiting: %v", report.Waiting)
	}
}

func TestAnInstallationThatFails(t *testing.T) {
	d := newDevice(t)
	d.waiting, d.breaksOn = []string{"libc6", "broken-package", "tzdata"}, "broken-package"
	report := d.job(context.Background(), JobInstall, 1)
	last := report.LastInstall
	if last.Result != ResultFailed || !strings.Contains(last.Message, "Installing failed") || !strings.Contains(last.Message, "journalctl -u sgc-os-updates") {
		t.Fatalf("installation: %+v", last)
	}
	// What did get installed is still told, and what is left is still shown.
	if strings.Join(last.Packages, " ") != "libc6" || strings.Join(report.Waiting, " ") != "broken-package tzdata" {
		t.Errorf("installed %v, waiting %v", last.Packages, report.Waiting)
	}

	// No connection: nothing is tried.
	d = newDevice(t)
	d.waiting, d.offline = []string{"libc6"}, true
	report = d.job(context.Background(), JobInstall, 2)
	if last := report.LastInstall; last.Result != ResultFailed || !strings.Contains(last.Message, "connected to the internet") || len(d.installed) != 0 {
		t.Errorf("offline: %+v", last)
	}

	// The device shuts down in the middle.
	d = newDevice(t)
	d.waiting = []string{"libc6", "tzdata"}
	ctx, cancel := context.WithCancel(context.Background())
	d.whileInstalling = cancel
	report = d.job(ctx, JobInstall, 3)
	if last := report.LastInstall; last.Result != ResultFailed || !strings.Contains(last.Message, "shutting down") {
		t.Errorf("stopped in the middle: %+v", last)
	}
	if strings.Join(report.Waiting, " ") != "libc6 tzdata" {
		t.Errorf("stopped in the middle, waiting: %v", report.Waiting)
	}
}

// The job's process is killed. What runs after it must leave a report that
// nobody waits on.
func TestAJobThatDiedIsCleanedUp(t *testing.T) {
	d := newDevice(t)
	since := d.now
	os.MkdirAll(d.system.Paths.RunDir, 0o755)
	if err := d.system.writeReport(Report{Running: JobInstall, RunningID: 42, RunningSince: &since, Waiting: []string{"libc6"}}); err != nil {
		t.Fatal(err)
	}
	if err := d.system.Finished(); err != nil {
		t.Fatal(err)
	}
	report := d.report()
	if report.Running != "" || report.LastInstall == nil || report.LastInstall.ID != 42 || report.LastInstall.Result != ResultFailed {
		t.Fatalf("after a killed installation: %+v, %+v", report, report.LastInstall)
	}
	if strings.Join(report.Waiting, " ") != "libc6" {
		t.Errorf("what was known was lost: %v", report.Waiting)
	}

	// After a job that finished by itself there is nothing to do, and the
	// outcome it recorded stays.
	d.waiting = []string{"tzdata"}
	finished := d.job(context.Background(), JobInstall, 43)
	if err := d.system.Finished(); err != nil {
		t.Fatal(err)
	}
	if after := d.report(); after.LastInstall.ID != 43 || after.LastInstall.Result != finished.LastInstall.Result {
		t.Errorf("a finished job's outcome was changed: %+v", after.LastInstall)
	}

	// A look that died leaves no invented installation behind.
	d.system.writeReport(Report{Running: JobCheck, RunningID: 44, RunningSince: &since})
	d.system.Finished()
	if after := d.report(); after.Running != "" || after.LastInstall != nil {
		t.Errorf("after a killed look: %+v", after)
	}
}

func TestSettingsWhileDebianIsAtWork(t *testing.T) {
	d := newDevice(t)
	d.dailyState = "activating" // how systemd calls a one-shot job that is running
	if s := d.settings(); !s.DailyRunning {
		t.Errorf("settings: %+v", s)
	}
	d.dailyState = "inactive"
	d.timers[installTimer] = "inactive"
	if s := d.settings(); s.DailyRunning || s.Timers || s.Daily() {
		t.Errorf("with a stopped timer: %+v", s)
	}
}
