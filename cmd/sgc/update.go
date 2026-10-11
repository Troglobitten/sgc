package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/release"
	"github.com/Troglobitten/sgc/internal/store"
	"github.com/Troglobitten/sgc/internal/update"
	"github.com/Troglobitten/sgc/internal/updater"
)

const (
	// The GitHub repository SGC's releases are published in.
	releaseRepository = "Troglobitten/sgc"
	// Environment variable naming another place to look for releases (see
	// update.MirrorSource). Releases from there must still carry a valid
	// signature and be newer than the installed version.
	updateSourceVariable = "SGC_UPDATE_SOURCE"

	settingLastReportedUpdate = "update.last_reported_id"
)

func newUpdateChecker(db *sql.DB, stateDir string, log *slog.Logger) (*update.Checker, error) {
	userAgent := "sgc/" + sgc.Version()
	source := update.GitHubSource(releaseRepository, userAgent)
	if address := os.Getenv(updateSourceVariable); address != "" {
		mirror, err := update.MirrorSource(address, userAgent)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", updateSourceVariable, err)
		}
		source = mirror
		log.Warn("looking for updates at a non-default source", "source", address)
	}
	keys, err := release.ParsePublicKeys(sgc.ReleasePublicKeyPEM())
	if err != nil {
		return nil, err
	}
	return update.NewChecker(update.Config{
		DB:             db,
		Source:         source,
		CurrentVersion: sgc.Version(),
		Arch:           runtime.GOARCH,
		TrustedKeys:    keys,
		StateDir:       stateDir,
		Log:            log,
	})
}

// reportUpdateOutcome writes the result of the last update into the audit
// log, once. The updater itself cannot: it runs as root, outside the
// database, and SGC is stopped while it works.
//
// SGC is started by the updater while the update is still in progress: the
// updater first waits for this very process to answer, and only then records
// success (or, failing that, rolls back and restarts the previous version).
// So at start the outcome is usually not known yet, and this waits for it.
func reportUpdateOutcome(ctx context.Context, db *sql.DB, auditLog *audit.Log, workDir string, log *slog.Logger) {
	// Longer than any update can take (see updateTimeout in sgc-helper).
	deadline := time.Now().Add(10 * time.Minute)
	for {
		status, err := updater.ReadStatus(workDir)
		if err != nil {
			log.Error("read update outcome", "error", err)
			return
		}
		if status == nil {
			return // no update was ever attempted
		}
		if status.State != updater.StateRunning {
			if err := recordUpdateOutcome(ctx, db, auditLog, status); err != nil {
				log.Error("record update outcome", "error", err)
			}
			return
		}
		if time.Now().After(deadline) {
			log.Error("the last update never recorded an outcome", "to", status.To)
			return
		}
		// Checked often: it is one small file, and the sooner the outcome is
		// in the audit log, the smaller the chance that something else (a
		// further update, a restart) happens before it is written down.
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// recordUpdateOutcome adds a finished update to the audit log unless that
// same attempt is already in it.
func recordUpdateOutcome(ctx context.Context, db *sql.DB, auditLog *audit.Log, status *updater.Status) error {
	id := strconv.FormatInt(status.ID, 10)
	reported, _, err := store.Setting(ctx, db, settingLastReportedUpdate)
	if err != nil || reported == id {
		return err
	}

	action := audit.ActionUpdateFailed
	switch status.State {
	case updater.StateSucceeded:
		action = audit.ActionUpdateSucceeded
	case updater.StateRolledBack:
		action = audit.ActionUpdateRolledBack
	}
	if err := auditLog.Record(ctx, audit.ActorSystem, action, status.Message, ""); err != nil {
		return err
	}
	return store.SetSetting(ctx, db, settingLastReportedUpdate, id)
}

// updateCommand is `sgc update`: look for a newer version and install it.
//
// It starts as root (it has to start the updater), but everything that
// touches the network or the database is done by a copy of itself running
// as the unprivileged service user. Root only starts the updater unit, which
// verifies the download again by itself.
func updateCommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sgc update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	checkOnly := flags.Bool("check", false, "only look for a newer version")
	yes := flags.Bool("yes", false, "install without asking")
	stateDir := flags.String("state-dir", defaultStateDir(), "folder for the database and certificate")
	// Internal: the part that runs as the service user. Prints the status as JSON.
	worker := flags.String("as-service-user", "", "")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "sgc: "+format+"\n", a...)
		return exitFailed
	}

	if *worker != "" {
		return updateWorker(ctx, *worker, *stateDir, stdout, stderr)
	}
	if os.Geteuid() != 0 {
		return fail("this command needs root. Run: sudo sgc update")
	}

	var status update.Status
	if err := runWorker(ctx, "check", *stateDir, &status, stderr); err != nil {
		return fail("%v", err)
	}
	if status.CheckError != "" {
		return fail("could not check for updates: %s", status.CheckError)
	}
	fmt.Fprintf(stdout, "Installed: SGC %s\n", status.Current)
	if !status.UpdateAvailable {
		fmt.Fprintln(stdout, "This is the newest version.")
		return exitOK
	}
	fmt.Fprintf(stdout, "Available: SGC %s\n", status.Latest)
	if notes := strings.TrimSpace(status.Notes); notes != "" {
		fmt.Fprintf(stdout, "\n%s\n", notes)
	}
	if *checkOnly {
		return exitOK
	}

	if !*yes {
		fmt.Fprintf(stdout, "\nInstall SGC %s now? SGC restarts; VPN, DNS and proxy keep running. [y/N] ", status.Latest)
		answer, _ := bufio.NewReader(stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Fprintln(stdout, "Nothing was changed.")
			return exitOK
		}
	}

	fmt.Fprintf(stdout, "Downloading and verifying SGC %s ...\n", status.Latest)
	if err := runWorker(ctx, "fetch:"+status.Latest, *stateDir, nil, stderr); err != nil {
		return fail("%v\nNothing was changed.", err)
	}

	fmt.Fprintln(stdout, "Installing ...")
	// Blocks until the update, including a possible rollback, has finished.
	// Its exit code is not the answer; the status it records is.
	exec.CommandContext(ctx, "/usr/bin/systemctl", "start", "sgc-update@"+status.Latest+".service").Run()
	outcome, err := updater.ReadStatus(layout.UpdateWorkDir)
	if err != nil || outcome == nil || outcome.To != status.Latest {
		return fail("the update did not report an outcome. Details: journalctl -u 'sgc-update@*' --no-pager -n 30")
	}
	fmt.Fprintln(stdout, outcome.Message)
	if outcome.State != updater.StateSucceeded {
		return exitFailed
	}
	return exitOK
}

// runWorker runs `sgc update --as-service-user <task>` as the service user
// and decodes the JSON it prints into out (if not nil).
func runWorker(ctx context.Context, task, stateDir string, out any, stderr io.Writer) error {
	account, err := user.Lookup(layout.ServiceUser)
	if err != nil {
		return fmt.Errorf("SGC does not seem to be installed: %w", err)
	}
	uid, _ := strconv.ParseUint(account.Uid, 10, 32)
	gid, _ := strconv.ParseUint(account.Gid, 10, 32)

	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, self, "update", "--as-service-user", task, "--state-dir", stateDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}},
	}
	// A minimal environment; the update source may be overridden for tests.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if source := os.Getenv(updateSourceVariable); source != "" {
		cmd.Env = append(cmd.Env, updateSourceVariable+"="+source)
	}
	cmd.Stderr = stderr
	output, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			// The worker has already explained the problem on stderr.
			return errors.New("the update could not be prepared")
		}
		return err
	}
	if out != nil {
		if err := json.Unmarshal(output, out); err != nil {
			return errors.New("unexpected answer while checking for updates")
		}
	}
	return nil
}

// updateWorker is the part of `sgc update` that runs as the service user.
// task is "check" or "fetch:<version>".
func updateWorker(ctx context.Context, task, stateDir string, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "sgc: %v\n", err)
		return exitFailed
	}
	syscall.Umask(0o077)
	db, err := store.Open(ctx, filepath.Join(stateDir, layout.DatabaseFile))
	if err != nil {
		return fail(err)
	}
	defer db.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	checker, err := newUpdateChecker(db, stateDir, log)
	if err != nil {
		return fail(err)
	}

	switch {
	case task == "check":
		status, err := checker.Check(ctx)
		if err != nil {
			return fail(err)
		}
		json.NewEncoder(stdout).Encode(status)
	case strings.HasPrefix(task, "fetch:"):
		version := strings.TrimPrefix(task, "fetch:")
		if err := audit.New(db).Record(ctx, audit.ActorConsole, audit.ActionUpdateStarted, "to "+version, ""); err != nil {
			return fail(err)
		}
		if err := checker.Fetch(ctx, version); err != nil {
			audit.New(db).Record(ctx, audit.ActorConsole, audit.ActionUpdateFailed, "to "+version+": "+err.Error(), "")
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("unknown task %q", task))
	}
	return exitOK
}
