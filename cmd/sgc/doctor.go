package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc"
	"github.com/Troglobitten/sgc/internal/doctor"
	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/sshd"
)

// doctorCommand is `sgc doctor`: look at every part of SGC on this machine
// and say what is wrong and what to do about it.
//
// It asks the machine directly (systemd, the firewall, the disk) rather
// than SGC's web interface, because this is what one runs when that
// interface does not answer. Each milestone adds the checks for what it
// brings.
func doctorCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sgc doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", defaultStateDir(), "folder for the database and certificate")
	// Internal: the part that runs as the service user.
	worker := flags.String("as-service-user", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: sgc doctor")
		return exitUsage
	}
	if *worker != "" {
		return doctorWorker(ctx, *worker, *stateDir, stdout, stderr)
	}
	// Reading the firewall's live rules and the state of other users'
	// services needs root.
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "sgc: this command needs root. Run: sudo sgc doctor")
		return exitFailed
	}
	hostname, _ := os.Hostname()
	fmt.Fprintf(stdout, "SGC %s on %s\n\n", sgc.Version(), hostname)

	results := doctor.Run(ctx, []doctor.Check{
		checkService,
		checkPage,
		checkHelper,
		checkFailedUnits,
		checkStorage,
		checkClock,
		checkFirewall,
		checkSSH,
		checkOSUpdates,
		checkDNS,
		checkLog2ram,
		checkDomain(*stateDir),
		checkCertificate(*stateDir),
		checkNames(*stateDir),
		checkProxy(*stateDir),
		checkVPN(*stateDir),
		checkBackupsAndSoftware(*stateDir),
		checkPorts,
	})
	if doctor.Print(stdout, results) > 0 {
		return exitFailed
	}
	return exitOK
}

// ask runs a program with fixed arguments and returns what it printed.
func ask(ctx context.Context, program string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	// English answers, whatever the system's language: some are compared.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func one(r doctor.Result) []doctor.Result { return []doctor.Result{r} }

const serviceLog = "Its log: sudo journalctl -u sgc --no-pager -n 30"

func checkService(ctx context.Context) []doctor.Result {
	// is-active prints the state and fails for anything but "active".
	state, err := ask(ctx, "/usr/bin/systemctl", "is-active", "sgc.service")
	if err == nil {
		return one(doctor.Good("The SGC service is running"))
	}
	return one(doctor.Bad(fmt.Sprintf("The SGC service is not running (systemd says: %s)", state),
		"Start it: sudo systemctl start sgc\n"+serviceLog))
}

func checkPage(ctx context.Context) []doctor.Result {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			// SGC's own certificate, on this machine itself; nothing secret is sent.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	port := strconv.Itoa(layout.WebPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort("127.0.0.1", port)+"/api/state", nil)
	if err != nil {
		return one(doctor.Bad(err.Error(), ""))
	}
	resp, err := client.Do(req)
	if err != nil {
		return one(doctor.Bad("SGC's page does not answer on port "+port, serviceLog))
	}
	defer resp.Body.Close()
	var state struct {
		Version string `json:"version"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&state) != nil {
		return one(doctor.Bad(fmt.Sprintf("SGC's page answers on port %s, but not as expected (status %d)", port, resp.StatusCode), serviceLog))
	}
	if state.Version != sgc.Version() {
		return one(doctor.Warn(
			fmt.Sprintf("SGC's page answers as version %s, but the installed programs are %s", state.Version, sgc.Version()),
			"Restart SGC: sudo systemctl restart sgc"))
	}
	return one(doctor.Good("SGC's page answers on port " + port))
}

func checkHelper(ctx context.Context) []doctor.Result {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := helper.NewClient(layout.HelperSocket).Ping(ctx); err != nil {
		return one(doctor.Bad("The root helper does not answer: restarting the device, updating and changing the firewall from SGC's page will not work",
			"Restart it: sudo systemctl restart sgc-helper.socket\nIts log: sudo journalctl -u sgc-helper --no-pager -n 30"))
	}
	return one(doctor.Good("The root helper answers"))
}

func checkFailedUnits(ctx context.Context) []doctor.Result {
	output, err := ask(ctx, "/usr/bin/systemctl", "list-units", "--failed", "--plain", "--no-legend", "sgc*")
	if err != nil {
		return one(doctor.Warn("systemd could not be asked which parts of SGC have failed", output))
	}
	var failed []string
	for line := range strings.Lines(output) {
		if fields := strings.Fields(line); len(fields) > 0 {
			failed = append(failed, fields[0])
		}
	}
	if len(failed) == 0 {
		return one(doctor.Good("No part of SGC is in a failed state"))
	}
	return one(doctor.Warn("In a failed state: "+strings.Join(failed, ", "),
		"What happened: sudo systemctl status "+failed[0]+" --no-pager"))
}

func checkStorage(context.Context) []doctor.Result {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(layout.StateDir, &stat); err != nil {
		return one(doctor.Bad("SGC's folder "+layout.StateDir+" cannot be read: "+err.Error(), ""))
	}
	free := stat.Bavail * uint64(stat.Bsize)
	total := stat.Blocks * uint64(stat.Bsize)
	summary := fmt.Sprintf("Storage: %.1f GB free of %.1f GB", float64(free)/1e9, float64(total)/1e9)
	const advice = "What takes the space: sudo du -xh / --max-depth=2 2>/dev/null | sort -h | tail -n 15"
	switch {
	case total == 0:
		return one(doctor.Bad("SGC's folder is on storage that reports no size", ""))
	case free < 200e6 || free*100 < total*3:
		return one(doctor.Bad(summary+": nearly full, SGC may stop working", advice))
	case free < 1e9 || free*100 < total*10:
		return one(doctor.Warn(summary+": getting full", advice))
	}
	return one(doctor.Good(summary))
}

func checkClock(ctx context.Context) []doctor.Result {
	answer, err := ask(ctx, "/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value")
	if err == nil && answer == "yes" {
		return one(doctor.Good("The clock is synchronised"))
	}
	// Right after start-up that is simply how it is, for some seconds.
	if uptime, err := sshd.Uptime(); err == nil && uptime < 120 {
		return one(doctor.Good(fmt.Sprintf("The clock is about to be set from the network (the device started %d seconds ago)", int(uptime))))
	}
	return one(doctor.Warn("The clock is not synchronised with the internet",
		"Certificates and updates depend on the right time. Check: timedatectl status"))
}

func checkSSH(ctx context.Context) []doctor.Result {
	state, err := sshd.ReadState(sshd.DefaultPaths())
	if err != nil {
		return one(doctor.Bad("What SGC has set up for SSH cannot be read: "+err.Error(),
			"Put it back in order: sudo sgc ssh allow-passwords, then set it up again in SGC's page"))
	}
	status, err := consoleSSH().Status(ctx)
	switch {
	case err != nil:
		return one(doctor.Bad("The SSH server could not be asked about its settings: "+err.Error(),
			"Its own check says more: sudo sshd -t"))
	case !status.Installed:
		return one(doctor.Good("This device has no SSH server"))
	}

	var results []doctor.Result
	if !status.Running {
		results = append(results, doctor.Warn("The SSH server is not running",
			"Start it: sudo systemctl start ssh"))
	}
	settings := status.Settings
	open := settings.PasswordLogins || settings.RootLogin != "no"
	switch {
	case state.Pending != nil && state.Pending.NeedsProof:
		results = append(results, doctor.Warn("A change to SSH is in effect and waits for a login with a key",
			"Log in over SSH with your key. Without that it is undone by itself two minutes after it was made."))
	case state.Confirmed.KeysOnly && open:
		results = append(results, doctor.Bad("\"Keys only\" is switched on, but the SSH server accepts passwords or root",
			"Put SGC's settings back in place: sudo systemctl start sgc-ssh"))
	case state.Confirmed.KeysOnly:
		results = append(results, doctor.Good("SSH accepts keys only, and nobody logs in as root"))
	case settings.PasswordLogins:
		results = append(results, doctor.Warn("SSH accepts passwords",
			"Add your key in SGC's page (System), log in with it, then switch to \"keys only\" there."))
	default:
		results = append(results, doctor.Good("SSH does not accept passwords (by this device's own settings)"))
	}
	if n := len(state.Confirmed.Keys); n > 0 {
		// The file the SSH server reads must be the one SGC confirmed.
		file := sshd.DefaultPaths().KeysDir + "/" + state.Confirmed.Account
		data, err := os.ReadFile(file)
		installed := 0
		for _, key := range state.Confirmed.Keys {
			if err == nil && strings.Contains(string(data), key.Line()) {
				installed++
			}
		}
		if installed != n {
			results = append(results, doctor.Bad(fmt.Sprintf("Of the %d key(s) added in SGC's page, %d are in place for the account %s", n, installed, state.Confirmed.Account),
				"Put them back in place: sudo systemctl start sgc-ssh"))
		} else {
			results = append(results, doctor.Good(fmt.Sprintf("The %d key(s) added in SGC's page are in place for the account %s", n, state.Confirmed.Account)))
		}
	}
	return results
}

func checkFirewall(ctx context.Context) []doctor.Result {
	state, err := firewall.ReadState(firewall.DefaultPaths())
	if err != nil {
		return one(doctor.Bad("The firewall's saved state cannot be read: "+err.Error(),
			"Start afresh: sudo sgc firewall off, then switch it on again in SGC's page"))
	}
	system := consoleFirewall()
	loaded, loadedErr := system.TableLoaded(ctx)
	on := state.Confirmed != nil && state.Confirmed.Enabled

	switch {
	case state.Pending != nil:
		return one(doctor.Warn("A firewall change is in effect and waiting for confirmation",
			"Confirm it in SGC's page. Without confirmation it is undone by itself a minute after it was made."))
	case on && loadedErr != nil:
		return one(doctor.Bad("The firewall is switched on, but nftables could not be asked whether its rules are loaded: "+loadedErr.Error(), ""))
	case on && !loaded:
		return one(doctor.Bad("The firewall is switched on, but its rules are not loaded",
			"Load them: sudo systemctl restart sgc-firewall"))
	case !on && loaded:
		return one(doctor.Warn("The firewall is switched off, but rules of it are still loaded",
			"Remove them: sudo sgc firewall off"))
	case !on:
		return one(doctor.Warn("The firewall is off: this device answers every request that reaches it",
			"Switch it on in SGC's page."))
	}

	results := one(doctor.Good("The firewall is on, and its rules are loaded"))
	// The rules must also come back after a restart. Either way of being
	// part of start-up is enough (see installer/sgc.service).
	enabled, _ := ask(ctx, "/usr/bin/systemctl", "is-enabled", "sgc-firewall.service")
	wants, _ := ask(ctx, "/usr/bin/systemctl", "show", "--property=Wants", "--value", "sgc.service")
	serviceEnabled, _ := ask(ctx, "/usr/bin/systemctl", "is-enabled", "sgc.service")
	if enabled == "enabled" || (serviceEnabled == "enabled" && strings.Contains(wants, "sgc-firewall.service")) {
		return append(results, doctor.Good("The firewall's rules load at every start-up"))
	}
	return append(results, doctor.Bad("The firewall's rules would not load after a restart",
		"Make them part of start-up: sudo systemctl enable sgc-firewall"))
}
