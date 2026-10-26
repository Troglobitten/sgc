package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/log2ram"
	"github.com/Troglobitten/sgc/internal/osupdate"
	"github.com/Troglobitten/sgc/internal/public"
	"github.com/Troglobitten/sgc/internal/wireguard"
)

const (
	packagesUnit = "sgc-packages.service"
	aptGet       = "/usr/bin/apt-get"
	// Where the helper says which feature's packages the unit is to install.
	packagesRequestFile = "/run/sgc-requests/packages.json"
)

type debianPackage struct {
	name string
	// program shows that the package is installed.
	program string
}

// requiredPackages are the Debian packages SGC's features need and a clean
// Debian may not bring, by feature.
//
// This is the whole of what the web process can cause to be installed: a
// request names a feature, never a package. The packages come from the
// Debian archive the machine is already set up to trust.
//
// One feature at a time, and only when that feature is switched on:
// installing unattended-upgrades, for one, makes Debian install updates by
// itself from then on, which nobody who switches on the firewall asked for.
var requiredPackages = map[string][]debianPackage{
	helper.PackagesFirewall: {{"nftables", firewall.NftProgram}},
	helper.PackagesUpdates:  {{"unattended-upgrades", osupdate.ToolProgram}},
	// rsync is what log2ram copies with. Without it log2ram falls back to a
	// way of copying that never removes a log from the disk again, so that
	// the logs on the disk only grow.
	helper.PackagesLog2ram: {{"log2ram", log2ram.DefaultPaths().Program}, {"rsync", "/usr/bin/rsync"}},
	// WireGuard itself is in the kernel; wg is its tool. The VPN's own
	// firewall table needs nftables, also with SGC's firewall off.
	helper.PackagesVPN: {{"wireguard-tools", wireguard.WG}, {"nftables", firewall.NftProgram}},
	// For services reachable from the internet. It brings Python with it.
	helper.PackagesFail2ban: {{"fail2ban", "/usr/bin/fail2ban-client"}},
}

type packagesRequest struct {
	For string `json:"for"`
}

// installPackages is the helper service's side: say which feature, run the
// unit and wait for it. feature is one of the names above (internal/helper
// lets nothing else through, and the unit looks again).
func installPackages(feature string) error {
	if _, known := requiredPackages[feature]; !known {
		return fmt.Errorf("unknown feature %q", feature)
	}
	if err := handOver(packagesRequestFile, packagesRequest{For: feature}); err != nil {
		return err
	}
	if err := runSystemctl("start", packagesUnit); err != nil {
		return errors.New("details: journalctl -u sgc-packages --no-pager -n 30")
	}
	return nil
}

// handOver puts a request where the unit that carries it out reads it: a
// folder only root can enter (RuntimeDirectory= in sgc-helper.service), so
// that what the unit reads is what was checked here.
func handOver(path string, request any) error {
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return fmt.Errorf("hand over the request: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("hand over the request: %w", err)
	}
	return nil
}

// runPackages is "sgc-helper packages" (sgc-packages.service).
func runPackages() error {
	if os.Geteuid() != 0 {
		return errors.New("installing packages needs root")
	}
	data, err := os.ReadFile(packagesRequestFile)
	if err != nil {
		return fmt.Errorf("read the request: %w", err)
	}
	var request packagesRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("read the request: %w", err)
	}
	wanted, known := requiredPackages[request.For]
	if !known {
		return fmt.Errorf("unknown feature %q", request.For)
	}

	var missing []string
	for _, p := range wanted {
		if !programExists(p.program) {
			missing = append(missing, p.name)
		}
	}
	if len(missing) == 0 {
		fmt.Println("nothing to install")
		return nil
	}
	fmt.Println("installing:", strings.Join(missing, " "))
	// Debian's fail2ban starts as soon as it is installed, with its SSH jail
	// on: a few wrong SSH logins from home would then lock that address out
	// of the device. SGC's own settings are put in place first, with that
	// jail and SGC's own switched off (internal/public).
	if slices.Contains(missing, "fail2ban") {
		files, err := public.Fail2banFileSet(public.Defaults().Fail2ban, nil)
		if err != nil {
			return err
		}
		if _, err := public.WriteFail2banFiles(public.DefaultPaths().Fail2banDir, files); err != nil {
			return fmt.Errorf("put SGC's settings for fail2ban in place: %w", err)
		}
	}

	install := append([]string{"install", "--yes", "--no-install-recommends"}, missing...)
	if err := apt(install...); err != nil {
		// A machine that has never fetched Debian's package lists does not
		// know the package exists. Fetch them and try once more.
		fmt.Println("that did not work; refreshing the package lists and trying again")
		if err := apt("update"); err != nil {
			return fmt.Errorf("refresh the package lists: %w", err)
		}
		if err := apt(install...); err != nil {
			return fmt.Errorf("install %s: %w", strings.Join(missing, " "), err)
		}
	}
	for _, p := range wanted {
		if !programExists(p.program) {
			return fmt.Errorf("%s was installed, but %s is still missing", p.name, p.program)
		}
	}
	// Debian's log2ram package makes itself part of start-up when it is
	// installed: at the next restart the logs would be in memory. Whether
	// they are is the owner's choice in SGC's page, so a log2ram that was
	// installed just now is switched off again at once. (It was not started:
	// the package leaves that to a restart.)
	if slices.Contains(missing, "log2ram") {
		if err := runSystemctl("disable", log2ram.ServiceUnit, log2ram.TimerUnit); err != nil {
			return fmt.Errorf("log2ram was installed, but could not be switched off again: %w", err)
		}
	}
	// fail2ban is switched on in SGC's page, with internet access.
	if slices.Contains(missing, "fail2ban") {
		if err := runSystemctl("disable", "--now", "fail2ban.service"); err != nil {
			return fmt.Errorf("fail2ban was installed, but could not be switched off again: %w", err)
		}
	}
	return nil
}

// apt runs apt-get with fixed options. Its output goes to the unit's log.
func apt(args ...string) error {
	// Another package operation may be running (the daily automatic one, for
	// example); wait for it instead of failing.
	options := []string{"-q", "-o", "DPkg::Lock::Timeout=300"}
	cmd := exec.Command(aptGet, append(options, args...)...)
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		// Never stop to ask a question: there is nobody to answer it.
		"DEBIAN_FRONTEND=noninteractive",
		"LC_ALL=C",
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
