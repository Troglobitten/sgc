package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Troglobitten/sgc/internal/firewall"
	"github.com/Troglobitten/sgc/internal/helper"
	"github.com/Troglobitten/sgc/internal/osupdate"
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
