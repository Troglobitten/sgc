package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Troglobitten/sgc/internal/firewall"
)

const (
	packagesUnit = "sgc-packages.service"
	aptGet       = "/usr/bin/apt-get"
)

// requiredPackages are the Debian packages SGC needs that a clean Debian
// does not bring, each with the program that shows it is installed.
//
// This list is the whole of what the web process can cause to be installed:
// the request carries no names. The packages come from the Debian archive
// the machine is already set up to trust.
var requiredPackages = []struct{ name, program string }{
	{"nftables", firewall.NftProgram},
}

// installPackages is the helper service's side: run the unit and wait for it.
func installPackages() error {
	if err := runSystemctl("start", packagesUnit); err != nil {
		return errors.New("details: journalctl -u sgc-packages --no-pager -n 30")
	}
	return nil
}

// runPackages is "sgc-helper packages" (sgc-packages.service).
func runPackages() error {
	if os.Geteuid() != 0 {
		return errors.New("installing packages needs root")
	}
	var missing []string
	for _, p := range requiredPackages {
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
	for _, p := range requiredPackages {
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
