package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/Troglobitten/sgc/internal/layout"
)

var (
	// errWorkerFailed: the copy of this program that ran as the service user
	// ended with an error, which it has already explained on stderr.
	errWorkerFailed = errors.New("the part running as the service user reported a problem")
	// errWorkerAnswer: it ended well but what it printed could not be read.
	errWorkerAnswer = errors.New("unexpected answer from the part running as the service user")
)

// runAsServiceUser runs this program once more, as the unprivileged service
// user, with the given arguments, and decodes the JSON it prints into out
// (if not nil).
//
// Commands that are started with sudo use it for everything that touches the
// database or the network: the database belongs to the service user (a file
// created in its folder by root would lock SGC out of its own data), and
// nothing that talks to the internet should do so as root.
func runAsServiceUser(ctx context.Context, args, env []string, out any, stderr io.Writer) error {
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
	cmd := exec.CommandContext(ctx, self, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}},
	}
	// A minimal environment, plus what the caller names.
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, env...)
	cmd.Stderr = stderr
	output, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return errWorkerFailed
		}
		return err
	}
	if out != nil {
		if err := json.Unmarshal(output, out); err != nil {
			return errWorkerAnswer
		}
	}
	return nil
}
