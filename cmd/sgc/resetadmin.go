package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/auth"
	"github.com/Troglobitten/sgc/internal/layout"
	"github.com/Troglobitten/sgc/internal/store"
)

// resetAdmin is "sudo sgc reset-admin": the way back in when the admin's
// password is lost (docs/design.md §4.8). It works only at the device, with
// sudo: whoever can do that owns the device anyway. It gives the admin a
// new random password, prints it once, and ends every sign-in.
func resetAdmin(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sgc reset-admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", defaultStateDir(), "folder for the database")
	worker := flags.Bool("as-service-user", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: sudo sgc reset-admin")
		return exitUsage
	}
	if *worker {
		return resetAdminWorker(ctx, *stateDir, stdout, stderr)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "sgc: this command needs root. Run: sudo sgc reset-admin")
		return exitFailed
	}
	var answer resetAnswer
	if err := runAsServiceUser(ctx, []string{"reset-admin", "--as-service-user", "--state-dir", *stateDir}, nil, &answer, stderr); err != nil {
		if !errors.Is(err, errWorkerFailed) {
			fmt.Fprintf(stderr, "sgc: %v\n", err)
		}
		return exitFailed
	}
	fmt.Fprintf(stdout, "The admin account %q has a new password:\n\n    %s\n\n", answer.Username, answer.Password)
	fmt.Fprintln(stdout, "It is shown only now. Every sign-in to SGC's page was ended; sign in with it.")
	return exitOK
}

type resetAnswer struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// newPassword is 24 letters and digits without look-alikes.
func newPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzACDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 24)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

func resetAdminWorker(ctx context.Context, stateDir string, stdout, stderr io.Writer) int {
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
	authService, err := auth.NewService(db)
	if err != nil {
		return fail(err)
	}
	password, err := newPassword()
	if err != nil {
		return fail(err)
	}
	username, err := authService.ResetAdminPassword(ctx, password)
	if err != nil {
		return fail(err)
	}
	audit.New(db).Record(ctx, audit.ActorConsole, audit.ActionAdminReset, "a new password for "+username, "")
	if err := json.NewEncoder(stdout).Encode(resetAnswer{Username: username, Password: password}); err != nil {
		return fail(err)
	}
	return exitOK
}
