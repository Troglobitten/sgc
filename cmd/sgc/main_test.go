package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Troglobitten/sgc"
)

func TestVersionCommandPrintsVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"version"}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if want := "sgc " + sgc.Version() + " "; !strings.HasPrefix(stdout.String(), want) {
		t.Errorf("stdout = %q, want it to start with %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestMisuseExitsWithUsageError(t *testing.T) {
	cases := map[string][]string{
		"no command":      {},
		"unknown command": {"frobnicate"},
		"unknown flag":    {"serve", "--no-such-flag"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run(context.Background(), args, &stdout, &stderr)

			if code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
			if stderr.Len() == 0 {
				t.Error("nothing was written to stderr")
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

func TestHelpGoesToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"help"}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "Usage: sgc") {
		t.Errorf("stdout = %q, want usage text", stdout.String())
	}
}
