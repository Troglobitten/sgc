// Package doctor is the frame of "sgc doctor": a list of checks, each with a
// plain-language result and, where something is wrong, what to do about it.
//
// The checks themselves live with the command (cmd/sgc/doctor.go). They look
// at the machine directly rather than asking SGC's web interface, because
// the doctor is what one runs when the web interface is not answering.
package doctor

import (
	"context"
	"fmt"
	"io"
	"strings"
)

type Status int

const (
	// OK: as it should be.
	OK Status = iota
	// Warning: works, but worth knowing about.
	Warning
	// Problem: something is broken.
	Problem
)

// Result is what one check found.
type Result struct {
	Status Status
	// Summary is one line saying what was found, problem or not.
	Summary string
	// Advice says what to do about a warning or problem: a command to run,
	// or where to look. Empty for OK.
	Advice string
}

// Check looks at one thing. It may return several results (the firewall,
// for example, has a few things worth a line each).
type Check func(ctx context.Context) []Result

// Run carries out the checks in order.
func Run(ctx context.Context, checks []Check) []Result {
	var results []Result
	for _, check := range checks {
		results = append(results, check(ctx)...)
	}
	return results
}

// Print writes the results and a closing line, and returns the number of
// problems (warnings do not count).
func Print(w io.Writer, results []Result) (problems int) {
	warnings := 0
	for _, r := range results {
		label := "ok  "
		switch r.Status {
		case Warning:
			label = "WARN"
			warnings++
		case Problem:
			label = "FAIL"
			problems++
		}
		fmt.Fprintf(w, "  %s  %s\n", label, r.Summary)
		if r.Advice != "" {
			for _, line := range strings.Split(r.Advice, "\n") {
				fmt.Fprintf(w, "        %s\n", line)
			}
		}
	}
	fmt.Fprintln(w)
	switch {
	case problems == 0 && warnings == 0:
		fmt.Fprintln(w, "Everything checked is as it should be.")
	case problems == 0:
		fmt.Fprintf(w, "No problems. %s.\n", count(warnings, "warning"))
	case warnings == 0:
		fmt.Fprintf(w, "%s.\n", count(problems, "problem"))
	default:
		fmt.Fprintf(w, "%s, %s.\n", count(problems, "problem"), count(warnings, "warning"))
	}
	return problems
}

func count(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// Good, Warn and Bad make results readable where the checks are written.
func Good(summary string) Result { return Result{Status: OK, Summary: summary} }

func Warn(summary, advice string) Result {
	return Result{Status: Warning, Summary: summary, Advice: advice}
}

func Bad(summary, advice string) Result {
	return Result{Status: Problem, Summary: summary, Advice: advice}
}
