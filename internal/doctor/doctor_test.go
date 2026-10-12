package doctor

import (
	"bytes"
	"context"
	"testing"
)

func TestRunKeepsTheOrderAndAllResults(t *testing.T) {
	results := Run(context.Background(), []Check{
		func(context.Context) []Result { return []Result{Good("first")} },
		func(context.Context) []Result { return nil },
		func(context.Context) []Result { return []Result{Warn("second", "look"), Bad("third", "fix")} },
	})
	if len(results) != 3 || results[0].Summary != "first" || results[1].Summary != "second" || results[2].Summary != "third" {
		t.Errorf("results = %+v", results)
	}
}

func TestPrint(t *testing.T) {
	cases := []struct {
		name     string
		results  []Result
		want     string
		problems int
	}{
		{
			"all well",
			[]Result{Good("The SGC service is running")},
			"  ok    The SGC service is running\n\nEverything checked is as it should be.\n",
			0,
		},
		{
			"a warning is not a problem",
			[]Result{Good("one"), Warn("The clock is not synchronised", "Check: timedatectl status")},
			"  ok    one\n  WARN  The clock is not synchronised\n        Check: timedatectl status\n\nNo problems. 1 warning.\n",
			0,
		},
		{
			"problems are counted, advice may have several lines",
			[]Result{Bad("a", "first line\nsecond line"), Bad("b", ""), Warn("c", "x"), Warn("d", "y")},
			"  FAIL  a\n        first line\n        second line\n  FAIL  b\n  WARN  c\n        x\n  WARN  d\n        y\n\n2 problems, 2 warnings.\n",
			2,
		},
		{
			"one problem",
			[]Result{Bad("a", "do this")},
			"  FAIL  a\n        do this\n\n1 problem.\n",
			1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			problems := Print(&out, c.results)
			if problems != c.problems {
				t.Errorf("problems = %d, want %d", problems, c.problems)
			}
			if out.String() != c.want {
				t.Errorf("output:\n%s\nwant:\n%s", out.String(), c.want)
			}
		})
	}
}
