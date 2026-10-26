package lasting

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAFailureIsNewsOnlyOnceItHasLasted(t *testing.T) {
	start := time.Date(2026, 10, 26, 4, 0, 0, 0, time.UTC)
	var f Failure
	for minutes := 0; minutes < 30; minutes += 5 {
		if f.Note(start.Add(time.Duration(minutes)*time.Minute), "lookup failed") {
			t.Fatalf("after %d minutes of failing, already news", minutes)
		}
	}
	if !f.Note(start.Add(30*time.Minute), "lookup failed again") {
		t.Error("after 30 minutes of failing, still not news")
	}
	if f.Last != "lookup failed again" {
		t.Errorf("Last = %q", f.Last)
	}

	// One look that gets through starts the count afresh.
	f.Clear()
	if f.Since != nil || f.Last != "" {
		t.Errorf("not cleared: %+v", f)
	}
	if f.Note(start.Add(40*time.Minute), "lookup failed") {
		t.Error("a new failure after a look that got through is news at once")
	}
}

func TestAClockSetBackStartsTheCountAgain(t *testing.T) {
	start := time.Date(2026, 10, 26, 4, 0, 0, 0, time.UTC)
	var f Failure
	f.Note(start, "x")
	// The clock jumps back an hour (a device without a clock that has not
	// asked the time yet): not a failure of minus an hour, and not news.
	if f.Note(start.Add(-time.Hour), "x") {
		t.Error("news after the clock went back")
	}
	if !f.Since.Equal(start.Add(-time.Hour)) {
		t.Errorf("Since = %v", f.Since)
	}
}

func TestItIsKeptWithTheState(t *testing.T) {
	var f Failure
	f.Note(time.Date(2026, 10, 26, 4, 0, 0, 0, time.UTC), "x")
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back Failure
	if err := json.Unmarshal(data, &back); err != nil || back.Since == nil || !back.Since.Equal(*f.Since) || back.Last != "x" {
		t.Errorf("round trip: %s → %+v, %v", data, back, err)
	}
	if data, _ := json.Marshal(Failure{}); string(data) != "{}" {
		t.Errorf("an empty failure is written as %s", data)
	}
}
