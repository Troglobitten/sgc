package main

import (
	"errors"
	"testing"
	"time"
)

var errWaiting = errors.New("another change is still waiting")

func shortWaits(t *testing.T) {
	t.Helper()
	wait, check := endingUnitWait, endingUnitCheck
	endingUnitWait, endingUnitCheck = 200*time.Millisecond, time.Millisecond
	t.Cleanup(func() { endingUnitWait, endingUnitCheck = wait, check })
}

func TestAChangeUnitThatIsOnlyEndingIsWaitedFor(t *testing.T) {
	shortWaits(t)
	looks := 0
	running := func() bool { looks++; return looks <= 3 }
	if err := waitForEndedChange(running, func() (bool, error) { return false, nil }, errWaiting); err != nil {
		t.Fatalf("a unit ending with nothing waiting: %v", err)
	}
	if looks != 4 {
		t.Errorf("looked %d times, want 4", looks)
	}
}

func TestAChangeThatIsStillWaitingIsRefusedAtOnce(t *testing.T) {
	shortWaits(t)
	start := time.Now()
	err := waitForEndedChange(func() bool { return true }, func() (bool, error) { return true, nil }, errWaiting)
	if !errors.Is(err, errWaiting) {
		t.Fatalf("got %v, want the refusal", err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Error("a waiting change was waited for instead of refused")
	}
}

func TestAUnitThatDoesNotEndIsGivenUpOn(t *testing.T) {
	shortWaits(t)
	err := waitForEndedChange(func() bool { return true }, func() (bool, error) { return false, nil }, errWaiting)
	if !errors.Is(err, errUnitStillEnding) {
		t.Fatalf("got %v, want errUnitStillEnding", err)
	}
}

func TestNotKnowingWhetherAChangeWaitsRefuses(t *testing.T) {
	shortWaits(t)
	unreadable := errors.New("unreadable")
	err := waitForEndedChange(func() bool { return true }, func() (bool, error) { return false, unreadable }, errWaiting)
	if !errors.Is(err, unreadable) {
		t.Fatalf("got %v, want the read error", err)
	}
}

func TestAStoppedUnitIsNotWaitedFor(t *testing.T) {
	shortWaits(t)
	err := waitForEndedChange(func() bool { return false }, func() (bool, error) {
		t.Error("asked what is waiting although the unit is stopped")
		return false, nil
	}, errWaiting)
	if err != nil {
		t.Fatal(err)
	}
}
