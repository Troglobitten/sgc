package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// A unit that carries out a firewall or SSH change keeps running while the
// change waits for its confirmation or its proof. When another job ends the
// change (the confirmation, the separate revert unit), the waiting process
// only notices at its next look, a quarter of a second later for the
// firewall and a second later for SSH, and systemd then runs the cleanup
// after it. For that moment the unit runs with nothing waiting. A new change
// then used to be refused as if one were waiting, and the page said the
// firewall "could not be switched on": once in ten quick firewall changes
// in the whole-machine test of 2026-10-25, and three times in a row right
// after a confirmation when tried on purpose. Such a unit is now given a
// moment to end.
var (
	endingUnitWait  = 5 * time.Second
	endingUnitCheck = 100 * time.Millisecond
)

// errUnitStillEnding: the unit went on running, with nothing waiting, for
// longer than endingUnitWait.
var errUnitStillEnding = errors.New("the previous change has not finished yet; try again in a moment")

// waitForEndedChange returns nil once running reports that the change unit
// has ended. While it runs and a change is still waiting, it returns
// waitingErr at once: that unit must not be started again, because starting
// a running unit does nothing and the new request would be lost.
func waitForEndedChange(running func() bool, waiting func() (bool, error), waitingErr error) error {
	deadline := time.Now().Add(endingUnitWait)
	for running() {
		pending, err := waiting()
		if err != nil {
			return fmt.Errorf("read whether a change is waiting: %w", err)
		}
		if pending {
			return waitingErr
		}
		if !time.Now().Before(deadline) {
			return errUnitStillEnding
		}
		time.Sleep(endingUnitCheck)
	}
	return nil
}

// unitRunning reports whether a unit is anything but stopped: running,
// starting or ending. Not knowing counts as running, which only means
// waiting.
func unitRunning(unit string) bool {
	cmd := exec.Command(systemctl, "show", "--property=ActiveState", "--value", unit)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := cmd.Output()
	if err != nil {
		return true
	}
	switch strings.TrimSpace(string(output)) {
	case "inactive", "failed":
		return false
	}
	return true
}
