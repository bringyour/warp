package main

import (
	"testing"
	"time"
)

// Reading the deployment selector logs nothing. Before, every read wrote a
// "Latest version" line, which with the poll line put two identical journal
// lines per unit every WarpPollTimeout.
func TestGetLatestVersionLogsNothing(t *testing.T) {
	output := captureErrOutput(t)
	worker := &RunWorker{
		dynamoClient:    fixedDeploymentVersionClient{version: "1.2.3"},
		env:             "fixture",
		service:         "worker",
		block:           "g1",
		configMountMode: MOUNT_MODE_NO,
	}
	for i := 0; i < 3; i += 1 {
		latestVersion, latestConfigVersion, err := worker.getLatestVersion()
		if err != nil {
			t.Fatalf("read %d: %s", i, err)
		}
		if latestVersion == nil || latestVersion.String() != "1.2.3" || latestConfigVersion != nil {
			t.Fatalf("read %d: versions %v, %v", i, latestVersion, latestConfigVersion)
		}
	}
	if output.Len() != 0 {
		t.Fatalf("getLatestVersion logged %q", output.String())
	}
}

// A poll is logged when it is the first, when its versions change, and
// otherwise once per polledVersionsLogInterval.
func TestPolledVersionsLogLogsFirstChangedAndHeartbeatPolls(t *testing.T) {
	start := time.Date(2026, 10, 19, 21, 0, 0, 0, time.UTC)
	firstLine := "Polled latest versions: 1.0.0, 2.0.0"
	changedLine := "Polled latest versions: 1.0.1, 2.0.0"
	polls := []struct {
		line   string
		offset time.Duration
		logged bool
	}{
		{line: firstLine, offset: 0, logged: true},
		{line: firstLine, offset: WarpPollTimeout, logged: false},
		{line: firstLine, offset: polledVersionsLogInterval - time.Second, logged: false},
		{line: firstLine, offset: polledVersionsLogInterval, logged: true},
		{line: changedLine, offset: polledVersionsLogInterval + WarpPollTimeout, logged: true},
		{line: changedLine, offset: polledVersionsLogInterval + 2*WarpPollTimeout, logged: false},
		{line: firstLine, offset: polledVersionsLogInterval + 3*WarpPollTimeout, logged: true},
	}
	var log polledVersionsLog
	for i, poll := range polls {
		if logged := log.shouldLog(poll.line, start.Add(poll.offset)); logged != poll.logged {
			t.Errorf("poll %d (%q at +%s): logged %t, want %t", i, poll.line, poll.offset, logged, poll.logged)
		}
	}
}

// An hour of steady polls logs one line per interval, not one per poll.
func TestPolledVersionsLogBoundsAnHourOfSteadyPolls(t *testing.T) {
	start := time.Date(2026, 10, 19, 21, 0, 0, 0, time.UTC)
	pollCount := int(time.Hour / WarpPollTimeout)
	var log polledVersionsLog
	loggedCount := 0
	for i := 0; i < pollCount; i += 1 {
		if log.shouldLog("Polled latest versions: 1.0.0, 2.0.0", start.Add(time.Duration(i)*WarpPollTimeout)) {
			loggedCount += 1
		}
	}
	if want := int(time.Hour / polledVersionsLogInterval); loggedCount != want {
		t.Fatalf("%d steady polls logged %d lines, want %d", pollCount, loggedCount, want)
	}
}
