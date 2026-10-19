package main

import (
	"time"
)

// The run loop polls the deployment selector every WarpPollTimeout. Logging
// every poll wrote two identical lines per unit every five seconds, about ten
// lines a second on a busy edge, and pushed the deploy and drain decisions
// that incidents need out of the one-hour edge journal. A poll is logged when
// it is the first, when the polled versions change, and otherwise once per
// polledVersionsLogInterval, so the versions a controller selects stay visible
// in any ten-minute window (SIGNALS.md §14.6 reads them from there).
const polledVersionsLogInterval = 5 * time.Minute

// The last poll line the run loop logged, and when.
//
// Not safe for concurrent use: the run loop owns it.
type polledVersionsLog struct {
	lastLine    string
	lastLogTime time.Time
}

// Whether line, polled at now, is logged. A logged line becomes the one later
// polls compare against.
func (self *polledVersionsLog) shouldLog(line string, now time.Time) bool {
	if !self.lastLogTime.IsZero() && line == self.lastLine && now.Sub(self.lastLogTime) < polledVersionsLogInterval {
		return false
	}
	self.lastLine = line
	self.lastLogTime = now
	return true
}
