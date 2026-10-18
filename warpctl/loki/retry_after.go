package loki

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// A terminal marker carries only parsed admission advice to the owner of the
// next CLI invocation. It is separate from the untrusted response body and
// must immediately precede the existing logs panic, whose stack is unchanged.
const retryAfterDiagnosticPrefix = "[warpctl][loki-retry-after-v1] until="

func WriteRetryAfterDiagnostic(out io.Writer, err error) {
	until := retryAfterTime(err).UTC()
	if until.IsZero() || until.Year() < 0 || until.Year() > 9999 {
		return
	}
	fmt.Fprintln(out, retryAfterDiagnosticPrefix+until.UTC().Format(time.RFC3339Nano))
}

func retryAfterTime(err error) time.Time {
	var queryErr *queryError
	if errors.As(err, &queryErr) && queryErr.statusCode == http.StatusTooManyRequests {
		return queryErr.retryAfter
	}
	var tailErr *tailConnectError
	if errors.As(err, &tailErr) {
		return tailErr.retryAfter
	}
	return time.Time{}
}

func parseRetryAfter(header http.Header, responseAt time.Time) time.Time {
	values := header.Values("Retry-After")
	if len(values) != 1 {
		return time.Time{}
	}
	value := strings.TrimSpace(values[0])
	seconds, parseErr := strconv.ParseInt(value, 10, 64)
	digits := value != "" && strings.IndexFunc(value, func(c rune) bool {
		return c < '0' || c > '9'
	}) < 0
	if digits && parseErr == nil && seconds <= int64((1<<63-1)/time.Second) {
		return responseAt.Add(time.Duration(seconds) * time.Second)
	}
	if retryAfter, parseErr := http.ParseTime(value); parseErr == nil {
		return retryAfter
	}
	return time.Time{}
}

// The failed WebSocket opening handshake has an HTTP response. Preserve its
// status without copying its response body into a new diagnostic protocol.
type tailConnectError struct {
	err        error
	retryAfter time.Time
}

func (self *tailConnectError) Error() string {
	return fmt.Sprintf("Loki tail error (429): %s", self.err)
}

func (self *tailConnectError) Unwrap() error { return self.err }
