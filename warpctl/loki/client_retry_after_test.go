package loki

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

const retryAfterFixtureQuery = `{env="fixture", service="worker"}`
const retryAfterFixtureBody = "synthetic-private-rejection"
const retryAfterFixtureSuccess = `{"status":"success","data":{"resultType":"streams","result":[]}}`

// The fake transport performs no socket or external I/O. Every attempt must
// preserve the same query window and result limit.
func retryAfterFixtureClient(t *testing.T, headers []string, statusCode int, successAttempt int) (*Client, *int, *bytes.Buffer) {
	t.Helper()
	attempts := 0
	var diagnostics bytes.Buffer
	client := &Client{
		baseUrl: "https://loki.example",
		errLog:  log.New(&diagnostics, "", 0),
		httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			attempts++
			query := request.URL.Query()
			if request.Method != http.MethodGet || request.URL.Path != "/loki/api/v1/query_range" ||
				query.Get("query") != retryAfterFixtureQuery || query.Get("start") != "1" ||
				query.Get("end") != "2" || query.Get("limit") != "100" || query.Get("direction") != "forward" {
				t.Error("retry changed the bounded query")
			}
			header := make(http.Header)
			for _, value := range headers {
				header.Add("Retry-After", value)
			}
			code, body := statusCode, retryAfterFixtureBody
			if successAttempt > 0 && attempts >= successAttempt {
				code, body = http.StatusOK, retryAfterFixtureSuccess
			}
			return &http.Response{
				StatusCode: code,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    request,
			}, nil
		})},
	}
	return client, &attempts, &diagnostics
}

// A repeated rejection with explicit future admission cannot justify the
// fixed 100/200ms retries. The red source issues three requests; green issues
// one and preserves exactly the same typed status and body error.
func TestQueryRangeRetryAfterDefersEarlyHttp429(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{name: "integer", header: "60"},
		{name: "http-date", header: time.Now().Add(time.Minute).UTC().Format(http.TimeFormat)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client, attempts, diagnostics := retryAfterFixtureClient(t, []string{test.header}, http.StatusTooManyRequests, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			response, err := client.queryRange(ctx, retryAfterFixtureQuery, 1, 2, 100, "forward")
			var queryErr *queryError
			if response != nil || !errors.As(err, &queryErr) || queryErr.statusCode != http.StatusTooManyRequests {
				t.Fatal("explicit future admission lost the typed 429")
			}
			if *attempts != 1 {
				t.Fatalf("attempts = %d, want one before future admission", *attempts)
			}
			if err.Error() != "Loki query error (429): "+retryAfterFixtureBody {
				t.Fatal("typed error format or original body changed")
			}
			if diagnostics.Len() != 0 {
				t.Fatal("a deferred attempt emitted a retry diagnostic")
			}
		})
	}
}

// A bad hint is not an invented prohibition. Existing transient recovery and
// the same absolute range remain available without usable future advice.
func TestQueryRangeRetryAfterKeepsExistingTransientRecovery(t *testing.T) {
	cases := []struct {
		name       string
		headers    []string
		statusCode int
	}{
		{name: "absent", statusCode: http.StatusTooManyRequests},
		{name: "malformed", headers: []string{"synthetic-invalid"}, statusCode: http.StatusTooManyRequests},
		{name: "negative", headers: []string{"-1"}, statusCode: http.StatusTooManyRequests},
		{name: "signed", headers: []string{"+1"}, statusCode: http.StatusTooManyRequests},
		{name: "overflow", headers: []string{"999999999999999999999"}, statusCode: http.StatusTooManyRequests},
		{name: "zero", headers: []string{"0"}, statusCode: http.StatusTooManyRequests},
		{name: "past-date", headers: []string{time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat)}, statusCode: http.StatusTooManyRequests},
		{name: "duplicate", headers: []string{"60", "0"}, statusCode: http.StatusTooManyRequests},
		{name: "other-status", headers: []string{"60"}, statusCode: http.StatusServiceUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client, attempts, _ := retryAfterFixtureClient(t, test.headers, test.statusCode, 2)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			response, err := client.queryRange(ctx, retryAfterFixtureQuery, 1, 2, 100, "forward")
			if err != nil || response == nil || response.Status != "success" || *attempts != 2 {
				t.Fatalf("transient recovery failed; attempts = %d", *attempts)
			}
		})
	}
}

func TestQueryRangeRetryAfterPreservesAttemptBudgetAndDeadline(t *testing.T) {
	t.Run("same-attempt-budget", func(t *testing.T) {
		client, attempts, _ := retryAfterFixtureClient(t, nil, http.StatusTooManyRequests, 0)
		_, err := client.queryRange(context.Background(), retryAfterFixtureQuery, 1, 2, 100, "forward")
		var queryErr *queryError
		if !errors.As(err, &queryErr) || queryErr.statusCode != http.StatusTooManyRequests || *attempts != queryRangeMaxAttempts {
			t.Fatalf("existing failed-query budget changed; attempts = %d", *attempts)
		}
	})
	t.Run("caller-deadline", func(t *testing.T) {
		client, attempts, _ := retryAfterFixtureClient(t, []string{"0"}, http.StatusTooManyRequests, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := client.queryRange(ctx, retryAfterFixtureQuery, 1, 2, 100, "forward")
		if !errors.Is(err, context.DeadlineExceeded) || *attempts != 1 {
			t.Fatalf("caller deadline failed; attempts = %d", *attempts)
		}
	})
}

// Admission is checked again after the timer. These fixed clocks cover an
// exact boundary and a backwards wall-clock move after a planned admission.
func TestQueryRangeRetryAfterClockBoundaries(t *testing.T) {
	boundary := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	queryErr := &queryError{statusCode: http.StatusTooManyRequests, retryAfter: boundary}
	cases := []struct {
		name    string
		now     time.Time
		allowed bool
	}{
		{name: "before", now: boundary.Add(-time.Nanosecond), allowed: false},
		{name: "equal", now: boundary, allowed: true},
		{name: "after", now: boundary.Add(time.Nanosecond), allowed: true},
		{name: "forward-clock", now: boundary.Add(time.Hour), allowed: true},
		{name: "backwards-after-planning", now: boundary.Add(-time.Hour), allowed: false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := queryErr.retryAllowedAt(test.now); got != test.allowed {
				t.Fatalf("retry admission = %v, want %v", got, test.allowed)
			}
		})
	}
	if !(&queryError{statusCode: http.StatusTooManyRequests}).retryAllowedAt(boundary) {
		t.Fatal("missing hint created a clock restriction")
	}
}

type retryAfterDelayedBody struct {
	reader *strings.Reader
	waited bool
}

func (self *retryAfterDelayedBody) Read(buffer []byte) (int, error) {
	if !self.waited {
		self.waited = true
		// Read starts after queryRangeOnce records header receipt. Waiting
		// one second here makes Retry-After: 1 expire before decoding ends.
		<-time.After(time.Second)
	}
	return self.reader.Read(buffer)
}

func (self *retryAfterDelayedBody) Close() error { return nil }

func TestQueryRangeRetryAfterDeltaStartsBeforeBodyRead(t *testing.T) {
	attempts := 0
	client := &Client{
		baseUrl: "https://loki.example",
		errLog:  log.New(io.Discard, "", 0),
		httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{"1"}},
					Body:       &retryAfterDelayedBody{reader: strings.NewReader(retryAfterFixtureBody)},
					Request:    request,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(retryAfterFixtureSuccess)),
				Request:    request,
			}, nil
		})},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := client.queryRange(ctx, retryAfterFixtureQuery, 1, 2, 100, "forward")
	if err != nil || response == nil || response.Status != "success" || attempts != 2 {
		t.Fatalf("expired delta hint blocked recovery; attempts = %d", attempts)
	}
}

func TestQueryRangeRetryAfterDoesNotCarryAcrossCalls(t *testing.T) {
	client, attempts, _ := retryAfterFixtureClient(t, []string{"60"}, http.StatusTooManyRequests, 2)
	_, err := client.queryRange(context.Background(), retryAfterFixtureQuery, 1, 2, 100, "forward")
	var queryErr *queryError
	if !errors.As(err, &queryErr) || *attempts != 1 {
		t.Fatalf("first operation did not retain its rejection; attempts = %d", *attempts)
	}
	response, err := client.queryRange(context.Background(), retryAfterFixtureQuery, 1, 2, 100, "forward")
	if err != nil || response == nil || response.Status != "success" || *attempts != 2 {
		t.Fatalf("operation-local advice became a cross-call cooldown; attempts = %d", *attempts)
	}
}
