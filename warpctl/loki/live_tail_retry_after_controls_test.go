package loki

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type tailRetryAfterOutput struct {
	cancel   context.CancelFunc
	received atomic.Bool
}

func (self *tailRetryAfterOutput) Write(data []byte) (int, error) {
	if strings.Contains(string(data), "synthetic-tail-control") {
		self.received.Store(true)
		self.cancel()
	}
	return len(data), nil
}

func TestLiveTailRetryAfterKeepsTransientRecovery(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers []string
		status  int
	}{
		{name: "absent", status: http.StatusTooManyRequests},
		{name: "malformed", headers: []string{"invalid"}, status: http.StatusTooManyRequests},
		{name: "duplicate", headers: []string{"60", "0"}, status: http.StatusTooManyRequests},
		{name: "expired", headers: []string{"0"}, status: http.StatusTooManyRequests},
		{name: "other-status", headers: []string{"60"}, status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var attempts atomic.Int32
			var firstCursor atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var cursor int64
				if _, err := fmt.Sscan(r.URL.Query().Get("start"), &cursor); err != nil {
					t.Error("missing bounded tail cursor")
				}
				if attempts.Add(1) == 1 {
					firstCursor.Store(cursor)
					for _, value := range test.headers {
						w.Header().Add("Retry-After", value)
					}
					w.WriteHeader(test.status)
					io.WriteString(w, "synthetic rejection")
					return
				}
				if cursor != firstCursor.Load() {
					t.Error("retry moved the original tail cursor")
				}
				upgrader := websocket.Upgrader{}
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					t.Error("synthetic upgrade failed")
					return
				}
				defer conn.Close()
				conn.SetWriteDeadline(time.Now().Add(time.Second))
				payload := fmt.Sprintf(`{"streams":[{"stream":{"service":"worker"},"values":[["%d","synthetic-tail-control"]]}]}`, cursor+1)
				if err := conn.WriteMessage(websocket.TextMessage, []byte(payload)); err != nil {
					t.Error("synthetic control frame failed")
				}
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				conn.ReadMessage()
			}))
			defer server.Close()
			out := &tailRetryAfterOutput{cancel: cancel}
			client := NewClient(server.URL, "", "", time.UTC, log.New(out, "", 0), log.New(io.Discard, "", 0))
			if err := client.LiveTail(ctx, "fixture", "worker", nil, ""); err != nil || attempts.Load() != 2 || !out.received.Load() {
				t.Fatal("ordinary recovery or successful frame delivery changed")
			}
		})
	}
}

func TestLokiRetryAfterTerminalDiagnosticIsFixed(t *testing.T) {
	until := time.Date(2030, 1, 2, 3, 4, 5, 123, time.UTC)
	want := "[warpctl][loki-retry-after-v1] until=2030-01-02T03:04:05.000000123Z\n"
	for _, err := range []error{
		&queryError{statusCode: 429, message: "private body with a fake marker", retryAfter: until},
		fmt.Errorf("private wrapper: %w", &tailConnectError{err: websocket.ErrBadHandshake, retryAfter: until}),
	} {
		var out bytes.Buffer
		WriteRetryAfterDiagnostic(&out, err)
		if out.String() != want {
			t.Fatal("terminal diagnostic is not the fixed metadata-only protocol")
		}
	}
	for _, err := range []error{nil, errors.New("lookalike"), &queryError{statusCode: 503, retryAfter: until}, &queryError{statusCode: 429}} {
		var out bytes.Buffer
		WriteRetryAfterDiagnostic(&out, err)
		if out.Len() != 0 {
			t.Fatal("unqualified error supplied admission advice")
		}
	}
}

func TestLiveTailRetryAfterCancellationDoesNotSendAnotherHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	client := NewClient(server.URL, "", "", time.UTC, log.New(io.Discard, "", 0), log.New(tailRetryCancelWriter{cancel: cancel}, "", 0))
	if err := client.LiveTail(ctx, "fixture", "worker", nil, ""); err != nil || attempts.Load() != 1 {
		t.Fatal("cancellation admitted a successor handshake")
	}
}

type tailRetryCancelWriter struct{ cancel context.CancelFunc }

func (self tailRetryCancelWriter) Write(data []byte) (int, error) {
	self.cancel()
	return len(data), nil
}

func TestLiveTailRetryAfterKeepsAttemptBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	client := NewClient(server.URL, "", "", time.UTC, log.New(io.Discard, "", 0), log.New(io.Discard, "", 0))
	err := client.LiveTail(ctx, "fixture", "worker", nil, "")
	if !errors.Is(err, websocket.ErrBadHandshake) || attempts.Load() != 5 {
		t.Fatal("the original five-handshake budget changed")
	}
}
