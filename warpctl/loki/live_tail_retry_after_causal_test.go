package loki

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// This exercises the real WebSocket handshake and owning retry loop. The
// original client sends a second request after one second despite the hint;
// the fake backend cancels that RED attempt so it cannot consume later tries.
func TestLiveTailRetryAfterFutureAdvice(t *testing.T) {
	for _, test := range []struct {
		name   string
		header string
	}{
		{name: "integer", header: "60"},
		{name: "http-date", header: time.Now().Add(time.Minute).UTC().Format(http.TimeFormat)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/loki/api/v1/tail" ||
					r.URL.Query().Get("query") != `{env="fixture", service="worker"}` || r.URL.Query().Get("limit") != "100" {
					t.Error("handshake changed the fixed tail selector")
				}
				if attempts.Add(1) == 2 {
					cancel()
				}
				w.Header().Set("Retry-After", test.header)
				w.WriteHeader(http.StatusTooManyRequests)
				io.WriteString(w, "synthetic private rejection")
			}))
			defer server.Close()
			client := NewClient(server.URL, "", "", time.UTC, log.New(io.Discard, "", 0), log.New(io.Discard, "", 0))
			err := client.LiveTail(ctx, "fixture", "worker", nil, "")
			if attempts.Load() != 1 {
				t.Fatalf("handshake attempts = %d, want one before future admission", attempts.Load())
			}
			if !errors.Is(err, websocket.ErrBadHandshake) {
				t.Fatal("future advice lost the original handshake failure")
			}
		})
	}
}
