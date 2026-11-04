package httpx

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestWithoutRetriesDoesNotReplayResponse(t *testing.T) {
	for _, status := range []int{200, 429, 502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			transport := NewAdaptiveTransport("example", 1, slog.New(slog.NewTextHandler(io.Discard, nil)), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: status, Header: http.Header{"X-Ratelimit-Requests-Remaining": {"0"}}, Body: io.NopCloser(strings.NewReader("response"))}, nil
			}))
			ctx, cancel := context.WithCancel(WithoutRetries(t.Context()))
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/graphql", strings.NewReader("mutation"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if calls != 1 || resp.StatusCode != status {
				t.Fatalf("calls=%d status=%d", calls, resp.StatusCode)
			}
		})
	}
	if RetriesDisabled(t.Context()) || !RetriesDisabled(WithoutRetries(t.Context())) {
		t.Fatal("retry control escaped its context")
	}
}
