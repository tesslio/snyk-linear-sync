package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type regressionRoundTripper func(*http.Request) (*http.Response, error)

func (f regressionRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type regressionBody struct {
	io.Reader
	closed int
}

func (b *regressionBody) Close() error {
	b.closed++
	return nil
}

func TestRetryAfterZeroDoesNotUseDefaultBackoff(t *testing.T) {
	delay := retryAfter(http.Header{"Retry-After": {"0"}}, 0)
	if delay != 0 {
		t.Fatalf("Retry-After: 0 gives %s; want no delay", delay)
	}
}

func TestOriginalRequestBodiesAreClosed(t *testing.T) {
	t.Run("replayable body", func(t *testing.T) {
		original := &regressionBody{Reader: strings.NewReader("payload")}
		req, err := http.NewRequest(http.MethodPost, "https://example.test", original)
		if err != nil {
			t.Fatal(err)
		}
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("payload")), nil
		}
		base := regressionRoundTripper(func(req *http.Request) (*http.Response, error) {
			_ = req.Body.Close()
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody}, nil
		})
		resp, err := NewAdaptiveTransport("test", 1, nil, base).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if original.closed != 1 {
			t.Fatalf("original body closed %d times; want 1", original.closed)
		}
	})
	t.Run("cancelled while waiting for a slot", func(t *testing.T) {
		original := &regressionBody{Reader: strings.NewReader("payload")}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test", original)
		if err != nil {
			t.Fatal(err)
		}
		transport := NewAdaptiveTransport("test", 1, nil, regressionRoundTripper(func(*http.Request) (*http.Response, error) {
			t.Fatal("cancelled request reached base transport")
			return nil, nil
		}))
		transport.sem <- struct{}{}
		_, err = transport.RoundTrip(req)
		<-transport.sem
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v; want context cancellation", err)
		}
		if original.closed != 1 {
			t.Fatalf("original body closed %d times; want 1", original.closed)
		}
	})
}
