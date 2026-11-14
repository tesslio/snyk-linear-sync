package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/diagnostic"
	"golang.org/x/oauth2"
)

func diagnostics(t *testing.T, logs *bytes.Buffer) []diagnostic.Record {
	t.Helper()
	var records []diagnostic.Record
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		var row struct {
			Diagnostic string `json:"diagnostic_json"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row.Diagnostic == "" {
			continue
		}
		if strings.Contains(row.Diagnostic, "SYNTHETIC_SECRET") {
			t.Fatal("unsafe diagnostic")
		}
		var r diagnostic.Record
		if err := json.Unmarshal([]byte(row.Diagnostic), &r); err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	return records
}

func TestDiagnosticRetryExhaustionAndDisabledRetries(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		var logs bytes.Buffer
		calls := 0
		transport := NewAdaptiveTransport("snyk", 1, slog.New(slog.NewJSONHandler(&logs, nil)), roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			// A past reset avoids real sleeps using the existing retry policy.
			return &http.Response{StatusCode: 503, Header: http.Header{"X-Ratelimit-Requests-Remaining": {"0"}, "X-Ratelimit-Requests-Reset": {"1000000001"}, "X-Request-Id": {"SYNTHETIC_SECRET"}}, Body: io.NopCloser(strings.NewReader("SYNTHETIC_SECRET"))}, nil
		}))
		ctx := t.Context()
		if disabled {
			ctx = WithoutRetries(ctx)
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.test/rest/orgs/SYNTHETIC_SECRET/issues?token=SYNTHETIC_SECRET", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(got) != "SYNTHETIC_SECRET" {
			t.Fatal("response changed")
		}
		want := 5
		if disabled {
			want = 1
		}
		records := diagnostics(t, &logs)
		if calls != want || len(records) != 1 {
			t.Fatalf("calls=%d records=%+v", calls, records)
		}
		r := records[0]
		if *r.Attempts != want || *r.RetryExhausted == disabled || *r.Status != 503 || r.Stage != "snyk_rest" {
			t.Fatalf("%+v", r)
		}
	}
}

type brokenBody struct{ closed bool }

func (*brokenBody) Read(p []byte) (int, error) {
	return copy(p, "SYNTHETIC_SECRET"), io.ErrUnexpectedEOF
}
func (b *brokenBody) Close() error { b.closed = true; return nil }

func TestDiagnosticTruncatedBodyPreservesReadAndClose(t *testing.T) {
	var logs bytes.Buffer
	b := &brokenBody{}
	transport := NewAdaptiveTransport("linear", 1, slog.New(slog.NewJSONHandler(&logs, nil)), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: b}, nil
	}))
	req, _ := http.NewRequest("POST", "https://example.test/graphql", strings.NewReader("SYNTHETIC_SECRET"))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != io.ErrUnexpectedEOF || string(raw) != "SYNTHETIC_SECRET" || !b.closed {
		t.Fatal("body behavior changed")
	}
	records := diagnostics(t, &logs)
	if len(records) != 1 || records[0].Family != "truncated_response" || records[0].Phase != "response_read" || records[0].Stage != "linear_graphql" {
		t.Fatalf("%+v", records)
	}
}

type failingTokenSource struct{ err error }

func (s failingTokenSource) Token() (*oauth2.Token, error) { return nil, s.err }

func TestOAuthDiagnosticsDoNotDispatchRESTOrChangeError(t *testing.T) {
	for _, failure := range []error{
		fmt.Errorf("SYNTHETIC_SECRET: %w", &oauth2.RetrieveError{Response: &http.Response{StatusCode: 503}, Body: []byte("SYNTHETIC_SECRET"), ErrorDescription: "SYNTHETIC_SECRET"}),
		errors.Join(errors.New("SYNTHETIC_SECRET"), context.DeadlineExceeded),
	} {
		var logs bytes.Buffer
		tr := &BearerTransport{TokenSource: failingTokenSource{failure}, Logger: slog.New(slog.NewJSONHandler(&logs, nil)), Base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("REST dispatched after OAuth failure")
			return nil, nil
		})}
		req, _ := http.NewRequest("GET", "https://example.test/rest/orgs/private", nil)
		_, err := tr.RoundTrip(req)
		if err != failure {
			t.Fatal("error changed")
		}
		records := diagnostics(t, &logs)
		if len(records) != 1 || records[0].Stage != "snyk_oauth" || records[0].Attempts != nil || records[0].RetryExhausted != nil {
			t.Fatalf("%+v", records)
		}
	}
}

func TestDiagnosticTimeoutAndCancellationDoNotRetry(t *testing.T) {
	var logs bytes.Buffer
	failure := fmt.Errorf("SYNTHETIC_SECRET: %w", context.DeadlineExceeded)
	calls := 0
	tr := NewAdaptiveTransport("snyk", 1, slog.New(slog.NewJSONHandler(&logs, nil)), roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, failure }))
	req, _ := http.NewRequestWithContext(diagnostic.SDKContext(t.Context()), "GET", "https://example.test/rest/orgs/private/projects", nil)
	_, err := tr.RoundTrip(req)
	if err != failure || calls != 1 {
		t.Fatal("retry/error behavior changed")
	}
	r := diagnostics(t, &logs)[0]
	if r.Stage != "snyk_sdk" || r.Family != "timeout" || *r.Attempts != 1 || *r.RetryExhausted {
		t.Fatalf("%+v", r)
	}
}

func TestDiagnosticsPreserveSuccessfulReplayAndUnreplayableRequests(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		status                 int
		replayable             bool
		wantCalls, wantRecords int
	}{
		{"existing-success-rate-limit-policy", 200, true, 5, 0},
		{"unreplayable-503", 503, false, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			calls := 0
			tr := NewAdaptiveTransport("linear", 1, slog.New(slog.NewJSONHandler(&logs, nil)), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: tc.status, Header: http.Header{"X-Ratelimit-Requests-Remaining": {"0"}, "X-Ratelimit-Requests-Reset": {"1000000001"}}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
			}))
			req, _ := http.NewRequest("POST", "https://example.test/graphql", strings.NewReader("mutation"))
			if !tc.replayable {
				req.GetBody = nil
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			records := diagnostics(t, &logs)
			if calls != tc.wantCalls || len(records) != tc.wantRecords {
				t.Fatalf("calls=%d records=%+v", calls, records)
			}
			if len(records) > 0 && *records[0].RetryExhausted {
				t.Fatal("unreplayable request reported exhausted retries")
			}
		})
	}
}
