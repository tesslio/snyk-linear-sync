package snyk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/diagnostic"
	"github.com/tesslio/snyk-linear-sync/internal/httpx"
)

func TestDecodeDiagnosticsExcludeBodiesAndValidationDetails(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		family string
	}{
		{503, "SYNTHETIC_SECRET", "http_status"},
		{200, `{"data":null,"SYNTHETIC_SECRET":"private"}`, "invalid_response"},
		{200, `{"data":`, "invalid_response"},
	} {
		var logs bytes.Buffer
		c := &Client{requireFresh: true, logger: slog.New(slog.NewJSONHandler(&logs, nil))}
		req, _ := http.NewRequest("GET", "https://example.test/rest/orgs/SYNTHETIC_SECRET/issues?key=SYNTHETIC_SECRET", nil)
		resp := &http.Response{StatusCode: tc.status, Request: req, Body: io.NopCloser(strings.NewReader(tc.body))}
		var result issueListResponse
		if err := c.decodeJSON(resp, &result); err == nil {
			t.Fatal("invalid response accepted")
		}
		var row struct {
			Diagnostic string `json:"diagnostic_json"`
		}
		if err := json.Unmarshal(logs.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(row.Diagnostic, "SYNTHETIC_SECRET") {
			t.Fatal("unsafe diagnostic")
		}
		var record diagnostic.Record
		if err := json.Unmarshal([]byte(row.Diagnostic), &record); err != nil {
			t.Fatal(err)
		}
		// EOF from strict token validation is intentionally classified as truncation.
		if record.Family != tc.family && !(tc.body == `{"data":` && record.Family == "truncated_response") {
			t.Fatalf("%+v", record)
		}
		if record.Stage != "snyk_rest" || record.Attempts != nil || record.RetryExhausted != nil {
			t.Fatalf("%+v", record)
		}
	}
}

type secretReadFailure struct{}

func (secretReadFailure) Read([]byte) (int, error) { return 0, errors.New("SYNTHETIC_SECRET") }
func (secretReadFailure) Close() error             { return nil }

func TestDecodeDiagnosticsPreserveUnknownReadFailure(t *testing.T) {
	for _, strict := range []bool{false, true} {
		var logs bytes.Buffer
		c := &Client{requireFresh: strict, logger: slog.New(slog.NewJSONHandler(&logs, nil))}
		var into issueListResponse
		if err := c.decodeJSON(&http.Response{StatusCode: 200, Body: secretReadFailure{}}, &into); err == nil {
			t.Fatal("read error lost")
		}
		var row struct {
			Diagnostic string `json:"diagnostic_json"`
		}
		if err := json.Unmarshal(logs.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		var record diagnostic.Record
		if err := json.Unmarshal([]byte(row.Diagnostic), &record); err != nil {
			t.Fatal(err)
		}
		if record.Family != "unknown" || strings.Contains(row.Diagnostic, "SYNTHETIC_SECRET") {
			t.Fatalf("%+v", record)
		}
	}
}

type diagnosticRoundTripper func(*http.Request) (*http.Response, error)

func (f diagnosticRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type diagnosticBody struct {
	data    string
	failure error
	closed  bool
}

func (b *diagnosticBody) Read(p []byte) (int, error) {
	n := copy(p, b.data)
	b.data = b.data[n:]
	if len(b.data) == 0 {
		return n, b.failure
	}
	return n, nil
}
func (b *diagnosticBody) Close() error { b.closed = true; return nil }

func readDiagnosticRecords(t *testing.T, logs *bytes.Buffer) []diagnostic.Record {
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
		var record diagnostic.Record
		if err := json.Unmarshal([]byte(row.Diagnostic), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func TestResponseDiagnosticBoundaries(t *testing.T) {
	for _, instrumented := range []bool{false, true} {
		for _, strict := range []bool{false, true} {
			for _, ignores := range []bool{false, true} {
				for _, tc := range []struct {
					name, data, family, phase string
					failure                   error
				}{
					{"partial-read", `{"data":`, "truncated_response", "response_read", io.ErrUnexpectedEOF},
					{"truncated-read", "", "truncated_response", "response_read", io.ErrUnexpectedEOF},
					{"timeout-read", "", "timeout", "response_read", &net.DNSError{Err: "SYNTHETIC_SECRET", IsTimeout: true}},
					{"unknown-read", "", "unknown", "response_read", errors.New("SYNTHETIC_SECRET")},
					{"decode", `{"SYNTHETIC_SECRET":`, "invalid_response", "response_validation", io.EOF},
				} {
					t.Run(fmt.Sprintf("%s/instrumented=%t/strict=%t/ignores=%t", tc.name, instrumented, strict, ignores), func(t *testing.T) {
						var logs bytes.Buffer
						logger := slog.New(slog.NewJSONHandler(&logs, nil))
						body := &diagnosticBody{data: tc.data, failure: tc.failure}
						calls := 0
						var transport http.RoundTripper = diagnosticRoundTripper(func(req *http.Request) (*http.Response, error) {
							calls++
							return &http.Response{StatusCode: 200, Body: body, Request: req}, nil
						})
						if instrumented {
							transport = httpx.NewAdaptiveTransport("snyk", 1, logger, transport)
						}
						base, _ := url.Parse("https://example.test/v1/")
						c := &Client{requireFresh: strict, logger: logger, httpClient: &http.Client{Transport: transport}, v1Base: base, orgID: "SYNTHETIC_SECRET"}
						var err error
						if ignores {
							_, err = c.fetchProjectIgnoresWithRetry(t.Context(), "project-a", 1)
						} else {
							req, _ := http.NewRequest("GET", "https://example.test/rest/orgs/SYNTHETIC_SECRET/issues", nil)
							resp, requestErr := c.httpClient.Do(req)
							if requestErr != nil {
								t.Fatal(requestErr)
							}
							var result issueListResponse
							err = c.decodeJSON(resp, &result)
						}
						if err == nil || !body.closed || calls != 1 {
							t.Fatalf("error=%v closed=%t calls=%d", err, body.closed, calls)
						}
						if tc.phase == "response_read" && (!ignores || strict) && !errors.Is(err, tc.failure) {
							t.Fatal("read cause lost")
						}
						records := readDiagnosticRecords(t, &logs)
						wantCount := 1
						// Legacy ignores intentionally continues decoding after read failure.
						if ignores && !strict && tc.phase == "response_read" {
							wantCount = 2
						}
						if len(records) != wantCount {
							t.Fatalf("records=%+v", records)
						}
						for i, r := range records {
							phase, family := tc.phase, tc.family
							if i == 1 {
								phase, family = "response_validation", "invalid_response"
							}
							// Streaming JSON reports an incomplete value as truncation.
							if !strict && !ignores && tc.name == "decode" {
								family = "truncated_response"
							}
							if r.Phase != phase || r.Family != family || r.Status == nil || *r.Status != 200 || r.Scope != "transport" {
								t.Fatalf("record=%+v want %s/%s", r, phase, family)
							}
							if instrumented {
								if r.Attempts == nil || *r.Attempts != 1 || r.RetryExhausted == nil || *r.RetryExhausted || r.ElapsedMS == nil {
									t.Fatalf("lost evidence: %+v", r)
								}
							} else if r.Attempts != nil || r.RetryExhausted != nil || r.ElapsedMS != nil {
								t.Fatalf("invented evidence: %+v", r)
							}
							if ignores && (r.Stage != "snyk_v1" || r.Endpoint != "/v1/org/{org}/project/{project}/ignores") {
								t.Fatalf("%+v", r)
							}
							if !ignores && (r.Stage != "snyk_rest" || r.Endpoint != "/rest/orgs/{org}/issues") {
								t.Fatalf("%+v", r)
							}
						}
					})
				}
			}
		}
	}
}

func TestStreamingReadErrorWithCompleteOrInvalidJSON(t *testing.T) {
	for _, instrumented := range []bool{false, true} {
		for _, tc := range []struct {
			data      string
			wantError bool
			records   int
		}{
			{`{"data":[]}`, false, 1},
			{`{"data":]}`, true, 2},
		} {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			body := &diagnosticBody{data: tc.data, failure: errors.New("SYNTHETIC_SECRET")}
			req, _ := http.NewRequest("GET", "https://example.test/rest/orgs/org-a/issues", nil)
			resp := &http.Response{StatusCode: 200, Request: req, Body: body}
			if instrumented {
				r := diagnostic.Request("snyk", req)
				r.Status, r.Attempts, r.RetryExhausted = new(200), new(3), new(false)
				diagnostic.ObserveBody(resp, r, time.Now().Add(-time.Second), logger)
			}
			c := &Client{logger: logger}
			var into issueListResponse
			err := c.decodeJSON(resp, &into)
			if (err != nil) != tc.wantError || !body.closed {
				t.Fatalf("error=%v closed=%t", err, body.closed)
			}
			records := readDiagnosticRecords(t, &logs)
			if len(records) != tc.records || records[0].Phase != "response_read" || records[0].Family != "unknown" {
				t.Fatalf("%+v", records)
			}
			if tc.wantError && (records[1].Phase != "response_validation" || records[1].Family != "invalid_response") {
				t.Fatalf("%+v", records)
			}
			if instrumented {
				for _, r := range records {
					if r.Attempts == nil || *r.Attempts != 3 || r.ElapsedMS == nil || *r.ElapsedMS < 1000 {
						t.Fatalf("lost transport history: %+v", r)
					}
				}
			}
		}
	}
}
