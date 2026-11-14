package snyk

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/diagnostic"
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
