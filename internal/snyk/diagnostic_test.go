package snyk

import (
	"bytes"
	"encoding/json"
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
