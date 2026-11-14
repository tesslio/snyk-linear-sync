package linear

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/diagnostic"
	"github.com/tesslio/snyk-linear-sync/internal/httpx"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

func TestDiagnosticGraphQLFailurePreservesSingleMutation(t *testing.T) {
	calls := 0
	c := reviewedMutationClient(t, func(string) string {
		calls++
		return `{"errors":[{"message":"rate limit exceeded SYNTHETIC_SECRET","path":["SYNTHETIC_SECRET"],"extensions":{"secret":"SYNTHETIC_SECRET"}}]}`
	})
	var logs bytes.Buffer
	c.log = slog.New(slog.NewJSONHandler(&logs, nil))
	_, err := c.CreateIssues(httpx.WithoutRetries(t.Context()), []model.DesiredIssue{{State: model.StateTodo}})
	if err == nil || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
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
	var r diagnostic.Record
	if err := json.Unmarshal([]byte(row.Diagnostic), &r); err != nil {
		t.Fatal(err)
	}
	if r.Stage != "linear_graphql" || r.Family != "graphql" || *r.Attempts != 1 || *r.RetryExhausted || r.Status != nil {
		t.Fatalf("%+v", r)
	}
}
