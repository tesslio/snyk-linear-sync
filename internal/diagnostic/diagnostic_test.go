package diagnostic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClosedProjectionAndNestedFailures(t *testing.T) {
	secret := "SYNTHETIC_SECRET\nAuthorization: bearer malicious"
	for _, tc := range []struct {
		err    error
		family string
	}{
		{errors.Join(errors.New(secret), fmt.Errorf("%s: %w", secret, context.DeadlineExceeded)), "timeout"},
		{fmt.Errorf("%s: %w", secret, io.ErrUnexpectedEOF), "truncated_response"},
		{&url.Error{Op: secret, URL: secret, Err: context.Canceled}, "canceled"},
		{errors.New(secret), "unknown"},
	} {
		var logs bytes.Buffer
		Emit(slog.New(slog.NewJSONHandler(&logs, nil)), Record{Provider: secret, Stage: secret, Endpoint: secret, Method: secret, Phase: secret, Family: Family(tc.err), Scope: secret, Status: new(1000), Attempts: new(-1)}, time.Now())
		if strings.Contains(logs.String(), "SYNTHETIC_SECRET") {
			t.Fatal("secret leaked")
		}
		var line struct {
			Diagnostic string `json:"diagnostic_json"`
		}
		if err := json.Unmarshal(logs.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		var r Record
		if err := json.Unmarshal([]byte(line.Diagnostic), &r); err != nil {
			t.Fatal(err)
		}
		if r.Family != tc.family || r.Status != nil || r.Attempts != nil || r.Endpoint != "unknown" || r.Version != 1 {
			t.Fatalf("unexpected projection: %+v", r)
		}
	}
}

func TestEndpointProjection(t *testing.T) {
	for _, tc := range []struct{ path, stage, endpoint string }{
		{"/rest/orgs/SYNTHETIC_SECRET", "snyk_rest", "/rest/orgs/{org}"},
		{"/rest/orgs/SYNTHETIC_SECRET/issues", "snyk_rest", "/rest/orgs/{org}/issues"},
		{"/rest/orgs/SYNTHETIC_SECRET/projects", "snyk_rest", "/rest/orgs/{org}/projects"},
		{"/v1/org/SYNTHETIC_SECRET/project/private", "snyk_v1", "/v1/org/{org}/project/{project}"},
		{"/v1/org/SYNTHETIC_SECRET/project/private/ignores", "snyk_v1", "/v1/org/{org}/project/{project}/ignores"},
		{"/unexpected/SYNTHETIC_SECRET", "unknown", "unknown"},
	} {
		req, _ := http.NewRequest("GET", "https://user:SYNTHETIC_SECRET@example.test"+tc.path+"?token=SYNTHETIC_SECRET", nil)
		r := Request("snyk", req)
		if r.Stage != tc.stage || r.Endpoint != tc.endpoint {
			t.Fatalf("%+v", r)
		}
	}
}

func TestConsumerFixturesAndTextEncoding(t *testing.T) {
	raw, err := os.ReadFile("../../docs/fixtures/failure-diagnostics-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name       string `json:"name"`
		Diagnostic Record `json:"diagnostic"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			var logs bytes.Buffer
			start := time.Now()
			if fixture.Diagnostic.ElapsedMS == nil {
				start = time.Time{}
			}
			Emit(slog.New(slog.NewTextHandler(&logs, nil)), fixture.Diagnostic, start)
			_, value, found := strings.Cut(strings.TrimSpace(logs.String()), "diagnostic_json=")
			if !found {
				t.Fatal("missing field")
			}
			decoded, err := strconv.Unquote(value)
			if err != nil {
				t.Fatal(err)
			}
			var actual Record
			if err := json.Unmarshal([]byte(decoded), &actual); err != nil {
				t.Fatal(err)
			}
			if actual.ElapsedMS != nil {
				actual.ElapsedMS = new(int64(0))
			}
			if !reflect.DeepEqual(actual, fixture.Diagnostic) {
				t.Fatalf("fixture changed: %+v", actual)
			}
		})
	}
}
