// Package diagnostic emits a closed, value-free failure contract. Ordinary logs
// and errors are not part of this contract and must not be retained as diagnostics.
package diagnostic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Record describes one failed boundary, not a final sync outcome. Attempts count
// invocations at Scope only; nil means the boundary cannot observe that fact.
type Record struct {
	Version        int    `json:"version"`
	Provider       string `json:"provider"`
	Stage          string `json:"stage"`
	Endpoint       string `json:"endpoint"`
	Method         string `json:"method"`
	Phase          string `json:"phase"`
	Status         *int   `json:"status"`
	Family         string `json:"family"`
	Scope          string `json:"attempt_scope"`
	Attempts       *int   `json:"attempts"`
	RetryExhausted *bool  `json:"retry_exhausted"`
	ElapsedMS      *int64 `json:"elapsed_ms"`
}

// Family never parses or copies exception text. errors.As/Is also recognize
// wrapped and joined failures; precedence is cancellation, timeout, truncation,
// invalid JSON, network, then unknown.
func Family(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if hasTimeout(err) {
		return "timeout"
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return "truncated_response"
	}
	var syntax *json.SyntaxError
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &typeError) {
		return "invalid_response"
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return "network"
	}
	return "unknown"
}

// errors.As finds only the first matching error. Inspect every unwrap branch
// before allowing a lower-priority family to win, including beneath net.Errors
// whose own Timeout method returns false.
func hasTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		if slices.ContainsFunc(e.Unwrap(), hasTimeout) {
			return true
		}
	case interface{ Unwrap() error }:
		return hasTimeout(e.Unwrap())
	}
	return false
}

type sdkKey struct{}

func SDKContext(ctx context.Context) context.Context { return context.WithValue(ctx, sdkKey{}, true) }

// Request uses only known path shapes. Hosts, query values and dynamic path
// segments are never returned, including for custom or malformed endpoints.
func Request(provider string, req *http.Request) Record {
	r := Record{Provider: provider, Stage: "unknown", Endpoint: "unknown", Method: "unknown", Scope: "transport"}
	if req == nil {
		return r
	}
	r.Method = req.Method
	if provider == "linear" {
		r.Stage, r.Endpoint = "linear_graphql", "/graphql"
		return r
	}
	if provider != "snyk" || req.URL == nil {
		return r
	}
	p := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(p) >= 3 && p[0] == "rest" && p[1] == "orgs" {
		r.Stage = "snyk_rest"
		if len(p) == 3 {
			r.Endpoint = "/rest/orgs/{org}"
		}
		if len(p) == 4 && p[3] == "projects" {
			r.Endpoint = "/rest/orgs/{org}/projects"
		}
		if len(p) == 4 && p[3] == "issues" {
			r.Endpoint = "/rest/orgs/{org}/issues"
		}
	}
	if len(p) >= 5 && p[0] == "v1" && p[1] == "org" && p[3] == "project" {
		r.Stage = "snyk_v1"
		if len(p) == 5 {
			r.Endpoint = "/v1/org/{org}/project/{project}"
		}
		if len(p) == 6 && p[5] == "ignores" {
			r.Endpoint = "/v1/org/{org}/project/{project}/ignores"
		}
	}
	if sdk, _ := req.Context().Value(sdkKey{}).(bool); sdk {
		r.Stage = "snyk_sdk"
	}
	return r
}

func allowed(value string, values ...string) string {
	if slices.Contains(values, value) {
		return value
	}
	return "unknown"
}

// Emit projects even internal callers onto the closed schema. No arbitrary
// strings, headers, error text or body bytes can enter the retained record.
func Emit(logger *slog.Logger, r Record, start time.Time) {
	r.Version = 1
	r.Provider = allowed(r.Provider, "snyk", "linear")
	r.Stage = allowed(r.Stage, "snyk_oauth", "snyk_rest", "snyk_v1", "snyk_sdk", "linear_graphql")
	r.Endpoint = allowed(r.Endpoint, "/oauth2/token", "/graphql", "/rest/orgs/{org}", "/rest/orgs/{org}/projects", "/rest/orgs/{org}/issues", "/v1/org/{org}/project/{project}", "/v1/org/{org}/project/{project}/ignores")
	r.Method = allowed(r.Method, "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
	r.Phase = allowed(r.Phase, "transport", "response_read", "response_validation", "operation")
	r.Family = allowed(r.Family, "http_status", "graphql", "canceled", "timeout", "truncated_response", "invalid_response", "network", "unknown")
	r.Scope = allowed(r.Scope, "transport", "graphql_execute", "token_source", "sdk_call")
	if r.Status != nil && (*r.Status < 100 || *r.Status > 599) {
		r.Status = nil
	}
	if r.Attempts != nil && (*r.Attempts < 0 || *r.Attempts > 1000) {
		r.Attempts = nil
	}
	r.ElapsedMS = nil
	if !start.IsZero() {
		r.ElapsedMS = new(max(0, time.Since(start).Milliseconds()))
	}
	if logger == nil {
		logger = slog.Default()
	}
	encoded, _ := json.Marshal(r) // closed record has no fallible JSON values
	logger.Error("external operation failed", slog.String("diagnostic_json", string(encoded)))
}

// Response evidence follows the body without changing response/request headers.
// Read delegates exactly once and returns precisely the original bytes/error.
type body struct {
	io.ReadCloser
	record   Record
	start    time.Time
	logger   *slog.Logger
	reported bool
}

func (b *body) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF && !b.reported {
		b.reported = true
		r := b.record
		r.Phase, r.Family = "response_read", Family(err)
		Emit(b.logger, r, b.start)
	}
	return n, err
}
func ObserveBody(resp *http.Response, r Record, start time.Time, logger *slog.Logger) {
	if resp != nil && resp.Body != nil {
		resp.Body = &body{ReadCloser: resp.Body, record: r, start: start, logger: logger}
	}
}

// ResponseReadFailure reports an actual non-EOF body read failure, unless the
// transport's body observer already reported it. Decode/validation failures use
// ResponseFailure, even when their family is truncated_response.
func ResponseReadFailure(logger *slog.Logger, resp *http.Response, err error) {
	if err == nil || err == io.EOF {
		return
	}
	if resp != nil {
		if b, ok := resp.Body.(*body); ok && b.reported {
			return
		}
	}
	responseFailure(logger, resp, "response_read", Family(err))
}

func ResponseFailure(logger *slog.Logger, resp *http.Response, family string) {
	responseFailure(logger, resp, "response_validation", family)
}

func responseFailure(logger *slog.Logger, resp *http.Response, phase, family string) {
	r := Request("snyk", nil)
	var start time.Time
	if resp != nil {
		r = Request("snyk", resp.Request)
		r.Status = new(resp.StatusCode)
		if b, ok := resp.Body.(*body); ok {
			r, start = b.record, b.start
		}
	}
	r.Phase, r.Family = phase, family
	Emit(logger, r, start)
}
