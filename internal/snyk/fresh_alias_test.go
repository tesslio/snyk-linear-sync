package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestFreshDecodeRejectsCaseAliasedFields(t *testing.T) {
	issuePage := func(row string) string { return `{"data":[` + row + `],"links":{}}` }
	for _, tc := range []struct {
		name string
		body string
		into func() any
	}{
		{"issue rows", `{"data":[` + freshIssueRow + `],"DATA":null,"links":{}}`, func() any { return &issueListResponse{} }},
		{"issue rows reverse order", `{"DATA":[],"data":[` + freshIssueRow + `],"links":{}}`, func() any { return &issueListResponse{} }},
		{"project rows", `{"data":[` + freshProjectRow + `],"DaTa":[],"links":{}}`, func() any { return &freshProjectsResponse{} }},
		{"links", `{"data":[],"links":{"next":"?starting_after=next","NEXT":null}}`, func() any { return &issueListResponse{} }},
		{"attributes", issuePage(strings.Replace(freshIssueRow, `"ignored":false`, `"ignored":false,"IGNORED":true`, 1)), func() any { return &issueListResponse{} }},
		{"relationship identity", issuePage(strings.Replace(freshIssueRow, `"id":"project-a"`, `"id":"project-a","ID":"project-b"`, 1)), func() any { return &issueListResponse{} }},
		{"relationship container", issuePage(strings.Replace(freshIssueRow, `"scan_item":`, `"SCAN_ITEM":{"data":{"id":"project-b","type":"host"}},"scan_item":`, 1)), func() any { return &issueListResponse{} }},
		{"project status", `{"data":[` + strings.Replace(freshProjectRow, `"status":"active"`, `"status":"active","STATUS":"inactive"`, 1) + `],"links":{}}`, func() any { return &freshProjectsResponse{} }},
		{"organization slug", `{"data":{"attributes":{"slug":"org-a","SLUG":"org-b"}}}`, func() any { return &orgResponse{} }},
		{"cluster", `{"imageCluster":"cluster-a","IMAGECLUSTER":"cluster-b"}`, func() any { return &v1ProjectDetail{} }},
		{"nested array fields", issuePage(strings.Replace(freshIssueRow, `"ignored":false`, `"ignored":false,"coordinates":[{"representations":[{"sourceLocation":{"region":{"start":{"line":1,"LINE":2}}}}]}]`, 1)), func() any { return &issueListResponse{} }},
		{"unicode field alias", issuePage(strings.Replace(freshIssueRow, `"ignored":false`, `"ignored":false,"key":"SNYK-100","\u212aey":"SNYK-200"`, 1)), func() any { return &issueListResponse{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := func() *http.Response {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.body))}
			}
			strict := &Client{requireFresh: true}
			if err := strict.decodeJSON(response(), tc.into()); err == nil || !strings.Contains(err.Error(), "duplicate JSON field alias") {
				t.Fatalf("case alias was not rejected: %v", err)
			}
			// The opt-in provenance gate must not change ordinary v1 decoding.
			legacy := &Client{}
			if err := legacy.decodeJSON(response(), tc.into()); err != nil {
				t.Fatalf("ordinary decoder changed: %v", err)
			}
		})
	}
}

func TestFreshDecodeAllowsUnambiguousFields(t *testing.T) {
	body := `{"data":[` + strings.Replace(freshIssueRow, `"ignored":false`, `"ignored":false,"TITLE":"Example issue","extension":{"key":1,"KEY":2}`, 1) + `],"links":{"NEXT":null},"Extension":1,"extension":2}`
	var page issueListResponse
	strict := &Client{requireFresh: true}
	if err := strict.decodeJSON(&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Data) != 1 || page.Data[0].Attributes.Title != "Example issue" {
		t.Fatalf("unambiguous fields were not consumed: %+v", page)
	}

	// This is the original row-erasure reproducer without the strict gate.
	body = `{"data":[` + freshIssueRow + `],"DATA":null,"links":{}}`
	var legacyPage issueListResponse
	if err := (&Client{}).decodeJSON(&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, &legacyPage); err != nil {
		t.Fatal(err)
	}
	if legacyPage.Data != nil {
		t.Fatal("fixture did not reproduce encoding/json's case-insensitive overwrite")
	}
}

func TestFreshIgnoresRejectCaseAliasedDetails(t *testing.T) {
	for name, details := range map[string]string{
		"created":       `{"created":"2025-01-01T00:00:00Z","CREATED":"invalid"}`,
		"expires":       `{"created":"2025-01-01T00:00:00Z","expires":"2025-02-01T00:00:00Z","EXPIRES":"invalid"}`,
		"flag":          `{"created":"2025-01-01T00:00:00Z","disregardIfFixable":true,"DISREGARDIFFIXABLE":false}`,
		"unicode flag":  `{"created":"2025-01-01T00:00:00Z","disregardIfFixable":true,"di\u017fregardIfFixable":false}`,
		"expiry casing": `{"created":"2025-01-01T00:00:00Z","EXPIRES":"invalid"}`,
		"null flag":     `{"created":"2025-01-01T00:00:00Z","DISREGARDIFFIXABLE":null}`,
		"invalid flag":  `{"created":"2025-01-01T00:00:00Z","DISREGARDIFFIXABLE":"true"}`,
	} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%t", name, nested), func(t *testing.T) {
				entry := details
				if nested {
					entry = `{"Src/File.go":` + entry + `}`
				}
				body := `{"issue-1":[` + entry + `]}`
				c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
				if _, err := c.fetchProjectIgnoresWithRetry(context.Background(), "project-a", 1); err == nil {
					t.Fatal("accepted malformed ignore details")
				}
				c.requireFresh = false
				if _, err := c.fetchProjectIgnoresWithRetry(context.Background(), "project-a", 1); err != nil {
					t.Fatalf("ordinary ignore decoder changed: %v", err)
				}
			})
		}
	}
}

func TestFreshIgnoresPreserveCaseDistinctKeysAndPaths(t *testing.T) {
	body := `{
		"ISSUE-1":[
			{"Src/File.go":{"created":"2025-01-01T00:00:00Z","EXPIRES":"2025-02-01T00:00:00Z"}},
			{"src/file.go":{"created":"2025-01-02T00:00:00Z","expires":"2025-03-01T00:00:00Z"}}
		],
		"issue-1":[{"CREATED":{"created":"2025-01-03T00:00:00Z","DISREGARDIFFIXABLE":true,"extra":1,"EXTRA":2}}]
	}`
	c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
	got, err := c.fetchProjectIgnoresWithRetry(context.Background(), "project-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got["ISSUE-1"]) != 2 || len(got["issue-1"]) != 1 {
		t.Fatalf("case-distinct identities were lost: %+v", got)
	}
	if got["ISSUE-1"][0].Expires != "2025-02-01T00:00:00Z" || !got["issue-1"][0].DisregardIfFixable {
		t.Fatalf("unambiguous case aliases were not consumed: %+v", got)
	}
	var legacy v1ProjectIgnores
	if err := json.Unmarshal([]byte(body), &legacy); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, legacy) {
		t.Fatalf("strict validation changed consumed values: got %+v, legacy %+v", got, legacy)
	}
}
