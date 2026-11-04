package snyk

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	snyksdk "github.com/pavel-snyk/snyk-sdk-go/v2/snyk"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
)

func freshFixtureClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	rest, _ := url.Parse(server.URL + "/rest/")
	v1, _ := url.Parse(server.URL + "/v1/")
	sdk, err := snyksdk.NewClient("test-token", snyksdk.WithHTTPClient(server.Client()), snyksdk.WithRegion(snyksdk.Region{
		Alias: "test", AppBaseURL: server.URL, RESTBaseURL: rest.String(), V1BaseURL: v1.String(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return &Client{orgID: "org-a", httpClient: server.Client(), restBase: rest, v1Base: v1, sdk: sdk, requireFresh: true, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

const freshProjectRow = `{"id":"project-a","attributes":{"name":"owner/repo","origin":"github","status":"active"}}`
const freshIssueRow = `{"id":"issue-1","attributes":{"created_at":"2025-01-01T00:00:00Z","ignored":false,"status":"open"},"relationships":{"scan_item":{"data":{"id":"project-a","type":"project"}}}}`

func TestFreshSnapshotProvenance(t *testing.T) {
	saved := ignoresRetryBackoff
	ignoresRetryBackoff = 0
	t.Cleanup(func() { ignoresRetryBackoff = saved })
	broken := false
	c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/orgs/org-a":
			fmt.Fprint(w, `{"data":{"attributes":{"slug":"org-a"}}}`)
		case "/rest/orgs/org-a/projects":
			fmt.Fprintf(w, `{"data":[%s],"links":{"next":null}}`, freshProjectRow)
		case "/rest/orgs/org-a/issues":
			if broken {
				fmt.Fprint(w, `{"data":null,"links":{"next":null}}`)
				return
			}
			fmt.Fprintf(w, `{"data":[%s],"links":{"next":null}}`, freshIssueRow)
		case "/v1/org/org-a/project/project-a/ignores":
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected request: %s", r.URL)
			http.NotFound(w, r)
		}
	})
	if err := c.ValidateFreshSnapshot(); err == nil {
		t.Fatal("unread client attested")
	}
	snapshot, err := c.LoadSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Findings) != 1 {
		t.Fatalf("findings: %d", len(snapshot.Findings))
	}
	reads, err := c.FreshSourceReads()
	if err != nil {
		t.Fatal(err)
	}
	if !reads.Complete || !reads.Organization || reads.ProjectPages != 1 || reads.IssuePages != 1 || reads.IgnoreProjects != 1 {
		t.Fatalf("reads: %+v", reads)
	}
	broken = true
	if _, err := c.LoadSnapshot(context.Background()); err == nil {
		t.Fatal("accepted broken snapshot")
	}
	if err := c.ValidateFreshSnapshot(); err == nil {
		t.Fatal("retained old provenance after failure")
	}
}

func TestFreshIssuesRejectIncompletePages(t *testing.T) {
	for name, body := range map[string]string{
		"missing data":       `{"links":{"next":null}}`,
		"null data":          `{"data":null,"links":{"next":null}}`,
		"missing links":      `{"data":[]}`,
		"bad continuation":   `{"data":[],"links":{"next":"?limit=100"}}`,
		"null row":           `{"data":[null],"links":{"next":null}}`,
		"missing attributes": `{"data":[{"id":"issue-1"}],"links":{"next":null}}`,
		"missing ignored":    `{"data":[{"id":"issue-1","attributes":{"status":"open"}}],"links":{"next":null}}`,
		"duplicate keys":     `{"data":[],"data":[],"links":{"next":null}}`,
		"trailing data":      `{"data":[],"links":{"next":null}} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, _, err := c.listIssuesPage(context.Background(), ""); err == nil {
				t.Fatal("accepted incomplete page")
			}
		})
	}
}

func TestFreshProjectPagination(t *testing.T) {
	for _, mode := range []string{"duplicate rows", "repeated cursor", "exhausted", "missing status", "success"} {
		t.Run(mode, func(t *testing.T) {
			requests := 0
			c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				switch mode {
				case "duplicate rows":
					fmt.Fprintf(w, `{"data":[%s,%s],"links":{"next":null}}`, freshProjectRow, freshProjectRow)
				case "repeated cursor":
					fmt.Fprint(w, `{"data":[],"links":{"next":"?starting_after=same"}}`)
				case "exhausted":
					fmt.Fprint(w, `{"data":[],"links":{"next":"?starting_after=next"}}`)
				case "missing status":
					fmt.Fprint(w, `{"data":[{"id":"project-a","attributes":{}}],"links":{"next":null}}`)
				default:
					fmt.Fprintf(w, `{"data":[%s],"links":{"next":null}}`, freshProjectRow)
				}
			})
			if mode == "exhausted" {
				c.sourceReads.ProjectPages = freshMaxPages - 1
			}
			_, err := c.listProjects(context.Background())
			if (err == nil) != (mode == "success") {
				t.Fatalf("error = %v", err)
			}
			if requests > 2 {
				t.Fatalf("unbounded requests: %d", requests)
			}
		})
	}
}

func TestFreshIgnoresRejectMalformed(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `{"issue-1":null}`, `{"issue-1":[null]}`, `{"issue-1":[{}]}`, `{"issue-1":[{"created":"invalid"}]}`, `{"issue-1":[{"a":{"created":"2025-01-01T00:00:00Z"},"b":{"created":"2025-01-01T00:00:00Z"}}]}`} {
		t.Run(body, func(t *testing.T) {
			c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := c.fetchProjectIgnoresWithRetry(context.Background(), "project-a", 1); err == nil {
				t.Fatal("accepted malformed ignores")
			}
		})
	}
	for _, body := range []string{`{}`, `{"issue-1":[{"created":"2025-01-01T00:00:00Z","expires":null}]}`, `{"issue-1":[{"*":{"created":"2025-01-01T00:00:00Z","disregardIfFixable":true}}]}`} {
		if err := validateFreshIgnores([]byte(body)); err != nil {
			t.Fatalf("valid %s: %v", body, err)
		}
	}
}

// Identical merged inputs would produce the same findings/plan despite the
// unavailable source. Strict mode must reject that provenance, not just hash it.
func TestFreshIgnoresRejectIdenticalCachedFallback(t *testing.T) {
	saved := ignoresRetryBackoff
	ignoresRetryBackoff = 0
	t.Cleanup(func() { ignoresRetryBackoff = saved })
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			fail := false
			c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if fail {
					w.WriteHeader(status)
					return
				}
				fmt.Fprint(w, `{"issue-1":[{"created":"2025-01-01T00:00:00Z","expires":"2025-02-01T00:00:00Z"}]}`)
			})
			store := openIgnoresStore(t)
			c.SetCache(store)
			if err := store.SaveIgnores(context.Background(), "project-a", map[string]cache.IgnoreMeta{"issue-1": {CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)}}); err != nil {
				t.Fatal(err)
			}
			c.requireFresh = false
			live, err := c.fetchProjectIgnores(context.Background(), "project-a")
			if err != nil {
				t.Fatal(err)
			}
			fail = true
			fallback, err := c.fetchProjectIgnores(context.Background(), "project-a")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(live.merged, fallback.merged) {
				t.Fatalf("fixture must reproduce identical merged data: %#v vs %#v", live.merged, fallback.merged)
			}
			c.requireFresh = true
			if _, err := c.fetchProjectIgnores(context.Background(), "project-a"); err == nil || !strings.Contains(err.Error(), "fresh") {
				t.Fatalf("fallback accepted: %v", err)
			}
		})
	}
}

func TestFreshSnapshotRejectsDuplicateIssuesAndCursorLoops(t *testing.T) {
	saved := ignoresRetryBackoff
	ignoresRetryBackoff = 0
	t.Cleanup(func() { ignoresRetryBackoff = saved })
	for _, mode := range []string{"duplicate issues", "cursor loop"} {
		t.Run(mode, func(t *testing.T) {
			requests := 0
			c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/rest/orgs/org-a":
					fmt.Fprint(w, `{"data":{"attributes":{"slug":"org-a"}}}`)
				case "/rest/orgs/org-a/projects":
					fmt.Fprintf(w, `{"data":[%s],"links":{"next":null}}`, freshProjectRow)
				case "/rest/orgs/org-a/issues":
					requests++
					if mode == "duplicate issues" {
						fmt.Fprintf(w, `{"data":[%s,%s],"links":{"next":null}}`, freshIssueRow, freshIssueRow)
					} else {
						fmt.Fprint(w, `{"data":[],"links":{"next":"?starting_after=same"}}`)
					}
				case "/v1/org/org-a/project/project-a/ignores":
					fmt.Fprint(w, `{}`)
				default:
					http.NotFound(w, r)
				}
			})
			if _, err := c.LoadSnapshot(context.Background()); err == nil {
				t.Fatal("accepted incomplete snapshot")
			}
			if err := c.ValidateFreshSnapshot(); err == nil {
				t.Fatal("attested failed snapshot")
			}
			if requests > 2 {
				t.Fatalf("requests=%d", requests)
			}
		})
	}
}

func TestFreshIgnoresRejectLast404AfterSuccess(t *testing.T) {
	saved := ignoresRetryBackoff
	ignoresRetryBackoff = 0
	t.Cleanup(func() { ignoresRetryBackoff = saved })
	calls := 0
	c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			fmt.Fprint(w, `{"issue-1":[{"created":"2025-01-01T00:00:00Z"}]}`)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	if _, err := c.fetchProjectIgnoresWithRetry(context.Background(), "project-a", 2); err == nil {
		t.Fatal("accepted partial successful attempts followed by 404")
	}
}

type freshBrokenReader struct{}

func (freshBrokenReader) Read(p []byte) (int, error) { copy(p, `{}`); return 2, io.ErrUnexpectedEOF }
func (freshBrokenReader) Close() error               { return nil }

func TestFreshDecodeRejectsBodyReadFailure(t *testing.T) {
	c := &Client{requireFresh: true}
	resp := &http.Response{StatusCode: http.StatusOK, Body: freshBrokenReader{}}
	var org orgResponse
	if err := c.decodeJSON(resp, &org); err == nil {
		t.Fatal("accepted truncated response")
	}
}

// The bundled SDK's TestProject_List uses an empty terminal links object;
// JSON:API pagination explicitly permits omitted unavailable link keys.
func TestFreshTerminalNextMayBeOmitted(t *testing.T) {
	for _, body := range []string{`{"data":[],"links":{}}`, `{"data":[],"links":{"next":null}}`} {
		c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, next, err := c.listIssuesPage(context.Background(), ""); err != nil || next != "" {
			t.Fatalf("issues terminal page: %q %v", next, err)
		}
		if _, err := c.listProjects(context.Background()); err != nil {
			t.Fatalf("projects terminal page: %v", err)
		}
	}
}

func TestFreshClusterRequiresKnownContext(t *testing.T) {
	for _, body := range []string{`{}`, `{"imageCluster":null}`, `{"imageCluster":42}`} {
		c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, err := c.fetchProjectCluster(context.Background(), "project-a"); err == nil || !strings.Contains(err.Error(), "context unknown") {
			t.Fatalf("unknown cluster: %v", err)
		}
	}
	for _, body := range []string{`{"imageCluster":""}`, `{"imageCluster":"cluster-a"}`} {
		c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, err := c.fetchProjectCluster(context.Background(), "project-a"); err != nil {
			t.Fatalf("explicit cluster: %v", err)
		}
	}
}

func TestFreshSnapshotReadsOnlyProjectIgnores(t *testing.T) {
	saved := ignoresRetryBackoff
	ignoresRetryBackoff = 0
	t.Cleanup(func() { ignoresRetryBackoff = saved })
	nonProjectIssue := strings.ReplaceAll(strings.Replace(freshIssueRow, `"id":"issue-1"`, `"id":"issue-2"`, 1), `"id":"project-a","type":"project"`, `"id":"target-a","type":"cloud_resource"`)
	for _, tc := range []struct {
		name           string
		strict         bool
		rows           []string
		failProject    bool
		wantErr        bool
		wantFindings   int
		wantIgnoreRead bool
		wantTargetRead bool
	}{
		{name: "strict excluded type", strict: true, rows: []string{nonProjectIssue}},
		{name: "strict mixed types", strict: true, rows: []string{nonProjectIssue, freshIssueRow}, wantFindings: 1, wantIgnoreRead: true},
		{name: "strict required ignores fail closed", strict: true, rows: []string{nonProjectIssue, freshIssueRow}, failProject: true, wantErr: true, wantIgnoreRead: true},
		{name: "ordinary excluded type keeps legacy reads", rows: []string{nonProjectIssue}, wantTargetRead: true},
		{name: "ordinary unstated type remains a project", rows: []string{strings.Replace(freshIssueRow, `"type":"project"`, `"type":""`, 1)}, wantFindings: 1, wantIgnoreRead: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ignoreRead, targetRead := false, false
			c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/rest/orgs/org-a":
					fmt.Fprint(w, `{"data":{"attributes":{"slug":"org-a"}}}`)
				case "/rest/orgs/org-a/projects":
					fmt.Fprintf(w, `{"data":[%s],"links":{}}`, freshProjectRow)
				case "/rest/orgs/org-a/issues":
					fmt.Fprintf(w, `{"data":[%s],"links":{}}`, strings.Join(tc.rows, ","))
				case "/v1/org/org-a/project/project-a/ignores":
					ignoreRead = true
					if tc.failProject {
						http.NotFound(w, r)
					} else {
						fmt.Fprint(w, `{}`)
					}
				case "/v1/org/org-a/project/target-a/ignores":
					targetRead = true
					http.NotFound(w, r)
				default:
					t.Errorf("unexpected request: %s", r.URL)
					http.NotFound(w, r)
				}
			})
			c.requireFresh = tc.strict
			snapshot, err := c.LoadSnapshot(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadSnapshot error = %v, want error %t", err, tc.wantErr)
			}
			if len(snapshot.Findings) != tc.wantFindings || ignoreRead != tc.wantIgnoreRead || targetRead != tc.wantTargetRead {
				t.Fatalf("findings=%d, project read=%t, excluded target read=%t", len(snapshot.Findings), ignoreRead, targetRead)
			}
			if tc.strict {
				reads, err := c.FreshSourceReads()
				if (err != nil) != tc.wantErr {
					t.Fatalf("fresh provenance error = %v, want error %t", err, tc.wantErr)
				}
				if !tc.wantErr && reads.IgnoreProjects != tc.wantFindings {
					t.Fatalf("fresh ignore project count = %d, want %d", reads.IgnoreProjects, tc.wantFindings)
				}
			}
		})
	}
}
