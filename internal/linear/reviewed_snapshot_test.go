package linear

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	gqlclient "git.sr.ht/~emersion/gqlclient"

	"github.com/tesslio/snyk-linear-sync/internal/config"
)

func reviewedSnapshotClient(t *testing.T, page func(string, int) string, calls *int) *Client {
	t.Helper()
	c := &Client{cfg: config.LinearConfig{TeamID: "11111111-1111-4111-8111-111111111111"}, resolvedTeam: "11111111-1111-4111-8111-111111111111", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c.gql = gqlclient.New("https://linear.test/graphql", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var payload struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(payload.Query, "existingIssues") {
			t.Fatalf("unexpected query: %s", payload.Query)
		}
		*calls++
		if *calls > maxSnapshotPages+2 {
			return nil, fmt.Errorf("test request cap exceeded")
		}
		cursor, _ := payload.Variables["after"].(string)
		return jsonResponse(t, page(cursor, *calls)), nil
	})})
	return c
}

func reviewedSnapshotPage(next bool, cursor string, nodes ...string) string {
	return fmt.Sprintf(`{"data":{"issues":{"nodes":[%s],"pageInfo":{"hasNextPage":%t,"endCursor":%q}}}}`, strings.Join(nodes, ","), next, cursor)
}
func reviewedSnapshotNode(id string) string {
	return fmt.Sprintf(`{"id":%q,"identifier":"SNYK-100","title":"Snyk: Example","description":null,"url":"https://example.test/issue","priority":0,"dueDate":null,"archivedAt":null,"createdAt":null,"completedAt":null,"canceledAt":null,"state":{"id":"state-todo","name":"Todo"},"labels":{"nodes":[]}}`, id)
}

func TestReviewedSnapshotRejectsIncompleteShapes(t *testing.T) {
	cases := map[string]string{
		"missing issues":   `{"data":{}}`,
		"null issues":      `{"data":{"issues":null}}`,
		"missing nodes":    `{"data":{"issues":{"pageInfo":{"hasNextPage":false}}}}`,
		"null nodes":       `{"data":{"issues":{"nodes":null,"pageInfo":{"hasNextPage":false}}}}`,
		"missing pageInfo": `{"data":{"issues":{"nodes":[]}}}`,
		"null pageInfo":    `{"data":{"issues":{"nodes":[],"pageInfo":null}}}`,
		"missing next":     `{"data":{"issues":{"nodes":[],"pageInfo":{}}}}`,
		"null next":        `{"data":{"issues":{"nodes":[],"pageInfo":{"hasNextPage":null}}}}`,
		"null node":        reviewedSnapshotPage(false, "", "null"),
		"missing id":       reviewedSnapshotPage(false, "", `{"title":"Snyk: Example"}`),
		"empty id":         reviewedSnapshotPage(false, "", reviewedSnapshotNode("")),
		"blank id":         reviewedSnapshotPage(false, "", reviewedSnapshotNode(" \t ")),
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c := reviewedSnapshotClient(t, func(string, int) string { return response }, &calls)
			rows, err := c.loadIssues(t.Context())
			if err == nil || len(rows) != 0 || calls != 1 {
				t.Fatalf("incomplete inventory accepted: rows=%v err=%v calls=%d", rows, err, calls)
			}
		})
	}
}

func TestReviewedSnapshotRejectsIncompleteContinuation(t *testing.T) {
	cases := map[string]struct {
		pages map[string]string
		calls int
	}{
		"missing cursor":    {map[string]string{"": `{"data":{"issues":{"nodes":[],"pageInfo":{"hasNextPage":true}}}}`}, 1},
		"null cursor":       {map[string]string{"": `{"data":{"issues":{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":null}}}}`}, 1},
		"empty cursor":      {map[string]string{"": reviewedSnapshotPage(true, "")}, 1},
		"blank cursor":      {map[string]string{"": reviewedSnapshotPage(true, " \t ")}, 1},
		"repeated cursor":   {map[string]string{"": reviewedSnapshotPage(true, "page-a"), "page-a": reviewedSnapshotPage(true, "page-a")}, 2},
		"cycle":             {map[string]string{"": reviewedSnapshotPage(true, "page-a"), "page-a": reviewedSnapshotPage(true, "page-b"), "page-b": reviewedSnapshotPage(true, "page-a")}, 3},
		"broken later page": {map[string]string{"": reviewedSnapshotPage(true, "page-a", reviewedSnapshotNode("issue-1")), "page-a": `{"data":{}}`}, 2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c := reviewedSnapshotClient(t, func(cursor string, _ int) string {
				if p, ok := tc.pages[cursor]; ok {
					return p
				}
				return `{"data":{}}`
			}, &calls)
			rows, err := c.loadIssues(t.Context())
			if err == nil || len(rows) != 0 || calls != tc.calls {
				t.Fatalf("broken continuation accepted: rows=%v err=%v calls=%d", rows, err, calls)
			}
		})
	}
}

func TestReviewedSnapshotAcceptsCompleteInventory(t *testing.T) {
	for _, mode := range []string{"empty", "single", "multi", "empty-continuation"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			c := reviewedSnapshotClient(t, func(cursor string, call int) string {
				if mode == "empty" {
					return reviewedSnapshotPage(false, "")
				}
				if mode == "single" {
					return reviewedSnapshotPage(false, "", reviewedSnapshotNode("issue-1"))
				}
				if cursor == "" {
					if mode == "empty-continuation" {
						return reviewedSnapshotPage(true, "page-a")
					}
					return reviewedSnapshotPage(true, "page-a", reviewedSnapshotNode("issue-1"))
				}
				return reviewedSnapshotPage(false, "", reviewedSnapshotNode("issue-2"))
			}, &calls)
			rows, err := c.loadIssues(t.Context())
			wantRows, wantCalls := 1, 1
			switch mode {
			case "empty":
				wantRows = 0
			case "multi":
				wantRows = 2
				wantCalls = 2
			case "empty-continuation":
				wantCalls = 2
			}
			if err != nil || len(rows) != wantRows || calls != wantCalls {
				t.Fatalf("complete inventory rejected: rows=%v err=%v calls=%d", rows, err, calls)
			}
		})
	}
}

func TestReviewedSnapshotPaginationBound(t *testing.T) {
	calls := 0
	c := reviewedSnapshotClient(t, func(_ string, call int) string { return reviewedSnapshotPage(true, fmt.Sprintf("page-%d", call)) }, &calls)
	rows, err := c.loadIssues(t.Context())
	if err == nil || len(rows) != 0 || calls != maxSnapshotPages {
		t.Fatalf("snapshot page bound not enforced: rows=%v err=%v calls=%d limit=%d", rows, err, calls, maxSnapshotPages)
	}
}
