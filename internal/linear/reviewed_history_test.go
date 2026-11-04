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

func TestReviewedHistoryRejectsMalformedNodes(t *testing.T) {
	cases := map[string]string{
		"null node":             `null`,
		"empty node":            `{}`,
		"missing createdAt":     `{"fromStateId":null,"toStateId":null}`,
		"null createdAt":        `{"createdAt":null,"fromStateId":null,"toStateId":null}`,
		"invalid nonstate time": `{"createdAt":"not-a-time","fromStateId":null,"toStateId":null}`,
		"missing fromStateId":   `{"createdAt":"2026-01-01T00:00:00Z","toStateId":"s-done"}`,
		"missing toStateId":     `{"createdAt":"2026-01-01T00:00:00Z","fromStateId":"s-todo"}`,
		"invalid fromStateId":   `{"createdAt":"2026-01-01T00:00:00Z","fromStateId":false,"toStateId":"s-done"}`,
		"invalid toStateId":     `{"createdAt":"2026-01-01T00:00:00Z","fromStateId":"s-todo","toStateId":{}}`,
		"blank state ID":        `{"createdAt":"2026-01-01T00:00:00Z","fromStateId":null,"toStateId":" "}`,
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			var requests []map[string]any
			client := historyClient(t, map[string]map[string]string{
				"issue-1": {"": historyPage(false, "", node)},
			}, &requests)
			states, err := client.LastOpenStates(t.Context(), []string{"issue-1"})
			if err == nil || len(states) != 0 {
				t.Fatalf("malformed history accepted: states=%v, error=%v", states, err)
			}
		})
	}
}

func TestReviewedHistoryAcceptsExplicitNullStateFields(t *testing.T) {
	var requests []map[string]any
	client := historyClient(t, map[string]map[string]string{
		"issue-1": {"": historyPage(false, "", historyNode("2026-01-01T00:00:00Z", "", ""))},
	}, &requests)
	states, err := client.LastOpenStates(t.Context(), []string{"issue-1"})
	if err != nil || len(states) != 0 || len(requests) != 1 {
		t.Fatalf("complete nonstate history rejected: states=%v, error=%v, requests=%d", states, err, len(requests))
	}
}

func TestReviewedHistoryRejectsBrokenContinuation(t *testing.T) {
	cases := map[string]struct {
		pages map[string]string
		calls int
	}{
		"missing cursor": {map[string]string{"": `{"data":{"issue":{"history":{"nodes":[],"pageInfo":{"hasNextPage":true}}}}}`}, 1},
		"blank cursor":   {map[string]string{"": historyPage(true, " \t ")}, 1},
		"cursor cycle": {map[string]string{
			"": historyPage(true, "page-a"), "page-a": historyPage(true, "page-b"), "page-b": historyPage(true, "page-a"),
		}, 3},
		"malformed later page": {map[string]string{
			"":       historyPage(true, "page-a", historyNode("2026-01-01T00:00:00Z", "s-todo", "s-done")),
			"page-a": historyPage(false, "", "null"),
		}, 2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var requests []map[string]any
			client := historyClient(t, map[string]map[string]string{"issue-1": tc.pages}, &requests)
			states, err := client.LastOpenStates(t.Context(), []string{"issue-1"})
			if err == nil || len(states) != 0 || len(requests) != tc.calls {
				t.Fatalf("incomplete history accepted or wrong request count: states=%v, error=%v, requests=%d", states, err, len(requests))
			}
		})
	}
}

func TestReviewedHistoryPageLimit(t *testing.T) {
	pages := map[string]string{}
	cursor := ""
	for i := 0; i <= maxHistoryPages; i++ {
		next := fmt.Sprintf("page-%d", i+1)
		pages[cursor] = historyPage(true, next)
		cursor = next
	}
	var requests []map[string]any
	client := historyClient(t, map[string]map[string]string{"issue-1": pages}, &requests)
	if _, err := client.LastOpenStates(t.Context(), []string{"issue-1"}); err == nil || len(requests) != maxHistoryPages {
		t.Fatalf("history limit was not enforced: error=%v, requests=%d", err, len(requests))
	}
}

func reviewedStatesClient(t *testing.T, page func(string, int) string, calls *int) *Client {
	t.Helper()
	return &Client{
		cfg:          config.LinearConfig{TeamID: "team-1"},
		resolvedTeam: "team-1",
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		gql: gqlclient.New("http://linear.test/graphql", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var payload struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(payload.Query, "states(") {
					t.Fatalf("unexpected query: %s", payload.Query)
				}
				*calls++
				// Bound a defective loader too, so the regression reports failure
				// rather than hanging on a repeated continuation cursor.
				if *calls > 21 {
					return nil, fmt.Errorf("test state-page request limit exceeded")
				}
				cursor, _ := payload.Variables["after"].(string)
				return jsonResponse(t, page(cursor, *calls)), nil
			}),
		}),
	}
}

func reviewedStatesPage(hasNext bool, cursor string, nodes ...string) string {
	return fmt.Sprintf(`{"data":{"team":{"states":{"nodes":[%s],"pageInfo":{"hasNextPage":%t,"endCursor":%q}}}}}`, strings.Join(nodes, ","), hasNext, cursor)
}

func TestReviewedStatesRejectsIncompleteInventory(t *testing.T) {
	cases := map[string]string{
		"missing team":     `{"data":{}}`,
		"null team":        `{"data":{"team":null}}`,
		"missing states":   `{"data":{"team":{}}}`,
		"null states":      `{"data":{"team":{"states":null}}}`,
		"missing nodes":    `{"data":{"team":{"states":{"pageInfo":{"hasNextPage":false}}}}}`,
		"null nodes":       `{"data":{"team":{"states":{"nodes":null,"pageInfo":{"hasNextPage":false}}}}}`,
		"missing pageInfo": `{"data":{"team":{"states":{"nodes":[]}}}}`,
		"null pageInfo":    `{"data":{"team":{"states":{"nodes":[],"pageInfo":null}}}}`,
		"missing next":     `{"data":{"team":{"states":{"nodes":[],"pageInfo":{}}}}}`,
		"null next":        `{"data":{"team":{"states":{"nodes":[],"pageInfo":{"hasNextPage":null}}}}}`,
		"null node":        reviewedStatesPage(false, "", "null"),
		"missing id":       reviewedStatesPage(false, "", `{"name":"Todo","type":"unstarted"}`),
		"empty id":         reviewedStatesPage(false, "", `{"id":"","name":"Todo","type":"unstarted"}`),
		"missing name":     reviewedStatesPage(false, "", `{"id":"s-todo","type":"unstarted"}`),
		"empty name":       reviewedStatesPage(false, "", `{"id":"s-todo","name":"","type":"unstarted"}`),
		"missing type":     reviewedStatesPage(false, "", `{"id":"s-todo","name":"Todo"}`),
		"empty type":       reviewedStatesPage(false, "", `{"id":"s-todo","name":"Todo","type":""}`),
	}
	for name, page := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			client := reviewedStatesClient(t, func(string, int) string { return page }, &calls)
			if err := client.loadStates(t.Context()); err == nil || calls != 1 {
				t.Fatalf("incomplete state inventory accepted: error=%v, requests=%d", err, calls)
			}
		})
	}
}

func TestReviewedStatesRejectsBrokenContinuation(t *testing.T) {
	cases := map[string]struct {
		pages map[string]string
		calls int
	}{
		"missing cursor": {map[string]string{"": `{"data":{"team":{"states":{"nodes":[],"pageInfo":{"hasNextPage":true}}}}}`}, 1},
		"null cursor":    {map[string]string{"": `{"data":{"team":{"states":{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":null}}}}}`}, 1},
		"empty cursor":   {map[string]string{"": reviewedStatesPage(true, "")}, 1},
		"blank cursor":   {map[string]string{"": reviewedStatesPage(true, " \t ")}, 1},
		"repeated cursor": {map[string]string{
			"": reviewedStatesPage(true, "page-a"), "page-a": reviewedStatesPage(true, "page-a"),
		}, 2},
		"cursor cycle": {map[string]string{
			"": reviewedStatesPage(true, "page-a"), "page-a": reviewedStatesPage(true, "page-b"), "page-b": reviewedStatesPage(true, "page-a"),
		}, 3},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			client := reviewedStatesClient(t, func(cursor string, _ int) string { return tc.pages[cursor] }, &calls)
			if err := client.loadStates(t.Context()); err == nil || calls != tc.calls {
				t.Fatalf("broken state pagination accepted or wrong request count: error=%v, requests=%d", err, calls)
			}
		})
	}
}

func TestReviewedStatesPageLimit(t *testing.T) {
	calls := 0
	client := reviewedStatesClient(t, func(_ string, call int) string {
		return reviewedStatesPage(true, fmt.Sprintf("page-%d", call))
	}, &calls)
	if err := client.loadStates(t.Context()); err == nil || calls != 20 {
		t.Fatalf("state inventory page limit was not enforced: error=%v, requests=%d", err, calls)
	}
}

func TestReviewedStatesDoesNotPublishPartialInventory(t *testing.T) {
	calls := 0
	client := reviewedStatesClient(t, func(cursor string, _ int) string {
		if cursor == "" {
			return reviewedStatesPage(true, "page-a", `{"id":"s-new","name":"New","type":"unstarted"}`)
		}
		return `{"data":{"team":{"states":null}}}`
	}, &calls)
	client.statesByName = map[string]string{"old": "s-old"}
	client.statesByType = map[string]string{"started": "s-old"}
	client.statesByID = map[string]workflowState{"s-old": {name: "Old", stateType: "started"}}
	if err := client.loadStates(t.Context()); err == nil {
		t.Fatal("malformed continuation was accepted")
	}
	if len(client.statesByName) != 1 || client.statesByName["old"] != "s-old" || len(client.statesByID) != 1 || client.statesByID["s-old"].name != "Old" || client.statesByType["started"] != "s-old" {
		t.Fatal("incomplete state inventory replaced the last complete inventory")
	}
}

func TestReviewedStatesAcceptsCompleteInventory(t *testing.T) {
	for _, multiplePages := range []bool{false, true} {
		t.Run(fmt.Sprint(multiplePages), func(t *testing.T) {
			calls := 0
			client := reviewedStatesClient(t, func(cursor string, call int) string {
				if multiplePages && cursor == "" {
					return reviewedStatesPage(true, "page-a", `{"id":"s-todo","name":"Todo","type":"unstarted"}`)
				}
				return reviewedStatesPage(false, "", `{"id":"s-done","name":"Done","type":"completed"}`)
			}, &calls)
			if err := client.loadStates(t.Context()); err != nil {
				t.Fatal(err)
			}
			if client.statesByID["s-done"].name != "Done" || multiplePages && client.statesByID["s-todo"].name != "Todo" {
				t.Fatalf("complete state inventory was not loaded: %+v", client.statesByID)
			}
		})
	}
}
