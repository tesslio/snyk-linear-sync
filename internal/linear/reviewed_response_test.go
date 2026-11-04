package linear

import (
	"strings"
	"testing"
)

func TestReviewedRequiredDataCannotLeakFromFailedReadAttempt(t *testing.T) {
	for _, kind := range []string{"history", "states"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			client := reviewedMutationClient(t, func(query string) string {
				calls++
				if calls > 1 {
					return `{"data":{}}`
				}
				var data string
				if kind == "history" {
					if !strings.Contains(query, "issueStateHistory") {
						t.Fatal("wrong history query")
					}
					data = historyPage(false, "", historyNode("2026-01-01T00:00:00Z", "s-todo", "s-done"))
				} else {
					if !strings.Contains(query, "teamStates") {
						t.Fatal("wrong states query")
					}
					data = reviewedStatesPage(false, "", `{"id":"s-todo","name":"Todo","type":"unstarted"}`)
				}
				return strings.TrimSuffix(data, "}") + `,"errors":[{"message":"rate limit exceeded"}]}`
			})
			client.statesByID = map[string]workflowState{"s-todo": {name: "Todo", stateType: "unstarted"}}
			if kind == "history" {
				states, err := client.LastOpenStates(t.Context(), []string{"issue-1"})
				if err == nil || len(states) != 0 {
					t.Fatal("failed-attempt history made incomplete retry look complete")
				}
			} else {
				if err := client.loadStates(t.Context()); err == nil {
					t.Fatal("failed-attempt inventory made incomplete retry look complete")
				}
			}
			if calls != 2 {
				t.Fatalf("did not exercise the retry: calls=%d", calls)
			}
		})
	}
}
