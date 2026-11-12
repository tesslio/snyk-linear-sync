package linear

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	gqlclient "git.sr.ht/~emersion/gqlclient"

	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/httpx"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

func reviewedMutationClient(t *testing.T, response func(string) string) *Client {
	t.Helper()
	return &Client{
		cfg: config.LinearConfig{TeamID: "team-1", States: config.StateConfig{Todo: "Todo"}},
		gql: gqlclient.New("https://linear.test/graphql", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var request struct{ Query string }
			if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(t, response(request.Query)), nil
		})}),
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), resolvedTeam: "team-1",
		statesByName: map[string]string{"todo": "state-1"}, statesByType: map[string]string{"unstarted": "state-1"},
	}
}

func TestReviewedMutationDoesNotRetryGraphQLRateLimit(t *testing.T) {
	calls := 0
	client := reviewedMutationClient(t, func(string) string {
		calls++
		return `{"errors":[{"message":"rate limit exceeded"}]}`
	})
	_, err := client.CreateIssues(httpx.WithoutRetries(t.Context()), []model.DesiredIssue{{State: model.StateTodo}})
	if err == nil || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
}

func TestReviewedMutationRequiresCompleteAcknowledgments(t *testing.T) {
	for _, operation := range []string{"create", "update", "comment"} {
		for _, data := range []string{`{}`, `null`, `{"success":true}`} {
			t.Run(operation+data, func(t *testing.T) {
				client := reviewedMutationClient(t, func(query string) string {
					if strings.Contains(query, "issueLabelsByID") {
						return `{"data":{"issues":{"nodes":[{"id":"issue-1","labels":{"nodes":[]}}]}}}`
					}
					alias := map[string]string{"create": "issueCreate0", "update": "issueUpdate0", "comment": "commentCreate0"}[operation]
					if operation == "update" && data == `{"success":true}` {
						return `{"data":{}}` // Expected alias missing, not a valid acknowledgment.
					}
					return `{"data":{"` + alias + `":` + data + `}}`
				})
				ctx := httpx.WithoutRetries(t.Context())
				update := model.IssueUpdate{Existing: model.ExistingIssue{ID: "issue-1"}, Desired: model.DesiredIssue{State: model.StateTodo}, Diff: &model.IssueDiff{TitleChanged: true}}
				switch operation {
				case "create":
					outcomes, err := client.CreateIssues(ctx, []model.DesiredIssue{update.Desired})
					if err == nil && len(outcomes) == 1 && outcomes[0].Acknowledged {
						t.Fatal("accepted missing create acknowledgment or ID")
					}
				case "update":
					if err := client.UpdateIssues(ctx, []model.IssueUpdate{update}); err == nil {
						t.Fatal("accepted missing update acknowledgment")
					}
				case "comment":
					failed, err := client.PostComments(ctx, []model.IssueUpdate{update})
					if err == nil && len(failed) == 0 {
						t.Fatal("accepted missing comment acknowledgment or ID")
					}
				}
			})
		}
	}
}

func TestReviewedCreateStopsAfterPartialOrUncertainCleanup(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncertain-cleanup", true: "partial-create"}[partial], func(t *testing.T) {
			cleanup := 0
			client := reviewedMutationClient(t, func(query string) string {
				if strings.Contains(query, "issueCreateBatch") {
					if partial {
						return `{"data":{"issueCreate0":{"success":true}}}`
					}
					return `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1"}}}}`
				}
				cleanup++
				return `{"data":{}}`
			})
			client.cfg.UnsubscribeActor = true
			outcomes, err := client.CreateIssues(httpx.WithoutRetries(t.Context()), []model.DesiredIssue{{State: model.StateTodo}})
			if err == nil && len(outcomes) == 1 && outcomes[0].Acknowledged {
				t.Fatal("concealed uncertain create or cleanup response")
			}
			if partial && cleanup != 0 || !partial && cleanup != 1 {
				t.Fatalf("cleanup calls=%d", cleanup)
			}
		})
	}
}
