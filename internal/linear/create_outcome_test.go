package linear

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	gqlclient "git.sr.ht/~emersion/gqlclient"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/httpx"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

func TestCreateOutcomesPreserveAliasesWithoutUncertainRetries(t *testing.T) {
	for _, tc := range []struct {
		name, body    string
		wantError     bool
		first, second bool
	}{
		{"all acknowledged", `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"SNYK-1"}},"issueCreate1":{"success":true,"issue":{"id":"issue-2","identifier":"SNYK-2"}}}}`, false, true, true},
		{"explicit failure", `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"SNYK-1"}},"issueCreate1":{"success":false}}}`, false, true, false},
		{"partial graphql rate limit", `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"SNYK-1"}},"issueCreate1":null},"errors":[{"message":"rate limit exceeded","path":["issueCreate1"]}]}`, true, true, false},
		{"missing alias", `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"SNYK-1"}}}}`, true, true, false},
		{"empty id", `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"SNYK-1"}},"issueCreate1":{"success":true,"issue":{"id":" "}}}}`, true, true, false},
		{"null alias", `{"data":{"issueCreate0":null,"issueCreate1":null}}`, true, false, false},
		{"empty aliases", `{"data":{"issueCreate0":{},"issueCreate1":{}}}`, true, false, false},
		{"contradictory id", `{"data":{"issueCreate0":{"success":false,"issue":{"id":"issue-1"}},"issueCreate1":{"success":false}}}`, true, false, false},
	} {
		for _, guarded := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: " ordinary", true: " guarded"}[guarded], func(t *testing.T) {
				calls := 0
				client := reviewedMutationClient(t, func(string) string { calls++; return tc.body })
				ctx := t.Context()
				if guarded {
					ctx = httpx.WithoutRetries(ctx)
				}
				got, err := client.CreateIssues(ctx, []model.DesiredIssue{{State: model.StateTodo}, {State: model.StateTodo}})
				if (err != nil) != tc.wantError || calls != 1 || len(got) != 2 {
					t.Fatalf("outcomes=%+v error=%v calls=%d", got, err, calls)
				}
				if got[0].Index != 0 || got[1].Index != 1 || got[0].Acknowledged != tc.first || got[1].Acknowledged != tc.second {
					t.Fatalf("outcomes=%+v", got)
				}
				if tc.first && (got[0].ID != "issue-1" || got[0].Identifier != "SNYK-1") {
					t.Fatalf("lost acknowledged identity: %+v", got[0])
				}
			})
		}
	}
}

func TestCreateTransportErrorNeverRetries(t *testing.T) {
	calls := 0
	client := &Client{cfg: config.LinearConfig{TeamID: "team-1", States: config.StateConfig{Todo: "Todo"}},
		gql: gqlclient.New("https://example.test/graphql", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("response lost") })}),
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), resolvedTeam: "team-1", statesByName: map[string]string{"todo": "state-1"}, statesByType: map[string]string{"unstarted": "state-1"}}
	got, err := client.CreateIssues(context.Background(), []model.DesiredIssue{{State: model.StateTodo}})
	if err == nil || calls != 1 || len(got) != 1 || got[0].Acknowledged {
		t.Fatalf("outcomes=%+v error=%v calls=%d", got, err, calls)
	}
}

func TestCreateCleanupErrorPreservesAcknowledgedID(t *testing.T) {
	calls := 0
	client := reviewedMutationClient(t, func(string) string {
		calls++
		if calls == 1 {
			return `{"data":{"issueCreate0":{"success":true,"issue":{"id":"issue-1","identifier":"SNYK-1"}}}}`
		}
		return `{"errors":[{"message":"cleanup failed"}]}`
	})
	client.cfg.UnsubscribeActor = true
	got, err := client.CreateIssues(httpx.WithoutRetries(t.Context()), []model.DesiredIssue{{State: model.StateTodo}})
	if err == nil || calls != 2 || len(got) != 1 || !got[0].Acknowledged || got[0].ID != "issue-1" {
		t.Fatalf("outcomes=%+v error=%v calls=%d", got, err, calls)
	}
}
