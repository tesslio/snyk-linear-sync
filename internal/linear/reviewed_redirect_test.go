package linear

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/httpx"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

func TestReviewedRealClientNeverReplaysRedirectedMutation(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			calls := 0
			http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: status, Header: http.Header{"Location": {"https://api.linear.app/redirected"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
			})
			client := New(config.LinearConfig{TeamID: "11111111-1111-4111-8111-111111111111", States: config.StateConfig{Todo: "Todo"}}, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
			client.statesByName = map[string]string{"todo": "state-1"}
			_, err := client.CreateIssues(httpx.WithoutRetries(t.Context()), []model.DesiredIssue{{State: model.StateTodo}})
			if err == nil || calls != 1 {
				t.Fatalf("redirected mutation replayed: calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestOrdinaryRedirectPolicyPreservesTenRequestLimit(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := linearRedirect(req, make([]*http.Request, 9)); err != nil {
		t.Fatal("ordinary redirect blocked too early")
	}
	if err := linearRedirect(req, make([]*http.Request, 10)); err == nil {
		t.Fatal("ordinary redirect lost default limit")
	}
}
