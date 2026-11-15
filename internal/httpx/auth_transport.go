package httpx

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/diagnostic"

	"golang.org/x/oauth2"
)

type BearerTransport struct {
	Base        http.RoundTripper
	TokenSource oauth2.TokenSource
	Logger      *slog.Logger
}

func (t *BearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	token, err := t.TokenSource.Token()
	if err != nil {
		r := diagnostic.Record{Provider: "snyk", Stage: "snyk_oauth", Endpoint: "/oauth2/token", Method: "POST", Phase: "operation", Scope: "token_source", Family: diagnostic.Family(err)}
		var retrieval *oauth2.RetrieveError
		if errors.As(err, &retrieval) && retrieval.Response != nil {
			r.Status = new(retrieval.Response.StatusCode)
			r.Family = "http_status"
		}
		diagnostic.Emit(t.Logger, r, start)
		return nil, err
	}

	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	cloned.Header.Set("Authorization", "Bearer "+token.AccessToken)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(cloned)
}

type HeaderTransport struct {
	Base  http.RoundTripper
	Key   string
	Value string
}

func (t *HeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	cloned.Header.Set(t.Key, t.Value)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(cloned)
}
