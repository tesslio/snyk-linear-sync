package snyk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	snyksdk "github.com/pavel-snyk/snyk-sdk-go/v2/snyk"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/httpx"
)

const issuesAPIVersion = "2024-10-15"

type Client struct {
	requireFresh bool
	sourceReads  SourceReads
	orgID        string
	httpClient   *http.Client
	restBase     *url.URL
	v1Base       *url.URL
	sdk          *snyksdk.Client
	logger       *slog.Logger
	cache        *cache.Store
	// now, when set, replaces time.Now for the retention decisions on cached
	// ignores, so tests can simulate the passage of days.
	now func() time.Time
}

func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*Client, error) {
	region, ok := findRegion(cfg.Snyk.Region)
	if !ok {
		return nil, fmt.Errorf("unknown Snyk region %q", cfg.Snyk.Region)
	}

	tokenURL, err := url.Parse(region.RESTBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse region REST URL: %w", err)
	}
	tokenURL.Path = "/oauth2/token"
	tokenURL.RawQuery = ""
	tokenURL.Fragment = ""

	oauthCfg := clientcredentials.Config{
		ClientID:     cfg.Snyk.ClientID,
		ClientSecret: cfg.Snyk.ClientSecret,
		TokenURL:     tokenURL.String(),
		Scopes:       cfg.Snyk.Scopes,
		AuthStyle:    oauth2.AuthStyleInParams,
	}

	baseTransport := httpx.NewAdaptiveTransport("snyk", cfg.Sync.SnykConcurrency, logger, nil)
	httpClient := &http.Client{
		Transport: &httpx.BearerTransport{
			Base:        baseTransport,
			TokenSource: oauthCfg.TokenSource(ctx),
		},
	}

	sdkClient, err := snyksdk.NewClient("oauth-managed", snyksdk.WithHTTPClient(httpClient), snyksdk.WithRegion(region))
	if err != nil {
		return nil, err
	}

	restBase, err := url.Parse(region.RESTBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse region REST URL: %w", err)
	}

	v1Base, err := url.Parse(region.V1BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse region V1 URL: %w", err)
	}

	return &Client{
		requireFresh: cfg.ReplaySafe || cfg.ObservationCheckpoint != "",
		orgID:        cfg.Snyk.OrgID,
		httpClient:   httpClient,
		restBase:     restBase,
		v1Base:       v1Base,
		sdk:          sdkClient,
		logger:       logger,
	}, nil
}

// SetCache attaches a SQLite cache store so the client can persist v1 ignore
// metadata. This lets the sync survive flaky 404s from the Snyk v1 ignores
// endpoint without losing snooze expiries or disregard-if-fixable flags.
func (c *Client) SetCache(store *cache.Store) {
	c.cache = store
}

func findRegion(alias string) (snyksdk.Region, bool) {
	for _, region := range snyksdk.Regions() {
		if region.Alias == alias {
			return region, true
		}
	}
	return snyksdk.Region{}, false
}

func (c *Client) decodeJSON(resp *http.Response, into any) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("snyk API %s %s failed with %d: %s", resp.Request.Method, resp.Request.URL, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if c.requireFresh {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("read complete Snyk response: %w", err)
		}
		if err := validateFreshJSON(body, into); err != nil {
			return err
		}
		return json.Unmarshal(body, into)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("decode Snyk API response: %w", err)
	}
	return nil
}

// SourceReads describes successful reads in the most recent strict snapshot.
// It is evidence of validated HTTP responses, not a server-side atomic snapshot.
type SourceReads struct {
	Organization    bool `json:"organization"`
	ProjectPages    int  `json:"project_pages"`
	IssuePages      int  `json:"issue_pages"`
	IgnoreProjects  int  `json:"ignore_projects"`
	ClusterProjects int  `json:"cluster_projects"`
	Complete        bool `json:"complete"`
}

func (c *Client) FreshSourceReads() (SourceReads, error) {
	if !c.requireFresh || !c.sourceReads.Complete || !c.sourceReads.Organization || c.sourceReads.ProjectPages == 0 || c.sourceReads.IssuePages == 0 {
		return SourceReads{}, fmt.Errorf("fresh Snyk source reads are not complete")
	}
	return c.sourceReads, nil
}

// requireJSONObject rejects absent/null objects without imposing a closed schema.
func requireJSONObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("missing or null Snyk object")
	}
	return obj, nil
}

func validateFreshJSON(body []byte, into any) error {
	// Reject duplicate keys anywhere, including case aliases for typed fields:
	// encoding/json otherwise silently merges or replaces values, making
	// completeness and identity checks ambiguous. Map keys remain case-sensitive.
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := uniqueJSONValue(dec, reflect.TypeOf(into)); err != nil {
		return fmt.Errorf("invalid fresh Snyk response: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing Snyk response data")
	}
	obj, err := requireJSONObject(body)
	if err != nil {
		return err
	}
	switch into.(type) {
	case *issueListResponse, *freshProjectsResponse:
		var rows []json.RawMessage
		if err := json.Unmarshal(obj["data"], &rows); err != nil || rows == nil {
			return fmt.Errorf("missing, null or invalid Snyk data array")
		}
		_, err := requireJSONObject(obj["links"])
		if err != nil {
			return fmt.Errorf("Snyk links: %w", err)
		}
		// JSON:API allows an unavailable next link to be omitted or null.
		// Keep the links object mandatory so a missing container is not
		// mistaken for the server's terminal-page signal.
		for _, row := range rows {
			resource, err := requireJSONObject(row)
			if err != nil {
				return err
			}
			var id string
			if err := json.Unmarshal(resource["id"], &id); err != nil || strings.TrimSpace(id) == "" {
				return fmt.Errorf("Snyk row missing id")
			}
			attrs, err := requireJSONObject(resource["attributes"])
			if err != nil {
				return err
			}
			if _, ok := into.(*issueListResponse); ok {
				var ignored *bool
				if err := json.Unmarshal(attrs["ignored"], &ignored); err != nil || ignored == nil {
					return fmt.Errorf("Snyk issue missing ignored flag")
				}
				var issue issueResource
				if err := json.Unmarshal(row, &issue); err != nil {
					return err
				}
				if issue.Attributes.Status == "" || issue.Relationships.ScanItem.Data.ID == "" || issue.Relationships.ScanItem.Data.Type == "" {
					return fmt.Errorf("Snyk issue missing status or scan item identity")
				}
				if _, err := parseIssueCreatedAt(issue.Attributes.CreatedAt); err != nil {
					return err
				}
			} else {
				var status string
				if err := json.Unmarshal(attrs["status"], &status); err != nil || (status != "active" && status != "inactive") {
					return fmt.Errorf("Snyk project missing or unknown status")
				}
			}
		}
	case *orgResponse:
		var org orgResponse
		if err := json.Unmarshal(body, &org); err != nil || strings.TrimSpace(org.Data.Attributes.Slug) == "" {
			return fmt.Errorf("Snyk organization missing slug")
		}
	case *v1ProjectDetail:
		// This is a replay safety requirement, not a claim that Snyk's
		// schema requires imageCluster. Missing/null cluster context is
		// unknown; only an explicit string (including empty) is usable.
		var cluster *string
		if err := json.Unmarshal(obj["imageCluster"], &cluster); err != nil || cluster == nil {
			return fmt.Errorf("fresh Snyk cluster context unknown: imageCluster absent, null or invalid")
		}
	}
	return nil
}

func uniqueJSONValue(dec *json.Decoder, typ reflect.Type) error {
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delimiter, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		seenFields := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid JSON object key")
			}
			seen[name] = true
			field, valueType := freshJSONField(typ, name)
			if field != "" {
				if seenFields[field] {
					return fmt.Errorf("duplicate JSON field alias %q", name)
				}
				seenFields[field] = true
			}
			if err := uniqueJSONValue(dec, valueType); err != nil {
				return err
			}
		}
	case '[':
		var valueType reflect.Type
		if typ != nil && (typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array) {
			valueType = typ.Elem()
		}
		for dec.More() {
			if err := uniqueJSONValue(dec, valueType); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = dec.Token()
	return err
}

// freshJSONField follows encoding/json's exact-then-case-insensitive matching
// for the explicit, non-embedded fields in the strict source response types.
// Unknown fields and map keys are not aliases; their spelling is significant.
// Custom v1 ignore entries are checked separately once their shape is known.
func freshJSONField(typ reflect.Type, key string) (string, reflect.Type) {
	if typ == nil {
		return "", nil
	}
	if typ.Kind() == reflect.Map {
		return "", typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return "", nil
	}
	var foldedName string
	var foldedType reflect.Type
	for field := range typ.Fields() {
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		if name == key {
			return name, field.Type
		}
		if foldedName == "" && strings.EqualFold(name, key) {
			foldedName, foldedType = name, field.Type
		}
	}
	return foldedName, foldedType
}

// ValidateFreshSnapshot is the fail-closed provenance gate for replay callers.
func (c *Client) ValidateFreshSnapshot() error {
	_, err := c.FreshSourceReads()
	return err
}
