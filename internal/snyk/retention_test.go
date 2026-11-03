package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	snyksdk "github.com/pavel-snyk/snyk-sdk-go/v2/snyk"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// snykFixture is the state a fake Snyk API serves to LoadSnapshot. Tests
// mutate it between runs to simulate Snyk changing its mind: the REST issue
// flipping ignored=false, the v1 ignores endpoint forgetting an entry, or
// failing outright.
type snykFixture struct {
	issues []issueResource
	// v1 holds each project's v1 ignores response. A project absent from
	// the map answers 404.
	v1 map[string]v1ProjectIgnores
	// v1Status, when non-zero, is answered for every v1 ignores request in
	// place of the body (e.g. 500).
	v1Status int
}

const (
	fixtureOrg     = "org-1"
	fixtureProject = "project-a"
)

// newSnapshotClient serves the fixture over httptest and returns a Client
// whose REST, SDK and v1 calls all land on it, with the given cache and
// clock. The projects list always holds fixtureProject as an active GitHub
// project.
func newSnapshotClient(t *testing.T, fx *snykFixture, store *cache.Store, now *time.Time) *Client {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case path == "/rest/orgs/"+fixtureOrg:
			_, _ = io.WriteString(w, `{"data":{"attributes":{"slug":"org-a"}}}`)
		case path == "/rest/orgs/"+fixtureOrg+"/projects":
			_, _ = io.WriteString(w, `{"data":[{"id":"`+fixtureProject+`","type":"project","attributes":{"name":"owner/repo","origin":"github","status":"active","target_reference":"main"}}]}`)
		case path == "/rest/orgs/"+fixtureOrg+"/issues":
			if err := json.NewEncoder(w).Encode(issueListResponse{Data: fx.issues}); err != nil {
				t.Errorf("encode issues: %v", err)
			}
		case strings.HasPrefix(path, "/v1/org/"+fixtureOrg+"/project/") && strings.HasSuffix(path, "/ignores"):
			if fx.v1Status != 0 {
				w.WriteHeader(fx.v1Status)
				return
			}
			projectID := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/org/"+fixtureOrg+"/project/"), "/ignores")
			ignores, ok := fx.v1[projectID]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if err := json.NewEncoder(w).Encode(ignores); err != nil {
				t.Errorf("encode v1 ignores: %v", err)
			}
		default:
			t.Errorf("unexpected request %s %s", r.Method, path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	restBase, err := url.Parse(server.URL + "/rest/")
	if err != nil {
		t.Fatalf("parse REST base: %v", err)
	}
	v1Base, err := url.Parse(server.URL + "/v1/")
	if err != nil {
		t.Fatalf("parse v1 base: %v", err)
	}
	sdk, err := snyksdk.NewClient("test-token", snyksdk.WithHTTPClient(server.Client()), snyksdk.WithRegion(snyksdk.Region{
		Alias:       "test",
		AppBaseURL:  server.URL,
		RESTBaseURL: restBase.String(),
		V1BaseURL:   v1Base.String(),
	}))
	if err != nil {
		t.Fatalf("new SDK client: %v", err)
	}

	saved := ignoresRetryBackoff
	ignoresRetryBackoff = 0
	t.Cleanup(func() { ignoresRetryBackoff = saved })

	return &Client{
		orgID:      fixtureOrg,
		httpClient: server.Client(),
		restBase:   restBase,
		v1Base:     v1Base,
		sdk:        sdk,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cache:      store,
		now:        func() time.Time { return *now },
	}
}

func openIgnoresStore(t *testing.T) *cache.Store {
	t.Helper()
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// fixtureIssue is an open dependency issue of fixtureProject keyed SNYK-100
// by default; the options adjust it.
func fixtureIssue(id, key string, ignored bool) issueResource {
	issue := issueResource{ID: id, Type: "issue"}
	issue.Attributes.Key = key
	issue.Attributes.Title = "Example vulnerability"
	issue.Attributes.Type = "package_vulnerability"
	issue.Attributes.EffectiveSeverity = "high"
	issue.Attributes.Status = "open"
	issue.Attributes.Ignored = ignored
	issue.Attributes.CreatedAt = "2026-01-01T00:00:00Z"
	issue.Attributes.Coordinates = []coordinate{{
		State:           "open",
		Representations: []representation{{Dependency: dependencyRepresentation{PackageName: "example-pkg", PackageVersion: "1.0.0"}}},
	}}
	issue.Relationships.ScanItem.Data.ID = fixtureProject
	issue.Relationships.ScanItem.Data.Type = "project"
	return issue
}

func resolvedIssue(issue issueResource) issueResource {
	issue.Attributes.Status = "resolved"
	for i := range issue.Attributes.Coordinates {
		issue.Attributes.Coordinates[i].State = "resolved"
	}
	return issue
}

func snooze(created, expires time.Time) v1IgnoreEntry {
	entry := v1IgnoreEntry{Created: created.Format(time.RFC3339Nano)}
	if !expires.IsZero() {
		entry.Expires = expires.Format(time.RFC3339Nano)
	}
	return entry
}

func loadOne(t *testing.T, c *Client) model.Finding {
	t.Helper()
	snapshot, err := c.LoadSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LoadSnapshot() error = %v", err)
	}
	if len(snapshot.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(snapshot.Findings))
	}
	return snapshot.Findings[0]
}

func cachedRow(t *testing.T, store *cache.Store, key string) (cache.IgnoreMeta, bool) {
	t.Helper()
	rows, err := store.LoadIgnores(context.Background(), fixtureProject)
	if err != nil {
		t.Fatalf("LoadIgnores() error = %v", err)
	}
	row, ok := rows[key]
	return row, ok
}

var t0 = time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)

// TestLoadSnapshotKeepsExpiredSnoozeAfterV1ForgetsIt is the incident shape
// in neutral terms: a timed ignore expires, Snyk flips the REST issue to
// ignored=false, and some time later the v1 ignores endpoint stops returning
// the expired record. The cached expiry is the base of the ticket's due date
// and must survive indefinitely, not for the seven days the old TTL gave it.
func TestLoadSnapshotKeepsExpiredSnoozeAfterV1ForgetsIt(t *testing.T) {
	store := openIgnoresStore(t)
	expires := t0.Add(5 * 24 * time.Hour)
	fx := &snykFixture{
		issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {snooze(t0.Add(-24*time.Hour), expires)}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)

	finding := loadOne(t, c)
	if finding.Status != model.FindingOpen || !finding.IgnoreExpiresAt.Equal(expires) {
		t.Fatalf("run 1: status %q expiry %v, want open with expiry %v", finding.Status, finding.IgnoreExpiresAt, expires)
	}

	// The snooze lapses, Snyk un-ignores the issue and v1 forgets the record.
	fx.issues[0].Attributes.Ignored = false
	fx.v1[fixtureProject] = v1ProjectIgnores{}
	for _, days := range []int{8, 30, 120} {
		now = t0.Add(time.Duration(days) * 24 * time.Hour)
		finding = loadOne(t, c)
		if finding.Status != model.FindingOpen {
			t.Fatalf("day %d: status = %q, want open", days, finding.Status)
		}
		if !finding.IgnoreExpiresAt.Equal(expires) {
			t.Fatalf("day %d: IgnoreExpiresAt = %v, want %v kept from the cache", days, finding.IgnoreExpiresAt, expires)
		}
		row, ok := cachedRow(t, store, "SNYK-100")
		if !ok || !row.ExpiresAt.Equal(expires) {
			t.Fatalf("day %d: cached row = %+v (present %v), want expiry %v", days, row, ok, expires)
		}
	}
}

// TestLoadSnapshotKeepsExpiredSnoozeWhileSnykStillIgnores covers the expired
// snooze Snyk has not yet flipped: with the cached expiry the finding stays
// open (not the "no metadata, permanent ignore" path), whatever v1 returns.
func TestLoadSnapshotKeepsExpiredSnoozeWhileSnykStillIgnores(t *testing.T) {
	store := openIgnoresStore(t)
	expires := t0.Add(5 * 24 * time.Hour)
	fx := &snykFixture{
		issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {snooze(t0.Add(-24*time.Hour), expires)}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)
	loadOne(t, c)

	fx.v1[fixtureProject] = v1ProjectIgnores{}
	now = t0.Add(30 * 24 * time.Hour)
	finding := loadOne(t, c)
	if finding.Status != model.FindingOpen {
		t.Fatalf("status = %q, want open (expired snooze still asserted by Snyk is not a permanent ignore)", finding.Status)
	}
	if !finding.IgnoreExpiresAt.Equal(expires) {
		t.Fatalf("IgnoreExpiresAt = %v, want %v", finding.IgnoreExpiresAt, expires)
	}
	if _, ok := cachedRow(t, store, "SNYK-100"); !ok {
		t.Fatal("cached row dropped while Snyk still reports the issue ignored")
	}
}

// TestLoadSnapshotKeepsActiveSnoozeSnykStillAsserts: v1 is silent about an
// active snooze but the REST issue is still ignored. Snyk asserts the ignore,
// so the row is kept past the grace period and never aged.
func TestLoadSnapshotKeepsActiveSnoozeSnykStillAsserts(t *testing.T) {
	store := openIgnoresStore(t)
	expires := t0.Add(60 * 24 * time.Hour)
	fx := &snykFixture{
		issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {snooze(t0.Add(-24*time.Hour), expires)}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)
	loadOne(t, c)

	fx.v1[fixtureProject] = v1ProjectIgnores{}
	for _, days := range []int{8, 40} {
		now = t0.Add(time.Duration(days) * 24 * time.Hour)
		finding := loadOne(t, c)
		if finding.Status != model.FindingOpen || !finding.IgnoreExpiresAt.Equal(expires) {
			t.Fatalf("day %d: status %q expiry %v, want open with %v", days, finding.Status, finding.IgnoreExpiresAt, expires)
		}
		if _, ok := cachedRow(t, store, "SNYK-100"); !ok {
			t.Fatalf("day %d: cached row dropped while Snyk still reports the issue ignored", days)
		}
	}
}

// TestLoadSnapshotDropsRevokedActiveSnoozeAfterGrace: v1 stops returning an
// active snooze and the REST issue is open and not ignored. That is a
// revocation, but partial v1 responses happen, so the row is kept for the
// grace period and dropped once it has run out.
func TestLoadSnapshotDropsRevokedActiveSnoozeAfterGrace(t *testing.T) {
	store := openIgnoresStore(t)
	expires := t0.Add(60 * 24 * time.Hour)
	fx := &snykFixture{
		issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {snooze(t0.Add(-24*time.Hour), expires)}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)
	loadOne(t, c)

	fx.issues[0].Attributes.Ignored = false
	fx.v1[fixtureProject] = v1ProjectIgnores{}

	now = t0.Add(3 * 24 * time.Hour)
	finding := loadOne(t, c)
	if !finding.IgnoreExpiresAt.Equal(expires) {
		t.Fatalf("day 3: IgnoreExpiresAt = %v, want %v (within grace)", finding.IgnoreExpiresAt, expires)
	}
	if _, ok := cachedRow(t, store, "SNYK-100"); !ok {
		t.Fatal("day 3: cached row dropped within the grace period")
	}

	now = t0.Add(8 * 24 * time.Hour)
	finding = loadOne(t, c)
	if !finding.IgnoreExpiresAt.IsZero() {
		t.Fatalf("day 8: IgnoreExpiresAt = %v, want zero (revoked snooze dropped)", finding.IgnoreExpiresAt)
	}
	if finding.Status != model.FindingOpen {
		t.Fatalf("day 8: status = %q, want open", finding.Status)
	}
	if _, ok := cachedRow(t, store, "SNYK-100"); ok {
		t.Fatal("day 8: cached row still present after the grace period")
	}
}

// TestLoadSnapshotResolvedFindingKeepsCachedSnooze: a resolved finding is
// terminal whatever the cache says, and the row stays as inert memory.
func TestLoadSnapshotResolvedFindingKeepsCachedSnooze(t *testing.T) {
	store := openIgnoresStore(t)
	expires := t0.Add(5 * 24 * time.Hour)
	fx := &snykFixture{
		issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {snooze(t0.Add(-24*time.Hour), expires)}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)
	loadOne(t, c)

	fx.issues[0] = resolvedIssue(fixtureIssue("issue-1", "SNYK-100", false))
	fx.v1[fixtureProject] = v1ProjectIgnores{}
	now = t0.Add(30 * 24 * time.Hour)
	finding := loadOne(t, c)
	if finding.Status != model.FindingFixed {
		t.Fatalf("status = %q, want fixed", finding.Status)
	}
	if _, ok := cachedRow(t, store, "SNYK-100"); !ok {
		t.Fatal("cached row dropped for a resolved finding; it is inert and should stay")
	}
}

// TestLoadSnapshotRuleKeyedRowKeptWhileOneSiblingIgnored: a snooze filed
// under a rule key applies to several findings. One sibling still ignored
// means Snyk still asserts the ignore, so the open, un-ignored sibling does
// not get the row dropped, and (as before) does not consume it either.
func TestLoadSnapshotRuleKeyedRowKeptWhileOneSiblingIgnored(t *testing.T) {
	store := openIgnoresStore(t)
	expires := t0.Add(60 * 24 * time.Hour)
	ignored := fixtureIssue("issue-1", "", true)
	ignored.Attributes.Problems = []problem{{ID: "RULE-1"}}
	open := fixtureIssue("issue-2", "", false)
	open.Attributes.Problems = []problem{{ID: "RULE-1"}}
	fx := &snykFixture{
		issues: []issueResource{ignored, open},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"RULE-1": {snooze(t0.Add(-24*time.Hour), expires)}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)
	if _, err := c.LoadSnapshot(context.Background()); err != nil {
		t.Fatalf("LoadSnapshot() error = %v", err)
	}

	fx.v1[fixtureProject] = v1ProjectIgnores{}
	now = t0.Add(10 * 24 * time.Hour)
	snapshot, err := c.LoadSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LoadSnapshot() error = %v", err)
	}
	if _, ok := cachedRow(t, store, "RULE-1"); !ok {
		t.Fatal("rule-keyed row dropped while a sibling finding is still ignored")
	}
	for _, finding := range snapshot.Findings {
		switch finding.SnykIssueID {
		case "issue-1":
			if !finding.IgnoreExpiresAt.Equal(expires) {
				t.Fatalf("ignored sibling IgnoreExpiresAt = %v, want %v", finding.IgnoreExpiresAt, expires)
			}
		case "issue-2":
			if !finding.IgnoreExpiresAt.IsZero() {
				t.Fatalf("un-ignored sibling IgnoreExpiresAt = %v, want zero (rule-key gate)", finding.IgnoreExpiresAt)
			}
		}
	}
}

// TestLoadSnapshotNewerPermanentIgnoreReplacesCachedSnooze: a later v1 entry
// without expiry means the user now ignores the finding permanently; the
// cached snooze must not resurrect an expiry.
func TestLoadSnapshotNewerPermanentIgnoreReplacesCachedSnooze(t *testing.T) {
	store := openIgnoresStore(t)
	fx := &snykFixture{
		issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {snooze(t0.Add(-24*time.Hour), t0.Add(30*24*time.Hour))}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)
	loadOne(t, c)

	fx.v1[fixtureProject] = v1ProjectIgnores{"SNYK-100": {snooze(t0.Add(24*time.Hour), time.Time{})}}
	now = t0.Add(2 * 24 * time.Hour)
	finding := loadOne(t, c)
	if finding.Status != model.FindingIgnored {
		t.Fatalf("status = %q, want ignored (permanent)", finding.Status)
	}
	if !finding.IgnoreExpiresAt.IsZero() {
		t.Fatalf("IgnoreExpiresAt = %v, want zero", finding.IgnoreExpiresAt)
	}
	if row, ok := cachedRow(t, store, "SNYK-100"); ok && !row.ExpiresAt.IsZero() {
		t.Fatalf("cache still holds the superseded snooze expiry %v", row.ExpiresAt)
	}

	// And it stays permanent once v1 forgets the whole history.
	fx.v1[fixtureProject] = v1ProjectIgnores{}
	now = t0.Add(20 * 24 * time.Hour)
	finding = loadOne(t, c)
	if finding.Status != model.FindingIgnored || !finding.IgnoreExpiresAt.IsZero() {
		t.Fatalf("after v1 forgets: status %q expiry %v, want ignored with zero expiry", finding.Status, finding.IgnoreExpiresAt)
	}
}

// TestLoadSnapshotReIgnoreAdvancesExpiryHighWaterMark: a nightly re-ignore
// with a later created and expiry moves the expiry forward in both the
// finding and the cache.
func TestLoadSnapshotReIgnoreAdvancesExpiryHighWaterMark(t *testing.T) {
	store := openIgnoresStore(t)
	first := t0.Add(30 * 24 * time.Hour)
	second := t0.Add(60 * 24 * time.Hour)
	fx := &snykFixture{
		issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {snooze(t0.Add(-24*time.Hour), first)}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)
	loadOne(t, c)

	fx.v1[fixtureProject] = v1ProjectIgnores{"SNYK-100": {snooze(t0.Add(24*time.Hour), second)}}
	now = t0.Add(2 * 24 * time.Hour)
	finding := loadOne(t, c)
	if !finding.IgnoreExpiresAt.Equal(second) {
		t.Fatalf("IgnoreExpiresAt = %v, want %v", finding.IgnoreExpiresAt, second)
	}
	row, ok := cachedRow(t, store, "SNYK-100")
	if !ok || !row.ExpiresAt.Equal(second) {
		t.Fatalf("cached row = %+v (present %v), want expiry %v", row, ok, second)
	}
}

// TestLoadSnapshotV1NotFoundKeepsEveryCachedRow: when the v1 endpoint 404s
// after every retry, the cached rows stand in for it and none is aged into a
// drop, even past the grace period with the issue open and not ignored.
func TestLoadSnapshotV1NotFoundKeepsEveryCachedRow(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			store := openIgnoresStore(t)
			active := t0.Add(60 * 24 * time.Hour)
			lapsed := t0.Add(2 * 24 * time.Hour)
			fx := &snykFixture{
				issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true), fixtureIssue("issue-2", "SNYK-101", true)},
				v1: map[string]v1ProjectIgnores{fixtureProject: {
					"SNYK-100": {snooze(t0.Add(-24*time.Hour), active)},
					"SNYK-101": {snooze(t0.Add(-24*time.Hour), lapsed)},
				}},
			}
			now := t0
			c := newSnapshotClient(t, fx, store, &now)
			if _, err := c.LoadSnapshot(context.Background()); err != nil {
				t.Fatalf("LoadSnapshot() error = %v", err)
			}

			fx.issues[0].Attributes.Ignored = false
			fx.issues[1].Attributes.Ignored = false
			fx.v1Status = status
			now = t0.Add(10 * 24 * time.Hour)
			snapshot, err := c.LoadSnapshot(context.Background())
			if err != nil {
				t.Fatalf("LoadSnapshot() with v1 failing: error = %v, want nil (cached rows stand in)", err)
			}
			want := map[string]time.Time{"issue-1": active, "issue-2": lapsed}
			for _, finding := range snapshot.Findings {
				if !finding.IgnoreExpiresAt.Equal(want[finding.SnykIssueID]) {
					t.Fatalf("%s IgnoreExpiresAt = %v, want %v", finding.SnykIssueID, finding.IgnoreExpiresAt, want[finding.SnykIssueID])
				}
			}
			for _, key := range []string{"SNYK-100", "SNYK-101"} {
				if _, ok := cachedRow(t, store, key); !ok {
					t.Fatalf("cached row %s dropped on a failed v1 fetch", key)
				}
			}
		})
	}
}

func disregardEntry(created, expires time.Time) v1IgnoreEntry {
	entry := snooze(created, expires)
	entry.DisregardIfFixable = true
	return entry
}

// TestLoadSnapshotStampsIgnoreEndWhenFixArrives: an "ignore until fix
// available" ignore is lifted by Snyk (ignored=false) when a fix ships. The
// first run that sees it stamps the cached row, the finding carries the
// stamp as IgnoreEndedAt from then on, including after v1 forgets the
// record, and a later re-ignore clears it until the next lift.
func TestLoadSnapshotStampsIgnoreEndWhenFixArrives(t *testing.T) {
	store := openIgnoresStore(t)
	fx := &snykFixture{
		issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {disregardEntry(t0.Add(-24*time.Hour), time.Time{})}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)

	finding := loadOne(t, c)
	if finding.Status != model.FindingAwaitingFix || !finding.IgnoreEndedAt.IsZero() {
		t.Fatalf("run 1: status %q ended %v, want awaiting_fix with no end", finding.Status, finding.IgnoreEndedAt)
	}

	// The fix arrives; the v1 record is still returned for now.
	fx.issues[0].Attributes.Ignored = false
	lifted := t0.Add(10 * 24 * time.Hour)
	now = lifted
	finding = loadOne(t, c)
	if finding.Status != model.FindingOpen || !finding.DisregardIfFixable || !finding.IgnoreEndedAt.Equal(lifted) {
		t.Fatalf("run 2: status %q disregard %v ended %v, want open, disregard, ended %v", finding.Status, finding.DisregardIfFixable, finding.IgnoreEndedAt, lifted)
	}
	row, ok := cachedRow(t, store, "SNYK-100")
	if !ok || !row.UnignoredAt.Equal(lifted) {
		t.Fatalf("run 2: cached row = %+v (present %v), want unignored_at %v", row, ok, lifted)
	}

	// Later runs keep the stamp, even once v1 forgets the record.
	fx.v1[fixtureProject] = v1ProjectIgnores{}
	now = t0.Add(40 * 24 * time.Hour)
	finding = loadOne(t, c)
	if !finding.IgnoreEndedAt.Equal(lifted) || !finding.DisregardIfFixable {
		t.Fatalf("run 3: ended %v disregard %v, want %v kept", finding.IgnoreEndedAt, finding.DisregardIfFixable, lifted)
	}

	// Re-ignored until a (better) fix: the end is cleared and the finding
	// is awaiting a fix again; the next lift stamps a new end.
	fx.issues[0].Attributes.Ignored = true
	fx.v1[fixtureProject] = v1ProjectIgnores{"SNYK-100": {disregardEntry(t0.Add(41*24*time.Hour), time.Time{})}}
	now = t0.Add(42 * 24 * time.Hour)
	finding = loadOne(t, c)
	if finding.Status != model.FindingAwaitingFix || !finding.IgnoreEndedAt.IsZero() {
		t.Fatalf("run 4: status %q ended %v, want awaiting_fix with no end", finding.Status, finding.IgnoreEndedAt)
	}
	fx.issues[0].Attributes.Ignored = false
	liftedAgain := t0.Add(50 * 24 * time.Hour)
	now = liftedAgain
	finding = loadOne(t, c)
	if !finding.IgnoreEndedAt.Equal(liftedAgain) {
		t.Fatalf("run 5: ended %v, want %v", finding.IgnoreEndedAt, liftedAgain)
	}
}

// TestLoadSnapshotDisregardIgnoreLapsedByExpiryKeepsExpiry: an ignore until
// fix available that also carries an expiry can simply reach it with no fix.
// Snyk then reports the issue un-ignored like a fix arrival would, but the
// finding carries both the expiry (before the end) and the end, so the sync
// can base the due date on the expiry rather than claim a fix arrived.
func TestLoadSnapshotDisregardIgnoreLapsedByExpiryKeepsExpiry(t *testing.T) {
	store := openIgnoresStore(t)
	expires := t0.Add(5 * 24 * time.Hour)
	fx := &snykFixture{
		issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)},
		v1:     map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {disregardEntry(t0.Add(-24*time.Hour), expires)}}},
	}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)
	if finding := loadOne(t, c); finding.Status != model.FindingAwaitingFix {
		t.Fatalf("run 1: status = %q, want awaiting_fix", finding.Status)
	}

	fx.issues[0].Attributes.Ignored = false
	fx.v1[fixtureProject] = v1ProjectIgnores{}
	lapsedSeen := t0.Add(10 * 24 * time.Hour)
	for _, days := range []int{10, 30} {
		now = t0.Add(time.Duration(days) * 24 * time.Hour)
		finding := loadOne(t, c)
		if finding.Status != model.FindingOpen {
			t.Fatalf("day %d: status = %q, want open", days, finding.Status)
		}
		if !finding.DisregardIfFixable || !finding.IgnoreExpiresAt.Equal(expires) || !finding.IgnoreEndedAt.Equal(lapsedSeen) {
			t.Fatalf("day %d: disregard %v expiry %v ended %v, want disregard, expiry %v, ended %v", days, finding.DisregardIfFixable, finding.IgnoreExpiresAt, finding.IgnoreEndedAt, expires, lapsedSeen)
		}
	}
}

// Rule history must survive a transition without leaking to a never-ignored
// sibling. Repeated loads exercise the persisted associations.
func TestLoadSnapshotRuleHistoryScopedAcrossTransition(t *testing.T) {
	for _, untilFix := range []bool{false, true} {
		t.Run(fmt.Sprint("until-fix-", untilFix), func(t *testing.T) {
			store := openIgnoresStore(t)
			expiry := t0.Add(2 * 24 * time.Hour)
			entry := snooze(t0.Add(-24*time.Hour), expiry)
			if untilFix {
				entry = disregardEntry(t0.Add(-24*time.Hour), time.Time{})
			}
			a, b := fixtureIssue("issue-1", "", true), fixtureIssue("issue-2", "", false)
			a.Attributes.Problems = []problem{{ID: "RULE-1"}}
			b.Attributes.Problems = []problem{{ID: "RULE-1"}}
			fx := &snykFixture{issues: []issueResource{a, b}, v1: map[string]v1ProjectIgnores{fixtureProject: {"RULE-1": {entry}}}}
			now := t0
			c := newSnapshotClient(t, fx, store, &now)
			if _, err := c.LoadSnapshot(context.Background()); err != nil {
				t.Fatal(err)
			}
			fx.issues[0].Attributes.Ignored = false
			fx.v1[fixtureProject] = v1ProjectIgnores{}
			now = t0.Add(10 * 24 * time.Hour)
			end := now
			for range 2 {
				snapshot, err := c.LoadSnapshot(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range snapshot.Findings {
					if f.SnykIssueID == "issue-1" {
						if untilFix {
							if !f.DisregardIfFixable || !f.IgnoreEndedAt.Equal(end) {
								t.Fatalf("lost rule end: %+v", f)
							}
						} else if !f.IgnoreExpiresAt.Equal(expiry) {
							t.Fatalf("lost rule expiry: %+v", f)
						}
					} else if !f.IgnoreExpiresAt.IsZero() || !f.IgnoreEndedAt.IsZero() || f.DisregardIfFixable {
						t.Fatalf("never-ignored sibling inherited history: %+v", f)
					}
				}
				now = now.Add(30 * 24 * time.Hour)
			}
		})
	}
}

func TestLoadSnapshotNewIgnoreLiftedBetweenRuns(t *testing.T) {
	store := openIgnoresStore(t)
	first := t0.Add(-24 * time.Hour)
	oldEnd := t0.Add(10 * 24 * time.Hour)
	if err := store.SaveIgnores(context.Background(), fixtureProject, map[string]cache.IgnoreMeta{
		"SNYK-100": {CreatedAt: first, DisregardIfFixable: true, UnignoredAt: oldEnd},
	}); err != nil {
		t.Fatal(err)
	}
	newer := t0.Add(20 * 24 * time.Hour)
	fx := &snykFixture{issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", false)}, v1: map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {disregardEntry(newer, time.Time{})}}}}
	now := t0.Add(25 * 24 * time.Hour)
	c := newSnapshotClient(t, fx, store, &now)
	f := loadOne(t, c)
	if !f.IgnoreEndedAt.Equal(now) {
		t.Fatalf("end = %v, want first observation %v", f.IgnoreEndedAt, now)
	}
	now = now.Add(24 * time.Hour)
	if next := loadOne(t, c); !next.IgnoreEndedAt.Equal(f.IgnoreEndedAt) {
		t.Fatalf("unstable end: %v", next.IgnoreEndedAt)
	}
}

func TestLoadSnapshotReusedIssueDoesNotInheritOldIgnore(t *testing.T) {
	for _, untilFix := range []bool{false, true} {
		t.Run(fmt.Sprint(untilFix), func(t *testing.T) {
			store := openIgnoresStore(t)
			entry := snooze(t0.Add(-24*time.Hour), t0.Add(2*24*time.Hour))
			if untilFix {
				entry.DisregardIfFixable = true
			}
			fx := &snykFixture{issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)}, v1: map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {entry}}}}
			now := t0
			c := newSnapshotClient(t, fx, store, &now)
			loadOne(t, c)
			fx.issues[0].Attributes.Ignored = false
			now = t0.Add(5 * 24 * time.Hour)
			same := loadOne(t, c)
			if same.IgnoreExpiresAt.IsZero() {
				t.Fatal("continuous occurrence lost expiry")
			}
			fx.issues[0].Attributes.Coordinates[0].LastResolvedAt = t0.Add(10 * 24 * time.Hour).Format(time.RFC3339)
			fx.v1[fixtureProject] = v1ProjectIgnores{}
			now = t0.Add(20 * 24 * time.Hour)
			f := loadOne(t, c)
			if !f.IgnoreExpiresAt.IsZero() || !f.IgnoreEndedAt.IsZero() || f.DisregardIfFixable {
				t.Fatalf("new occurrence inherited history: %+v", f)
			}
		})
	}
}

func TestLoadSnapshotRemembersColdStartBeforeSeeding(t *testing.T) {
	store := openIgnoresStore(t)
	fx := &snykFixture{issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", true)}, v1: map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {snooze(t0, t0.Add(24*time.Hour))}}}}
	now := t0
	c := newSnapshotClient(t, fx, store, &now)
	// A diagnostic load can seed the cache before Service.Run ever sees it.
	loadOne(t, c)
	present, err := store.HasIgnoreRows(context.Background())
	if err != nil || !present {
		t.Fatalf("seeded rows: %v, %v", present, err)
	}
	pending, err := cache.PrepareIgnoreMemory(context.Background(), store)
	if err != nil || !pending {
		t.Fatalf("lost cold-start evidence: %v, %v", pending, err)
	}
}

func TestLoadSnapshotNewRuleIgnoreDoesNotRewriteSiblingHistory(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		t.Run(fmt.Sprint("permanent-", permanent), func(t *testing.T) {
			store := openIgnoresStore(t)
			a, b := fixtureIssue("issue-1", "", true), fixtureIssue("issue-2", "", false)
			a.Attributes.Problems = []problem{{ID: "RULE-1"}}
			b.Attributes.Problems = []problem{{ID: "RULE-1"}}
			fx := &snykFixture{issues: []issueResource{a, b}, v1: map[string]v1ProjectIgnores{fixtureProject: {"RULE-1": {disregardEntry(t0, time.Time{})}}}}
			now := t0
			c := newSnapshotClient(t, fx, store, &now)
			if _, err := c.LoadSnapshot(context.Background()); err != nil {
				t.Fatal(err)
			}
			fx.issues[0].Attributes.Ignored = false
			now = t0.Add(10 * 24 * time.Hour)
			end := now
			if _, err := c.LoadSnapshot(context.Background()); err != nil {
				t.Fatal(err)
			}
			// A later path-scoped ignore covers B, while A remains actionable.
			fx.issues[1].Attributes.Ignored = true
			expiry := t0.Add(90 * 24 * time.Hour)
			if permanent {
				expiry = time.Time{}
			}
			fx.v1[fixtureProject] = v1ProjectIgnores{"RULE-1": {snooze(t0.Add(20*24*time.Hour), expiry)}}
			now = t0.Add(25 * 24 * time.Hour)
			for run := range 2 {
				snapshot, err := c.LoadSnapshot(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range snapshot.Findings {
					if f.SnykIssueID == "issue-1" && (!f.DisregardIfFixable || !f.IgnoreEndedAt.Equal(end) || !f.IgnoreExpiresAt.IsZero()) {
						t.Fatalf("sibling rewrote A's history: %+v", f)
					}
					if run == 1 && f.SnykIssueID == "issue-2" && (!f.IgnoreExpiresAt.IsZero() || f.DisregardIfFixable) {
						t.Fatalf("revoked sibling retained history: %+v", f)
					}
				}
				// Snyk revokes B's newer ignore and stops returning its entry.
				fx.issues[1].Attributes.Ignored = false
				fx.v1[fixtureProject] = v1ProjectIgnores{}
				now = now.Add(10 * 24 * time.Hour)
			}
		})
	}
}

func TestIgnoreMemorySurvivesPartialCoordinateResolution(t *testing.T) {
	meta := ignoreMetadata{CreatedAt: t0, ExpiresAt: t0.Add(2 * 24 * time.Hour)}
	coordinates := []coordinate{{LastResolvedAt: t0.Add(24 * time.Hour).Format(time.RFC3339)}, {State: "open"}}
	if ignorePredatesResolvedOccurrence(meta, coordinates) {
		t.Fatal("one resolved coordinate erased a continuously open occurrence's memory")
	}
	coordinates[1].LastResolvedAt = "unparseable"
	if ignorePredatesResolvedOccurrence(meta, coordinates) {
		t.Fatal("unparseable resolution erased history")
	}
}

func TestLoadSnapshotDirectIgnoreDoesNotAcquireSiblingRuleHistory(t *testing.T) {
	for _, liveRule := range []bool{false, true} {
		t.Run(fmt.Sprint("live-rule-", liveRule), func(t *testing.T) {
			store := openIgnoresStore(t)
			a, b := fixtureIssue("issue-1", "", false), fixtureIssue("issue-2", "", true)
			a.Attributes.Problems = []problem{{ID: "RULE-1"}}
			b.Attributes.Problems = []problem{{ID: "RULE-1"}}
			expiry := t0.Add(2 * 24 * time.Hour)
			fx := &snykFixture{issues: []issueResource{a, b}, v1: map[string]v1ProjectIgnores{fixtureProject: {"RULE-1": {snooze(t0, expiry)}}}}
			now := t0
			c := newSnapshotClient(t, fx, store, &now)
			if _, err := c.LoadSnapshot(context.Background()); err != nil {
				t.Fatal(err)
			}
			// Rule snooze on B expires. A receives an independent permanent UUID ignore.
			now = t0.Add(10 * 24 * time.Hour)
			fx.issues[0].Attributes.Ignored = true
			fx.issues[1].Attributes.Ignored = false
			fx.v1[fixtureProject] = v1ProjectIgnores{"issue-1": {snooze(now, time.Time{})}}
			if liveRule {
				fx.v1[fixtureProject]["RULE-1"] = []v1IgnoreEntry{snooze(t0, expiry)}
			}
			if _, err := c.LoadSnapshot(context.Background()); err != nil {
				t.Fatal(err)
			}
			// Lift only A's permanent ignore. A never had a timed or until-fix ignore.
			now = t0.Add(20 * 24 * time.Hour)
			fx.issues[0].Attributes.Ignored = false
			fx.v1[fixtureProject] = v1ProjectIgnores{}
			snap, err := c.LoadSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range snap.Findings {
				if f.SnykIssueID == "issue-1" && !f.IgnoreExpiresAt.IsZero() {
					t.Fatalf("A inherited B-only expiry %s", f.IgnoreExpiresAt)
				}
			}

		})
	}
}

// The same live creation timestamp must not repeatedly reset the ignore end
// merely because older cache versions discarded fractional seconds.
func TestLoadSnapshotFractionalIgnoreCreationKeepsObservedEnd(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy-seconds-", legacy), func(t *testing.T) {
			store := openIgnoresStore(t)
			created := t0.Add(123 * time.Millisecond)
			cachedCreated := created
			if legacy {
				cachedCreated = cachedCreated.Truncate(time.Second)
			}
			oldEnd := t0.Add(10 * 24 * time.Hour)
			if err := store.SaveIgnores(context.Background(), fixtureProject, map[string]cache.IgnoreMeta{
				"SNYK-100": {CreatedAt: cachedCreated, DisregardIfFixable: true, UnignoredAt: oldEnd},
			}); err != nil {
				t.Fatal(err)
			}
			fx := &snykFixture{issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", false)}, v1: map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {disregardEntry(created, time.Time{})}}}}
			now := t0.Add(20 * 24 * time.Hour)
			c := newSnapshotClient(t, fx, store, &now)
			for range 2 {
				if f := loadOne(t, c); !f.IgnoreEndedAt.Equal(oldEnd) {
					t.Fatalf("same ignore reset its observed end: %v, want %v", f.IgnoreEndedAt, oldEnd)
				}
				row, ok := cachedRow(t, store, "SNYK-100")
				if !ok || !row.CreatedAt.Equal(created) {
					t.Fatalf("creation precision lost: %+v", row)
				}
				now = now.Add(24 * time.Hour)
			}
		})
	}
}
