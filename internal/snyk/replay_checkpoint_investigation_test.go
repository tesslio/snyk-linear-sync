package snyk

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
	syncsvc "github.com/tesslio/snyk-linear-sync/internal/sync"
)

// Investigation-only integration tests. They exercise the unmodified pinned
// loader and reconciliation guard; this file does not add a production command.
type checkpointLinear struct{ writes int }

func (l *checkpointLinear) LoadSnapshot(context.Context) ([]model.ExistingIssue, error) {
	return []model.ExistingIssue{}, nil
}
func (l *checkpointLinear) CreateIssues(_ context.Context, d []model.DesiredIssue) ([]model.CreateOutcome, error) {
	l.writes += len(d)
	out := make([]model.CreateOutcome, len(d))
	for i := range d {
		out[i] = model.CreateOutcome{Index: i, ID: fmt.Sprintf("created-%d", i), Acknowledged: true}
	}
	return out, nil
}

func (l *checkpointLinear) UpdateIssues(_ context.Context, d []model.IssueUpdate) error {
	l.writes += len(d)
	return nil
}
func (l *checkpointLinear) PostComments(_ context.Context, d []model.IssueUpdate) ([]int, error) {
	l.writes += len(d)
	return nil, nil
}
func (l *checkpointLinear) LastOpenStates(context.Context, []string) (map[string]model.WorkflowState, error) {
	return map[string]model.WorkflowState{}, nil
}

func checkpointCfg() config.Config {
	return config.Config{DryRun: true, PlanJSON: "private.json", Linear: config.LinearConfig{
		TeamID: "11111111-1111-4111-8111-111111111111",
		States: config.StateConfig{Todo: "Todo", Backlog: "Backlog", Done: "Done", Cancelled: "Cancelled"},
		Due:    config.DueDateConfig{CriticalDays: 15, HighDays: 30, MediumDays: 45, LowDays: 90},
	}, Sync: config.SyncConfig{Workers: 1}}
}
func checkpointCopy(t *testing.T, data []byte) *cache.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "copy.db")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := cache.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestInvestigationObservationCheckpointSupportsFreshExactGuard(t *testing.T) {
	for _, scenario := range []string{"unprepared-rejects", "checkpoint-matches", "new-lifecycle-rejects", "source-title-drift-rejects", "api-order-drift-rejects", "cached-fallback-still-matches-current-v1"} {
		t.Run(scenario, func(t *testing.T) {
			start := time.Date(2030, 1, 1, 23, 0, 0, 123456789, time.UTC)
			path := filepath.Join(t.TempDir(), "source.db")
			base, err := cache.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			old := start.Add(-24 * time.Hour)
			originalHashes := cache.Snapshot{SnykHashes: map[string]string{"old-finding": "old-hash"}, LinearHashes: map[string]string{"old-ticket": "old-hash"}}
			if err := base.Save(t.Context(), originalHashes); err != nil {
				t.Fatal(err)
			}
			if err := base.SetMeta(t.Context(), cache.IgnoreMemoryStateKey, cache.IgnoreMemoryTrusted); err != nil {
				t.Fatal(err)
			}
			if err := base.SetMeta(t.Context(), "ignores_cold_start_at", "2029-12-01T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
			if err := base.SaveIgnores(t.Context(), fixtureProject, map[string]cache.IgnoreMeta{"SNYK-100": {
				CreatedAt: old, UpdatedAt: old, DisregardIfFixable: true,
				ObservedIssues: map[string]cache.IgnoreObservation{"issue-1": {CreatedAt: old, DisregardIfFixable: true}},
			}}); err != nil {
				t.Fatal(err)
			}
			fx := &snykFixture{issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", false)}, v1: map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {disregardEntry(old, time.Time{})}}}}
			if scenario == "api-order-drift-rejects" {
				fx.issues = append(fx.issues, fixtureIssue("issue-2", "SNYK-100", false))
			}
			now := start
			c := newSnapshotClient(t, fx, base, &now)
			if scenario != "unprepared-rejects" {
				observedSnapshot, err := c.LoadSnapshot(t.Context())
				if err != nil || len(observedSnapshot.Findings) == 0 {
					t.Fatalf("observation failed: %v", err)
				}
				observed := observedSnapshot.Findings[0]
				if !observed.IgnoreEndedAt.Equal(start) {
					t.Fatalf("observation not recorded: %v", observed.IgnoreEndedAt)
				}
				rows, err := base.LoadIgnores(t.Context(), fixtureProject)
				if err != nil {
					t.Fatal(err)
				}
				if !rows["SNYK-100"].UnignoredAt.Equal(start) || !rows["SNYK-100"].ObservedIssues["issue-1"].EndedAt.Equal(start) {
					t.Fatal("both observation levels must persist")
				}
				hashes, err := base.Load(t.Context())
				if err != nil || !reflect.DeepEqual(hashes, originalHashes) {
					t.Fatalf("checkpoint changed sync hashes: %#v %v", hashes, err)
				}
				for key, want := range map[string]string{cache.IgnoreMemoryStateKey: cache.IgnoreMemoryTrusted, "ignores_cold_start_at": "2029-12-01T00:00:00Z"} {
					got, ok, err := base.GetMeta(t.Context(), key)
					if err != nil || !ok || got != want {
						t.Fatalf("checkpoint changed safety metadata %s: %s %v", key, got, err)
					}
				}
			}
			if err := base.Close(); err != nil {
				t.Fatal(err)
			}
			immutable, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			sourceDigest := sha256.Sum256(immutable)
			preview := checkpointCopy(t, immutable)
			c.SetCache(preview)
			now = start.Add(30 * time.Minute)
			cfg := checkpointCfg()
			l := &checkpointLinear{}
			result, err := syncsvc.New(cfg, c.logger, c, l, preview).Run(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if l.writes != 0 || result.Plan == nil || !result.Plan.Complete {
				t.Fatal("preview must be complete and read-only")
			}
			accepted := filepath.Join(t.TempDir(), "accepted.json")
			if err := syncsvc.WritePlanJSON(accepted, result.Plan); err != nil {
				t.Fatal(err)
			}
			planBytes, err := os.ReadFile(accepted)
			if err != nil {
				t.Fatal(err)
			}
			cfg.DryRun = false
			cfg.PlanJSON = ""
			cfg.ReviewedPlanJSON = accepted
			cfg.ReviewedPlanSHA256 = fmt.Sprintf("%x", sha256.Sum256(planBytes))
			now = start.Add(26 * time.Hour) // crosses UTC midnight, with fresh loader time
			if scenario == "new-lifecycle-rejects" {
				fx.v1[fixtureProject]["SNYK-100"] = []v1IgnoreEntry{disregardEntry(start.Add(time.Hour), time.Time{})}
			}
			if scenario == "source-title-drift-rejects" {
				fx.issues[0].Attributes.Title = "Changed source content with same counts"
			}
			if scenario == "api-order-drift-rejects" {
				fx.issues[0], fx.issues[1] = fx.issues[1], fx.issues[0]
			}
			if scenario == "cached-fallback-still-matches-current-v1" {
				fx.v1Status = 500
			}
			execution := checkpointCopy(t, immutable)
			c.SetCache(execution)
			l = &checkpointLinear{}
			_, err = syncsvc.New(cfg, c.logger, c, l, execution).Run(t.Context())
			if scenario == "checkpoint-matches" || scenario == "cached-fallback-still-matches-current-v1" {
				if err != nil || l.writes != 1 {
					t.Fatalf("fresh exact guard failed: writes=%d err=%v", l.writes, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "differs from reviewed plan") || l.writes != 0 {
				t.Fatalf("drift not rejected before writes: writes=%d err=%v", l.writes, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || sha256.Sum256(after) != sourceDigest {
				t.Fatal("source checkpoint was mutated")
			}
		})
	}
}

func TestInvestigationCheckpointRetainsRealTimeGrace(t *testing.T) {
	start := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "source.db")
	source, err := cache.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.SaveIgnores(t.Context(), fixtureProject, map[string]cache.IgnoreMeta{"SNYK-100": {CreatedAt: start.Add(-time.Hour), UpdatedAt: start, ExpiresAt: start.Add(30 * 24 * time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fx := &snykFixture{issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", false)}, v1: map[string]v1ProjectIgnores{fixtureProject: {}}}
	now := start.Add(24 * time.Hour)
	c := newSnapshotClient(t, fx, checkpointCopy(t, data), &now)
	retained := loadOne(t, c)
	if retained.IgnoreExpiresAt.IsZero() {
		t.Fatal("grace ended too early")
	}
	now = start.Add(8 * 24 * time.Hour)
	c.SetCache(checkpointCopy(t, data))
	current := loadOne(t, c)
	if !current.IgnoreExpiresAt.IsZero() {
		t.Fatal("current wall clock must expire revocation grace")
	}
	now = start.Add(24 * time.Hour)
	c.SetCache(checkpointCopy(t, data))
	frozen := loadOne(t, c)
	if frozen.IgnoreExpiresAt.IsZero() {
		t.Fatal("fixture must demonstrate stale retention with frozen clock")
	}
}

func TestInvestigationObservationCheckpointPreservesEmptyStartProvenance(t *testing.T) {
	store := openIgnoresStore(t)
	now := t0
	fx := &snykFixture{issues: []issueResource{fixtureIssue("issue-1", "SNYK-100", false)}, v1: map[string]v1ProjectIgnores{fixtureProject: {"SNYK-100": {disregardEntry(now.Add(-time.Hour), time.Time{})}}}}
	loadOne(t, newSnapshotClient(t, fx, store, &now))
	state, ok, err := store.GetMeta(t.Context(), cache.IgnoreMemoryStateKey)
	if err != nil || !ok || state != "pending" {
		t.Fatalf("empty-start protection lost after seeding: %s %v", state, err)
	}
	hashes, err := store.Load(t.Context())
	if err != nil || len(hashes.SnykHashes) != 0 || len(hashes.LinearHashes) != 0 {
		t.Fatal("loader must not save reconciliation hashes")
	}
}

func TestInvestigationReplaySafeCheckpointFreshOrderedIntegration(t *testing.T) {
	for _, scenario := range []string{"reordered-matches", "unavailable-source-refuses", "new-lifecycle-refuses"} {
		t.Run(scenario, func(t *testing.T) {
			saved := ignoresRetryBackoff
			ignoresRetryBackoff = 0
			t.Cleanup(func() { ignoresRetryBackoff = saved })
			now := time.Date(2030, 1, 1, 23, 0, 0, 123, time.UTC)
			observedAt := now
			created := now.Add(-time.Hour)
			issues := []issueResource{fixtureIssue("issue-1", "SNYK-100", false), fixtureIssue("issue-2", "SNYK-100", false)}
			unavailable := false
			c := freshFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/rest/orgs/org-a":
					fmt.Fprint(w, `{"data":{"attributes":{"slug":"org-a"}}}`)
				case "/rest/orgs/org-a/projects":
					fmt.Fprintf(w, `{"data":[%s],"links":{"next":null}}`, freshProjectRow)
				case "/rest/orgs/org-a/issues":
					_ = json.NewEncoder(w).Encode(map[string]any{"data": issues, "links": map[string]any{"next": nil}})
				case "/v1/org/org-a/project/project-a/ignores":
					if unavailable {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					_ = json.NewEncoder(w).Encode(v1ProjectIgnores{"SNYK-100": {disregardEntry(created, time.Time{})}})
				default:
					t.Errorf("unexpected endpoint %s", r.URL.Path)
					http.NotFound(w, r)
				}
			})
			c.now = func() time.Time { return now }
			path := filepath.Join(t.TempDir(), "source.db")
			store, err := cache.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SetMeta(t.Context(), cache.IgnoreMemoryStateKey, cache.IgnoreMemoryTrusted); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveIgnores(t.Context(), fixtureProject, map[string]cache.IgnoreMeta{"SNYK-100": {CreatedAt: created, UpdatedAt: created, DisregardIfFixable: true, ObservedIssues: map[string]cache.IgnoreObservation{"issue-1": {CreatedAt: created, DisregardIfFixable: true}, "issue-2": {CreatedAt: created, DisregardIfFixable: true}}}}); err != nil {
				t.Fatal(err)
			}
			c.SetCache(store)
			if _, err := c.LoadSnapshot(t.Context()); err != nil {
				t.Fatal(err)
			}
			observedRows, err := store.LoadIgnores(t.Context(), fixtureProject)
			if err != nil || !observedRows["SNYK-100"].UnignoredAt.Equal(observedAt) || !observedRows["SNYK-100"].ObservedIssues["issue-1"].EndedAt.Equal(observedAt) || !observedRows["SNYK-100"].ObservedIssues["issue-2"].EndedAt.Equal(observedAt) {
				t.Fatalf("both observation levels not checkpointed: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			immutable, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg := checkpointCfg()
			cfg.ReplaySafe = true
			preview := checkpointCopy(t, immutable)
			c.SetCache(preview)
			now = now.Add(time.Hour)
			l := &checkpointLinear{}
			result, err := syncsvc.New(cfg, c.logger, c, l, preview).Run(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if result.Plan.Version != 2 || l.writes != 0 {
				t.Fatal("expected read-only v2 plan")
			}
			accepted := filepath.Join(t.TempDir(), "reviewed.json")
			if err := syncsvc.WritePlanJSON(accepted, result.Plan); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(accepted)
			if err != nil {
				t.Fatal(err)
			}
			cfg.DryRun = false
			cfg.PlanJSON = ""
			cfg.ReviewedPlanJSON = accepted
			cfg.ReviewedPlanSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
			now = observedAt.Add(26 * time.Hour)
			issues[0], issues[1] = issues[1], issues[0]
			if scenario == "unavailable-source-refuses" {
				unavailable = true
			}
			if scenario == "new-lifecycle-refuses" {
				created = observedAt.Add(2 * time.Hour)
			}
			execution := checkpointCopy(t, immutable)
			c.SetCache(execution)
			l = &checkpointLinear{}
			_, err = syncsvc.New(cfg, c.logger, c, l, execution).Run(t.Context())
			if scenario == "reordered-matches" {
				if err != nil || l.writes != 2 {
					t.Fatalf("v2 fresh replay failed: writes %d err %v", l.writes, err)
				}
			} else if err == nil || l.writes != 0 {
				t.Fatalf("v2 drift not refused: writes %d err %v", l.writes, err)
			}
		})
	}
}
