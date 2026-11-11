package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

func boundCfg(t *testing.T) config.Config {
	t.Helper()
	cfg := planCfg()
	cfg.DryRun, cfg.PlanJSON, cfg.ReplaySafe, cfg.PlanAndExecuteBound = false, "", true, true
	cfg.Linear.TeamID = "11111111-1111-4111-8111-111111111111"
	n := int64(100)
	cfg.MaxCreates, cfg.MaxUpdates, cfg.MaxResolves, cfg.MaxCancelDuplicates = &n, &n, &n, &n
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.PlanJSON = filepath.Join(parent, "plan.json")
	return cfg
}
func artifactPath(cfg config.Config, name string) string {
	if name == "plan.json" {
		return cfg.PlanJSON
	}
	return filepath.Join(boundDir(cfg), name)
}
func boundDir(cfg config.Config) string { return cfg.PlanJSON + ".receipts" }

func readBound[T any](t *testing.T, cfg config.Config, name string) T {
	t.Helper()
	path := filepath.Join(boundDir(cfg), name)
	if name == "plan.json" {
		path = cfg.PlanJSON
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("receipt is not private")
	}
	return value
}

type boundLinear struct {
	planLinear
	before  func()
	refresh func() ([]model.ExistingIssue, error)
}

func (l *boundLinear) LoadSnapshot(ctx context.Context) ([]model.ExistingIssue, error) {
	if l.calls == 0 {
		return l.planLinear.LoadSnapshot(ctx)
	}
	l.calls++
	if l.refresh != nil {
		return l.refresh()
	}
	return l.snapshot, l.err
}

func (l *boundLinear) CreateIssues(ctx context.Context, d []model.DesiredIssue) ([]int, error) {
	l.before()
	return l.fakeLinear.CreateIssues(ctx, d)
}
func (l *boundLinear) UpdateIssues(ctx context.Context, u []model.IssueUpdate) error {
	l.before()
	return l.fakeLinear.UpdateIssues(ctx, u)
}

func TestBoundExecutesOnePlanningSnapshotThenRefreshesAfterAllWrites(t *testing.T) {
	cfg := boundCfg(t)
	changed := planFixtureFinding("issue-change")
	ticket := storedIssue("ticket-change", "SNYK-100", "Todo", desiredIssue(cfg, changed))
	ticket.Title = "previous title"
	duplicate := ticket
	duplicate.ID = "ticket-duplicate"
	duplicate.Identifier = "SNYK-102"
	absent := storedIssue("ticket-absent", "SNYK-103", "Todo", desiredIssue(cfg, planFixtureFinding("issue-absent")))
	snapshot := planSnapshot(changed, planFixtureFinding("issue-new"))
	source := &planSnyk{snapshot: snapshot}
	store := &fakeCache{ignoreRows: true}
	linear := &boundLinear{planLinear: planLinear{fakeLinear: fakeLinear{snapshot: []model.ExistingIssue{ticket, duplicate, absent}}}}
	linear.before = func() {
		if source.calls != 1 || linear.calls != 1 {
			t.Fatal("reloaded planning snapshots before dispatch completed")
		}
		attempt := readBound[BoundAttempt](t, cfg, "attempt.json")
		data, err := os.ReadFile(cfg.PlanJSON)
		if err != nil || attempt.PlanSHA256 != planTextDigest(string(data)) || attempt.Status != "attempt_started" {
			t.Fatal("mutation preceded durable binding")
		}
		if _, err := os.Stat(filepath.Join(boundDir(cfg), "result.json")); !os.IsNotExist(err) {
			t.Fatal("premature result")
		}
		// Simulate source drift after first write. Buffered payloads must not change.
		source.snapshot = planSnapshot(planFixtureFinding("unrelated-later-source"))
		linear.snapshot = nil
	}
	refreshedTicket := ticket
	refreshedTicket.Title = "new remote value after dispatch"
	refreshedNew := storedIssue("ticket-new", "SNYK-104", "Todo", desiredIssue(cfg, snapshot.Findings[1]))
	linear.refresh = func() ([]model.ExistingIssue, error) {
		if len(linear.created) != 1 || len(linear.updated) != 3 {
			t.Fatal("post-write refresh preceded final mutation")
		}
		return []model.ExistingIssue{refreshedTicket, duplicate, absent, refreshedNew}, nil
	}
	result, err := New(cfg, discardLogger(), source, linear, store).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan != nil || result.PlannedCreates != 1 || result.PlannedUpdates != 1 || result.PlannedResolves != 1 || result.CancelledDuplicates != 1 {
		t.Fatalf("wrong result: %+v", result)
	}
	if source.calls != 1 || linear.calls != 2 || len(linear.created) != 1 || len(linear.updated) != 3 {
		t.Fatal("reloaded, skipped or repeated jobs")
	}
	if !reflect.DeepEqual(linear.created[0], desiredIssue(cfg, snapshot.Findings[1])) {
		t.Fatal("executed changed source payload")
	}
	plan := readBound[ReconciliationPlan](t, cfg, "plan.json")
	if err := validateReviewedPlan(&plan); err != nil {
		t.Fatal(err)
	}
	attempt := readBound[BoundAttempt](t, cfg, "attempt.json")
	final := readBound[BoundResult](t, cfg, "result.json")
	if final.Status != "success" || final.PlanSHA256 != attempt.PlanSHA256 || final.JobsSHA256 != attempt.JobsSHA256 || final.BatchesAcknowledged != 4 || final.BatchesAttempted != 4 || final.CacheStatus != "saved" || len(store.saved.LinearHashes) != 3 || store.saved.LinearHashes[changed.Fingerprint] != existingIssueHash(refreshedTicket) || len(store.saved.SnykHashes) != 2 {
		t.Fatalf("wrong proof: %+v", final)
	}
	// Receipt directory reservation rejects a second run before any reads/writes.
	_, err = New(cfg, discardLogger(), source, linear, store).Run(t.Context())
	if err == nil || source.calls != 1 || linear.calls != 2 {
		t.Fatal("reused attempt directory")
	}
}

func TestBoundLimitsRejectAllMutationKindsBeforeWrites(t *testing.T) {
	for _, kind := range []string{"create", "update", "resolve", "cancel-duplicate"} {
		t.Run(kind, func(t *testing.T) {
			cfg := boundCfg(t)
			zero := int64(0)
			f := planFixtureFinding("issue-a")
			snapshot := planSnapshot(f)
			ticket := storedIssue("ticket-a", "SNYK-100", "Todo", desiredIssue(cfg, f))
			ticket.Title = "old"
			issues := []model.ExistingIssue{ticket}
			switch kind {
			case "create":
				cfg.MaxCreates = &zero
				issues = nil
			case "update":
				cfg.MaxUpdates = &zero
			case "resolve":
				cfg.MaxResolves = &zero
				snapshot = planSnapshot(planFixtureFinding("different-issue"))
			case "cancel-duplicate":
				cfg.MaxCancelDuplicates = &zero
				duplicate := ticket
				duplicate.ID = "ticket-b"
				duplicate.Identifier = "SNYK-101"
				issues = append(issues, duplicate)
			}
			linear := &planLinear{fakeLinear: fakeLinear{snapshot: issues}}
			store := &fakeCache{ignoreRows: true}
			_, err := New(cfg, discardLogger(), &planSnyk{snapshot: snapshot}, linear, store).Run(t.Context())
			if err == nil || !strings.Contains(err.Error(), "limits") {
				t.Fatalf("error=%v", err)
			}
			var limitErr *BoundLimitError
			if !errors.As(err, &limitErr) {
				t.Fatalf("missing typed refusal: %v", err)
			}
			refusal := readBound[BoundRefusal](t, cfg, "refusal.json")
			expected := map[string]string{"create": "creates", "update": "updates", "resolve": "resolves", "cancel-duplicate": "cancel_duplicates"}[kind]
			if !reflect.DeepEqual(refusal, limitErr.Refusal) || !reflect.DeepEqual(refusal.Exceeded, []string{expected}) || refusal.Version != 1 || refusal.Status != "limits_exceeded" {
				t.Fatalf("wrong refusal: %+v", refusal)
			}
			if _, err := os.Stat(cfg.PlanJSON); !os.IsNotExist(err) {
				t.Fatal("rejected plan persisted")
			}
			assertNoReviewedWrites(t, linear)
			final := readBound[BoundResult](t, cfg, "result.json")
			if final.LinearWritesAttempted || final.Status != "failed_before_writes" || store.saved.SnykHashes != nil {
				t.Fatal("limit failure published cache or wrote")
			}
			if _, err := os.Stat(filepath.Join(boundDir(cfg), "attempt.json")); !os.IsNotExist(err) {
				t.Fatal("bound rejected plan")
			}
		})
	}
}

func TestBoundRejectsIncompleteHistoryAndFreshness(t *testing.T) {
	for _, kind := range []string{"history", "freshness"} {
		t.Run(kind, func(t *testing.T) {
			cfg := boundCfg(t)
			f := planFixtureFinding("issue-reopen")
			ticket := storedIssue("ticket-a", "SNYK-100", "Done", desiredIssue(cfg, f))
			created := f.CreatedAt.Add(24 * time.Hour)
			closed := created.Add(time.Hour)
			ticket.CreatedAt = &created
			ticket.ClosedAt = &closed
			linear := &planLinear{fakeLinear: fakeLinear{snapshot: []model.ExistingIssue{ticket}, lastOpenStatesErr: errors.New("unreadable history")}}
			var source SnykClient = &planSnyk{snapshot: planSnapshot(f, planFixtureFinding("issue-new"))}
			if kind == "freshness" {
				source = &failedFreshReplaySource{planSnyk: planSnyk{snapshot: planSnapshot(f)}}
			}
			_, err := New(cfg, discardLogger(), source, linear, nil).Run(t.Context())
			if err == nil {
				t.Fatal("incomplete evidence accepted")
			}
			assertNoReviewedWrites(t, linear)
		})
	}
}

func TestBoundPartialCreateStopsWithoutRetryOrCache(t *testing.T) {
	cfg := boundCfg(t)
	var findings []model.Finding
	for i := range 23 {
		findings = append(findings, planFixtureFinding(string(rune('a'+i))))
	}
	failures := map[string]int{findings[1].Fingerprint: 1}
	linear := &planLinear{fakeLinear: fakeLinear{createFailFingerprints: failures}}
	store := &fakeCache{ignoreRows: true}
	_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, linear, store).Run(t.Context())
	if err == nil || len(linear.createCallBatches) != 1 || len(linear.created) != 9 || store.saved.SnykHashes != nil {
		t.Fatal("partial failure retried, continued or cached")
	}
	final := readBound[BoundResult](t, cfg, "result.json")
	if !final.LinearWritesAttempted || final.Status != "partial_or_uncertain" || final.BatchesAttempted != 1 || final.BatchesAcknowledged != 0 || final.CacheStatus != "not_saved" {
		t.Fatalf("dishonest result: %+v", final)
	}
}

type boundFailCache struct{ fakeCache }

func (s *boundFailCache) Save(context.Context, cache.Snapshot) error {
	return errors.New("cache save failed")
}
func TestBoundCacheFailureCannotClaimSuccess(t *testing.T) {
	cfg := boundCfg(t)
	f := planFixtureFinding("issue-a")
	linear := &boundLinear{before: func() {}, refresh: func() ([]model.ExistingIssue, error) {
		return []model.ExistingIssue{storedIssue("ticket-a", "SNYK-100", "Todo", desiredIssue(cfg, f))}, nil
	}}
	_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(f)}, linear, &boundFailCache{fakeCache{ignoreRows: true}}).Run(t.Context())
	if err == nil || len(linear.created) != 1 {
		t.Fatal("cache failure hidden")
	}
	final := readBound[BoundResult](t, cfg, "result.json")
	if final.Status == "success" || final.CacheStatus != "save_failed_or_uncertain" || final.BatchesAcknowledged != 1 {
		t.Fatalf("wrong cache proof: %+v", final)
	}
}

func TestBoundReceiptsRejectTamperingAndUnsafePaths(t *testing.T) {
	for _, kind := range []string{"plan", "attempt", "jobs", "directory", "symlink-plan", "existing-result"} {
		t.Run(kind, func(t *testing.T) {
			cfg := boundCfg(t)
			b, err := reserveBoundRun(cfg.PlanJSON)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			f := planFixtureFinding("issue-a")
			desired := desiredIssue(cfg, f)
			preview := cfg
			preview.PlanAndExecuteBound = false
			preview.PlanJSON = ""
			preview.MaxCreates = nil
			preview.MaxUpdates = nil
			preview.MaxResolves = nil
			preview.MaxCancelDuplicates = nil
			preview.DryRun = true
			preview.PlanJSON = "unused.json"
			result, _, _ := runPlan(t, preview, planSnapshot(f), nil, nil)
			jobs := []job{{kind: jobCreateBatch, desiredBatch: []model.DesiredIssue{desired}}}
			if err := b.bind(cfg, result.Plan, jobs); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "plan", "attempt":
				if err := os.WriteFile(artifactPath(cfg, kind+".json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "jobs":
				jobs[0].desiredBatch[0].Title = "tampered"
			case "directory":
				if err := os.Chmod(boundDir(cfg), 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink-plan":
				path := cfg.PlanJSON
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("attempt.json", path); err != nil {
					t.Fatal(err)
				}
			case "existing-result":
				if _, err := b.write("result.json", b.result); err != nil {
					t.Fatal(err)
				}
				if _, err := b.write("result.json", b.result); err == nil {
					t.Fatal("overwrote result")
				}
				return
			}
			if err := b.verify(jobs); err == nil {
				t.Fatal("accepted tampering")
			}
		})
	}
	cfg := boundCfg(t)
	parent := filepath.Dir(boundDir(cfg))
	link := parent + "-link"
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(link)
	if b, err := reserveBoundRun(filepath.Join(link, "attempt")); err == nil {
		b.close()
		t.Fatal("followed parent symlink")
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if b, err := reserveBoundRun(cfg.PlanJSON); err == nil {
		b.close()
		t.Fatal("used public parent")
	}
}

func TestBoundRejectsCorruptPlanAndJobs(t *testing.T) {
	cfg := boundCfg(t)
	f := planFixtureFinding("issue-a")
	desired := desiredIssue(cfg, f)
	preview := planCfg()
	preview.ReplaySafe = true
	result, _, _ := runPlan(t, preview, planSnapshot(f), nil, nil)
	jobs := []job{{kind: jobCreateBatch, desiredBatch: []model.DesiredIssue{desired}}}
	if err := validateBoundJobs(result.Plan, jobs); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing-job", "extra-job", "wrong-kind", "wrong-candidate", "incomplete-coverage", "unknown-action"} {
		t.Run(kind, func(t *testing.T) {
			data, _ := json.Marshal(result.Plan)
			var plan ReconciliationPlan
			_ = json.Unmarshal(data, &plan)
			candidate := append([]job(nil), jobs...)
			switch kind {
			case "missing-job":
				candidate = nil
			case "extra-job":
				candidate = append(candidate, jobs[0])
			case "wrong-kind":
				candidate[0].kind = jobUpdate
			case "wrong-candidate":
				plan.Records[0].DueDate.Planned = "2099-01-01"
				plan.DecisionsSHA256, _ = planDigest(plan.Records)
			case "incomplete-coverage":
				plan.Summary.CoveredFindings = 0
			case "unknown-action":
				plan.Records[0].Action = "unknown"
				plan.DecisionsSHA256, _ = planDigest(plan.Records)
			}
			b, err := reserveBoundRun(filepath.Join(filepath.Dir(boundDir(cfg)), kind))
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			if err := b.bind(cfg, &plan, candidate); err == nil {
				t.Fatal("bound corrupt plan/jobs")
			}
		})
	}
}

func TestBoundDisablesRetriesAndStopsCommentFailure(t *testing.T) {
	cfg := boundCfg(t)
	cfg.Linear.CommentsEnabled = true
	f := planFixtureFinding("issue-a")
	ticket := storedIssue("ticket-a", "SNYK-100", "Todo", desiredIssue(cfg, f))
	ticket.Title = "old"
	linear := &reviewedContextLinear{t: t, fakeLinear: fakeLinear{snapshot: []model.ExistingIssue{ticket}, commentFailFingerprints: map[string]int{f.Fingerprint: 1}}}
	_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(f)}, linear, nil).Run(t.Context())
	if err == nil || len(linear.updated) != 1 || len(linear.commentCallBatches) != 1 {
		t.Fatal("comment failure concealed/retried")
	}
	final := readBound[BoundResult](t, cfg, "result.json")
	if final.BatchesAcknowledged != 0 || !final.LinearWritesAttempted {
		t.Fatal("claimed complete update after comment failure")
	}
}

func TestBoundFailuresBeforeDispatchAndResultCollision(t *testing.T) {
	for _, kind := range []string{"load", "cancel", "attempt-collision", "result-collision", "late-tamper"} {
		t.Run(kind, func(t *testing.T) {
			cfg := boundCfg(t)
			f := planFixtureFinding("issue-a")
			store := &fakeCache{ignoreRows: true}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			source := &planSnyk{snapshot: planSnapshot(f)}
			var snyk SnykClient = source
			linear := &boundLinear{}
			linear.before = func() {}
			switch kind {
			case "load":
				source.err = errors.New("source load failed")
			case "cancel", "attempt-collision":
				snyk = &boundHookSource{planSnyk: source, hook: func() {
					if kind == "cancel" {
						cancel()
						return
					}
					if err := os.WriteFile(filepath.Join(boundDir(cfg), "attempt.json"), []byte("existing"), 0600); err != nil {
						t.Error(err)
					}
				}}
			case "result-collision", "late-tamper":
				linear.before = func() {
					name := "result.json"
					if kind == "late-tamper" {
						name = "plan.json"
					}
					if err := os.WriteFile(artifactPath(cfg, name), []byte("existing"), 0600); err != nil {
						t.Error(err)
					}
				}
			}
			_, err := New(cfg, discardLogger(), snyk, linear, store).Run(ctx)
			if err == nil {
				t.Fatal("failed execution claimed success")
			}
			expected := 0
			if kind == "result-collision" || kind == "late-tamper" {
				expected = 1
			}
			if len(linear.created) != expected {
				t.Fatal("wrong dispatch count")
			}
			if kind != "result-collision" && store.saved.SnykHashes != nil {
				t.Fatal("incomplete failure saved hashes")
			}
			if kind == "result-collision" {
				data, _ := os.ReadFile(filepath.Join(boundDir(cfg), "result.json"))
				if string(data) != "existing" {
					t.Fatal("overwrote collision")
				}
			}
		})
	}
}

type boundHookSource struct {
	*planSnyk
	hook func()
}

func (s *boundHookSource) LoadSnapshot(ctx context.Context) (model.SnykSnapshot, error) {
	s.hook()
	return s.planSnyk.LoadSnapshot(ctx)
}

func TestBoundZeroLimitsAllowOnlyEmptyMutationPlan(t *testing.T) {
	cfg := boundCfg(t)
	zero := int64(0)
	cfg.MaxCreates = &zero
	cfg.MaxUpdates = &zero
	cfg.MaxResolves = &zero
	cfg.MaxCancelDuplicates = &zero
	linear := &planLinear{}
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot()}, linear, nil).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	final := readBound[BoundResult](t, cfg, "result.json")
	if final.Status != "success" || final.LinearWritesAttempted || final.BatchesAttempted != 0 {
		t.Fatal("empty plan claimed writes")
	}
}

func TestBoundHashLogMatchesExactFileAndOnlyFollowsBinding(t *testing.T) {
	for _, exceeded := range []bool{false, true} {
		t.Run(fmt.Sprint(exceeded), func(t *testing.T) {
			cfg := boundCfg(t)
			if exceeded {
				zero := int64(0)
				cfg.MaxCreates = &zero
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			linear := &boundLinear{}
			linear.before = func() {
				data, err := os.ReadFile(cfg.PlanJSON)
				if err != nil {
					t.Fatal(err)
				}
				text := logs.String()
				if strings.Count(text, `msg="bound plan written"`) != 1 || !strings.Contains(text, "plan_sha256="+planTextDigest(string(data))) {
					t.Fatal("missing exact pre-write hash log")
				}
				_ = readBound[BoundAttempt](t, cfg, "attempt.json")
			}
			_, err := New(cfg, logger, &planSnyk{snapshot: planSnapshot(planFixtureFinding("issue-a"))}, linear, nil).Run(t.Context())
			if exceeded {
				if err == nil || strings.Contains(logs.String(), "bound plan written") {
					t.Fatal("rejected plan logged a binding")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBoundExistingPlanRefusesBeforeSourceAccess(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(fmt.Sprint(symlink), func(t *testing.T) {
			cfg := boundCfg(t)
			if symlink {
				if err := os.Symlink("missing.json", cfg.PlanJSON); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(cfg.PlanJSON, []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
			source := &planSnyk{}
			linear := &planLinear{}
			if _, err := New(cfg, discardLogger(), source, linear, nil).Run(t.Context()); err == nil {
				t.Fatal("accepted existing plan")
			}
			if source.calls != 0 || linear.calls != 0 {
				t.Fatal("loaded before rejecting existing plan")
			}
		})
	}
}

func TestBoundRefreshFailureStopsWithoutRetryOrStaleCache(t *testing.T) {
	for _, kind := range []string{"transport", "empty", "duplicate-id", "missing-id", "no-fingerprint", "late-tamper", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			cfg := boundCfg(t)
			f := planFixtureFinding("issue-a")
			store := &fakeCache{ignoreRows: true}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			linear := &boundLinear{before: func() {}}
			linear.refresh = func() ([]model.ExistingIssue, error) {
				if len(linear.created) != 1 {
					t.Fatal("refresh preceded mutation")
				}
				ticket := storedIssue("ticket-a", "SNYK-100", "Todo", desiredIssue(cfg, f))
				switch kind {
				case "transport":
					return nil, errors.New("post-write read failed")
				case "empty":
					return nil, nil
				case "duplicate-id":
					return []model.ExistingIssue{ticket, ticket}, nil
				case "missing-id":
					ticket.ID = ""
				case "no-fingerprint":
					ticket.Fingerprint = ""
				case "late-tamper":
					if err := os.WriteFile(cfg.PlanJSON, []byte("{}"), 0600); err != nil {
						t.Fatal(err)
					}
				case "canceled":
					cancel()
				}
				return []model.ExistingIssue{ticket}, nil
			}
			_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(f)}, linear, store).Run(ctx)
			if err == nil || linear.calls != 2 || len(linear.createCallBatches) != 1 || store.saved.SnykHashes != nil {
				t.Fatal("failed refresh retried, repeated mutations or saved cache")
			}
			final := readBound[BoundResult](t, cfg, "result.json")
			if final.Status == "success" || final.BatchesAcknowledged != 1 || final.CacheStatus == "saved" {
				t.Fatalf("dishonest refresh proof: %+v", final)
			}
		})
	}
}

func TestBoundEmptySourceCacheRefusesBeforeMutation(t *testing.T) {
	cfg := boundCfg(t)
	f := planFixtureFinding("issue-absent")
	ticket := storedIssue("ticket-a", "SNYK-100", "Todo", desiredIssue(cfg, f))
	linear := &planLinear{fakeLinear: fakeLinear{snapshot: []model.ExistingIssue{ticket}}}
	_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot()}, linear, &fakeCache{ignoreRows: true}).Run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "nonempty Snyk hashes") {
		t.Fatalf("error=%v", err)
	}
	assertNoReviewedWrites(t, linear)
}

func TestBoundOversizedPlanCannotBindOrExecute(t *testing.T) {
	cfg := boundCfg(t)
	f := planFixtureFinding("issue-a")
	preview := planCfg()
	preview.ReplaySafe = true
	result, _, _ := runPlan(t, preview, planSnapshot(f), nil, nil)
	result.Plan.Records[0].Reason = strings.Repeat("x", maxBoundPlanBytes)
	result.Plan.DecisionsSHA256, _ = planDigest(result.Plan.Records)
	b, err := reserveBoundRun(cfg.PlanJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	jobs := []job{{kind: jobCreateBatch, desiredBatch: []model.DesiredIssue{desiredIssue(cfg, f)}}}
	if err := b.bind(cfg, result.Plan, jobs); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized plan bound: %v", err)
	}
	for _, path := range []string{cfg.PlanJSON, filepath.Join(boundDir(cfg), "attempt.json")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("oversized binding created artifacts")
		}
	}
}

func TestBoundArtifactSizeBoundaryIncludesExactFileBytes(t *testing.T) {
	cfg := boundCfg(t)
	b, err := reserveBoundRun(cfg.PlanJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	// JSON quotes and newline consume three bytes beyond this ASCII string.
	data, err := b.write("plan.json", strings.Repeat("x", maxBoundPlanBytes-3))
	if err != nil || len(data) != maxBoundPlanBytes {
		t.Fatalf("exact boundary rejected: %v", err)
	}
	if _, err := b.write("attempt.json", strings.Repeat("x", maxBoundReceiptBytes)); err == nil {
		t.Fatal("unbounded receipt accepted")
	}
}

func TestBoundExpectedSettingsBeforeWrites(t *testing.T) {
	for _, match := range []bool{false, true} {
		t.Run(fmt.Sprint(match), func(t *testing.T) {
			cfg := boundCfg(t)
			digest, err := PlanSettingsSHA256(cfg)
			if err != nil {
				t.Fatal(err)
			}
			cfg.ExpectedSettingsSHA256 = digest
			if !match {
				cfg.ExpectedSettingsSHA256 = strings.Repeat("0", 64)
			}
			linear := &planLinear{}
			_, err = New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(planFixtureFinding("issue-a"))}, linear, nil).Run(t.Context())
			if match {
				if err != nil || len(linear.created) != 1 {
					t.Fatalf("matching settings did not execute: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "settings differ") {
				t.Fatalf("wrong refusal: %v", err)
			}
			if len(linear.created) != 0 || len(linear.updated) != 0 {
				t.Fatal("mutation preceded refusal")
			}
			if _, err := os.Stat(artifactPath(cfg, "attempt.json")); !os.IsNotExist(err) {
				t.Fatal("attempt persisted before refusal")
			}
			if _, err := os.Stat(cfg.PlanJSON); !os.IsNotExist(err) {
				t.Fatal("plan persisted before refusal")
			}
			final := readBound[BoundResult](t, cfg, "result.json")
			if final.LinearWritesAttempted || final.BatchesAttempted != 0 || final.Status != "failed_before_writes" || final.CacheStatus != "not_saved" {
				t.Fatalf("wrong result: %+v", final)
			}
		})
	}
}

func TestBoundStrictDeferredCreatesBeforeWrites(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			cfg := boundCfg(t)
			if strict {
				var err error
				cfg.ExpectedSettingsSHA256, err = PlanSettingsSHA256(cfg)
				if err != nil {
					t.Fatal(err)
				}
			}
			old := planFixtureFinding("issue-old")
			old.ProjectID = "project-old"
			old.Fingerprint = model.Fingerprint(old.ProjectID, old.SnykIssueID, "package-a@1")
			old.ProjectName = "namespace/deployment.apps/app:example.test/image"
			old.ProjectOrigin = "kubernetes"
			old.ProjectReference = ""
			old.ProjectTargetFile = ""
			old.ProjectCluster = "cluster-a"
			issue := storedIssue("ticket-old", "SNYK-100", "Todo", desiredIssue(cfg, old))
			finding := old
			finding.ProjectID = "project-new"
			finding.SnykIssueID = "issue-new"
			finding.Fingerprint = model.Fingerprint(finding.ProjectID, finding.SnykIssueID, "package-a@1")
			finding.ProjectCluster = ""
			finding.ProjectClusterUnknown = true
			snapshot := model.SnykSnapshot{Findings: []model.Finding{finding}, ProjectIDs: map[string]struct{}{"project-new": {}}, ClusterLookupFailures: 1}
			linear := &planLinear{fakeLinear: fakeLinear{snapshot: []model.ExistingIssue{issue}}}
			_, err := New(cfg, discardLogger(), &planSnyk{snapshot: snapshot}, linear, nil).Run(t.Context())
			if !strict {
				if err != nil || len(linear.updated) != 1 {
					t.Fatalf("manual compatibility changed: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "deferred creates") {
				t.Fatalf("wrong refusal: %v", err)
			}
			if len(linear.created) != 0 || len(linear.updated) != 0 {
				t.Fatal("executed jobs despite deferred create")
			}
			if _, err := os.Stat(artifactPath(cfg, "attempt.json")); !os.IsNotExist(err) {
				t.Fatal("attempt persisted before refusal")
			}
			if _, err := os.Stat(cfg.PlanJSON); !os.IsNotExist(err) {
				t.Fatal("plan persisted before refusal")
			}
			final := readBound[BoundResult](t, cfg, "result.json")
			if final.LinearWritesAttempted || final.BatchesAttempted != 0 || final.Status != "failed_before_writes" || final.CacheStatus != "not_saved" {
				t.Fatalf("wrong result: %+v", final)
			}
		})
	}
}

func TestBoundExactAndMultipleLimits(t *testing.T) {
	for _, exceeded := range []bool{false, true} {
		t.Run(fmt.Sprint(exceeded), func(t *testing.T) {
			cfg := boundCfg(t)
			limit := int64(1)
			if exceeded {
				limit = 0
			}
			cfg.MaxCreates, cfg.MaxUpdates, cfg.MaxResolves, cfg.MaxCancelDuplicates = &limit, &limit, &limit, &limit
			finding := planFixtureFinding("issue-a")
			ticket := storedIssue("ticket-a", "SNYK-100", "Todo", desiredIssue(cfg, finding))
			ticket.Title = "old"
			duplicate := ticket
			duplicate.ID, duplicate.Identifier = "ticket-b", "SNYK-101"
			absent := storedIssue("ticket-c", "SNYK-102", "Todo", desiredIssue(cfg, planFixtureFinding("issue-absent")))
			linear := &planLinear{fakeLinear: fakeLinear{snapshot: []model.ExistingIssue{ticket, duplicate, absent}}}
			store := &fakeCache{ignoreRows: true}
			var cacheStore CacheStore
			if exceeded {
				cacheStore = store
			}
			_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(finding, planFixtureFinding("issue-new"))}, linear, cacheStore).Run(t.Context())
			if !exceeded {
				if err != nil {
					t.Fatal(err)
				}
				if len(linear.created) != 1 || len(linear.updated) != 3 {
					t.Fatal("exact limits rejected")
				}
				if _, err := os.Stat(artifactPath(cfg, "refusal.json")); !os.IsNotExist(err) {
					t.Fatal("success emitted refusal")
				}
				return
			}
			var limitErr *BoundLimitError
			if !errors.As(err, &limitErr) {
				t.Fatalf("missing refusal: %v", err)
			}
			refusal := readBound[BoundRefusal](t, cfg, "refusal.json")
			data, err := os.ReadFile(artifactPath(cfg, "refusal.json"))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			keys := []string{"version", "status", "creates", "updates", "resolves", "cancel_duplicates", "max_creates", "max_updates", "max_resolves", "max_cancel_duplicates", "exceeded"}
			if len(fields) != len(keys) {
				t.Fatal("unexpected refusal fields")
			}
			for _, key := range keys {
				if _, ok := fields[key]; !ok {
					t.Fatalf("missing field %s", key)
				}
			}
			if len(data) > maxBoundReceiptBytes {
				t.Fatal("unbounded refusal")
			}
			if refusal.Creates != 1 || refusal.Updates != 1 || refusal.Resolves != 1 || refusal.CancelDuplicates != 1 || !reflect.DeepEqual(refusal.Exceeded, []string{"creates", "updates", "resolves", "cancel_duplicates"}) {
				t.Fatalf("wrong refusal: %+v", refusal)
			}
			assertNoReviewedWrites(t, linear)
			final := readBound[BoundResult](t, cfg, "result.json")
			if final.LinearWritesAttempted || final.BatchesAttempted != 0 || final.BatchesAcknowledged != 0 || final.CacheStatus != "not_saved" || final.Status != "failed_before_writes" || final.PlanSHA256 != "" || final.JobsSHA256 != "" || store.saved.SnykHashes != nil {
				t.Fatal("refusal claimed writes or saved cache")
			}
			for _, name := range []string{"plan.json", "attempt.json"} {
				if _, err := os.Stat(artifactPath(cfg, name)); !os.IsNotExist(err) {
					t.Fatal("refusal bound execution")
				}
			}
		})
	}
}

func TestBoundRefusalRequiresValidEvidenceAndExclusiveArtifact(t *testing.T) {
	for _, kind := range []string{"negative-summary", "wrong-summary", "missing-job", "collision", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			cfg := boundCfg(t)
			zero := int64(0)
			cfg.MaxCreates = &zero
			finding := planFixtureFinding("issue-a")
			preview := planCfg()
			preview.ReplaySafe = true
			result, _, _ := runPlan(t, preview, planSnapshot(finding), nil, nil)
			jobs := []job{{kind: jobCreateBatch, desiredBatch: []model.DesiredIssue{desiredIssue(cfg, finding)}}}
			b, err := reserveBoundRun(cfg.PlanJSON)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			refusalPath := artifactPath(cfg, "refusal.json")
			switch kind {
			case "negative-summary":
				result.Plan.Summary.Creates = -1
			case "wrong-summary":
				result.Plan.Summary.Creates = 2
			case "missing-job":
				jobs = nil
			case "collision":
				if err := os.WriteFile(refusalPath, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing", refusalPath); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Chmod(boundDir(cfg), 0755); err != nil {
					t.Fatal(err)
				}
			}
			err = b.bind(cfg, result.Plan, jobs)
			if err == nil {
				t.Fatal("invalid evidence bound")
			}
			if kind == "negative-summary" || kind == "wrong-summary" || kind == "missing-job" {
				var limitErr *BoundLimitError
				if errors.As(err, &limitErr) {
					t.Fatal("malformed evidence misreported as limits")
				}
				if _, err := os.Stat(refusalPath); !os.IsNotExist(err) {
					t.Fatal("malformed evidence emitted refusal")
				}
			} else if !strings.Contains(err.Error(), "persist bound refusal") {
				t.Fatalf("artifact error hidden: %v", err)
			}
			if kind == "collision" {
				data, _ := os.ReadFile(refusalPath)
				if string(data) != "existing" {
					t.Fatal("overwrote refusal")
				}
			}
			for _, name := range []string{"plan.json", "attempt.json"} {
				if _, err := os.Stat(artifactPath(cfg, name)); !os.IsNotExist(err) {
					t.Fatal("failed refusal bound execution")
				}
			}
		})
	}
}
