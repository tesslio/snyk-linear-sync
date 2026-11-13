package sync

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/httpx"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

func reviewedServiceCfg(t *testing.T, cfg config.Config, snapshot model.SnykSnapshot, issues []model.ExistingIssue, store CacheStore) config.Config {
	t.Helper()
	if cfg.Linear.TeamID == "" {
		cfg.Linear.TeamID = "11111111-1111-4111-8111-111111111111"
	}
	result, _, _ := runPlan(t, cfg, snapshot, issues, store)
	path := filepath.Join(t.TempDir(), "reviewed.json")
	if err := WritePlanJSON(path, result.Plan); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DryRun = false
	cfg.PlanJSON = ""
	cfg.ReviewedPlanJSON = path
	cfg.ReviewedPlanSHA256 = planTextDigest(string(data))
	return cfg
}

func assertNoReviewedWrites(t *testing.T, linear *planLinear) {
	t.Helper()
	if len(linear.createCallBatches)+len(linear.updates)+len(linear.commentCallBatches) != 0 {
		t.Fatal("rejected reviewed run attempted Linear writes")
	}
}

func TestReviewedServiceExecutesMatchingBufferedPlanOnce(t *testing.T) {
	cfg := planCfg()
	changed := planFixtureFinding("issue-change")
	ticket := storedIssue("ticket-change", "SNYK-100", "Todo", desiredIssue(cfg, changed))
	ticket.Title = "previous title"
	snapshot := planSnapshot(changed, planFixtureFinding("issue-new"))
	cfg = reviewedServiceCfg(t, cfg, snapshot, []model.ExistingIssue{ticket}, nil)
	snyk := &planSnyk{snapshot: snapshot}
	linear := &planLinear{fakeLinear: fakeLinear{snapshot: []model.ExistingIssue{ticket}}}
	result, err := New(cfg, discardLogger(), snyk, linear, nil).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.PlannedCreates != 1 || result.PlannedUpdates != 1 || len(linear.created) != 1 || len(linear.updated) != 1 {
		t.Fatalf("wrong operations: %+v", result)
	}
	if result.Plan != nil {
		t.Fatal("live result must not expose unattempted dry-run plan as execution receipt")
	}
	if snyk.calls != 1 || linear.calls != 1 {
		t.Fatalf("replanned or reloaded inputs: %d/%d", snyk.calls, linear.calls)
	}
}

func TestReviewedServiceReplaysEveryMutationKindFromOneBuffer(t *testing.T) {
	cfg := planCfg()
	changed := planFixtureFinding("issue-change")
	ticket := storedIssue("ticket-change", "SNYK-100", "Todo", desiredIssue(cfg, changed))
	ticket.Title = "previous title"
	duplicate := ticket
	duplicate.ID = "ticket-duplicate"
	duplicate.Identifier = "SNYK-102"
	absent := storedIssue("ticket-absent", "SNYK-103", "Todo", desiredIssue(cfg, planFixtureFinding("issue-absent")))
	snapshot := planSnapshot(changed, planFixtureFinding("issue-new"))
	issues := []model.ExistingIssue{ticket, duplicate, absent}
	cfg = reviewedServiceCfg(t, cfg, snapshot, issues, nil)
	linear := &planLinear{fakeLinear: fakeLinear{snapshot: issues}}
	result, err := New(cfg, discardLogger(), &planSnyk{snapshot: snapshot}, linear, nil).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.PlannedCreates != 1 || result.PlannedUpdates != 1 || result.PlannedResolves != 1 || result.CancelledDuplicates != 1 || len(linear.created) != 1 || len(linear.updated) != 3 {
		t.Fatalf("incomplete or repeated buffered replay: %+v", result)
	}
	if len(linear.createCallBatches) != 1 || len(linear.updates) != 3 {
		t.Fatal("mutation batch was repeated")
	}
}

func TestReviewedServiceRejectsDriftBeforeAnyLinearWrite(t *testing.T) {
	for _, field := range []string{"snyk", "linear", "settings", "team-uuid", "sync-cache", "late-retention"} {
		t.Run(field, func(t *testing.T) {
			cfg := planCfg()
			var findings []model.Finding
			for i := range 23 {
				f := planFixtureFinding(string(rune('a' + i)))
				findings = append(findings, f)
			}
			snapshot := planSnapshot(findings...)
			issues := []model.ExistingIssue{{ID: "last-ticket", Identifier: "SNYK-100", StateName: "Done", DueDate: "2026-01-01"}}
			baseCache := cache.Snapshot{SnykHashes: map[string]string{}, LinearHashes: map[string]string{}}
			cfg = reviewedServiceCfg(t, cfg, snapshot, issues, &fakeCache{snapshot: baseCache, ignoreRows: true})
			liveStore := &fakeCache{snapshot: baseCache, ignoreRows: true}
			switch field {
			case "snyk":
				snapshot.Findings[22].IssueTitle = "changed source title"
			case "linear":
				issues[0].Title = "changed title"
			case "settings":
				cfg.Linear.CommentsEnabled = !cfg.Linear.CommentsEnabled
			case "team-uuid":
				cfg.Linear.TeamID = "22222222-2222-4222-8222-222222222222"
			case "sync-cache":
				liveStore.snapshot = cache.Snapshot{SnykHashes: map[string]string{"other": "changed"}, LinearHashes: map[string]string{}}
			case "late-retention":
				issues[0].DueDate = "2026-02-02"
			}
			snyk := &planSnyk{snapshot: snapshot}
			linear := &planLinear{fakeLinear: fakeLinear{snapshot: issues}}
			_, err := New(cfg, discardLogger(), snyk, linear, liveStore).Run(t.Context())
			if err == nil {
				t.Fatal("drift was accepted")
			}
			assertNoReviewedWrites(t, linear)
			if liveStore.saved.SnykHashes != nil {
				t.Fatal("rejected plan saved sync hashes")
			}
		})
	}
}

func TestReviewedServiceRejectsTeamAliasBeforeLoadingEvenForEmptySnapshot(t *testing.T) {
	cfg := planCfg()
	cfg.Linear.TeamID = "TEAM"
	snapshot := planSnapshot(planFixtureFinding("issue-new"))
	cfg = reviewedServiceCfg(t, cfg, snapshot, nil, nil)
	// Another token can resolve the same team key to an entirely different
	// workspace with the same empty snapshot. Keys must never reach that lookup.
	cfg.Linear.APIKey = "different-example-token"
	snyk := &planSnyk{snapshot: snapshot}
	linear := &planLinear{}
	if _, err := New(cfg, discardLogger(), snyk, linear, nil).Run(t.Context()); err == nil {
		t.Fatal("mutable team destination was accepted")
	}
	if snyk.calls != 0 || linear.calls != 0 {
		t.Fatal("loaded snapshots before rejecting mutable destination")
	}
	assertNoReviewedWrites(t, linear)
}

func TestReviewedServiceRejectsChangedUUIDForEmptySnapshotCreatePlan(t *testing.T) {
	snapshot := planSnapshot(planFixtureFinding("issue-new"))
	cfg := reviewedServiceCfg(t, planCfg(), snapshot, nil, nil)
	cfg.Linear.TeamID = "22222222-2222-4222-8222-222222222222"
	cfg.Linear.APIKey = "different-example-token"
	snyk := &planSnyk{snapshot: snapshot}
	linear := &planLinear{}
	if _, err := New(cfg, discardLogger(), snyk, linear, nil).Run(t.Context()); err == nil {
		t.Fatal("changed destination matched an empty-snapshot create plan")
	}
	if snyk.calls != 1 || linear.calls != 1 {
		t.Fatal("test did not reach fresh snapshot comparison")
	}
	assertNoReviewedWrites(t, linear)
}

func TestReviewedServiceRejectsUnsupportedOptionsBeforeLoading(t *testing.T) {
	for _, field := range []string{"missing-path", "missing-hash", "dry-run", "export"} {
		t.Run(field, func(t *testing.T) {
			cfg := planCfg()
			cfg.DryRun = false
			cfg.PlanJSON = ""
			cfg.ReviewedPlanJSON = "not-read.json"
			cfg.ReviewedPlanSHA256 = "digest"
			switch field {
			case "missing-path":
				cfg.ReviewedPlanJSON = ""
			case "missing-hash":
				cfg.ReviewedPlanSHA256 = ""
			case "dry-run":
				cfg.DryRun = true
			case "export":
				cfg.PlanJSON = "export.json"
			}
			snyk := &planSnyk{}
			linear := &planLinear{}
			if _, err := New(cfg, discardLogger(), snyk, linear, nil).Run(t.Context()); err == nil {
				t.Fatal("invalid options accepted")
			}
			if snyk.calls != 0 || linear.calls != 0 {
				t.Fatal("loaded before validating options")
			}
			assertNoReviewedWrites(t, linear)
		})
	}
}

func TestReviewedServiceStopsPartialCreateWithoutRetryOrLaterBatches(t *testing.T) {
	cfg := planCfg()
	var findings []model.Finding
	failures := map[string]int{}
	for i := range 23 {
		f := planFixtureFinding(string(rune('a' + i)))
		findings = append(findings, f)
		failures[f.Fingerprint] = 1
	}
	snapshot := planSnapshot(findings...)
	cfg = reviewedServiceCfg(t, cfg, snapshot, nil, nil)
	linear := &planLinear{fakeLinear: fakeLinear{createFailFingerprints: failures}}
	_, err := New(cfg, discardLogger(), &planSnyk{snapshot: snapshot}, linear, nil).Run(t.Context())
	if err == nil {
		t.Fatal("partial mutation was accepted")
	}
	if len(linear.createCallBatches) != 1 || len(linear.created) != 0 {
		t.Fatal("partial create retried or later batch attempted")
	}
}

type reviewedHookSnyk struct {
	snapshot model.SnykSnapshot
	hook     func()
}

func (s reviewedHookSnyk) LoadSnapshot(context.Context) (model.SnykSnapshot, error) {
	s.hook()
	return s.snapshot, nil
}

func TestReviewedServiceUsesAcceptedBytesOnlyOnce(t *testing.T) {
	cfg := planCfg()
	snapshot := planSnapshot(planFixtureFinding("issue-new"))
	cfg = reviewedServiceCfg(t, cfg, snapshot, nil, nil)
	linear := &planLinear{}
	source := reviewedHookSnyk{snapshot: snapshot, hook: func() {
		if err := os.WriteFile(cfg.ReviewedPlanJSON, []byte("replaced after initial validation"), 0600); err != nil {
			t.Error(err)
		}
	}}
	if _, err := New(cfg, discardLogger(), source, linear, nil).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(linear.created) != 1 {
		t.Fatal("matching accepted plan did not execute")
	}
}

func TestReviewedServiceCancellationBeforeGateHasNoWrites(t *testing.T) {
	cfg := planCfg()
	snapshot := planSnapshot(planFixtureFinding("issue-new"))
	cfg = reviewedServiceCfg(t, cfg, snapshot, nil, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	linear := &planLinear{}
	source := reviewedHookSnyk{snapshot: snapshot, hook: cancel}
	if _, err := New(cfg, discardLogger(), source, linear, nil).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	assertNoReviewedWrites(t, linear)
}

func TestReviewedServiceHistoryDriftPreventsBufferedCreates(t *testing.T) {
	for _, mode := range []string{"partial", "different-restored-state"} {
		t.Run(mode, func(t *testing.T) {
			cfg := planCfg()
			finding := planFixtureFinding("issue-reopen")
			ticket := storedIssue("ticket-reopen", "SNYK-100", "Done", desiredIssue(cfg, finding))
			created := finding.CreatedAt.Add(24 * time.Hour)
			closed := created.Add(24 * time.Hour)
			ticket.CreatedAt = &created
			ticket.ClosedAt = &closed
			snapshot := planSnapshot(finding, planFixtureFinding("issue-new"))
			cfg = reviewedServiceCfg(t, cfg, snapshot, []model.ExistingIssue{ticket}, nil)
			linear := &planLinear{fakeLinear: fakeLinear{snapshot: []model.ExistingIssue{ticket}}}
			switch mode {
			case "partial":
				linear.lastOpenStatesErr = errors.New("unreadable history")
			case "different-restored-state":
				linear.lastOpenStates = map[string]model.WorkflowState{ticket.ID: {ID: "state-progress", Name: "In Progress"}}
			}
			if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: snapshot}, linear, nil).Run(t.Context()); err == nil {
				t.Fatal("changed history accepted")
			}
			if len(linear.lastOpenStatesCalls) != 1 {
				t.Fatal("test did not consult reopen history")
			}
			assertNoReviewedWrites(t, linear)
		})
	}
}

func TestReviewedCommentFailureIsNotRetried(t *testing.T) {
	cfg := planCfg()
	cfg.Linear.CommentsEnabled = true
	finding := planFixtureFinding("issue-change")
	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{commentFailFingerprints: map[string]int{finding.Fingerprint: 1}}
	svc := New(cfg, discardLogger(), nil, linear, nil)
	err := svc.executeReviewedJob(t.Context(), job{kind: jobUpdate, updateBatch: []model.IssueUpdate{{Existing: model.ExistingIssue{ID: "ticket-1"}, Desired: desired}}})
	if err == nil || len(linear.updated) != 1 || len(linear.commentCallBatches) != 1 || len(linear.comments) != 0 {
		t.Fatal("comment failure retried or concealed")
	}
}

type reviewedContextLinear struct {
	fakeLinear
	t           *testing.T
	afterUpdate func()
}

func (l *reviewedContextLinear) CreateIssues(ctx context.Context, desired []model.DesiredIssue) ([]model.CreateOutcome, error) {
	if !httpx.RetriesDisabled(ctx) {
		l.t.Fatal("guarded create allows lower-layer retries")
	}
	return l.fakeLinear.CreateIssues(ctx, desired)
}

func (l *reviewedContextLinear) UpdateIssues(ctx context.Context, updates []model.IssueUpdate) error {
	if !httpx.RetriesDisabled(ctx) {
		l.t.Fatal("guarded update allows lower-layer retries")
	}
	err := l.fakeLinear.UpdateIssues(ctx, updates)
	if l.afterUpdate != nil {
		l.afterUpdate()
	}
	return err
}

func (l *reviewedContextLinear) PostComments(ctx context.Context, updates []model.IssueUpdate) ([]int, error) {
	if !httpx.RetriesDisabled(ctx) {
		l.t.Fatal("guarded comment allows lower-layer retries")
	}
	return l.fakeLinear.PostComments(ctx, updates)
}

func TestReviewedJobsDisableRetriesThroughMutationCallTree(t *testing.T) {
	cfg := planCfg()
	cfg.Linear.CommentsEnabled = true
	linear := &reviewedContextLinear{t: t}
	svc := New(cfg, discardLogger(), nil, linear, nil)
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	for _, kind := range []jobKind{jobCreateBatch, jobUpdate, jobResolve, jobCancelDuplicate} {
		if err := svc.executeReviewedJob(t.Context(), job{kind: kind, desiredBatch: []model.DesiredIssue{desired}, updateBatch: []model.IssueUpdate{{Existing: model.ExistingIssue{ID: "ticket-1"}, Desired: desired}}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(linear.commentCallBatches) != 1 {
		t.Fatal("comment path was not covered")
	}
}

func TestReviewedCancellationBetweenUpdateAndCommentStopsDispatch(t *testing.T) {
	cfg := planCfg()
	cfg.Linear.CommentsEnabled = true
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	linear := &reviewedContextLinear{t: t, afterUpdate: cancel}
	svc := New(cfg, discardLogger(), nil, linear, nil)
	err := svc.executeReviewedJob(ctx, job{kind: jobUpdate, updateBatch: []model.IssueUpdate{{Existing: model.ExistingIssue{ID: "ticket-1"}}}})
	if !errors.Is(err, context.Canceled) || len(linear.updated) != 1 || len(linear.commentCallBatches) != 0 {
		t.Fatal("cancellation did not stop the next mutation")
	}
}

type reviewedFailureLinear struct {
	fakeLinear
	createErr, updateErr, commentErr       error
	failed                                 []int
	createCalls, updateCalls, commentCalls int
}

func (l *reviewedFailureLinear) CreateIssues(_ context.Context, desired []model.DesiredIssue) ([]model.CreateOutcome, error) {
	l.createCalls++
	outcomes := make([]model.CreateOutcome, len(desired))
	for i := range desired {
		outcomes[i] = model.CreateOutcome{Index: i, ID: fmt.Sprintf("created-%d", i), Acknowledged: true}
		for _, failed := range l.failed {
			if failed == i {
				outcomes[i].ID = ""
				outcomes[i].Acknowledged = false
			}
		}
	}
	return outcomes, l.createErr
}

func (l *reviewedFailureLinear) UpdateIssues(context.Context, []model.IssueUpdate) error {
	l.updateCalls++
	return l.updateErr
}
func (l *reviewedFailureLinear) PostComments(context.Context, []model.IssueUpdate) ([]int, error) {
	l.commentCalls++
	return l.failed, l.commentErr
}

func TestReviewedDispatchPreservesCauseAndBatchContext(t *testing.T) {
	for _, operation := range []string{"create", "update", "resolve", "cancel-duplicate", "comment"} {
		t.Run(operation, func(t *testing.T) {
			cfg := planCfg()
			cfg.Linear.CommentsEnabled = true
			cause := errors.Join(errors.New("example actionable failure"), context.Canceled)
			linear := &reviewedFailureLinear{failed: []int{1}}
			j := job{kind: jobKind(operation), desiredBatch: make([]model.DesiredIssue, 2), updateBatch: make([]model.IssueUpdate, 2)}
			switch operation {
			case "create":
				linear.createErr = cause
			case "comment":
				linear.commentErr = cause
				j.kind = jobUpdate
			default:
				linear.updateErr = cause
			}
			err := New(cfg, discardLogger(), nil, linear, nil).executeReviewedJob(t.Context(), j)
			if !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "example actionable failure") || !strings.Contains(err.Error(), "batch size=2") || !strings.Contains(err.Error(), "reviewed "+operation) {
				t.Fatalf("lost failure diagnostics: %v", err)
			}
			if operation == "create" || operation == "comment" {
				if !strings.Contains(err.Error(), "failed indexes=[1]") {
					t.Fatal("lost failed-item indexes")
				}
			}
			if linear.createCalls > 1 || linear.updateCalls > 1 || linear.commentCalls > 1 {
				t.Fatal("failure reporting retried a mutation")
			}
			if operation != "comment" && linear.commentCalls != 0 {
				t.Fatal("continued to comments after update failure")
			}
		})
	}
}

func TestReviewedDispatchReportsPartialFailureIndexesWithoutRetry(t *testing.T) {
	for _, operation := range []string{"create", "comment"} {
		t.Run(operation, func(t *testing.T) {
			cfg := planCfg()
			cfg.Linear.CommentsEnabled = true
			linear := &reviewedFailureLinear{failed: []int{1}}
			j := job{kind: jobCreateBatch, desiredBatch: make([]model.DesiredIssue, 2), updateBatch: make([]model.IssueUpdate, 2)}
			if operation == "comment" {
				j.kind = jobUpdate
			}
			err := New(cfg, discardLogger(), nil, linear, nil).executeReviewedJob(t.Context(), j)
			if err == nil || !strings.Contains(err.Error(), "partial or unacknowledged") || !strings.Contains(err.Error(), "failed indexes=[1]") || !strings.Contains(err.Error(), "batch size=2") {
				t.Fatalf("lost partial failure details: %v", err)
			}
			if operation == "create" && linear.createCalls != 1 || operation == "comment" && (linear.updateCalls != 1 || linear.commentCalls != 1) {
				t.Fatal("retried partial failure")
			}
		})
	}
}
