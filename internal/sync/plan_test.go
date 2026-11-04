package sync

import (
	"context"
	"encoding/json"
	"errors"
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

type planSnyk struct {
	snapshot model.SnykSnapshot
	calls    int
	err      error
}

func (s *planSnyk) LoadSnapshot(context.Context) (model.SnykSnapshot, error) {
	s.calls++
	return s.snapshot, s.err
}

type planLinear struct {
	fakeLinear
	calls int
	err   error
}

func (l *planLinear) LoadSnapshot(context.Context) ([]model.ExistingIssue, error) {
	l.calls++
	return l.snapshot, l.err
}

func planCfg() config.Config {
	cfg := minimalCfg()
	cfg.DryRun = true
	cfg.PlanJSON = "private-plan.json"
	cfg.Sync.Workers = 4
	cfg.Linear.Labels = config.LabelConfig{Managed: "sync-managed", AwaitingFix: "awaiting-fix", CreateOnly: []string{"initial-triage"}, Protected: []string{"human-owned"}}
	return cfg
}
func planFixtureFinding(issue string) model.Finding {
	return model.Finding{Fingerprint: model.Fingerprint("project-a", issue, "package-a@1"), SnykIssueID: issue, SnykIssueKey: "SNYK-100", ProjectID: "project-a", ProjectName: "owner/repo(main):Containerfile", ProjectOrigin: "github", ProjectReference: "main", ProjectTargetFile: "Containerfile", Repository: "owner/repo", IssueTitle: "Example finding", PackageName: "package-a", VulnerableVersion: "1", Severity: "high", Status: model.FindingOpen, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}
func planSnapshot(findings ...model.Finding) model.SnykSnapshot {
	return model.SnykSnapshot{Findings: findings, ProjectIDs: map[string]struct{}{"project-a": {}}}
}
func runPlan(t *testing.T, cfg config.Config, snapshot model.SnykSnapshot, issues []model.ExistingIssue, store CacheStore) (RunResult, *planSnyk, *planLinear) {
	t.Helper()
	snyk := &planSnyk{snapshot: snapshot}
	linear := &planLinear{fakeLinear: fakeLinear{snapshot: issues}}
	result, err := New(cfg, discardLogger(), snyk, linear, store).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan == nil || !result.Plan.Complete {
		t.Fatal("missing complete plan")
	}
	if snyk.calls != 1 || linear.calls != 1 {
		t.Fatalf("snapshot loads = %d/%d", snyk.calls, linear.calls)
	}
	if len(linear.created)+len(linear.updated)+len(linear.comments) != 0 {
		t.Fatal("dry run mutated Linear")
	}
	if result.Plan.Summary.CoveredFindings != len(snapshot.Findings) || result.Plan.Summary.CoveredExistingIssues != len(issues) {
		t.Fatalf("incomplete coverage: %+v", result.Plan.Summary)
	}
	for _, row := range result.Plan.Records {
		if row.ExecutionStatus != "not_attempted" {
			t.Fatalf("misleading status %+v", row)
		}
	}
	return result, snyk, linear
}
func planRow(t *testing.T, p *ReconciliationPlan, issueID, action string) PlanRecord {
	t.Helper()
	for _, r := range p.Records {
		if r.IssueID == issueID && r.Action == action {
			return r
		}
	}
	t.Fatalf("missing %s/%s in %+v", issueID, action, p.Records)
	return PlanRecord{}
}

func TestPlanCapturesAllOperationsAndPreservesDryRunCounters(t *testing.T) {
	cfg := planCfg()
	newFinding := planFixtureFinding("issue-new")
	changed := planFixtureFinding("issue-change")
	unchanged := planFixtureFinding("issue-same")
	changedTicket := storedIssue("ticket-change", "SNYK-100", "In Progress", desiredIssue(cfg, changed))
	changedTicket.Title = "old title"
	changedTicket.DueDate = "2026-03-01"
	sameTicket := storedIssue("ticket-same", "SNYK-101", "Todo", desiredIssue(cfg, unchanged))
	sameTicket.Labels = []model.IssueLabel{{Name: "sync-managed"}}
	missing := planFixtureFinding("issue-missing")
	missingTicket := storedIssue("ticket-missing", "SNYK-102", "Todo", desiredIssue(cfg, missing))
	duplicate := changedTicket
	duplicate.ID = "ticket-duplicate"
	duplicate.Identifier = "SNYK-103"
	terminalDuplicate := changedTicket
	terminalDuplicate.ID = "ticket-terminal"
	terminalDuplicate.Identifier = "SNYK-104"
	terminalDuplicate.StateName = "Done"
	unmanaged := model.ExistingIssue{ID: "ticket-unmanaged", Identifier: "SNYK-105", StateName: "Todo"}
	snapshot := planSnapshot(newFinding, changed, unchanged)
	issues := []model.ExistingIssue{changedTicket, sameTicket, missingTicket, duplicate, terminalDuplicate, unmanaged}
	result, _, _ := runPlan(t, cfg, snapshot, issues, nil)
	if result.PlannedCreates != 1 || result.PlannedUpdates != 1 || result.PlannedResolves != 1 || result.CancelledDuplicates != 1 {
		t.Fatalf("unexpected operations: %+v", result)
	}
	planRow(t, result.Plan, "", "create")
	update := planRow(t, result.Plan, "ticket-change", "update")
	if !update.State.Preserve || update.State.Before != "In Progress" || !update.CandidateDiff.TitleChanged || !update.CandidateDiff.DueDateChanged {
		t.Fatalf("update %+v", update)
	}
	if update.DueDate.RawSLADueDate != "2026-01-31" || update.DueDate.Planned != "2026-01-31" {
		t.Fatalf("due %+v", update.DueDate)
	}
	planRow(t, result.Plan, "ticket-same", "no-op")
	resolved := planRow(t, result.Plan, "ticket-missing", "resolve")
	if resolved.State.ProposedModel != "done" || resolved.State.Reason == "" {
		t.Fatalf("resolve %+v", resolved)
	}
	planRow(t, result.Plan, "ticket-duplicate", "cancel-duplicate")
	if r := planRow(t, result.Plan, "ticket-terminal", "retain"); r.Reason != "terminal-duplicate" {
		t.Fatalf("terminal %+v", r)
	}
	if r := planRow(t, result.Plan, "ticket-unmanaged", "retain"); r.Reason != "no-managed-fingerprint" {
		t.Fatalf("unmanaged %+v", r)
	}
	// Exporting is observational: the original dry-run returns identical counts.
	cfg.PlanJSON = ""
	plain, err := New(cfg, discardLogger(), fakeSnyk{snapshot: snapshot}, &fakeLinear{snapshot: issues}, nil).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result.Plan = nil
	if !reflect.DeepEqual(result, plain) {
		t.Fatalf("export changed run result: %+v vs %+v", result, plain)
	}
}

func TestPlanColdStartAndStickyDatesShowRawAndFinal(t *testing.T) {
	for _, sticky := range []bool{false, true} {
		t.Run(map[bool]string{false: "cold-start", true: "sticky"}[sticky], func(t *testing.T) {
			cfg := planCfg()
			finding := planFixtureFinding("issue-1")
			if sticky {
				finding.UpdatedAt = finding.CreatedAt.AddDate(0, 3, 0)
			}
			existing := storedIssue("ticket-1", "SNYK-100", "Todo", desiredIssue(cfg, finding))
			existing.DueDate = "2026-06-01"
			store := &fakeCache{ignoreRows: sticky}
			result, _, _ := runPlan(t, cfg, planSnapshot(finding), []model.ExistingIssue{existing}, store)
			row := result.Plan.Records[0]
			if row.DueDate.Calculated == existing.DueDate || row.DueDate.Proposed != existing.DueDate || row.DueDate.Planned != existing.DueDate {
				t.Fatalf("dates %+v", row.DueDate)
			}
			if row.DueDate.HeldByColdStart == sticky || row.DueDate.UsedUpdatedAtFallback != sticky {
				t.Fatalf("guards %+v", row.DueDate)
			}
			if store.saved.SnykHashes != nil {
				t.Fatal("dry run saved sync hashes")
			}
			if !sticky && store.meta[ignoresColdStartMetaKey] == "" {
				t.Fatal("fixture did not exercise existing local guard write")
			}
		})
	}
}

func TestPlanCacheHitArchivedMetadataBackfillAndSourceCoverage(t *testing.T) {
	cfg := planCfg()
	finding := planFixtureFinding("issue-cache")
	desired := desiredIssue(cfg, finding)
	desired.PreserveState = true
	issue := storedIssue("ticket-cache", "SNYK-100", "Todo", desired)
	issue.Labels = []model.IssueLabel{{Name: "sync-managed"}}
	store := &fakeCache{ignoreRows: true, snapshot: cache.Snapshot{SnykHashes: map[string]string{finding.Fingerprint: desiredIssueHash(desired)}, LinearHashes: map[string]string{finding.Fingerprint: existingIssueHash(issue)}}}
	result, _, _ := runPlan(t, cfg, planSnapshot(finding), []model.ExistingIssue{issue}, store)
	if r := planRow(t, result.Plan, issue.ID, "no-op"); r.Reason != "cache-hit" {
		t.Fatalf("cache %+v", r)
	}
	archived := issue
	archived.ID = "ticket-archived"
	archived.Fingerprint = "snyk:project-gone:issue-archive"
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	archived.ArchivedAt = &now
	result, _, _ = runPlan(t, cfg, planSnapshot(), []model.ExistingIssue{archived}, nil)
	if r := planRow(t, result.Plan, archived.ID, "retain"); r.Reason != "archived" {
		t.Fatalf("archive %+v", r)
	}
	finding.Status = model.FindingAwaitingFix
	desired = desiredIssue(cfg, finding)
	issue = storedIssue("ticket-awaiting", "SNYK-101", "Backlog", desired)
	issue.AwaitingFix = false
	issue.Description = strings.ReplaceAll(issue.Description, "awaiting_fix: yes\n", "")
	issue.Labels = []model.IssueLabel{{Name: "sync-managed"}, {Name: "awaiting-fix"}}
	result, _, _ = runPlan(t, cfg, planSnapshot(finding, finding), []model.ExistingIssue{issue}, nil)
	row := planRow(t, result.Plan, issue.ID, "update")
	if !row.CandidateDiff.MetadataOnly || !row.CandidateDiff.AwaitingFixBackfill || row.DueDate.Proposed != "" {
		t.Fatalf("backfill %+v", row)
	}
	found := false
	for _, r := range result.Plan.Records {
		if r.Reason == "superseded-source-fingerprint" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing superseded source coverage")
	}
}

func TestPlanReopenGuardAndRestoredHistory(t *testing.T) {
	cfg := planCfg()
	finding := planFixtureFinding("issue-1")
	desired := desiredIssue(cfg, finding)
	closed := storedIssue("ticket-1", "SNYK-100", "Done", desired)
	// Unknown creation history cannot justify reopening an old terminal ticket.
	result, _, _ := runPlan(t, cfg, planSnapshot(finding), []model.ExistingIssue{closed}, nil)
	if r := planRow(t, result.Plan, closed.ID, "retain"); r.Reason != "reopen-guard-retained" {
		t.Fatalf("reopen guard %+v", r)
	}
	planRow(t, result.Plan, "", "create")
	created := finding.CreatedAt.AddDate(0, 0, 1)
	closed.CreatedAt = &created
	closedAt := created.AddDate(0, 0, 1)
	closed.ClosedAt = &closedAt
	for _, historyError := range []bool{false, true} {
		t.Run(map[bool]string{false: "found", true: "failed"}[historyError], func(t *testing.T) {
			linear := &planLinear{fakeLinear: fakeLinear{snapshot: []model.ExistingIssue{closed}, lastOpenStates: map[string]model.WorkflowState{closed.ID: {ID: "state-progress", Name: "In Progress"}}}}
			if historyError {
				linear.lastOpenStates = nil
				linear.lastOpenStatesErr = errors.New("private error detail")
			}
			result, err := New(cfg, discardLogger(), fakeSnyk{snapshot: planSnapshot(finding)}, linear, nil).Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			row := planRow(t, result.Plan, closed.ID, "update")
			if !row.Reopen || row.HistoryStateFound == historyError || len(linear.lastOpenStatesCalls) != 1 || len(linear.updated) != 0 {
				t.Fatalf("reopen %+v", row)
			}
			if historyError && result.Plan.ReopenHistoryStatus != "partial_or_failed" {
				t.Fatal(result.Plan.ReopenHistoryStatus)
			}
		})
	}
}

func TestPlanPrivacyDeterminismAndInputDigests(t *testing.T) {
	cfg := planCfg()
	cfg.Snyk.ClientSecret = "secret-snyk-token"
	cfg.Linear.APIKey = "secret-linear-token"
	finding := planFixtureFinding("private-issue-id")
	finding.SourceFile = "private/source/path.go"
	finding.Fingerprint = model.Fingerprint("private-project-id", finding.SnykIssueID, finding.SourceFile)
	finding.IssueTitle = "private issue title"
	finding.Description = "private prose"
	finding.IssueURL = "https://private.example.test/secret"
	issue := storedIssue("ticket-1", "SNYK-100", "Todo", desiredIssue(cfg, finding))
	issue.Title = "private old title"
	issue.URL = "https://private.example.test/ticket"
	snapshot := planSnapshot(finding, planFixtureFinding("issue-2"), planFixtureFinding("issue-3"))
	result, _, _ := runPlan(t, cfg, snapshot, []model.ExistingIssue{issue}, nil)
	data, err := json.Marshal(result.Plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{cfg.Snyk.ClientSecret, cfg.Linear.APIKey, finding.SourceFile, finding.Fingerprint, finding.IssueTitle, finding.Description, finding.IssueURL, issue.Title, issue.URL, "private-project-id", "private-issue-id"} {
		if strings.Contains(string(data), private) {
			t.Fatalf("plan leaked %q", private)
		}
	}
	for range 20 {
		again, _, _ := runPlan(t, cfg, snapshot, []model.ExistingIssue{issue}, nil)
		next, _ := json.Marshal(again.Plan)
		if string(next) != string(data) {
			t.Fatal("same input produced different plan JSON")
		}
	}
	cfg.Linear.APIKey = "different-secret"
	again, _, _ := runPlan(t, cfg, snapshot, []model.ExistingIssue{issue}, nil)
	if result.Plan.Inputs != again.Plan.Inputs {
		t.Fatal("credentials affect public input fingerprints")
	}
	changed := snapshot
	changed.Findings = append([]model.Finding(nil), snapshot.Findings...)
	changed.Findings[0].Description += " changed"
	again, _, _ = runPlan(t, cfg, changed, []model.ExistingIssue{issue}, nil)
	if result.Plan.Inputs.SnykSHA256 == again.Plan.Inputs.SnykSHA256 {
		t.Fatal("full source change was not hashed")
	}
	changed.Findings[0], changed.Findings[1] = changed.Findings[1], changed.Findings[0]
	third, _, _ := runPlan(t, cfg, changed, []model.ExistingIssue{issue}, nil)
	if third.Plan.Inputs.SnykSHA256 == again.Plan.Inputs.SnykSHA256 {
		t.Fatal("source order was not hashed")
	}
}

func TestPlanFailsClosedBeforeWritesOrOnSourceFailure(t *testing.T) {
	cfg := planCfg()
	cfg.DryRun = false
	snyk := &planSnyk{}
	linear := &planLinear{}
	if _, err := New(cfg, discardLogger(), snyk, linear, nil).Run(context.Background()); err == nil || snyk.calls+linear.calls != 0 {
		t.Fatal("non-dry-run export did not fail before loads")
	}
	cfg.DryRun = true
	snyk.err = errors.New("source failed")
	result, err := New(cfg, discardLogger(), snyk, linear, nil).Run(context.Background())
	if err == nil || result.Plan != nil {
		t.Fatal("source failure yielded a plan")
	}
}

func TestWritePlanJSONPrivateExclusiveAndComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	plan := &ReconciliationPlan{Version: 1, Complete: true}
	if err := WritePlanJSON(path, plan); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	original, _ := os.ReadFile(path)
	if err := WritePlanJSON(path, plan); err == nil {
		t.Fatal("overwrote existing artifact")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(original) {
		t.Fatal("existing artifact changed")
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := WritePlanJSON(link, plan); err == nil {
		t.Fatal("followed symlink")
	}
	for _, invalid := range []*ReconciliationPlan{nil, {}, {Complete: true, LinearWritesAttempted: true}} {
		if err := WritePlanJSON(filepath.Join(t.TempDir(), "bad.json"), invalid); err == nil {
			t.Fatal("exported invalid plan")
		}
	}
}

func TestPlanCapturesCoarseMigrationAndIdentityRebind(t *testing.T) {
	cfg := planCfg()
	finding := planFixtureFinding("issue-new")
	for _, kind := range []string{"coarse-migration", "identity-rebind"} {
		t.Run(kind, func(t *testing.T) {
			old := finding
			if kind == "coarse-migration" {
				old.Fingerprint = model.CoarseFingerprint(finding.Fingerprint)
			} else {
				old.ProjectID = "project-old"
				old.SnykIssueID = "issue-old"
				old.Fingerprint = model.Fingerprint(old.ProjectID, old.SnykIssueID, "package-a@1")
			}
			issue := storedIssue("ticket-1", "SNYK-100", "Todo", desiredIssue(cfg, old))
			result, _, _ := runPlan(t, cfg, planSnapshot(finding), []model.ExistingIssue{issue}, nil)
			row := planRow(t, result.Plan, issue.ID, "update")
			if row.Match != kind || row.FingerprintSHA256 == row.PreviousFingerprintSHA256 || row.FindingIndex != 1 || row.ExistingIndex != 1 {
				t.Fatalf("migration %+v", row)
			}
			if len(result.Plan.Records) != 1 || result.PlannedCreates != 0 || result.PlannedResolves != 0 {
				t.Fatalf("unexpected extra operation: %+v", result.Plan)
			}
		})
	}
}

func TestPlanCapturesDeferredFindingAndMissingProjectCancellation(t *testing.T) {
	cfg := planCfg()
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
	result, _, _ := runPlan(t, cfg, snapshot, []model.ExistingIssue{issue}, nil)
	if result.DeferredCreates != 1 || result.PlannedCreates != 0 || result.PlannedResolves != 1 {
		t.Fatalf("deferral counters %+v", result)
	}
	deferred := planRow(t, result.Plan, "", "defer-create")
	if deferred.MutationPlanned || deferred.FindingIndex != 1 {
		t.Fatalf("deferral %+v", deferred)
	}
	resolved := planRow(t, result.Plan, issue.ID, "resolve")
	if resolved.State.ProposedModel != "cancelled" || resolved.State.Reason != "the Snyk project no longer exists" {
		t.Fatalf("resolve %+v", resolved)
	}
	snapshot.Findings = nil
	snapshot.InactiveProjectIDs = map[string]struct{}{"project-old": {}}
	result, _, _ = runPlan(t, cfg, snapshot, []model.ExistingIssue{issue}, nil)
	if row := planRow(t, result.Plan, issue.ID, "resolve"); row.State.Reason != "the Snyk project has been deactivated" {
		t.Fatalf("inactive %+v", row)
	}
}

func TestPlanCancellationDoesNotReturnCompleteArtifact(t *testing.T) {
	cfg := planCfg()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := New(cfg, discardLogger(), fakeSnyk{snapshot: planSnapshot()}, &fakeLinear{}, nil).Run(ctx)
	if err == nil || result.Plan != nil {
		t.Fatal("cancelled run produced complete plan")
	}
}

func TestPlanRepeatedSourcePreservesEarlierMigrationMatch(t *testing.T) {
	cfg := planCfg()
	finding := planFixtureFinding("issue-1")
	coarse := finding
	coarse.Fingerprint = model.CoarseFingerprint(finding.Fingerprint)
	issue := storedIssue("ticket-1", "SNYK-100", "Todo", desiredIssue(cfg, coarse))
	result, _, _ := runPlan(t, cfg, planSnapshot(finding, finding), []model.ExistingIssue{issue}, nil)
	row := planRow(t, result.Plan, issue.ID, "update")
	if row.Match != "coarse-migration" || row.FindingIndex != 2 {
		t.Fatalf("inherited matching %+v", row)
	}
	for _, r := range result.Plan.Records {
		if r.State.ResolutionStatus == "" || r.Labels.ResolutionStatus == "" || r.Labels.Added == nil {
			t.Fatalf("inconsistent schema defaults: %+v", r)
		}
	}
}

func TestPlanCoverageInvariantRejectsMissingDecision(t *testing.T) {
	cfg := planCfg()
	finding := planFixtureFinding("issue-1")
	collector, err := newPlanCollector(cfg, planSnapshot(finding), nil, cache.Snapshot{}, false)
	if err != nil {
		t.Fatal(err)
	}
	collector.finding(0, finding, desiredIssue(cfg, finding))
	if plan, err := collector.finish(RunResult{Findings: 1}, coldStartGuard{}); err == nil || plan != nil {
		t.Fatal("missing latest decision marked complete")
	}
}
