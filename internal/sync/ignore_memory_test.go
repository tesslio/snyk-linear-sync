package sync

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// The tests in this file cover the due dates the sync derives from what the
// Snyk loader remembers about ignores in its cache: the expiry of a snooze
// Snyk has since forgotten, and the day an "ignore until fix available"
// ignore stopped applying (IgnoreEndedAt).

func fixArrivedFinding() model.Finding {
	return model.Finding{
		Fingerprint:        "snyk:project-a:issue-1",
		SnykIssueID:        "issue-1",
		ProjectID:          "project-a",
		ProjectName:        "Project A",
		IssueTitle:         "Example vulnerability",
		IssueType:          "package_vulnerability",
		Severity:           "high",
		Status:             model.FindingOpen,
		CreatedAt:          time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		DisregardIfFixable: true,
		IgnoreEndedAt:      time.Date(2026, time.March, 10, 23, 30, 0, 0, time.UTC),
	}
}

// TestIssueDueDateFixAvailabilityUsesIgnoreEnd: the SLA of a finding whose
// ignore-until-fix-available ignore was lifted starts on the UTC day it was
// lifted, as remembered by the loader, not on the day the run happens to be.
func TestIssueDueDateFixAvailabilityUsesIgnoreEnd(t *testing.T) {
	cfg := minimalCfg()
	desired := desiredIssue(cfg, fixArrivedFinding())
	if desired.DueDate != "2026-04-09" || desired.DueDateBase != "2026-04-09" {
		t.Fatalf("due date = %q (base %q), want 2026-04-09 (30 days from the UTC day the ignore ended)", desired.DueDate, desired.DueDateBase)
	}
	if !strings.Contains(desired.DueDateReason, "fix availability") {
		t.Fatalf("reason = %q, want it to name fix availability", desired.DueDateReason)
	}

	// With an expiry still ahead when the fix arrived, the end is the base.
	finding := fixArrivedFinding()
	finding.IgnoreExpiresAt = time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	desired = desiredIssue(cfg, finding)
	if desired.DueDate != "2026-04-09" || !strings.Contains(desired.DueDateReason, "fix availability") {
		t.Fatalf("due date = %q reason %q, want 2026-04-09 from fix availability", desired.DueDate, desired.DueDateReason)
	}
}

// TestIssueDueDateLapsedDisregardIgnoreUsesExpiry: an ignore until fix
// available that reached its own expiry with no fix is an expired snooze,
// not a fix arrival. The expiry stays the base and the reason says so.
func TestIssueDueDateLapsedDisregardIgnoreUsesExpiry(t *testing.T) {
	cfg := minimalCfg()
	finding := fixArrivedFinding()
	finding.IgnoreExpiresAt = time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC) // before IgnoreEndedAt
	desired := desiredIssue(cfg, finding)
	if desired.DueDate != "2026-03-31" {
		t.Fatalf("due date = %q, want 2026-03-31 (30 days from the expiry)", desired.DueDate)
	}
	if !strings.Contains(desired.DueDateReason, "ignore expiry") || strings.Contains(desired.DueDateReason, "fix availability") {
		t.Fatalf("reason = %q, want ignore expiry, not fix availability", desired.DueDateReason)
	}
	// The same on the next run: the date derives from remembered data only.
	if again := desiredIssue(cfg, finding); again.DueDate != desired.DueDate {
		t.Fatalf("second run due date = %q, want %q", again.DueDate, desired.DueDate)
	}
}

// TestRunFixAvailabilityDueDateIsStableAcrossRuns: the run that sees the fix
// arrive moves the ticket out of Backlog with a due date based on the
// remembered ignore end, and the next run, seeing the same finding, computes
// the same date and leaves the ticket alone. The old today-based date lasted
// one run and was recomputed from created_at on the next.
func TestRunFixAvailabilityDueDateIsStableAcrossRuns(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	finding := fixArrivedFinding()

	awaiting := finding
	awaiting.Status = model.FindingAwaitingFix
	awaiting.IgnoreEndedAt = time.Time{}
	parked := storedIssue("existing-1", "SEC-1", "Backlog", desiredIssue(cfg, awaiting))
	if !parked.AwaitingFix || parked.DueDate != "" {
		t.Fatalf("fixture: parked ticket = %+v, want awaiting_fix marker and no due date", parked)
	}

	snyk := fakeSnyk{snapshot: model.SnykSnapshot{Findings: []model.Finding{finding}, ProjectIDs: map[string]struct{}{"project-a": {}}}}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{parked}}
	store := &fakeCache{}
	if _, err := New(cfg, discardLogger(), snyk, linear, store).Run(context.Background()); err != nil {
		t.Fatalf("run 1: Run() error = %v", err)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("run 1: updated = %d, want 1", len(linear.updated))
	}
	first := linear.updated[0]
	if first.State != model.StateTodo || first.DueDate != "2026-04-09" {
		t.Fatalf("run 1: state %q due %q, want todo with 2026-04-09", first.State, first.DueDate)
	}

	// Run 2 reads back what run 1 wrote.
	linear2 := &fakeLinear{snapshot: []model.ExistingIssue{storedIssue("existing-1", "SEC-1", "Todo", first)}}
	store.snapshot = store.saved
	result, err := New(cfg, discardLogger(), snyk, linear2, store).Run(context.Background())
	if err != nil {
		t.Fatalf("run 2: Run() error = %v", err)
	}
	if result.PlannedUpdates != 0 || len(linear2.updated) != 0 {
		t.Fatalf("run 2 planned %d updates (%+v), want none: the due date must not move", result.PlannedUpdates, linear2.updated)
	}
}

// TestRunExpiryDueDateStableAfterV1ForgetsSnooze is the sync half of the
// incident shape: a ticket whose due date is the snooze expiry + SLA must not
// be touched on later runs, once the loader keeps the expiry from its cache
// while the v1 API no longer returns the record and the REST issue is open
// and un-ignored.
func TestRunExpiryDueDateStableAfterV1ForgetsSnooze(t *testing.T) {
	cfg := minimalCfg()
	finding := fixArrivedFinding()
	finding.Severity = "medium"
	finding.DisregardIfFixable = false
	finding.IgnoreEndedAt = time.Time{}
	finding.IgnoreExpiresAt = time.Date(2026, time.February, 10, 8, 0, 0, 0, time.UTC)

	existing := storedIssue("existing-1", "SEC-1", "Todo", desiredIssue(cfg, finding))
	if existing.DueDate != "2026-03-27" {
		t.Fatalf("fixture: due date = %q, want 2026-03-27 (expiry + 45 days)", existing.DueDate)
	}
	snyk := fakeSnyk{snapshot: model.SnykSnapshot{Findings: []model.Finding{finding}, ProjectIDs: map[string]struct{}{"project-a": {}}}}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}
	result, err := New(cfg, discardLogger(), snyk, linear, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d (%+v), want 0", result.PlannedUpdates, linear.updated)
	}

	// Had the loader forgotten the expiry, the date would regress.
	forgotten := finding
	forgotten.IgnoreExpiresAt = time.Time{}
	if regressed := desiredIssue(cfg, forgotten); regressed.DueDate >= existing.DueDate {
		t.Fatalf("fixture: without the expiry the due date %q should be earlier than %q", regressed.DueDate, existing.DueDate)
	}
}

// TestRunAwaitingFixLabelOffDueDateComesFromIgnoreEnd: with the awaiting-fix
// label off and a ticket written before the marker existed, nothing on the
// ticket says it was awaiting a fix. The due date no longer depends on that:
// it comes from the ignore end the loader remembers. The ticket keeps its
// Backlog state, as documented for such tickets.
func TestRunAwaitingFixLabelOffDueDateComesFromIgnoreEnd(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.Labels.AwaitingFix = ""
	finding := fixArrivedFinding()

	legacy := model.ExistingIssue{
		ID:            "existing-1",
		Identifier:    "SEC-1",
		Title:         "Snyk: old title",
		Description:   "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\nmanaged_labels: snyk-automation\n-->",
		StateName:     "Backlog",
		Fingerprint:   finding.Fingerprint,
		Priority:      2,
		ManagedLabels: []string{"snyk-automation"},
		Labels:        []model.IssueLabel{{ID: "l1", Name: "snyk-automation"}},
	}
	snyk := fakeSnyk{snapshot: model.SnykSnapshot{Findings: []model.Finding{finding}, ProjectIDs: map[string]struct{}{"project-a": {}}}}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{legacy}}
	if _, err := New(cfg, discardLogger(), snyk, linear, nil).Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	updated := linear.updated[0]
	if updated.DueDate != "2026-04-09" {
		t.Fatalf("due date = %q, want 2026-04-09 from the remembered ignore end, label or no label", updated.DueDate)
	}
	if updated.State != model.StateBacklog || !updated.PreserveState {
		t.Fatalf("state %q preserve %v, want Backlog preserved for a ticket without the marker", updated.State, updated.PreserveState)
	}
}
