package sync

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RichardoC/snyk-linear-sync/internal/cache"
	"github.com/RichardoC/snyk-linear-sync/internal/config"
	"github.com/RichardoC/snyk-linear-sync/internal/model"
)

type fakeSnyk struct {
	snapshot model.SnykSnapshot
}

func (f fakeSnyk) LoadSnapshot(context.Context) (model.SnykSnapshot, error) {
	return f.snapshot, nil
}

type fakeLinear struct {
	snapshot []model.ExistingIssue
	created  []model.DesiredIssue
	updated  []model.DesiredIssue
	updates  []model.IssueUpdate
	comments []model.IssueUpdate

	// createCallBatches records the desired batch passed to each CreateIssues
	// call, in order, so tests can assert how many calls were made and how
	// they were shaped (e.g. a full batch followed by a single-item retry).
	createCallBatches [][]model.DesiredIssue
	// createFailFingerprints, when non-zero for a fingerprint, causes that
	// many future CreateIssues calls containing that fingerprint to report
	// it as failed (not appended to created) instead of succeeding. This
	// mimics a Linear alias reporting success:false for one item in a batch
	// while its siblings succeed.
	createFailFingerprints map[string]int

	// commentCallBatches / commentFailFingerprints mirror the create fields
	// above but for PostComments.
	commentCallBatches      [][]model.IssueUpdate
	commentFailFingerprints map[string]int
}

type fakeCache struct {
	snapshot cache.Snapshot
	saved    cache.Snapshot
}

func (f *fakeLinear) LoadSnapshot(context.Context) ([]model.ExistingIssue, error) {
	return f.snapshot, nil
}

func (f *fakeLinear) CreateIssues(_ context.Context, desired []model.DesiredIssue) ([]int, error) {
	f.createCallBatches = append(f.createCallBatches, append([]model.DesiredIssue(nil), desired...))
	var failed []int
	for i, d := range desired {
		if f.createFailFingerprints[d.Fingerprint] > 0 {
			f.createFailFingerprints[d.Fingerprint]--
			failed = append(failed, i)
			continue
		}
		f.created = append(f.created, d)
	}
	return failed, nil
}

func (f *fakeLinear) UpdateIssues(_ context.Context, updates []model.IssueUpdate) error {
	for _, update := range updates {
		f.updated = append(f.updated, update.Desired)
		f.updates = append(f.updates, update)
	}
	return nil
}

func (f *fakeLinear) PostComments(_ context.Context, updates []model.IssueUpdate) ([]int, error) {
	f.commentCallBatches = append(f.commentCallBatches, append([]model.IssueUpdate(nil), updates...))
	var failed []int
	for i, u := range updates {
		if f.commentFailFingerprints[u.Desired.Fingerprint] > 0 {
			f.commentFailFingerprints[u.Desired.Fingerprint]--
			failed = append(failed, i)
			continue
		}
		f.comments = append(f.comments, u)
	}
	return failed, nil
}

func (f *fakeCache) Load(context.Context) (cache.Snapshot, error) {
	return f.snapshot, nil
}

func (f *fakeCache) Save(_ context.Context, snapshot cache.Snapshot) error {
	f.saved = snapshot
	return nil
}

func TestRunPlansCreateUpdateAndResolve(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Outdated package",
					PackageName: "github.com/example/pkg",
					Severity:    "high",
					Status:      model.FindingOpen,
					IssueURL:    "https://example.test/issue-1",
					CreatedAt:   time.Date(2026, time.August, 1, 14, 0, 0, 0, time.UTC),
				},
				{
					Fingerprint: "snyk:project-b:issue-2",
					SnykIssueID: "issue-2",
					ProjectID:   "project-b",
					ProjectName: "Project B",
					IssueTitle:  "Ignored issue",
					Severity:    "low",
					Status:      model.FindingIgnored,
					IssueURL:    "https://example.test/issue-2",
					CreatedAt:   time.Date(2026, time.August, 1, 9, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{
				"project-a": {},
				"project-b": {},
				"project-z": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
			},
			{
				ID:          "existing-2",
				Identifier:  "SEC-2",
				Title:       "old resolved issue",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-z:issue-9",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1", result.PlannedCreates)
	}
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	if len(linear.updated) != 2 {
		t.Fatalf("updated = %d, want 2", len(linear.updated))
	}
	if linear.created[0].DueDate != "2026-10-30" {
		t.Fatalf("created due date = %q, want %q", linear.created[0].DueDate, "2026-10-30")
	}
	if !containsDesiredState(linear.updated, model.StateDone) {
		t.Fatalf("updated states = %#v, want one %q", desiredStates(linear.updated), model.StateDone)
	}
}

// TestRunMatchesFingerprintMangledByLinearMarkdown is the regression test
// for the hourly close-and-recreate loop: Linear's editor rewrites the
// stored fingerprint's "__main__.py" as "**main**.py", so without
// canonicalization the open ticket never matches the live finding — every
// run resolves the "orphaned" ticket and creates a fresh copy. With
// canonicalization the mangled ticket must match: no create, no resolve.
func TestRunMatchesFingerprintMangledByLinearMarkdown(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: model.Fingerprint("project-a", "issue-1", "sim/__main__.py"),
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Path Traversal",
					Severity:    "low",
					Status:      model.FindingOpen,
					IssueURL:    "https://example.test/issue-1",
					CreatedAt:   time.Date(2026, time.July, 5, 14, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{
				"project-a": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Todo",
				// Stored form as returned by the Linear API after its
				// markdown round-trip mangled the written __main__.py.
				Fingerprint: "snyk:project-a:issue-1:sim/**main**.py",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 0 {
		t.Fatalf("PlannedCreates = %d, want 0 (mangled fingerprint must match existing ticket)", result.PlannedCreates)
	}
	if result.PlannedResolves != 0 {
		t.Fatalf("PlannedResolves = %d, want 0 (matched ticket must not be resolved as missing)", result.PlannedResolves)
	}
	if len(linear.created) != 0 {
		t.Fatalf("created = %d, want 0", len(linear.created))
	}
	if containsDesiredState(linear.updated, model.StateDone) {
		t.Fatalf("updated states = %#v, matched open ticket must not be transitioned to Done", desiredStates(linear.updated))
	}
}

// TestNormalizeDescriptionForCompareTreatsLinearBoldRewriteAsEqual verifies
// that a description written with underscore emphasis compares equal to the
// asterisk form Linear stores, so re-matched tickets do not trigger a
// description rewrite on every run.
func TestNormalizeDescriptionForCompareTreatsLinearBoldRewriteAsEqual(t *testing.T) {
	written := "File: sim/__main__.py\n\n<!-- snyk-linear-sync\nfingerprint: snyk:p:i:sim/__main__.py\n-->"
	stored := "File: sim/**main**.py\n\n<!-- snyk-linear-sync\nfingerprint: snyk:p:i:sim/**main**.py\n-->"

	if normalizeDescriptionForCompare(written) != normalizeDescriptionForCompare(stored) {
		t.Fatalf("normalizeDescriptionForCompare: written and Linear-stored forms should compare equal\nwritten: %q\nstored:  %q",
			normalizeDescriptionForCompare(written), normalizeDescriptionForCompare(stored))
	}
}

func TestRunSkipsCachedUnchangedIssue(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:  "snyk:project-a:issue-1",
					SnykIssueID:  "issue-1",
					SnykIssueKey: "SNYK-ISSUE-1",
					ProjectID:    "project-a",
					ProjectName:  "Project A",
					IssueTitle:   "Outdated package",
					PackageName:  "github.com/example/pkg",
					Severity:     "high",
					Status:       model.FindingOpen,
					IssueURL:     "https://app.snyk.io/org/example/project/project-a#issue-SNYK-ISSUE-1",
					IssueAPIURL:  "https://api.snyk.io/rest/orgs/example/issues/issue-1?version=2024-10-15",
					CreatedAt:    time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{
				"project-a": {},
			},
		},
	}
	desired := desiredIssue(cfg, snyk.snapshot.Findings[0])
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       desired.Title,
		Description: desired.Description,
		DueDate:     desired.DueDate,
		StateName:   "Todo",
		Fingerprint: desired.Fingerprint,
		Priority:    desired.Priority,
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			SnykHashes: map[string]string{
				desired.Fingerprint: desiredIssueHash(desired),
			},
			LinearHashes: map[string]string{
				desired.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{existing},
	}

	service := New(cfg, logger, snyk, linear, cacheStore)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

// TestRunCancelsIgnoredFindingEvenIfCached verifies that a finding which is
// ignored in Snyk (desired state Cancelled) is moved to Cancelled even when its
// ticket was manually parked in "Todo" and the cache claims nothing changed.
// Regression test: the per-finding cache fast-path previously skipped these,
// leaving wont-fix-ignored tickets stuck open indefinitely.
func TestRunCancelsIgnoredFindingEvenIfCached(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:  "snyk:project-a:issue-1",
					SnykIssueID:  "issue-1",
					SnykIssueKey: "SNYK-ISSUE-1",
					ProjectID:    "project-a",
					ProjectName:  "Project A",
					IssueTitle:   "Base image vulnerability",
					PackageName:  "glibc/libc6",
					Severity:     "low",
					Status:       model.FindingIgnored,
					CreatedAt:    time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	// desired.State is Cancelled (ignored); the ticket was manually moved to
	// "Todo", so its state diverges from desired.
	desired := desiredIssue(cfg, snyk.snapshot.Findings[0])
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       desired.Title,
		Description: desired.Description,
		DueDate:     desired.DueDate,
		StateName:   "Todo",
		Fingerprint: desired.Fingerprint,
		Priority:    desired.Priority,
	}
	// Cache claims the issue is unchanged since last run — the masking condition
	// that previously suppressed the cancellation.
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			SnykHashes: map[string]string{
				desired.Fingerprint: desiredIssueHash(desired),
			},
			LinearHashes: map[string]string{
				desired.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}

	service := New(cfg, logger, snyk, linear, cacheStore)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("updated state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

// TestRunCacheStillSkipsNonTerminalStateDivergence locks in the narrow scope of
// the terminal-transition cache guard: an open finding whose ticket diverges
// only in a non-terminal state must still be cache-suppressed when its hashes
// are unchanged. (A broader !needsUpdate guard would incorrectly re-update it.)
func TestRunCacheStillSkipsNonTerminalStateDivergence(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:  "snyk:project-a:issue-1",
					SnykIssueID:  "issue-1",
					SnykIssueKey: "SNYK-ISSUE-1",
					ProjectID:    "project-a",
					ProjectName:  "Project A",
					IssueTitle:   "Outdated package",
					PackageName:  "github.com/example/pkg",
					Severity:     "high",
					Status:       model.FindingOpen, // desired Todo — non-terminal
					CreatedAt:    time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	desired := desiredIssue(cfg, snyk.snapshot.Findings[0]) // State == Todo
	// Ticket is in a *different open* state; needsUpdate is true, but the
	// transition is non-terminal so the cache should keep suppressing it.
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       desired.Title,
		Description: desired.Description,
		DueDate:     desired.DueDate,
		StateName:   "Triage",
		Fingerprint: desired.Fingerprint,
		Priority:    desired.Priority,
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			SnykHashes: map[string]string{
				desired.Fingerprint: desiredIssueHash(desired),
			},
			LinearHashes: map[string]string{
				desired.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}

	service := New(cfg, logger, snyk, linear, cacheStore)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (non-terminal divergence stays cached)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

func TestRunCancelsMissingIssueWhenProjectDeleted(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			ProjectIDs: map[string]struct{}{
				"project-a": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "missing project issue",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-z:issue-9",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

func TestRunCancelsMissingIssueWhenProjectDeletedEvenIfCached(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			ProjectIDs: map[string]struct{}{
				"project-a": {},
			},
		},
	}
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       "missing project issue",
		Description: "old description",
		StateName:   "Todo",
		Fingerprint: "snyk:project-z:issue-9",
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			LinearHashes: map[string]string{
				existing.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{existing},
	}

	service := New(cfg, logger, snyk, linear, cacheStore)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

func TestNeedsUpdateUsesCaseInsensitiveLabels(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-01",
		State:       model.StateTodo,
		Priority:    2,
	}

	if needsUpdate(existing, desired, config.StateConfig{}) {
		t.Fatal("needsUpdate() = true, want false")
	}
}

func containsDesiredState(desired []model.DesiredIssue, state model.IssueState) bool {
	for _, issue := range desired {
		if issue.State == state {
			return true
		}
	}
	return false
}

func desiredStates(desired []model.DesiredIssue) []model.IssueState {
	out := make([]model.IssueState, 0, len(desired))
	for _, issue := range desired {
		out = append(out, issue.State)
	}
	return out
}

func TestDesiredIssueDueDateUsesSnykCreatedAt(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// Use a CreatedAt that produces a future due date so the guard against
	// past due dates does not kick in.
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectName: "Project A",
		IssueType:   "code",
		Severity:    "critical",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.August, 11, 23, 30, 0, 0, time.FixedZone("minus0500", -5*60*60)),
	}

	desired := desiredIssue(cfg, finding)

	if desired.DueDate != "2026-08-27" {
		t.Fatalf("desired due date = %q, want %q", desired.DueDate, "2026-08-27")
	}
}

func TestDesiredIssueDueDateLeavesPastSLAAsIs(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// CreatedAt is far in the past, so CreatedAt + 30 days is also in the past.
	// The due date is left as the raw SLA date (past dates show as overdue
	// in Linear and indicate how long the issue has exceeded its SLA).
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectName: "Project A",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	if desired.DueDate != "2026-01-31" {
		t.Fatalf("desired due date = %q, want %q (raw SLA date for past issues)", desired.DueDate, "2026-01-31")
	}
}

// TestDesiredIssueDueDateUsesUpdatedOnReusedIssueID verifies that when Snyk
// reuses an issue ID for a new code occurrence (updated_at >> created_at),
// the SLA clock restarts from updated_at rather than using the stale
// created_at. Without this, a freshly-detected occurrence gets a months-old
// due date and is immediately past due despite the code being only days old.
func TestDesiredIssueDueDateUsesUpdatedOnReusedIssueID(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// Snyk created the issue ID in January, but the current occurrence was
	// detected in July (updated_at). The 90-day gap exceeds the 45-day
	// medium SLA, so the SLA clock should restart from updated_at.
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1:src/file.py",
		SnykIssueID: "issue-1",
		ProjectName: "Project A",
		Severity:    "medium",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.January, 22, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, time.July, 9, 17, 32, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	// July 9 + 45 days = August 23
	want := "2026-08-23"
	if desired.DueDate != want {
		t.Fatalf("desired due date = %q, want %q (SLA from updated_at, not created_at)", desired.DueDate, want)
	}
	if !strings.Contains(desired.DueDateReason, "updated_at") {
		t.Fatalf("due date reason = %q, want it to mention updated_at", desired.DueDateReason)
	}
}

// TestDesiredIssueDueDateDoesNotUseUpdatedAtForRecentIssue verifies that
// when updated_at is close to created_at (within the SLA window), the SLA
// clock uses created_at as before. This avoids false positives from routine
// re-scans that bump updated_at by a day or two.
func TestDesiredIssueDueDateDoesNotUseUpdatedAtForRecentIssue(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// created_at and updated_at are only 10 days apart — within the 90-day
	// low SLA window, so the SLA clock should use created_at.
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1:src/file.py",
		SnykIssueID: "issue-1",
		ProjectName: "Project A",
		Severity:    "low",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, time.July, 11, 0, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	// July 1 + 90 days = September 29 (using created_at, NOT updated_at)
	want := "2026-09-29"
	if desired.DueDate != want {
		t.Fatalf("desired due date = %q, want %q (SLA from created_at, not updated_at)", desired.DueDate, want)
	}
	if !strings.Contains(desired.DueDateReason, "issue creation") {
		t.Fatalf("due date reason = %q, want it to mention issue creation", desired.DueDateReason)
	}
}

// TestDesiredIssueDueDateIgnoredAtZeroUpdatedAt verifies that the updated_at
// fallback does not fire when updated_at is zero (missing from API response).
func TestDesiredIssueDueDateIgnoredAtZeroUpdatedAt(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectName: "Project A",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		// UpdatedAt is zero — should fall back to created_at behavior
	}

	desired := desiredIssue(cfg, finding)

	// Jan 1 + 30 days = Jan 31 (uses created_at, no updated_at fallback)
	if desired.DueDate != "2026-01-31" {
		t.Fatalf("desired due date = %q, want 2026-01-31 (created_at fallback when updated_at is zero)", desired.DueDate)
	}
}

func TestDesiredIssueDueDateLeavesPastExpiredSnoozeAsIs(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// IgnoreExpiresAt is in the past (snooze already expired),
	// so IgnoreExpiresAt + 30 days is also in the past. The due date is
	// left as the raw SLA date.
	finding := model.Finding{
		Fingerprint:     "snyk:project-a:issue-1",
		SnykIssueID:     "issue-1",
		ProjectName:     "Project A",
		Severity:        "high",
		Status:          model.FindingOpen,
		CreatedAt:       time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		IgnoreExpiresAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	if desired.DueDate != "2026-03-31" {
		t.Fatalf("desired due date = %q, want %q (raw SLA date from expired snooze)", desired.DueDate, "2026-03-31")
	}
}

func TestDesiredIssueAddsGitHubSourceLinksWhenConfigured(t *testing.T) {
	cfg := config.Config{
		Source: config.SourceConfig{
			Provider: "github",
		},
		Linear: config.LinearConfig{
			Labels: config.LabelConfig{
				Managed:     "snyk-automation",
				Tool:        map[string]string{"code": "snyk-code"},
				ToolDefault: "snyk-automation",
			},
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk:project-a:issue-1",
		SnykIssueID:       "issue-1",
		SnykIssueKey:      "SNYK-CODE-ISSUE-1",
		IssueType:         "code",
		ProjectID:         "project-a",
		ProjectName:       "Project A",
		IssueTitle:        "Path Traversal",
		Severity:          "high",
		Status:            model.FindingOpen,
		IssueAPIURL:       "https://api.example.test/issue-1",
		IssueURL:          "https://app.example.test/issue-1",
		Repository:        "owner/repo",
		ProjectReference:  "main",
		SourceFile:        "src/main.go",
		SourceCommitID:    "abc123",
		SourceLineStart:   10,
		SourceColumnStart: 2,
		SourceLineEnd:     12,
		SourceColumnEnd:   8,
	}

	desired := desiredIssue(cfg, finding)

	if desired.Title != "Snyk: [high] owner/repo: Path Traversal in main.go" {
		t.Fatalf("title = %q, want %q", desired.Title, "Snyk: [high] owner/repo: Path Traversal in main.go")
	}
	if !strings.Contains(desired.Description, "## Path Traversal [HIGH]") {
		t.Fatalf("description missing heading: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Repository: [owner/repo](https://github.com/owner/repo)") {
		t.Fatalf("description missing GitHub repository link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Ref: `main` at [`abc123`](https://github.com/owner/repo/commit/abc123)") {
		t.Fatalf("description missing ref line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "[src/main.go (line 10:2 to 12:8)](https://github.com/owner/repo/blob/abc123/src/main.go#L10-L12)") {
		t.Fatalf("description missing GitHub source file link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Snyk: [Open issue](https://app.example.test/issue-1)") {
		t.Fatalf("description missing Snyk link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "API: [Issue details](https://api.example.test/issue-1)") {
		t.Fatalf("description missing API link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Status: `open`") {
		t.Fatalf("description missing status line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "managed_labels: snyk-automation,snyk-code") {
		t.Fatalf("description missing managed labels metadata: %s", desired.Description)
	}
	if len(desired.ManagedLabels) != 2 || desired.ManagedLabels[0] != "snyk-automation" || desired.ManagedLabels[1] != "snyk-code" {
		t.Fatalf("ManagedLabels = %#v, want [snyk-automation snyk-code]", desired.ManagedLabels)
	}
}

func TestIssueDescriptionEmbedsSnykIssueDetails(t *testing.T) {
	cfg := config.Config{
		Source: config.SourceConfig{Provider: "github"},
		Linear: config.LinearConfig{
			Labels: config.LabelConfig{Managed: "snyk-automation"},
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk:project-a:issue-1",
		SnykIssueID:       "issue-1",
		SnykIssueKey:      "SNYK-JS-LODASH-1",
		IssueType:         "package_vulnerability",
		ProjectID:         "project-a",
		ProjectName:       "owner/repo(main):package-lock.json",
		IssueTitle:        "Prototype Pollution",
		Severity:          "high",
		Status:            model.FindingOpen,
		IssueURL:          "https://app.example.test/issue-1",
		IssueAPIURL:       "https://api.example.test/issue-1",
		PackageName:       "lodash",
		VulnerableVersion: "4.17.20",
		FixedVersion:      "4.17.21",
		CVSS:              7.5,
		Classes: []model.IssueClass{
			{ID: "CWE-1321", Source: "CWE"},
			{ID: "CWE-915", Source: "CWE"},
		},
		CVEs:              []string{"CVE-2020-8203", "CVE-2021-23337"},
		Description:       "Prototype pollution in lodash allows an attacker to merge recursive objects.",
		Remediation:       "Upgrade lodash to version 4.17.21 or higher.",
		HasCoordinates:    true,
		IsFixableSnyk:     true,
		IsFixableManually: true,
	}

	desired := desiredIssue(cfg, finding)

	checks := map[string]string{
		"fix availability": "Fix availability: `Snyk automatic fix, manual fix`",
		"cvss":             "CVSS: `7.5`",
		"cwe":              "CWE: `CWE-1321, CWE-915`",
		"cve":              "CVE: `CVE-2020-8203, CVE-2021-23337`",
		"description":      "### Description\nPrototype pollution in lodash allows an attacker to merge recursive objects.",
		"remediation":      "### Remediation\nUpgrade lodash to version 4.17.21 or higher.",
	}
	for name, want := range checks {
		if !strings.Contains(desired.Description, want) {
			t.Fatalf("description missing %s line: want %q\ngot:\n%s", name, want, desired.Description)
		}
	}
}

// TestIssueDescriptionSanitizesEmbeddedMetadataMarkerInjection verifies that
// a line-anchored fake "<!-- snyk-linear-sync ... -->" block embedded in
// Snyk-controlled prose (finding.Description) cannot survive into the
// rendered ticket description as a second parseable metadata block. Even
// though findMetadataBlockStart already defends against this by taking the
// LAST line-anchored marker, the embedded prose is sanitized at the source
// so there is no ambiguity left for a human reader (or any other tool that
// scans the description) — and so a future block ordering change could not
// resurrect the bug.
func TestIssueDescriptionSanitizesEmbeddedMetadataMarkerInjection(t *testing.T) {
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "owner/repo",
		IssueTitle:  "Some issue",
		Severity:    "high",
		Status:      model.FindingOpen,
		Description: "Apply the patch below, which looks like:\n<!-- snyk-linear-sync\nfingerprint: snyk:spoofed:fake\n-->\nDo not remove the comment above.",
	}

	description := issueDescription(config.SourceConfig{}, []string{"snyk-automation"}, finding)

	// Exactly one line-anchored marker header must remain: the real,
	// sync-appended block. The embedded fake must no longer read as
	// "<!-- snyk-linear-sync" at all.
	if got := strings.Count(description, "<!-- snyk-linear-sync"); got != 1 {
		t.Fatalf("description contains %d occurrences of the metadata header, want exactly 1 (the real block):\n%s", got, description)
	}
	// The service-side metadata parser must find the real, last block and
	// resolve to the real fingerprint, not the spoofed one. (The spoofed
	// fingerprint text itself may still appear as plain, visible prose — it
	// is no longer inside a parseable comment block, which is what matters.)
	start := findMetadataBlockStart(description)
	if start < 0 {
		t.Fatalf("findMetadataBlockStart() found no block in:\n%s", description)
	}
	block := description[start:]
	if !strings.Contains(block, "fingerprint: snyk:project-a:issue-1") {
		t.Fatalf("real metadata block missing correct fingerprint:\n%s", block)
	}

	// Building the description again from the same finding must be
	// byte-identical (idempotent, no churn between runs).
	again := issueDescription(config.SourceConfig{}, []string{"snyk-automation"}, finding)
	if description != again {
		t.Fatalf("issueDescription() is not idempotent across builds:\nfirst:\n%s\nsecond:\n%s", description, again)
	}
}

// TestSanitizeSnykProseIsIdempotent guards the core property the fix relies
// on: sanitizing already-sanitized text must be a no-op, so the sanitized
// description never churns between sync runs even if sanitized twice.
func TestSanitizeSnykProseIsIdempotent(t *testing.T) {
	cases := []string{
		"",
		"no markers here",
		"<!-- snyk-linear-sync\nfingerprint: fake\n-->",
		"<!--<!--<!--",
		"<!---",
		"text <!-- inline --> more <!-- snyk-linear-sync\nx\n-->",
	}
	for _, in := range cases {
		once := sanitizeSnykProse(in)
		twice := sanitizeSnykProse(once)
		if once != twice {
			t.Fatalf("sanitizeSnykProse(%q) is not idempotent: once=%q twice=%q", in, once, twice)
		}
		if strings.Contains(once, "<!--") {
			t.Fatalf("sanitizeSnykProse(%q) = %q still contains an unsanitized marker", in, once)
		}
	}
}

// TestIssueDescriptionTruncatesOversizedEmbeddedProse verifies that a very
// long finding.Description is capped so the managed metadata block appended
// after it can never be pushed past what Linear accepts. Without a cap, an
// oversized description risks Linear silently truncating away the metadata
// block, making the ticket unmanaged and causing duplicate-ticket creation
// on the next run.
func TestIssueDescriptionTruncatesOversizedEmbeddedProse(t *testing.T) {
	huge := strings.Repeat("x", 100000)
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "owner/repo",
		IssueTitle:  "Some issue",
		Severity:    "high",
		Status:      model.FindingOpen,
		Description: huge,
	}

	description := issueDescription(config.SourceConfig{}, []string{"snyk-automation"}, finding)

	if len(description) >= len(huge) {
		t.Fatalf("description length %d not bounded relative to raw input length %d", len(description), len(huge))
	}
	if !strings.Contains(description, truncationMarker) {
		t.Fatalf("description missing truncation marker:\n%s", description)
	}

	// The metadata block must still be present and parseable at the end.
	start := findMetadataBlockStart(description)
	if start < 0 {
		t.Fatalf("findMetadataBlockStart() found no block after truncation")
	}
	block := description[start:]
	if !strings.Contains(block, "fingerprint: snyk:project-a:issue-1") {
		t.Fatalf("metadata block missing fingerprint after truncation:\n%s", block)
	}
	if !strings.HasSuffix(strings.TrimSpace(description), "-->") {
		t.Fatalf("metadata block is not the last thing in the description:\n%s", description)
	}

	// Building twice from the same finding must be byte-identical.
	again := issueDescription(config.SourceConfig{}, []string{"snyk-automation"}, finding)
	if description != again {
		t.Fatalf("issueDescription() is not idempotent across builds for oversized input")
	}
}

func TestIssueDescriptionOmitsFixAvailabilityWithoutCoordinates(t *testing.T) {
	cfg := config.Config{
		Source: config.SourceConfig{Provider: "github"},
		Linear: config.LinearConfig{
			Labels: config.LabelConfig{Managed: "snyk-automation"},
		},
	}
	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "owner/repo",
		IssueTitle:  "Some issue",
		Severity:    "medium",
		Status:      model.FindingOpen,
		IssueURL:    "https://app.example.test/issue-1",
		// HasCoordinates false, no fixable flags, no CVSS, no classes/CVEs, no description/remediation.
	}

	desired := desiredIssue(cfg, finding)

	if strings.Contains(desired.Description, "Fix availability:") {
		t.Fatalf("description should omit fix availability when Snyk reports no coordinates:\n%s", desired.Description)
	}
	if strings.Contains(desired.Description, "CVSS:") {
		t.Fatalf("description should omit CVSS when not reported:\n%s", desired.Description)
	}
	if strings.Contains(desired.Description, "CWE:") {
		t.Fatalf("description should omit CWE when none reported:\n%s", desired.Description)
	}
	if strings.Contains(desired.Description, "### Description") {
		t.Fatalf("description should omit Description section when not reported:\n%s", desired.Description)
	}
	if strings.Contains(desired.Description, "### Remediation") {
		t.Fatalf("description should omit Remediation section when not reported:\n%s", desired.Description)
	}
}

func TestDesiredIssueAddsGitHubProjectTargetFileLinkWhenNoSourceLocationExists(t *testing.T) {
	cfg := config.Config{
		Source: config.SourceConfig{
			Provider: "github",
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk:project-a:issue-1",
		SnykIssueID:       "issue-1",
		IssueType:         "package_vulnerability",
		ProjectID:         "project-a",
		ProjectName:       "owner/repo(main):apps/backend/Dockerfile.dev",
		IssueTitle:        "Integer Overflow or Wraparound",
		Severity:          "critical",
		Status:            model.FindingOpen,
		IssueURL:          "https://app.example.test/issue-1",
		IssueAPIURL:       "https://api.example.test/issue-1",
		Repository:        "owner/repo",
		ProjectReference:  "main",
		ProjectTargetFile: "apps/backend/Dockerfile.dev",
		PackageName:       "zlib/zlib1g",
		SnykIssueKey:      "SNYK-DEBIAN-ZLIB-1",
	}

	desired := desiredIssue(cfg, finding)

	if desired.Title != "Snyk: [critical] owner/repo: Integer Overflow or Wraparound in zlib/zlib1g" {
		t.Fatalf("title = %q, want %q", desired.Title, "Snyk: [critical] owner/repo: Integer Overflow or Wraparound in zlib/zlib1g")
	}
	if !strings.Contains(desired.Description, "Repository: [owner/repo](https://github.com/owner/repo)") {
		t.Fatalf("description missing repository link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Ref: `main`") {
		t.Fatalf("description missing ref line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Target file: [apps/backend/Dockerfile.dev](https://github.com/owner/repo/blob/main/apps/backend/Dockerfile.dev)") {
		t.Fatalf("description missing GitHub project target file link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Package: `zlib/zlib1g`") {
		t.Fatalf("description missing package line: %s", desired.Description)
	}
}

func TestIssueTitleUsesReferenceForNonGitHubTargetFileFindings(t *testing.T) {
	finding := model.Finding{
		IssueTitle:        "Use of Default Credentials",
		Severity:          "critical",
		ProjectOrigin:     "kubernetes",
		ProjectReference:  "ghcr.io/berriai/litellm-database",
		ProjectTargetFile: "/app/pyproject.toml",
		PackageName:       "mlflow",
	}

	title := issueTitle(finding)

	if title != "Snyk: [critical] ghcr.io/berriai/litellm-database: Use of Default Credentials in mlflow" {
		t.Fatalf("title = %q, want %q", title, "Snyk: [critical] ghcr.io/berriai/litellm-database: Use of Default Credentials in mlflow")
	}
}

func TestUpsertManagedMetadataRemovesVisibleFingerprintFooter(t *testing.T) {
	description := "Status: `open`\n\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->\nFingerprint: snyk:project-a:issue-1"

	got := upsertManagedMetadata(description, "snyk:project-a:issue-1", []string{"snyk-automation", "snyk-code"})

	if strings.Contains(got, "Fingerprint: snyk:project-a:issue-1") {
		t.Fatalf("upsertManagedMetadata() left visible fingerprint footer: %s", got)
	}
	if !strings.Contains(got, "managed_labels: snyk-automation,snyk-code") {
		t.Fatalf("upsertManagedMetadata() missing managed labels metadata: %s", got)
	}
}

// TestUpsertManagedMetadataIgnoresInlineMarker verifies that the metadata
// marker appearing mid-sentence in user text does not corrupt the description.
// The marker must be at the start of a line to be treated as a metadata block.
func TestUpsertManagedMetadataIgnoresInlineMarker(t *testing.T) {
	description := "See <!-- snyk-linear-sync notes --> for details\n\nStatus: `open`"

	got := upsertManagedMetadata(description, "snyk:project-a:issue-1", []string{"snyk-automation"})

	// The inline marker should NOT be replaced; it should remain intact.
	if !strings.Contains(got, "See <!-- snyk-linear-sync notes -->") {
		t.Fatalf("upsertManagedMetadata() corrupted inline marker: %s", got)
	}
	// A proper metadata block should be appended at the end.
	if !strings.Contains(got, "<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1") {
		t.Fatalf("upsertManagedMetadata() missing proper metadata block: %s", got)
	}
}

func TestFindMetadataBlockStartAnchoredToLineBoundary(t *testing.T) {
	cases := []struct {
		name        string
		description string
		wantIdx     int
	}{
		{
			name:        "marker at start of description",
			description: "<!-- snyk-linear-sync\nfingerprint: test\n-->",
			wantIdx:     0,
		},
		{
			name:        "marker at start of line",
			description: "Some text\n<!-- snyk-linear-sync\nfingerprint: test\n-->",
			wantIdx:     10, // after "Some text\n"
		},
		{
			name:        "marker mid-sentence should not match",
			description: "See <!-- snyk-linear-sync notes --> for details",
			wantIdx:     -1,
		},
		{
			name:        "no marker at all",
			description: "Just a normal description",
			wantIdx:     -1,
		},
		{
			name:        "inline marker followed by real block",
			description: "See <!-- snyk-linear-sync notes -->\n<!-- snyk-linear-sync\nfingerprint: test\n-->",
			wantIdx:     36, // the real block, not the inline one
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findMetadataBlockStart(tc.description)
			if got != tc.wantIdx {
				t.Fatalf("findMetadataBlockStart() = %d, want %d", got, tc.wantIdx)
			}
		})
	}
}

// TestFindMetadataBlockStartReturnsLastLineAnchoredOccurrence verifies that
// when TWO line-anchored marker blocks are present, the LAST one is returned,
// not the first. This mirrors the fix applied to the equivalent function in
// internal/linear/client.go: Snyk-controlled prose embedded in the ticket
// body (e.g. quoted remediation text) can itself contain a line-anchored
// marker block, and the sync always appends the real managed block last.
func TestFindMetadataBlockStartReturnsLastLineAnchoredOccurrence(t *testing.T) {
	description := "<!-- snyk-linear-sync\nfingerprint: fake\n-->\n<!-- snyk-linear-sync\nfingerprint: real\n-->"
	want := strings.LastIndex(description, "<!-- snyk-linear-sync")

	got := findMetadataBlockStart(description)
	if got != want {
		t.Fatalf("findMetadataBlockStart() = %d, want %d (last line-anchored occurrence)", got, want)
	}
}

// TestUpsertManagedMetadataKeepsRealTrailingBlockWithFakeEarlierBlock verifies
// that when a ticket description contains an earlier, line-anchored block
// that merely looks like the managed metadata marker (e.g. copied into
// Snyk-controlled prose such as remediation text) followed by the real
// sync-managed block, upsertManagedMetadata updates the REAL (last) block and
// leaves the fake block untouched. Returning the first occurrence here would
// corrupt the fake prose and, in the Linear client's equivalent function,
// hijack fingerprint/label extraction and cause duplicate tickets.
func TestUpsertManagedMetadataKeepsRealTrailingBlockWithFakeEarlierBlock(t *testing.T) {
	description := strings.Join([]string{
		"### Remediation",
		"Apply the patch below, which looks like:",
		"<!-- snyk-linear-sync",
		"fingerprint: snyk:spoofed:fake",
		"-->",
		"",
		"<!-- snyk-linear-sync",
		"fingerprint: snyk:project-a:issue-1",
		"-->",
	}, "\n")

	got := upsertManagedMetadata(description, "snyk:project-a:issue-2", []string{"snyk-automation"})

	// The fake earlier block must be left alone.
	if !strings.Contains(got, "fingerprint: snyk:spoofed:fake") {
		t.Fatalf("upsertManagedMetadata() removed the fake earlier block: %s", got)
	}
	// The real trailing block must have been replaced with the new fingerprint,
	// not left stale.
	if strings.Contains(got, "fingerprint: snyk:project-a:issue-1") {
		t.Fatalf("upsertManagedMetadata() left the stale real block in place: %s", got)
	}
	if !strings.Contains(got, "fingerprint: snyk:project-a:issue-2") {
		t.Fatalf("upsertManagedMetadata() missing updated fingerprint in real block: %s", got)
	}
	if strings.Count(got, "fingerprint: snyk:project-a:issue-2") != 1 {
		t.Fatalf("expected exactly one occurrence of new fingerprint (only the real block touched): %s", got)
	}
	if !strings.Contains(got, "managed_labels: snyk-automation") {
		t.Fatalf("upsertManagedMetadata() missing managed labels: %s", got)
	}
}

func TestNeedsUpdateDetectsManagedLabelChange(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "title",
		Description:   "description",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		ManagedLabels: []string{"old-label"},
		Labels: []model.IssueLabel{
			{ID: "label-1", Name: "old-label"},
		},
		Priority: 2,
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "description",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		ManagedLabels: []string{"new-label"},
		Priority:      2,
	}

	if !needsUpdate(existing, desired, config.StateConfig{}) {
		t.Fatal("needsUpdate() = false, want true")
	}
}

func TestManagedLabelsUsesConfiguredToolMapping(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		Tool:        map[string]string{"code": "snyk-code"},
		ToolDefault: "snyk-automation",
	}, model.Finding{IssueType: "code"})

	if len(labels) != 2 || labels[0] != "snyk-automation" || labels[1] != "snyk-code" {
		t.Fatalf("managedLabels() = %#v, want [snyk-automation snyk-code]", labels)
	}
}

func TestManagedLabelsFallsBackToConfiguredDefault(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		ToolDefault: "snyk-fallback",
	}, model.Finding{IssueType: "custom"})

	if len(labels) != 2 || labels[0] != "snyk-automation" || labels[1] != "snyk-fallback" {
		t.Fatalf("managedLabels() = %#v, want [snyk-automation snyk-fallback]", labels)
	}
}

func TestManagedLabelsUsesConfiguredOriginMapping(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed: "snyk-automation",
		Origin:  map[string]string{"kubernetes": "snyk-kubernetes", "github": "snyk-github"},
	}, model.Finding{ProjectOrigin: "kubernetes"})

	if len(labels) != 2 || labels[0] != "snyk-automation" || labels[1] != "snyk-kubernetes" {
		t.Fatalf("managedLabels() = %#v, want [snyk-automation snyk-kubernetes]", labels)
	}
}

func TestManagedLabelsFallsBackToConfiguredOriginDefault(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:       "snyk-automation",
		OriginDefault: "snyk-origin",
	}, model.Finding{ProjectOrigin: "github"})

	if len(labels) != 2 || labels[0] != "snyk-automation" || labels[1] != "snyk-origin" {
		t.Fatalf("managedLabels() = %#v, want [snyk-automation snyk-origin]", labels)
	}
}

func TestManagedLabelsAddsAwaitingFixLabel(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		AwaitingFix: "triage-dependency",
	}, model.Finding{Status: model.FindingAwaitingFix})

	found := false
	for _, l := range labels {
		if l == "triage-dependency" {
			found = true
		}
	}
	if !found {
		t.Fatalf("managedLabels() = %#v, want triage-dependency for awaiting-fix issue", labels)
	}
}

func TestManagedLabelsOmitsAwaitingFixLabelWhenOff(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		AwaitingFix: "", // off
	}, model.Finding{Status: model.FindingAwaitingFix})

	for _, l := range labels {
		if l == "triage-dependency" {
			t.Fatalf("managedLabels() should not include triage-dependency when AwaitingFix is off")
		}
	}
}

func TestManagedLabelsOmitsAwaitingFixLabelForOpenIssue(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:     "snyk-automation",
		AwaitingFix: "triage-dependency",
	}, model.Finding{Status: model.FindingOpen})

	for _, l := range labels {
		if l == "triage-dependency" {
			t.Fatalf("managedLabels() should not include triage-dependency for open issues")
		}
	}
}

func TestNeedsUpdateClearsDueDateWhenDesiredIsEmpty(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-07-01",
		StateName:   "Backlog",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "", // cleared for awaiting-fix
		State:       model.StateBacklog,
		Priority:    2,
	}

	if !needsUpdate(existing, desired, config.StateConfig{}) {
		t.Fatal("needsUpdate() = false, want true (must clear stale due date for awaiting-fix)")
	}
}

func TestNeedsUpdateSkipsDueDateWhenBothEmpty(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "",
		StateName:   "Backlog",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "",
		State:       model.StateBacklog,
		Priority:    2,
	}

	if needsUpdate(existing, desired, config.StateConfig{}) {
		t.Fatal("needsUpdate() = true, want false (both due dates empty)")
	}
}

func TestNeedsUpdateIncludesDueDate(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-15",
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired, config.StateConfig{}) {
		t.Fatal("needsUpdate() = false, want true")
	}
}

func TestNeedsUpdateDetectsLinkOnlyDescriptionChange(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "Repository: owner/repo",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "Repository: [owner/repo](https://github.com/owner/repo)",
		DueDate:     "2026-04-01",
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired, config.StateConfig{}) {
		t.Fatal("needsUpdate() = false, want true")
	}
}

func TestIdentifierNum(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"SNYK-1", 1},
		{"SNYK-42", 42},
		{"SNYK-11596", 11596},
		{"SEC-999", 999},
		{"nodash", 0},
		{"", 0},
		{"SNYK-abc", 0},
	}
	for _, tc := range cases {
		if got := identifierNum(tc.input); got != tc.want {
			t.Errorf("identifierNum(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestRunCancelsDuplicateFingerprintKeepsLowerIdentifier(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	// SNYK-20 and SNYK-10 share the same fingerprint — concurrent-run duplicate.
	// SNYK-10 is older (lower number) and should be kept as canonical.
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-20",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-10",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Conflicts != 1 {
		t.Fatalf("Conflicts = %d, want 1", result.Conflicts)
	}
	if result.CancelledDuplicates != 1 {
		t.Fatalf("CancelledDuplicates = %d, want 1", result.CancelledDuplicates)
	}

	// SNYK-20 (the higher-identifier duplicate) must be cancelled.
	cancelledIDs := cancelledIdentifiers(linear.updates)
	if len(cancelledIDs) != 1 || cancelledIDs[0] != "SNYK-20" {
		t.Fatalf("cancelled identifiers = %v, want [SNYK-20]", cancelledIDs)
	}
}

func TestRunDuplicateCancellationIsIdempotentWhenAlreadyCancelled(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	// SNYK-20 is already Cancelled — a previous run already cleaned it up.
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-20",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-10",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Conflicts != 1 {
		t.Fatalf("Conflicts = %d, want 1", result.Conflicts)
	}
	// No update needed since SNYK-20 is already Cancelled.
	if result.CancelledDuplicates != 0 {
		t.Fatalf("CancelledDuplicates = %d, want 0 (already cancelled)", result.CancelledDuplicates)
	}
	if len(cancelledIdentifiers(linear.updates)) != 0 {
		t.Fatalf("expected no cancel mutations, got: %v", linear.updates)
	}
}

func TestRunThreeWayDuplicateCancelsTwoKeepsLowest(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{ID: "issue-c", Identifier: "SNYK-30", Title: "t", Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->", StateName: "Todo", Fingerprint: "snyk:project-a:issue-1"},
			{ID: "issue-a", Identifier: "SNYK-10", Title: "t", Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->", StateName: "Todo", Fingerprint: "snyk:project-a:issue-1"},
			{ID: "issue-b", Identifier: "SNYK-20", Title: "t", Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->", StateName: "Todo", Fingerprint: "snyk:project-a:issue-1"},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Conflicts != 2 {
		t.Fatalf("Conflicts = %d, want 2", result.Conflicts)
	}
	if result.CancelledDuplicates != 2 {
		t.Fatalf("CancelledDuplicates = %d, want 2", result.CancelledDuplicates)
	}

	cancelled := cancelledIdentifiers(linear.updates)
	if len(cancelled) != 2 {
		t.Fatalf("cancelled count = %d, want 2: %v", len(cancelled), cancelled)
	}
	for _, id := range cancelled {
		if id == "SNYK-10" {
			t.Fatalf("SNYK-10 (lowest) must not be cancelled; got cancelled: %v", cancelled)
		}
	}
}

func TestRunCancelsDuplicateAndStillSyncsCanonical(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	// SNYK-10 is canonical with a stale title — it should be updated.
	// SNYK-20 is the duplicate — it should be cancelled.
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-20",
				Title:       "stale title",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-10",
				Title:       "stale title",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.CancelledDuplicates != 1 {
		t.Fatalf("CancelledDuplicates = %d, want 1", result.CancelledDuplicates)
	}
	// Canonical (SNYK-10) must have been updated.
	if !containsStr(updatedIdentifiers(linear.updates), "SNYK-10") {
		t.Fatalf("SNYK-10 (canonical) was not updated; updates: %v", updatedIdentifiers(linear.updates))
	}
	// Duplicate (SNYK-20) must have been cancelled.
	if !containsStr(cancelledIdentifiers(linear.updates), "SNYK-20") {
		t.Fatalf("SNYK-20 (duplicate) was not cancelled; cancelled: %v", cancelledIdentifiers(linear.updates))
	}
}

// TestRunPrefersNonTerminalTicketAsCanonical is a regression test for the
// duplicate-ticket incident: SNYK-100 has the lower identifier but is
// Cancelled (terminal); SNYK-200 has a higher identifier but is Todo
// (non-terminal). The non-terminal ticket must be picked as canonical
// regardless of identifier number. Picking the terminal ticket as canonical
// would fire the reopen guard on every run (the finding is open), dropping
// the fingerprint from the index and creating a brand-new ticket each time --
// a self-sustaining loop that minted one duplicate per run forever (this is
// how 48 duplicates accumulated for one Snyk issue in production).
func TestRunPrefersNonTerminalTicketAsCanonical(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-100",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk:project-a:issue-1",
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-200",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 0 {
		t.Fatalf("PlannedCreates = %d, want 0 (must match the non-terminal SNYK-200 instead of creating a new ticket)", result.PlannedCreates)
	}
	if len(linear.created) != 0 {
		t.Fatalf("created = %d, want 0: %v", len(linear.created), linear.created)
	}
	if result.CancelledDuplicates != 0 {
		t.Fatalf("CancelledDuplicates = %d, want 0 (SNYK-100 is already terminal; cancelling it is a pointless mutation)", result.CancelledDuplicates)
	}
	cancelled := cancelledIdentifiers(linear.updates)
	if containsStr(cancelled, "SNYK-100") {
		t.Fatalf("SNYK-100 must not be re-cancelled; cancelled: %v", cancelled)
	}
	if containsStr(cancelled, "SNYK-200") {
		t.Fatalf("SNYK-200 (canonical) must not be cancelled; cancelled: %v", cancelled)
	}
}

// TestRunTerminalCanonicalConvergesAfterReopenGuardCreate is a regression test
// for the incident where the fingerprint's only existing ticket is terminal
// (Cancelled): run 1 correctly fires the reopen guard and creates a new
// ticket (expected/documented behavior). Run 2 must then converge: with both
// the old terminal ticket and the newly-created non-terminal ticket sharing
// the fingerprint, the non-terminal ticket becomes canonical, so no further
// ticket is created and nothing is cancelled. Before the canonical-selection
// fix, run 2 would instead pick the lower-identifier Cancelled ticket as
// canonical, fire the reopen guard again, and create yet another ticket --
// an unbounded loop that minted one duplicate per run.
func TestRunTerminalCanonicalConvergesAfterReopenGuardCreate(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "CVE-2026-1234",
		Severity:    "high",
		Status:      model.FindingOpen,
	}

	// --- Run 1: only a Cancelled ticket exists for this fingerprint. The
	// reopen guard must fire (documented expected behavior): the terminal
	// ticket is not reused, and a new ticket is created instead.
	snyk1 := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear1 := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-100",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk:project-a:issue-1",
			},
		},
	}
	service1 := New(cfg, logger, snyk1, linear1, nil)
	result1, err := service1.Run(context.Background())
	if err != nil {
		t.Fatalf("run 1: Run() error = %v", err)
	}
	if result1.PlannedCreates != 1 || len(linear1.created) != 1 {
		t.Fatalf("run 1: PlannedCreates = %d, created = %d, want 1 each (reopen guard should create a new ticket)", result1.PlannedCreates, len(linear1.created))
	}
	created := linear1.created[0]

	// --- Run 2: both the original Cancelled ticket and the newly-created
	// Todo ticket now exist, sharing the fingerprint, as they would once the
	// create from run 1 has landed in Linear. No new ticket should be
	// created, and neither ticket should be cancelled: this is the loop
	// terminating.
	snyk2 := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear2 := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-100",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk:project-a:issue-1",
			},
			{
				ID:            "issue-b",
				Identifier:    "SNYK-300",
				Title:         created.Title,
				Description:   created.Description,
				DueDate:       created.DueDate,
				StateName:     "Todo",
				Fingerprint:   created.Fingerprint,
				ManagedLabels: created.ManagedLabels,
				Priority:      created.Priority,
			},
		},
	}
	service2 := New(cfg, logger, snyk2, linear2, nil)
	result2, err := service2.Run(context.Background())
	if err != nil {
		t.Fatalf("run 2: Run() error = %v", err)
	}

	if result2.PlannedCreates != 0 {
		t.Fatalf("run 2: PlannedCreates = %d, want 0 (must converge, not create yet another duplicate)", result2.PlannedCreates)
	}
	if len(linear2.created) != 0 {
		t.Fatalf("run 2: created = %d, want 0: %v", len(linear2.created), linear2.created)
	}
	cancelled := cancelledIdentifiers(linear2.updates)
	if len(cancelled) != 0 {
		t.Fatalf("run 2: cancelled = %v, want none (flapping loop must terminate)", cancelled)
	}
}

// TestRunAllTerminalDuplicatesKeepsLowestIDNoCancelMutation covers the
// all-terminal duplicate case: both existing tickets are already Cancelled.
// The lowest identifier is still picked as canonical (existing behavior for
// same-class duplicates), the reopen guard fires on it producing exactly one
// new ticket, and neither pre-existing terminal ticket receives a pointless
// cancel mutation.
func TestRunAllTerminalDuplicatesKeepsLowestIDNoCancelMutation(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "CVE-2026-1234",
					Severity:    "high",
					Status:      model.FindingOpen,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-100",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk:project-a:issue-1",
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-200",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "d\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk:project-a:issue-1",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1", result.PlannedCreates)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	if result.CancelledDuplicates != 0 {
		t.Fatalf("CancelledDuplicates = %d, want 0 (both tickets are already terminal)", result.CancelledDuplicates)
	}
	if len(cancelledIdentifiers(linear.updates)) != 0 {
		t.Fatalf("expected no cancel mutations, got: %v", linear.updates)
	}
}

// minimalCfg returns the smallest valid Config needed to run the service in tests.
func minimalCfg() config.Config {
	return config.Config{
		Linear: config.LinearConfig{
			States: config.StateConfig{
				Todo:      "Todo",
				Backlog:   "Backlog",
				Done:      "Done",
				Cancelled: "Cancelled",
			},
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
}

func cancelledIdentifiers(updates []model.IssueUpdate) []string {
	var out []string
	for _, u := range updates {
		if u.Desired.State == model.StateCancelled {
			out = append(out, u.Existing.Identifier)
		}
	}
	return out
}

func updatedIdentifiers(updates []model.IssueUpdate) []string {
	out := make([]string, 0, len(updates))
	for _, u := range updates {
		out = append(out, u.Existing.Identifier)
	}
	return out
}

func containsStr(slice []string, s string) bool {
	return slices.Contains(slice, s)
}

// TestRunCancelsIssuesWhenProjectBecomesInactive verifies that managed Linear
// issues are cancelled when their Snyk project is de-activated (inactive).
func TestRunCancelsIssuesWhenProjectBecomesInactive(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// project-inactive has been de-activated; it still exists in Snyk but its
	// issues must be cancelled in Linear.
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{},
			ProjectIDs: map[string]struct{}{
				"project-active": {},
			},
			InactiveProjectIDs: map[string]struct{}{
				"project-inactive": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "issue from inactive project",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-inactive:issue-9",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

// TestRunCancelsIssuesWhenProjectBecomesInactiveEvenIfCached verifies that the
// cache does not prevent cancellation when a project transitions to inactive.
func TestRunCancelsIssuesWhenProjectBecomesInactiveEvenIfCached(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{},
			ProjectIDs: map[string]struct{}{
				"project-active": {},
			},
			InactiveProjectIDs: map[string]struct{}{
				"project-inactive": {},
			},
		},
	}
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       "issue from inactive project",
		Description: "old description",
		StateName:   "Todo",
		Fingerprint: "snyk:project-inactive:issue-9",
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			LinearHashes: map[string]string{
				existing.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{existing},
	}

	service := New(cfg, logger, snyk, linear, cacheStore)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

// TestRunDoesNotCreateIssuesForInactiveProjectFindings verifies that no new
// Linear issues are created for findings belonging to inactive Snyk projects.
// (In practice the Snyk client excludes these findings, but the service should
// not act on them even if they somehow appear in the snapshot.)
func TestRunDoesNotCreateIssuesForInactiveProjectFindings(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A finding whose project is inactive — it must not trigger a create.
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{},
			ProjectIDs: map[string]struct{}{
				"project-active": {},
			},
			InactiveProjectIDs: map[string]struct{}{
				"project-inactive": {},
			},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{}}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 0 {
		t.Fatalf("PlannedCreates = %d, want 0 (inactive project findings must not be created)", result.PlannedCreates)
	}
	if len(linear.created) != 0 {
		t.Fatalf("created = %d, want 0", len(linear.created))
	}
}

// TestRunInactiveProjectAlreadyCancelledIsIdempotent verifies that an issue
// already in the Cancelled state is not mutated again on a subsequent run.
func TestRunInactiveProjectAlreadyCancelledIsIdempotent(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{},
			ProjectIDs: map[string]struct{}{
				"project-active": {},
			},
			InactiveProjectIDs: map[string]struct{}{
				"project-inactive": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "issue from inactive project",
				Description: "old description\n<!-- snyk-linear-sync\nfingerprint: snyk:project-inactive:issue-9\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk:project-inactive:issue-9",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 0 {
		t.Fatalf("PlannedResolves = %d, want 0 (already cancelled)", result.PlannedResolves)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0 (no mutation needed)", len(linear.updated))
	}
}

func TestRunKeepsTemporaryIgnoreOpenWithExtendedDueDate(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ignoreExpires := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:     "snyk:project-a:issue-1",
					SnykIssueID:     "issue-1",
					ProjectID:       "project-a",
					ProjectName:     "Project A",
					IssueTitle:      "CVE-2026-1234",
					Severity:        "high",
					Status:          model.FindingOpen,
					CreatedAt:       time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
					IgnoreExpiresAt: ignoreExpires,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "Snyk: [high] CVE-2026-1234",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    2,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Temporary ignore should NOT be cancelled or moved to Backlog.
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	updated := linear.updated[0]
	if updated.State != model.StateTodo {
		t.Fatalf("updated state = %q, want %q", updated.State, model.StateTodo)
	}
	// Due date should be calculated from IgnoreExpiresAt (2026-06-01) + 30 days for high = 2026-07-01
	if updated.DueDate != "2026-07-01" {
		t.Fatalf("updated due date = %q, want %q", updated.DueDate, "2026-07-01")
	}
}

func TestDesiredIssueDueDateUsesIgnoreExpiresAt(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	finding := model.Finding{
		Fingerprint:     "snyk:project-a:issue-1",
		SnykIssueID:     "issue-1",
		ProjectName:     "Project A",
		IssueType:       "code",
		Severity:        "high",
		Status:          model.FindingOpen,
		CreatedAt:       time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		IgnoreExpiresAt: time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	if desired.DueDate != "2026-07-01" {
		t.Fatalf("desired due date = %q, want %q", desired.DueDate, "2026-07-01")
	}
	if desired.State != model.StateTodo {
		t.Fatalf("desired state = %q, want %q", desired.State, model.StateTodo)
	}
}

func TestRunRespectsManualBacklogMove(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Backlog",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Backlog override should prevent state-only update)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

func TestRunUpdatesTitleButKeepsBacklogState(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Backlog",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (title changed, state kept in Backlog)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateBacklog {
		t.Fatalf("updated state = %q, want %q", linear.updated[0].State, model.StateBacklog)
	}
}

func TestRunDoesNotOverrideBacklogForFixedFindings(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingFixed,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Backlog",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (fixed finding should move to Done)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateDone {
		t.Fatalf("updated state = %q, want %q", linear.updated[0].State, model.StateDone)
	}
}

func TestRunRespectsManualTodoMove(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Todo",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Todo override should prevent state-only update)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

func TestRunUpdatesTitleButKeepsTodoState(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Todo",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (title changed, state kept in Todo)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].PreserveState != true {
		t.Fatalf("updated[0].PreserveState = %v, want true", linear.updated[0].PreserveState)
	}
}

func TestIsConfiguredBacklogState(t *testing.T) {
	cases := []struct {
		existing   string
		configured string
		want       bool
	}{
		{"Backlog", "Backlog", true},
		{"backlog", "Backlog", true},
		{"BACKLOG", "Backlog", true},
		{"Todo", "Backlog", false},
		{"Done", "Backlog", false},
		{"Cancelled", "Backlog", false},
		{"", "Backlog", false},
		{"Backlog", "", false},
	}
	for _, tc := range cases {
		got := isConfiguredBacklogState(tc.existing, tc.configured)
		if got != tc.want {
			t.Errorf("isConfiguredBacklogState(%q, %q) = %v, want %v", tc.existing, tc.configured, got, tc.want)
		}
	}
}

// TestDesiredIssueDueDateUsesIgnoreExpiryForExpiredSnooze verifies that when an
// expired snooze still produces a future due date (IgnoreExpiresAt + offset),
// the due date is set correctly. When the result would be in the past, the
// due date is omitted instead (see TestDesiredIssueDueDateOmitsPastDueDateFromExpiredSnooze).
func TestDesiredIssueDueDateUsesIgnoreExpiryForExpiredSnooze(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	// The snooze expired on a date that still produces a future due date
	// when the offset is added.
	ignoreExpiresAt := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	finding := model.Finding{
		Fingerprint:     "snyk:project-a:issue-1",
		SnykIssueID:     "issue-1",
		ProjectName:     "Project A",
		IssueType:       "code",
		Severity:        "high",
		Status:          model.FindingOpen,
		CreatedAt:       time.Date(2026, time.April, 10, 8, 29, 14, 0, time.UTC),
		IgnoreExpiresAt: ignoreExpiresAt,
	}

	desired := desiredIssue(cfg, finding)

	// Due date should be IgnoreExpiresAt (August 29) + 30 days = September 28.
	if desired.DueDate != "2026-09-28" {
		t.Fatalf("desired due date = %q, want %q (ignore expiry + high offset)", desired.DueDate, "2026-09-28")
	}
}

// TestDesiredIssueDisregardIfFixableMapsToBacklog verifies that an issue with
// disregardIfFixable=true is mapped to FindingAwaitingFix, placed in Backlog
// with no due date, and receives the triage-dependency label.
func TestDesiredItemDisregardIfFixableMapsToBacklog(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	finding := model.Finding{
		Fingerprint:        "snyk:project-a:issue-1",
		SnykIssueID:        "issue-1",
		ProjectName:        "Project A",
		IssueType:          "package_vulnerability",
		Severity:           "medium",
		Status:             model.FindingAwaitingFix,
		CreatedAt:          time.Date(2026, time.April, 30, 11, 59, 47, 0, time.UTC),
		DisregardIfFixable: true,
	}

	desired := desiredIssue(cfg, finding)

	if desired.State != model.StateBacklog {
		t.Fatalf("desired state = %q, want %q for disregard-if-fixable issue", desired.State, model.StateBacklog)
	}
	if desired.DueDate != "" {
		t.Fatalf("desired due date = %q, want empty for disregard-if-fixable issue", desired.DueDate)
	}
	if desired.DueDateBase != "" {
		t.Fatalf("desired due date base = %q, want empty for disregard-if-fixable issue", desired.DueDateBase)
	}
	labelFound := false
	for _, label := range desired.ManagedLabels {
		if label == "triage-dependency" {
			labelFound = true
		}
	}
	if !labelFound {
		t.Fatalf("managed labels = %v, want triage-dependency for disregard-if-fixable issue", desired.ManagedLabels)
	}
	if !strings.Contains(desired.Description, "ignored (no fix available)") {
		t.Fatalf("description should contain 'ignored (no fix available)', got: %s", desired.Description)
	}
}

// TestNeedsUpdateAlwaysCorrectsDueDate verifies that the sync always flags
// a due date update when the desired date differs from the existing one.
// Snyk is authoritative: the sync must correct manual overrides and stale
// dates, even if the desired date is a floored "today" value.
func TestNeedsUpdateAlwaysCorrectsDueDate(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-07-15", // manually-overridden future date
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-01-31", // Snyk-derived SLA date (authoritative)
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired, config.StateConfig{}) {
		t.Fatal("needsUpdate() = false, want true (Snyk-derived due date must correct manual override)")
	}
}

// TestNeedsUpdateStillDetectsDueDateChangeWhenBothNonEmpty verifies that the
// due date change detection still works when both dates are non-empty.
func TestNeedsUpdateStillDetectsDueDateChangeWhenBothNonEmpty(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-07-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-07-15",
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired, config.StateConfig{}) {
		t.Fatal("needsUpdate() = false, want true (due dates differ)")
	}
}

// TestRunSetsRawSLADateOnNewIssueWithOldCreatedAt verifies that when a new
// Snyk finding has an old CreatedAt, the sync creates the Linear issue with
// the raw SLA date (past dates show as overdue in Linear and indicate how long
// the issue has exceeded its SLA).
func TestRunSetsFlooredDueDateOnNewIssueWithOldCreatedAt(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Old issue",
					Severity:    "high",
					Status:      model.FindingOpen,
					CreatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC), // old → due date would be past
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{}}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1", result.PlannedCreates)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	if linear.created[0].DueDate != "2026-01-31" {
		t.Fatalf("created due date = %q, want %q (raw SLA date for past issues)", linear.created[0].DueDate, "2026-01-31")
	}
}

// TestRunCorrectsOverriddenDueDateWithAuthoritativeCalculation verifies that
// when the Snyk-derived due date differs from the Linear due date, the sync
// always updates it — Snyk is authoritative, even over manual overrides.
func TestRunCorrectsOverriddenDueDateWithAuthoritativeCalculation(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Old issue",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     "2026-07-15", // manually-overridden future date
				StateName:   "Todo",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// The sync must correct the manually-overridden due date to the
	// authoritative Snyk-derived SLA date.
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (Snyk due date must correct manual override)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].DueDate != "2026-01-31" {
		t.Fatalf("updated due date = %q, want %q (authoritative Snyk SLA date)", linear.updated[0].DueDate, "2026-01-31")
	}
}

// TestRunUpdatedAtFallbackDueDateIsStickyAcrossRuns is a regression test for
// due-date churn: once the updated_at re-detection fallback fires (see
// issueDueDate), Snyk bumps updated_at on every routine re-scan, not just
// genuine re-detections. Without stickiness, the due date would advance every
// run, producing an endless stream of Linear due-date updates and
// change-comments. Once a matched ticket already has a due date, a second run
// must keep it fixed even though the finding's updated_at has moved on.
func TestRunUpdatedAtFallbackDueDateIsStickyAcrossRuns(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// created_at is far enough in the past, and updated_at far enough beyond
	// created_at plus the high-severity SLA window (30 days), that the
	// updated_at re-detection fallback fires on both runs.
	finding1 := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "CVE-2026-1234",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	snyk1 := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding1},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear1 := &fakeLinear{snapshot: []model.ExistingIssue{}}

	service1 := New(cfg, logger, snyk1, linear1, nil)
	result1, err := service1.Run(context.Background())
	if err != nil {
		t.Fatalf("run 1: Run() error = %v", err)
	}
	if result1.PlannedCreates != 1 || len(linear1.created) != 1 {
		t.Fatalf("run 1: PlannedCreates = %d, created = %d, want 1 each", result1.PlannedCreates, len(linear1.created))
	}
	created := linear1.created[0]
	// Jan 1 2026 (updated_at) + 30 days = Jan 31 2026.
	if created.DueDate != "2026-01-31" {
		t.Fatalf("run 1: created due date = %q, want %q", created.DueDate, "2026-01-31")
	}

	// --- Run 2: the finding's updated_at has advanced by a day, as it would
	// from a routine Snyk re-scan (not a genuine re-detection). The existing
	// ticket already has the due date set from run 1.
	finding2 := finding1
	finding2.UpdatedAt = finding1.UpdatedAt.AddDate(0, 0, 1)

	snyk2 := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding2},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear2 := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:            "issue-a",
				Identifier:    "SNYK-500",
				Title:         created.Title,
				Description:   created.Description,
				DueDate:       created.DueDate,
				StateName:     "Todo",
				Fingerprint:   created.Fingerprint,
				ManagedLabels: created.ManagedLabels,
				Priority:      created.Priority,
			},
		},
	}
	service2 := New(cfg, logger, snyk2, linear2, nil)
	result2, err := service2.Run(context.Background())
	if err != nil {
		t.Fatalf("run 2: Run() error = %v", err)
	}

	if result2.PlannedUpdates != 0 {
		t.Fatalf("run 2: PlannedUpdates = %d, want 0 (due date must not churn once set)", result2.PlannedUpdates)
	}
	if len(linear2.updated) != 0 {
		t.Fatalf("run 2: updated = %v, want none", linear2.updated)
	}
}

// TestRunUpdatedAtFallbackStillSetsDueDateWhenNeverSet verifies that a
// matched ticket which never had a due date still gets one computed from the
// updated_at fallback -- the stickiness added to prevent due-date churn must
// not suppress setting a due date for the first time.
func TestRunUpdatedAtFallbackStillSetsDueDateWhenNeverSet(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "CVE-2026-1234",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-500",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     "", // never set
				StateName:   "Todo",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (due date must be set for the first time)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].DueDate != "2026-01-31" {
		t.Fatalf("updated due date = %q, want %q", linear.updated[0].DueDate, "2026-01-31")
	}
}

// TestRunAwaitingFixIssueGoesToBacklogWithNoDueDate verifies the full flow for
// a Snyk finding with disregardIfFixable=true: the sync creates the Linear
// issue in Backlog with no due date and the triage-dependency label.
func TestRunAwaitingFixIssueGoesToBacklogWithNoDueDate(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:        "snyk:project-a:issue-1",
					SnykIssueID:        "issue-1",
					ProjectID:          "project-a",
					ProjectName:        "Project A",
					IssueTitle:         "XSS in postcss",
					IssueType:          "package_vulnerability",
					Severity:           "medium",
					Status:             model.FindingAwaitingFix,
					CreatedAt:          time.Date(2026, time.April, 24, 20, 20, 42, 0, time.UTC),
					DisregardIfFixable: true,
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{}}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1", result.PlannedCreates)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	created := linear.created[0]
	if created.State != model.StateBacklog {
		t.Fatalf("created state = %q, want %q", created.State, model.StateBacklog)
	}
	if created.DueDate != "" {
		t.Fatalf("created due date = %q, want empty for awaiting-fix issue", created.DueDate)
	}
	labelFound := false
	for _, label := range created.ManagedLabels {
		if label == "triage-dependency" {
			labelFound = true
		}
	}
	if !labelFound {
		t.Fatalf("created managed labels = %v, want triage-dependency", created.ManagedLabels)
	}
	if !strings.Contains(created.Description, "ignored (no fix available)") {
		t.Fatalf("description should contain 'ignored (no fix available)'")
	}
}

// TestRunAwaitingFixIssueMovedFromTodoToBacklog verifies that when an existing
// issue was previously synced as Todo (before the awaiting-fix feature) and
// the Snyk finding now maps to FindingAwaitingFix, the sync moves it to
// Backlog, clears the due date, and adds the triage-dependency label.
func TestRunAwaitingFixIssueMovedFromTodoToBacklog(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint:        "snyk:project-a:issue-1",
		SnykIssueID:        "issue-1",
		ProjectID:          "project-a",
		ProjectName:        "Project A",
		IssueTitle:         "XSS in postcss",
		IssueType:          "package_vulnerability",
		Severity:           "medium",
		Status:             model.FindingAwaitingFix,
		CreatedAt:          time.Date(2026, time.April, 24, 20, 20, 42, 0, time.UTC),
		DisregardIfFixable: true,
	}

	desired := desiredIssue(cfg, finding)

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:            "existing-1",
				Identifier:    "SEC-1",
				Title:         desired.Title,
				Description:   desired.Description,
				DueDate:       "2026-06-08", // old due date from before awaiting-fix
				StateName:     "Todo",       // was in Todo before
				Fingerprint:   finding.Fingerprint,
				Priority:      desired.Priority,
				ManagedLabels: []string{"snyk-automation"},
				Labels:        []model.IssueLabel{{ID: "l1", Name: "snyk-automation"}},
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	updated := linear.updated[0]
	if updated.State != model.StateBacklog {
		t.Fatalf("updated state = %q, want %q", updated.State, model.StateBacklog)
	}
	if updated.DueDate != "" {
		t.Fatalf("updated due date = %q, want empty (cleared for awaiting-fix)", updated.DueDate)
	}
	labelFound := false
	for _, label := range updated.ManagedLabels {
		if label == "triage-dependency" {
			labelFound = true
		}
	}
	if !labelFound {
		t.Fatalf("updated managed labels = %v, want triage-dependency", updated.ManagedLabels)
	}
}

func TestComputeDiffDetectsAllChanges(t *testing.T) {
	existing := model.ExistingIssue{
		ID:            "issue-1",
		Identifier:    "SEC-1",
		Title:         "old title",
		Description:   "old description",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      3,
		ManagedLabels: []string{"snyk-automation"},
		Labels:        []model.IssueLabel{{ID: "label-1", Name: "snyk-automation"}},
	}
	desired := model.DesiredIssue{
		Title:         "new title",
		Description:   "new description",
		DueDate:       "2026-05-01",
		State:         model.StateBacklog,
		Priority:      1,
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
	}

	diff := ComputeDiff(existing, desired, config.StateConfig{})

	if !diff.TitleChanged {
		t.Fatal("expected TitleChanged")
	}
	if diff.TitleFrom != "old title" || diff.TitleTo != "new title" {
		t.Fatalf("title diff = %q → %q", diff.TitleFrom, diff.TitleTo)
	}
	if !diff.DescriptionChanged {
		t.Fatal("expected DescriptionChanged")
	}
	if !diff.DueDateChanged {
		t.Fatal("expected DueDateChanged")
	}
	if diff.DueDateFrom != "2026-04-01" || diff.DueDateTo != "2026-05-01" {
		t.Fatalf("due date diff = %q → %q", diff.DueDateFrom, diff.DueDateTo)
	}
	if !diff.StateChanged {
		t.Fatal("expected StateChanged")
	}
	if diff.StateTo != "backlog" {
		t.Fatalf("state to = %q", diff.StateTo)
	}
	if !diff.PriorityChanged {
		t.Fatal("expected PriorityChanged")
	}
	if diff.PriorityFrom != 3 || diff.PriorityTo != 1 {
		t.Fatalf("priority diff = %d → %d", diff.PriorityFrom, diff.PriorityTo)
	}
	if len(diff.LabelsAdded) != 1 || diff.LabelsAdded[0] != "snyk-code" {
		t.Fatalf("labels added = %v, want [snyk-code]", diff.LabelsAdded)
	}
	if len(diff.LabelsRemoved) != 0 {
		t.Fatalf("labels removed = %v, want []", diff.LabelsRemoved)
	}
	if !diff.LabelsNeedUpdate {
		t.Fatal("expected LabelsNeedUpdate when labels are added")
	}
}

func TestComputeDiffDetectsNoChanges(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "same title",
		Description:   "same description",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      2,
		ManagedLabels: []string{"snyk-automation"},
	}
	desired := model.DesiredIssue{
		Title:         "same title",
		Description:   "same description",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		Priority:      2,
		ManagedLabels: []string{"snyk-automation"},
	}

	diff := ComputeDiff(existing, desired, config.StateConfig{})

	if diff.TitleChanged || diff.DescriptionChanged || diff.DueDateChanged ||
		diff.StateChanged || diff.PriorityChanged || diff.LabelsNeedUpdate ||
		len(diff.LabelsAdded) > 0 || len(diff.LabelsRemoved) > 0 {
		t.Fatalf("expected no changes, got: %+v", diff)
	}
}

func TestComputeDiffDetectsLabelRemoval(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      2,
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
		Labels: []model.IssueLabel{
			{ID: "l1", Name: "snyk-automation"},
			{ID: "l2", Name: "snyk-code"},
		},
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		Priority:      2,
		ManagedLabels: []string{"snyk-automation"},
	}

	diff := ComputeDiff(existing, desired, config.StateConfig{})

	if len(diff.LabelsRemoved) != 1 || diff.LabelsRemoved[0] != "snyk-code" {
		t.Fatalf("labels removed = %v, want [snyk-code]", diff.LabelsRemoved)
	}
	if !diff.LabelsNeedUpdate {
		t.Fatal("expected LabelsNeedUpdate when labels are removed")
	}
}

func TestComputeDiffNoStateChangeWhenPreserveState(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "desc",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		State:         model.StateBacklog,
		PreserveState: true,
		ManagedLabels: []string{"snyk-automation"},
	}

	diff := ComputeDiff(existing, desired, config.StateConfig{})

	if diff.StateChanged {
		t.Fatal("expected no state change when PreserveState=true")
	}
}

func TestComputeDiffDetectsLabelNotOnIssue(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      2,
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
		// snyk-code is managed but not actually on the issue (failed to apply).
		Labels: []model.IssueLabel{
			{ID: "l1", Name: "snyk-automation"},
		},
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		Priority:      2,
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
	}

	diff := ComputeDiff(existing, desired, config.StateConfig{})

	if !diff.LabelsNeedUpdate {
		t.Fatal("expected LabelsNeedUpdate when managed label is not on issue")
	}
	if len(diff.LabelsAdded) != 0 {
		t.Fatalf("LabelsAdded = %v, want empty (label was in previous managed set)", diff.LabelsAdded)
	}
	if len(diff.LabelsRemoved) != 0 {
		t.Fatalf("LabelsRemoved = %v, want empty", diff.LabelsRemoved)
	}
}

// TestComputeDiffNoFalseLabelRemovalWhenLabelAlreadyGone verifies that a
// previously managed label that is no longer desired AND already manually
// removed from the issue is NOT reported as LabelsRemoved. This prevents
// misleading change comments like "Removed X — no longer applicable" when
// the label isn't actually on the issue anymore.
func TestComputeDiffNoFalseLabelRemovalWhenLabelAlreadyGone(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      2,
		ManagedLabels: []string{"snyk-automation", "snyk-code"},
		// snyk-code was previously managed but has been manually removed.
		Labels: []model.IssueLabel{
			{ID: "l1", Name: "snyk-automation"},
		},
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		Priority:      2,
		ManagedLabels: []string{"snyk-automation"},
	}

	diff := ComputeDiff(existing, desired, config.StateConfig{})

	if len(diff.LabelsRemoved) != 0 {
		t.Fatalf("LabelsRemoved = %v, want empty (snyk-code is not on the issue)", diff.LabelsRemoved)
	}
	// LabelsNeedUpdate should be false because snyk-code is already absent from
	// the issue and snyk-automation is still present. The metadata block change
	// is captured by DescriptionChanged, not LabelsNeedUpdate.
	if diff.LabelsNeedUpdate {
		t.Fatal("expected no LabelsNeedUpdate since the label IDs on the issue are already correct")
	}
}

func TestRunPostsChangeCommentsOnUpdate(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.CommentsEnabled = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Updated title",
					PackageName: "github.com/example/pkg",
					Severity:    "high",
					Status:      model.FindingOpen,
					CreatedAt:   time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    3,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.comments) != 1 {
		t.Fatalf("comments = %d, want 1", len(linear.comments))
	}
}

// TestRunPreservesNonTerminalStateWhenUserMovesToTodo verifies the core bug
// fix: when the configured open state is "Triage" and a user manually moves
// an open finding's issue to "Todo", the sync must not drag it back to
// "Triage". This was the original isManualTodoState check, now generalized
// to cover any non-terminal state.
func TestRunPreservesNonTerminalStateWhenUserMovesToTodo(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage" // simulate the real workspace config
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	// The user manually moved the issue from Triage to Todo.
	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Todo", // not the configured open state "Triage"
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Todo state should be preserved)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

// TestRunPreservesNonTerminalStateWhenUserMovesToInProgress verifies that the
// general non-terminal state override also covers custom states like "In
// Progress" — not just the hardcoded "todo" that the old isManualTodoState
// checked for.
func TestRunPreservesNonTerminalStateWhenUserMovesToInProgress(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "In Progress", // custom non-terminal state
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (In Progress state should be preserved)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

// TestRunPreservesTodoWhenFindingIsAwaitingFix verifies that the sync does
// not override a user's manual move from Backlog to Todo when the Snyk
// finding is still in "awaiting fix" status. The old isManualTodoState check
// only fired when desired.State was Todo; when the finding was awaiting fix
// (desired Backlog), the check was bypassed and the issue was dragged back
// to Backlog.
func TestRunPreservesTodoWhenFindingIsAwaitingFix(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	cfg.Linear.States.Backlog = "Backlog"
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint:        "snyk:project-a:issue-1",
		SnykIssueID:        "issue-1",
		ProjectID:          "project-a",
		ProjectName:        "Project A",
		IssueTitle:         "Outdated package",
		Severity:           "high",
		Status:             model.FindingAwaitingFix,
		CreatedAt:          time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
		DisregardIfFixable: true,
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	// The user manually moved the issue from Backlog to Todo despite the
	// finding still being awaiting-fix. The sync must respect this.
	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:            "existing-1",
				Identifier:    "SEC-1",
				Title:         desired.Title,
				Description:   desired.Description,
				DueDate:       "", // awaiting-fix has no due date
				StateName:     "Todo",
				Fingerprint:   finding.Fingerprint,
				Priority:      desired.Priority,
				ManagedLabels: desired.ManagedLabels,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Todo state should be preserved even when finding is awaiting fix)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

// TestRunDoesNotPreserveTerminalStates verifies that a terminal (Done) ticket
// is never reopened when Snyk reports the finding as open. Instead of updating
// the closed ticket back to an open state, the sync creates a new ticket. This
// is the reopen guard: Snyk reusing a problem-type issueID is not a directive
// to reopen a closed Linear ticket.
func TestRunDoesNotPreserveTerminalStates(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	cfg.Linear.States.Done = "Done"
	cfg.Linear.States.Cancelled = "Cancelled"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Done", // terminal state — must not be reopened
				Fingerprint: finding.Fingerprint,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// A new ticket should be created, not an update to the closed one.
	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1 (should create new ticket, not reopen Done)", result.PlannedCreates)
	}
	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (must not reopen terminal ticket)", result.PlannedUpdates)
	}
}

// TestRunPreservesNonTerminalStateWithOtherFieldChanges verifies that when
// PreserveState is set due to a non-terminal state override, an update that
// changes OTHER fields (like title) still omits stateId from the mutation
// so the user's state choice is preserved.
func TestRunPreservesNonTerminalStateWithOtherFieldChanges(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "New title from Snyk",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "Stale title", // different from desired
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Todo", // user moved to Todo — should be preserved
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (title changed, state preserved)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	// The state should be preserved as Todo via PreserveState.
	// The user moved the issue to Todo; the sync should not override it
	// back to the configured open state (Triage).
	if linear.updated[0].State != model.StateTodo {
		t.Fatalf("updated state = %q, want %q (Todo state should be preserved when other fields change)", linear.updated[0].State, model.StateTodo)
	}
}

// TestRunNonTerminalOverrideDoesNotFireWhenStateMatchesConfig verifies that
// PreserveState is NOT set when the existing state already matches the
// configured state for the desired model state. This prevents the sync from
// unnecessarily adding ":preserve" to the Snyk hash.
func TestRunNonTerminalOverrideDoesNotFireWhenStateMatchesConfig(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Outdated package",
		Severity:    "high",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Triage", // matches configured Todo state
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (no override needed when state matches config)", result.PlannedUpdates)
	}
}

func TestRunSkipsCommentsForResolve(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:            "existing-1",
				Identifier:    "SEC-1",
				Title:         "resolved issue",
				Description:   "old description\n\u003c!-- snyk-linear-sync\nfingerprint: snyk:project-z:issue-9\n--\u003e",
				StateName:     "Todo",
				Fingerprint:   "snyk:project-z:issue-9",
				ManagedLabels: []string{"snyk-automation"},
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.comments) != 0 {
		t.Fatalf("comments = %d, want 0 (no comments for resolve)", len(linear.comments))
	}
}

// TestRunAwaitingFixToOpenRecalculatesDueDateFromFixAvailability verifies that
// when a Snyk finding transitions from awaiting-fix to open (fix became
// available), the due date is recalculated from today instead of the
// original created_at — because the old SLA date is meaningless when the
// team couldn't act on the issue while no fix existed.
func TestRunAwaitingFixToOpenRecalculatesDueDateFromFixAvailability(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	cfg.Linear.Labels.AwaitingFix = "triage-dependency"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "XSS in postcss",
		IssueType:   "package_vulnerability",
		Severity:    "high",
		Status:      model.FindingOpen,                                      // fix is now available
		CreatedAt:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC), // months ago
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:            "existing-1",
				Identifier:    "SEC-1",
				Title:         "Snyk: [high] XSS in postcss",
				Description:   "old body\n<!-- snyk-linear-sync\nfingerprint: snyk:project-a:issue-1\nmanaged_labels: snyk-automation,triage-dependency\n-->",
				DueDate:       "",        // was cleared for awaiting-fix
				StateName:     "Backlog", // was in Backlog for awaiting-fix
				Fingerprint:   finding.Fingerprint,
				Priority:      2,
				ManagedLabels: []string{"snyk-automation", "triage-dependency"}, // had the awaiting-fix label
				Labels:        []model.IssueLabel{{ID: "l1", Name: "snyk-automation"}, {ID: "l2", Name: "triage-dependency"}},
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	updated := linear.updated[0]

	// Due date should be calculated from today + 30 days (high severity SLA),
	// NOT from 2026-01-01 + 30 days (which would give 2026-01-31, a meaningless
	// past date for an issue that was blocked for months).
	expectedDueDate := time.Now().AddDate(0, 0, 30)
	expectedStr := time.Date(expectedDueDate.Year(), expectedDueDate.Month(), expectedDueDate.Day(), 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
	if updated.DueDate != expectedStr {
		t.Fatalf("updated due date = %q, want %q (SLA from fix availability, not from months-old created_at)", updated.DueDate, expectedStr)
	}

	// The triage-dependency label should be removed.
	for _, label := range updated.ManagedLabels {
		if label == "triage-dependency" {
			t.Fatalf("updated managed labels should not contain triage-dependency after fix is available: %v", updated.ManagedLabels)
		}
	}
}

// TestRunDoesNotReopenTerminalTicketForCoarseFingerprint reproduces the
// SNYK-6582 bug: a Done ticket with the old coarse fingerprint
// snyk:project:issue is matched when Snyk re-reports the same issue ID as
// open. The reopen guard must prevent reusing the closed ticket and instead
// create a fresh one.
func TestRunDoesNotReopenTerminalTicketForCoarseFingerprint(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Done = "Done"
	cfg.Linear.States.Cancelled = "Cancelled"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Path traversal",
		Severity:    "low",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SNYK-6582",
				Title:       "Snyk: [low] Path traversal",
				Description: "old description",
				StateName:   "Done",
				Fingerprint: "snyk:project-a:issue-1",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// A new ticket should be created, not an update to the closed one.
	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1 (should create new ticket for reopened finding)", result.PlannedCreates)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (must not reopen terminal ticket)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0 (must not send update for Done ticket)", len(linear.updated))
	}

	// The created ticket should carry the same fingerprint as the finding.
	if linear.created[0].Fingerprint != finding.Fingerprint {
		t.Fatalf("created fingerprint = %q, want %q", linear.created[0].Fingerprint, finding.Fingerprint)
	}
}

// TestRunDoesNotReopenTerminalTicketForFineGrainedFingerprint tests the case
// where Snyk starts reporting a fine-grained fingerprint (with location key)
// for an issue whose old coarse-fingerprint ticket is Done. The closed ticket
// must not be matched via the coarse fallback, and a new ticket must be created.
func TestRunDoesNotReopenTerminalTicketForFineGrainedFingerprint(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Done = "Done"
	cfg.Linear.States.Cancelled = "Cancelled"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1:e2e/prerequisite_gate.py",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Path traversal",
		Severity:    "low",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SNYK-6582",
				Title:       "Snyk: [low] Path traversal",
				Description: "old description",
				StateName:   "Done",
				Fingerprint: "snyk:project-a:issue-1", // old coarse fingerprint
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1 (should create new ticket for new code occurrence)", result.PlannedCreates)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (must not match terminal ticket via coarse fallback)", result.PlannedUpdates)
	}
	// The old Done ticket may be resolved (no-op update keeping it Done),
	// but it must not be reopened. Verify no update changed its state to
	// non-terminal.
	for _, u := range linear.updated {
		if u.State == model.StateTodo || u.State == model.StateBacklog {
			t.Fatalf("terminal ticket was reopened: state=%s", u.State)
		}
	}
}

// TestRunMigratesCoarseFingerprintForNonTerminalTicket tests the migration
// path: a non-terminal ticket with the old coarse fingerprint is updated
// (not duplicated) when Snyk starts reporting a fine-grained fingerprint.
func TestRunMigratesCoarseFingerprintForNonTerminalTicket(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Todo"
	cfg.Linear.States.Done = "Done"
	cfg.Linear.States.Cancelled = "Cancelled"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint: "snyk:project-a:issue-1:e2e/prerequisite_gate.py",
		SnykIssueID: "issue-1",
		ProjectID:   "project-a",
		ProjectName: "Project A",
		IssueTitle:  "Path traversal",
		Severity:    "low",
		Status:      model.FindingOpen,
		CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   []model.Finding{finding},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SNYK-100",
				Title:       "Snyk: [low] Path traversal",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1", // old coarse fingerprint
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Should update the existing non-terminal ticket, not create a duplicate.
	if result.PlannedCreates != 0 {
		t.Fatalf("PlannedCreates = %d, want 0 (should migrate, not duplicate)", result.PlannedCreates)
	}
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (should update existing ticket with new fingerprint)", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if len(linear.created) != 0 {
		t.Fatalf("created = %d, want 0", len(linear.created))
	}
}

// TestRunMigratesCoarseFingerprintForMultipleFindings verifies that when
// Snyk reports multiple fine-grained findings sharing a coarse prefix and a
// single non-terminal coarse ticket exists, only the first finding migrates
// (updates the existing ticket). The rest create fresh tickets. This prevents
// a race where multiple findings all bind to the same Linear issue.
func TestRunMigratesCoarseFingerprintForMultipleFindings(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	findings := []model.Finding{
		{
			Fingerprint: "snyk:project-a:issue-1:src/fileA.py",
			SnykIssueID: "issue-1",
			ProjectID:   "project-a",
			ProjectName: "Project A",
			IssueTitle:  "Path traversal",
			Severity:    "low",
			Status:      model.FindingOpen,
			CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
		},
		{
			Fingerprint: "snyk:project-a:issue-1:src/fileB.py",
			SnykIssueID: "issue-1",
			ProjectID:   "project-a",
			ProjectName: "Project A",
			IssueTitle:  "Path traversal",
			Severity:    "low",
			Status:      model.FindingOpen,
			CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
		},
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   findings,
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SNYK-100",
				Title:       "Snyk: [low] Path traversal",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1", // old coarse fingerprint
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// One finding migrates (updates the existing ticket), the other creates
	// a fresh ticket. Both must not update the same Linear issue.
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (only first finding migrates)", result.PlannedUpdates)
	}
	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1 (second finding creates new ticket)", result.PlannedCreates)
	}

	// Verify no two updates target the same existing issue.
	// (fakeLinear.updated is []DesiredIssue; duplicates would mean the same
	// coarse ticket was matched twice, which the deplete-on-match prevents.)
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want exactly 1 (no duplicate updates)", len(linear.updated))
	}
}

// TestRunDoesNotStealFineGrainedTicketViaCoarseFallback verifies that a
// fine-grained ticket (3-segment fingerprint) is never used as a coarse-
// fallback match for a DIFFERENT finding sharing the same coarse prefix.
// Without this guard, the fileA finding would steal the fileB ticket via
// the coarse index, causing perpetual fingerprint churn.
func TestRunDoesNotStealFineGrainedTicketViaCoarseFallback(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	findings := []model.Finding{
		{
			Fingerprint: "snyk:project-a:issue-1:src/fileA.py",
			SnykIssueID: "issue-1",
			ProjectID:   "project-a",
			ProjectName: "Project A",
			IssueTitle:  "Path traversal",
			Severity:    "low",
			Status:      model.FindingOpen,
			CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
		},
		{
			Fingerprint: "snyk:project-a:issue-1:src/fileB.py",
			SnykIssueID: "issue-1",
			ProjectID:   "project-a",
			ProjectName: "Project A",
			IssueTitle:  "Path traversal",
			Severity:    "low",
			Status:      model.FindingOpen,
			CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
		},
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   findings,
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}
	// Linear already has a fine-grained ticket for fileB (e.g. from a prior
	// migration or creation). fileA has no ticket yet.
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SNYK-100",
				Title:       "Snyk: [low] Path traversal",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1:src/fileB.py",
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// fileB finding updates its exact-match ticket. fileA finding must NOT
	// steal the fileB ticket via coarse fallback — it should create a new one.
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (only fileB updates its ticket)", result.PlannedUpdates)
	}
	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1 (fileA creates new ticket, not steal fileB's)", result.PlannedCreates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1 (no ticket stealing)", len(linear.updated))
	}
}

// TestRunDoesNotReopenArchivedTicket verifies that an archived Linear ticket
// is treated as terminal — the sync creates a new ticket instead of trying
// to reopen or update the archived one. Without this, auto-archiving would
// make closed tickets invisible and the sync would create duplicates.
func TestRunDoesNotReopenArchivedTicket(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	findings := []model.Finding{
		{
			Fingerprint: "snyk:project-a:issue-1:src/file.py",
			SnykIssueID: "issue-1",
			ProjectID:   "project-a",
			ProjectName: "Project A",
			IssueTitle:  "Path traversal",
			Severity:    "low",
			Status:      model.FindingOpen,
			CreatedAt:   time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
		},
	}

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   findings,
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	archivedAt := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "archived-1",
				Identifier:  "SNYK-999",
				Title:       "Snyk: [low] Path traversal",
				Description: "old description",
				StateName:   "Done",
				Fingerprint: "snyk:project-a:issue-1:src/file.py",
				ArchivedAt:  &archivedAt,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// The archived ticket must NOT be reopened or updated. A new ticket
	// should be created instead.
	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (archived ticket must not be updated)", result.PlannedUpdates)
	}
	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1 (new ticket for finding with archived match)", result.PlannedCreates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0 (archived ticket untouched)", len(linear.updated))
	}
}

// TestRunSkipsArchivedTicketInResolveLoop verifies that archived tickets are
// not included in the resolve batch — Linear doesn't allow updating archived
// issues, so trying to resolve them would produce API errors.
func TestRunSkipsArchivedTicketInResolveLoop(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// No findings — the sync should try to resolve all existing tickets.
	// The archived ticket must be skipped.
	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings:   nil,
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	archivedAt := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "open-1",
				Identifier:  "SNYK-100",
				Title:       "Snyk: [low] Some issue",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-2",
			},
			{
				ID:          "archived-1",
				Identifier:  "SNYK-101",
				Title:       "Snyk: [low] Old issue",
				StateName:   "Done",
				Fingerprint: "snyk:project-a:issue-3",
				ArchivedAt:  &archivedAt,
			},
		},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// The open ticket should be resolved (no matching finding). The archived
	// ticket should be skipped — not resolved, not updated.
	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1 (only the non-archived ticket)", result.PlannedResolves)
	}
}

// TestIsTerminalLinearStateArchived verifies that isTerminalLinearState
// returns true for archived tickets regardless of their workflow state name.
func TestIsTerminalLinearStateArchived(t *testing.T) {
	states := config.StateConfig{Done: "Done", Cancelled: "Cancelled"}
	archivedAt := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)

	// Archived + non-terminal state name → still terminal
	archived := model.ExistingIssue{StateName: "Todo", ArchivedAt: &archivedAt}
	if !isTerminalLinearState(archived, states) {
		t.Fatal("archived ticket with Todo state should be terminal")
	}

	// Not archived + terminal state name → terminal
	done := model.ExistingIssue{StateName: "Done"}
	if !isTerminalLinearState(done, states) {
		t.Fatal("non-archived Done ticket should be terminal")
	}

	// Not archived + non-terminal state name → not terminal
	open := model.ExistingIssue{StateName: "Todo"}
	if isTerminalLinearState(open, states) {
		t.Fatal("non-archived Todo ticket should not be terminal")
	}
}

// TestRunBatchCreatePartialFailureRetriesOnlyFailedIssue verifies that when
// CreateIssues reports a partial failure (one alias failed, siblings
// succeeded), only the failed issue is retried individually. Retrying the
// whole batch — the old behavior — recreated the already-created siblings,
// producing duplicate tickets.
func TestRunBatchCreatePartialFailureRetriesOnlyFailedIssue(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "First finding",
					Severity:    "high",
					Status:      model.FindingOpen,
					CreatedAt:   time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
				{
					Fingerprint: "snyk:project-a:issue-2",
					SnykIssueID: "issue-2",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Second finding",
					Severity:    "high",
					Status:      model.FindingOpen,
					CreatedAt:   time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	linear := &fakeLinear{
		// The first CreateIssues call containing issue-2 reports it as
		// failed (success: false alias) while issue-1 succeeds.
		createFailFingerprints: map[string]int{"snyk:project-a:issue-2": 1},
	}

	service := New(cfg, logger, snyk, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	counts := map[string]int{}
	for _, d := range linear.created {
		counts[d.Fingerprint]++
	}
	if counts["snyk:project-a:issue-1"] != 1 {
		t.Fatalf("issue-1 created %d times, want exactly 1 (batch-sibling must not be recreated on partial failure)", counts["snyk:project-a:issue-1"])
	}
	if counts["snyk:project-a:issue-2"] != 1 {
		t.Fatalf("issue-2 created %d times, want exactly 1 (failed item retried individually)", counts["snyk:project-a:issue-2"])
	}

	if len(linear.createCallBatches) != 2 {
		t.Fatalf("CreateIssues calls = %d, want 2 (initial batch + single-item retry)", len(linear.createCallBatches))
	}
	retry := linear.createCallBatches[1]
	if len(retry) != 1 || retry[0].Fingerprint != "snyk:project-a:issue-2" {
		t.Fatalf("retry batch = %+v, want only the failed issue-2", retry)
	}

	if result.FailedOps != 0 {
		t.Fatalf("FailedOps = %d, want 0 (the individual retry succeeded)", result.FailedOps)
	}
}

// TestRunBatchCommentPartialFailureRetriesOnlyFailedComment is the
// PostComments equivalent: a partial comment failure must only re-post the
// failed comment. Re-posting comments that already landed leaves duplicate
// change-summary comments (and duplicate notifications) on the issue.
func TestRunBatchCommentPartialFailureRetriesOnlyFailedComment(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.CommentsEnabled = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snyk := fakeSnyk{
		snapshot: model.SnykSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint: "snyk:project-a:issue-1",
					SnykIssueID: "issue-1",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Updated title one",
					Severity:    "high",
					Status:      model.FindingOpen,
					CreatedAt:   time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
				{
					Fingerprint: "snyk:project-a:issue-2",
					SnykIssueID: "issue-2",
					ProjectID:   "project-a",
					ProjectName: "Project A",
					IssueTitle:  "Updated title two",
					Severity:    "high",
					Status:      model.FindingOpen,
					CreatedAt:   time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			ProjectIDs: map[string]struct{}{"project-a": {}},
		},
	}

	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title one",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-1",
				Priority:    3,
			},
			{
				ID:          "existing-2",
				Identifier:  "SEC-2",
				Title:       "stale title two",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk:project-a:issue-2",
				Priority:    3,
			},
		},
		commentFailFingerprints: map[string]int{"snyk:project-a:issue-2": 1},
	}

	service := New(cfg, logger, snyk, linear, nil)
	if _, err := service.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	counts := map[string]int{}
	for _, u := range linear.comments {
		counts[u.Desired.Fingerprint]++
	}
	if counts["snyk:project-a:issue-1"] != 1 {
		t.Fatalf("issue-1 commented %d times, want exactly 1 (batch-sibling comment must not be re-posted)", counts["snyk:project-a:issue-1"])
	}
	if counts["snyk:project-a:issue-2"] != 1 {
		t.Fatalf("issue-2 commented %d times, want exactly 1 (failed comment retried individually)", counts["snyk:project-a:issue-2"])
	}

	if len(linear.commentCallBatches) != 2 {
		t.Fatalf("PostComments calls = %d, want 2 (initial batch + single-item retry)", len(linear.commentCallBatches))
	}
	retry := linear.commentCallBatches[1]
	if len(retry) != 1 || retry[0].Desired.Fingerprint != "snyk:project-a:issue-2" {
		t.Fatalf("comment retry batch = %+v, want only the failed issue-2 update", retry)
	}
}
