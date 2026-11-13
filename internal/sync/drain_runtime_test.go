package sync

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

type runtimeDrainLinear struct {
	fakeLinear
	reads           int
	mutations       int
	noEffect        bool
	uncertainCreate bool
	commentError    bool
	refreshError    bool
	unknownCreate   bool
	beforeWrite     func()
}

func (l *runtimeDrainLinear) LoadSnapshot(context.Context) ([]model.ExistingIssue, error) {
	l.reads++
	if l.refreshError && l.reads%2 == 0 {
		return nil, errors.New("synthetic refresh failure")
	}
	return slices.Clone(l.snapshot), nil
}
func (l *runtimeDrainLinear) UpdateIssues(ctx context.Context, updates []model.IssueUpdate) error {
	if l.beforeWrite != nil {
		l.beforeWrite()
	}
	l.mutations += len(updates)
	if l.noEffect {
		return nil
	}
	for _, u := range updates {
		for i, e := range l.snapshot {
			if e.ID == u.Existing.ID {
				state := e.StateName
				if !u.Desired.PreserveState {
					state = map[model.IssueState]string{model.StateTodo: "Todo", model.StateDone: "Done", model.StateCancelled: "Cancelled", model.StateBacklog: "Backlog"}[u.Desired.State]
				}
				next := storedIssue(e.ID, e.Identifier, state, u.Desired)
				next.StateID = e.StateID
				l.snapshot[i] = next
			}
		}
	}
	return l.fakeLinear.UpdateIssues(ctx, updates)
}
func (l *runtimeDrainLinear) CreateIssues(ctx context.Context, desired []model.DesiredIssue) ([]model.CreateOutcome, error) {
	if l.beforeWrite != nil {
		l.beforeWrite()
	}
	l.mutations += len(desired)
	if l.unknownCreate {
		return nil, errors.New("synthetic missing create response")
	}
	out, err := l.fakeLinear.CreateIssues(ctx, desired)
	for i, d := range desired {
		l.snapshot = append(l.snapshot, storedIssue(out[i].ID, "SNYK-100", "Todo", d))
	}
	if l.uncertainCreate {
		return out, errors.New("synthetic uncertain create")
	}
	return out, err
}
func (l *runtimeDrainLinear) PostComments(ctx context.Context, updates []model.IssueUpdate) ([]int, error) {
	if l.commentError {
		return nil, errors.New("synthetic uncertain comment")
	}
	return l.fakeLinear.PostComments(ctx, updates)
}

func runtimeDrainCfg(t *testing.T, prior cache.Snapshot, run int) config.Config {
	t.Helper()
	cfg := boundCfg(t)
	cfg.PlanAndExecuteBound = false
	cfg.PlanAndExecuteDrain = true
	cfg.Linear.Labels = config.LabelConfig{}
	cfg.Linear.UnsubscribeActor = false
	cfg.Cache.DBFile = "synthetic.db"
	n := int64(100)
	cfg.MaxIssueChanges = &n
	cfg.DrainRunID = fmt.Sprint(run)
	cfg.DrainRunAttempt = 1
	cfg.DrainPriorEvidenceSHA256 = planTextDigest(string(prior.BoundedDrainHashEvidence))
	cfg.DrainPriorPendingSHA256 = planTextDigest(string(prior.BoundedDrainPending))
	var err error
	cfg.ExpectedSettingsSHA256, err = PlanSettingsSHA256(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
func runtimeInitial(t *testing.T, issues []model.ExistingIssue) cache.Snapshot {
	t.Helper()
	pre := drainPreWriteHashes(issues, nil)
	p := drainEmptyPending()
	e := DrainHashEvidence{Version: 1, Generation: 0, ProducerRunID: "100", ProducerRunAttempt: 1, Refreshed: pre, PreWrite: pre, Withheld: map[string]DrainWithheld{}, Initialization: &DrainInitialization{SourceCacheKey: "synthetic-v2-cache", SourceCacheSHA256: planTextDigest("source"), V2ProducerRunID: "99", AuthorizingRunID: "100"}}
	pb, err := canonicalDrainJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	eb, err := canonicalDrainJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	return cache.Snapshot{SchemaSignature: managedSchemaSignature() + "+drain-v1", SnykHashes: map[string]string{}, LinearHashes: pre, BoundedDrainPending: pb, BoundedDrainHashEvidence: eb}
}
func runtimeFixture(t *testing.T, n int) ([]model.Finding, *runtimeDrainLinear, cache.Snapshot) {
	t.Helper()
	cfg := minimalCfg()
	findings := []model.Finding{}
	l := &runtimeDrainLinear{}
	for i := range n {
		f := planFixtureFinding(fmt.Sprintf("issue-%04d", i))
		findings = append(findings, f)
		e := storedIssue(fmt.Sprintf("ticket-%04d", i), fmt.Sprintf("SNYK-%d", i+100), "Todo", desiredIssue(cfg, f))
		e.Title = "previous title"
		e.StateID = "todo-state"
		l.snapshot = append(l.snapshot, e)
	}
	return findings, l, runtimeInitial(t, l.snapshot)
}

func TestDrainRuntimeRealPlannerAcrossSQLiteGenerations(t *testing.T) {
	findings, l, initial := runtimeFixture(t, 201)
	path := filepath.Join(t.TempDir(), "cache.db")
	db, err := cache.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Save(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	selected := []int{}
	for generation := 1; generation <= 3; generation++ {
		prior, err := db.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		cfg := runtimeDrainCfg(t, prior, 100+generation)
		cfg.Cache.DBFile = path
		l.beforeWrite = func() {
			a := readBound[DrainAttempt](t, cfg, "attempt.json")
			if a.Status != "attempt_started" || a.Generation != int64(generation) {
				t.Fatal("write before durable attempt")
			}
		}
		source := &planSnyk{snapshot: planSnapshot(findings...)}
		_, err = New(cfg, discardLogger(), source, l, db).Run(t.Context())
		if err != nil {
			t.Fatalf("generation %d: %v", generation, err)
		}
		r := readBound[DrainResult](t, cfg, "result.json")
		selected = append(selected, len(r.Verified))
		if r.CacheStatus != "saved" || len(r.Unverified) > 0 || source.calls != 1 {
			t.Fatalf("bad result: %+v", r)
		}
		next, err := db.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		p, _, err := validateDrainSnapshot(next)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Entries) != max(201-generation*100, 0) {
			t.Fatalf("pending %d", len(p.Entries))
		}
	}
	if !slices.Equal(selected, []int{100, 100, 1}) || l.mutations != 201 || l.reads != 6 {
		t.Fatalf("selected=%v mutations=%d reads=%d", selected, l.mutations, l.reads)
	}
	// A fourth unchanged generation is a no-op, not another mutation or a reset.
	prior, _ := db.Load(t.Context())
	cfg := runtimeDrainCfg(t, prior, 104)
	l.beforeWrite = nil
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, db).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	r := readBound[DrainResult](t, cfg, "result.json")
	if r.BatchesAttempted != 0 || r.LinearWritesAttempted || l.mutations != 201 {
		t.Fatal("unchanged generation wrote")
	}
}

func TestDrainRuntimeStallCheckpointIsDurable(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 1)
	l.noEffect = true
	for generation := 1; generation <= 3; generation++ {
		cfg := runtimeDrainCfg(t, prior, 100+generation)
		store := &fakeCache{snapshot: prior, ignoreRows: true}
		_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context())
		if err == nil {
			t.Fatal("unverified effect accepted")
		}
		r := readBound[DrainResult](t, cfg, "result.json")
		if r.CacheStatus != "saved" || r.Status != "partial_or_uncertain" {
			t.Fatalf("lost checkpoint: %+v", r)
		}
		prior = store.saved
		p, _, err := validateDrainSnapshot(prior)
		if err != nil || p.Entries["issue:ticket-0000"].UnverifiedGenerations != generation {
			t.Fatalf("lost stall: %v %+v", err, p)
		}
	}
	cfg := runtimeDrainCfg(t, prior, 104)
	source := &planSnyk{snapshot: planSnapshot(findings...)}
	_, err := New(cfg, discardLogger(), source, l, &fakeCache{snapshot: prior, ignoreRows: true}).Run(t.Context())
	if err == nil || source.calls != 0 || l.mutations != 3 {
		t.Fatal("stalled state dispatched")
	}
}

func TestDrainRuntimePriorMismatchBeforeSources(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 1)
	cfg := runtimeDrainCfg(t, prior, 101)
	cfg.DrainPriorEvidenceSHA256 = planTextDigest("wrong")
	source := &planSnyk{snapshot: planSnapshot(findings...)}
	if _, err := New(cfg, discardLogger(), source, l, &fakeCache{snapshot: prior}).Run(t.Context()); err == nil || source.calls != 0 || l.reads != 0 {
		t.Fatal("invalid prior loaded sources")
	}
}

func TestDrainRuntimeRefreshFailureLeavesPriorCheckpoint(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 1)
	l.refreshError = true
	cfg := runtimeDrainCfg(t, prior, 101)
	store := &fakeCache{snapshot: prior, ignoreRows: true}
	_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context())
	if err == nil || store.saved.SchemaSignature != "" {
		t.Fatal("refresh failure saved")
	}
	r := readBound[DrainResult](t, cfg, "result.json")
	if r.CacheStatus != "refresh_failed_or_uncertain" {
		t.Fatal(r.CacheStatus)
	}
}

func TestDrainRuntimeReceiptTamperingPreventsDispatch(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 11)
	cfg := runtimeDrainCfg(t, prior, 101)
	l.beforeWrite = func() {
		if err := os.WriteFile(cfg.PlanJSON, []byte("tampered"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store := &fakeCache{snapshot: prior, ignoreRows: true}
	_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context())
	if err == nil || l.mutations != 10 || store.saved.SchemaSignature != "" {
		t.Fatal("tampering allowed next batch")
	}
}

func TestDrainRuntimeUncertainCreateDoesNotRetryAndResumesOnlyRemaining(t *testing.T) {
	seed := planFixtureFinding("seed")
	cfg0 := minimalCfg()
	l := &runtimeDrainLinear{uncertainCreate: true}
	l.snapshot = []model.ExistingIssue{storedIssue("seed-ticket", "SNYK-100", "Todo", desiredIssue(cfg0, seed))}
	prior := runtimeInitial(t, l.snapshot)
	findings := []model.Finding{seed}
	for i := range 11 {
		findings = append(findings, planFixtureFinding(fmt.Sprintf("new-%03d", i)))
	}
	cfg := runtimeDrainCfg(t, prior, 101)
	store := &fakeCache{snapshot: prior, ignoreRows: true}
	_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context())
	if err == nil {
		t.Fatal("uncertain create returned success")
	}
	r := readBound[DrainResult](t, cfg, "result.json")
	if r.CacheStatus != "saved" || r.BatchesAttempted != 1 || len(r.Created) != 10 || len(r.Verified) != 10 || len(r.Unverified) != 1 || len(l.createCallBatches) != 1 {
		t.Fatalf("wrong uncertain result: %+v", r)
	}
	prior = store.saved
	cfg = runtimeDrainCfg(t, prior, 102)
	store = &fakeCache{snapshot: prior, ignoreRows: true}
	l.uncertainCreate = false
	if _, err = New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(l.createCallBatches) != 2 || len(l.createCallBatches[1]) != 1 || len(l.created) != 11 {
		t.Fatal("repeated acknowledged creates")
	}
}

func TestDrainRuntimeCommentsAreSeparatelyCountedAndNeverRetried(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 11)
	cfg := runtimeDrainCfg(t, prior, 101)
	cfg.Linear.CommentsEnabled = true
	cfg.ExpectedSettingsSHA256, _ = PlanSettingsSHA256(cfg)
	l.commentError = true
	store := &fakeCache{snapshot: prior, ignoreRows: true}
	_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context())
	if err == nil {
		t.Fatal("uncertain comment returned success")
	}
	r := readBound[DrainResult](t, cfg, "result.json")
	if r.CacheStatus != "saved" || r.BatchesAttempted != 1 || r.BatchesAcknowledged != 1 || r.AuxiliaryComments.BatchesAttempted != 1 || r.AuxiliaryComments.BatchesAcknowledged != 0 || l.mutations != 10 {
		t.Fatalf("auxiliary accounting %+v", r)
	}
}

func TestDrainRuntimeOldPendingWinsAgainstNewArrival(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 2)
	cfg := runtimeDrainCfg(t, prior, 101)
	one := int64(1)
	cfg.MaxIssueChanges = &one
	store := &fakeCache{snapshot: prior, ignoreRows: true}
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	p, _, err := validateDrainSnapshot(store.saved)
	if err != nil || len(p.Entries) != 1 {
		t.Fatalf("pending: %+v %v", p, err)
	}
	var old string
	for k := range p.Entries {
		old = k
	}
	// A lexically earlier new arrival cannot displace restored pending work.
	arrival := planFixtureFinding("aaa-new")
	findings = append(findings, arrival)
	cfg = runtimeDrainCfg(t, store.saved, 102)
	cfg.MaxIssueChanges = &one
	store = &fakeCache{snapshot: store.saved, ignoreRows: true}
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	a := readBound[DrainAttempt](t, cfg, "attempt.json")
	if len(a.Selected) != 1 || a.Selected[0].WorkKey != old {
		t.Fatalf("old work starved: %+v", a.Selected)
	}
	r := readBound[DrainResult](t, cfg, "result.json")
	if !drainSortedUnique(r.Verified) || !drainSortedUnique(r.Unverified) {
		t.Fatal("noncanonical receipt partition")
	}
}

type runtimeFailSave struct{ fakeCache }

func (f *runtimeFailSave) Save(context.Context, cache.Snapshot) error {
	return errors.New("synthetic save failure")
}

func TestDrainRuntimeSaveFailureDoesNotClaimCheckpoint(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 1)
	cfg := runtimeDrainCfg(t, prior, 101)
	store := &runtimeFailSave{fakeCache{snapshot: prior, ignoreRows: true}}
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context()); err == nil {
		t.Fatal("save failure ignored")
	}
	r := readBound[DrainResult](t, cfg, "result.json")
	if r.CacheStatus != "save_failed_or_uncertain" || r.Status != "partial_or_uncertain" {
		t.Fatalf("wrong failure result: %+v", r)
	}
}

func TestDrainRuntimeCancellationStopsNextBatchAndCheckpoint(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 11)
	cfg := runtimeDrainCfg(t, prior, 101)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	l.beforeWrite = cancel
	store := &fakeCache{snapshot: prior, ignoreRows: true}
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(ctx); err == nil {
		t.Fatal("cancellation ignored")
	}
	if l.mutations != 10 || store.saved.SchemaSignature != "" {
		t.Fatal("continued after cancellation")
	}
}

func TestDrainRuntimeUnknownCreateRequiresReconciliation(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 1)
	findings = append(findings, planFixtureFinding("new-unknown"))
	l.unknownCreate = true
	cfg := runtimeDrainCfg(t, prior, 101)
	store := &fakeCache{snapshot: prior, ignoreRows: true}
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context()); err == nil {
		t.Fatal("unknown create accepted")
	}
	r := readBound[DrainResult](t, cfg, "result.json")
	if r.CacheStatus != "not_saved" || r.BatchesAttempted != 1 || store.saved.SchemaSignature != "" || l.reads != 1 {
		t.Fatalf("uncertain create advanced: %+v", r)
	}
}

func TestDrainRuntimeOneBudgetAcrossCreatesAndUpdates(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 50)
	for i := range 51 {
		findings = append(findings, planFixtureFinding(fmt.Sprintf("new-%03d", i)))
	}
	cfg := runtimeDrainCfg(t, prior, 101)
	store := &fakeCache{snapshot: prior, ignoreRows: true}
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	a := readBound[DrainAttempt](t, cfg, "attempt.json")
	if a.SelectedCounts.Creates == 0 || a.SelectedCounts.Updates == 0 || a.SelectedCounts.Creates+a.SelectedCounts.Updates != 100 || l.mutations != 100 {
		t.Fatalf("not a shared budget: %+v", a.SelectedCounts)
	}
	cfg = runtimeDrainCfg(t, store.saved, 102)
	store = &fakeCache{snapshot: store.saved, ignoreRows: true}
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	a = readBound[DrainAttempt](t, cfg, "attempt.json")
	if len(a.Selected) != 1 || l.mutations != 101 || len(l.created) != 51 {
		t.Fatal("remaining mixed work not drained exactly once")
	}
}

func TestDrainRuntimeUnverifiedCommentedUpdateCannotAdvance(t *testing.T) {
	findings, l, prior := runtimeFixture(t, 1)
	cfg := runtimeDrainCfg(t, prior, 101)
	cfg.Linear.CommentsEnabled = true
	cfg.ExpectedSettingsSHA256, _ = PlanSettingsSHA256(cfg)
	l.noEffect, l.commentError = true, true
	store := &fakeCache{snapshot: prior, ignoreRows: true}
	if _, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(findings...)}, l, store).Run(t.Context()); err == nil {
		t.Fatal("uncertain comment accepted")
	}
	r := readBound[DrainResult](t, cfg, "result.json")
	if r.CacheStatus == "saved" || store.saved.SchemaSignature != "" || r.AuxiliaryComments.BatchesAttempted != 1 {
		t.Fatal("unverified commented update can replay")
	}
}
