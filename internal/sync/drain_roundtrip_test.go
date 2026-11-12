package sync

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// This exercises the ordinary-update loss mode: after the first partial slice,
// the saved Snyk hashes already equal the next run's unchanged source hashes.
// Saving refreshed Linear hashes for deferred issues would then hide that work.
func TestDrainNormalUpdatesSurviveSQLiteGenerations(t *testing.T) {
	const count = 201
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "drain.db")
	states := config.StateConfig{Todo: "Todo", Done: "Done", Cancelled: "Cancelled"}
	current := make([]model.ExistingIssue, count)
	desired := make([]model.DesiredIssue, count)
	sourceHashes := map[string]string{}
	initialSource := map[string]string{}
	for i := range count {
		fp := fmt.Sprintf("snyk:project-a:issue-%04d:location", i)
		current[i] = model.ExistingIssue{ID: fmt.Sprintf("issue-%04d", i), Fingerprint: fp, Title: "Snyk: previous title", StateName: "Todo"}
		desired[i] = model.DesiredIssue{Fingerprint: fp, Title: "Snyk: updated title", State: model.StateTodo}
		// The desired source is fixed for all three runs. Only the generation-zero
		// checkpoint predates that source change.
		sourceHashes[fp] = planTextDigest("new-source:" + fp)
		initialSource[fp] = planTextDigest("old-source:" + fp)
	}
	originalSource := maps.Clone(sourceHashes)
	digest := func(value any) string {
		t.Helper()
		got, err := drainDigest(value)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	encode := func(value any) []byte {
		t.Helper()
		got, err := canonicalDrainJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	pending := drainEmptyPending()
	pre := drainPreWriteHashes(current, nil)
	initialEvidence := DrainHashEvidence{Version: drainVersion, Generation: 0, ProducerRunID: "init-run", ProducerRunAttempt: 1, Refreshed: maps.Clone(pre), PreWrite: maps.Clone(pre), Withheld: map[string]DrainWithheld{}, Initialization: &DrainInitialization{SourceCacheKey: "source-cache", SourceCacheSHA256: planTextDigest("source-cache-bytes"), V2ProducerRunID: "source-run", AuthorizingRunID: "init-run"}}
	initial := cache.Snapshot{SchemaSignature: managedSchemaSignature() + "+drain-v1", SnykHashes: initialSource, LinearHashes: pre, BoundedDrainPending: encode(pending), BoundedDrainHashEvidence: encode(initialEvidence)}
	if _, _, err := validateDrainSnapshot(initial); err != nil {
		t.Fatal(err)
	}
	store, err := cache.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, initial); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	mutationCount := map[string]int{}
	selectedCounts := []int{}
	for generation := int64(1); generation <= 3; generation++ {
		store, err = cache.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := store.Load(ctx)
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		pending, _, err = validateDrainSnapshot(loaded)
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		if pending.Generation != generation-1 {
			t.Fatalf("restored generation %d", pending.Generation)
		}
		for _, entry := range pending.Entries {
			if entry.SinceGeneration != 1 {
				t.Fatalf("pending age reset after reopen: %+v", entry)
			}
		}
		plan := &ReconciliationPlan{Version: 2, Complete: true, ReopenHistoryStatus: "not_needed", Records: []PlanRecord{}, Inputs: PlanInputs{SnykSHA256: digest(sourceHashes), LinearSHA256: digest(current), SettingsSHA256: digest(states), SyncCacheSHA256: digest(loaded)}}
		jobs := []job{}
		for i, e := range current {
			sourceHit := loaded.SnykHashes[e.Fingerprint] == sourceHashes[e.Fingerprint]
			linearHit := loaded.LinearHashes[e.Fingerprint] == existingIssueHash(e)
			_, stillPending := pending.Entries["issue:"+e.ID]
			if generation > 1 && !sourceHit {
				t.Fatal("source changed between drain runs")
			}
			if stillPending && linearHit {
				t.Fatalf("deferred normal update became paired cache hit: %s", e.ID)
			}
			if sourceHit && linearHit {
				if needsUpdate(e, desired[i], states) {
					t.Fatalf("cache hit concealed update: %s", e.ID)
				}
				continue
			}
			if !needsUpdate(e, desired[i], states) {
				t.Fatalf("unexpected cache miss for completed update: %s", e.ID)
			}
			jobs = append(jobs, job{kind: jobUpdate, updateBatch: []model.IssueUpdate{{Existing: e, Desired: desired[i]}}})
			plan.Records = append(plan.Records, PlanRecord{Action: "update", IssueID: e.ID, CandidatePresent: true, MutationPlanned: true, ExecutionStatus: "not_attempted", FingerprintSHA256: planTextDigest(e.Fingerprint), State: PlanState{ProposedModel: model.StateName(desired[i].State)}})
			plan.Summary.Updates++
		}
		plan.DecisionsSHA256, err = planDigest(plan.Records)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := selectDrain(plan, jobs, pending, drainDefaultLimits(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		selectedCounts = append(selectedCounts, len(selection.selected))
		before := append([]model.ExistingIssue(nil), current...)
		pre = drainPreWriteHashes(before, nil)
		selectedIDs := map[string]bool{}
		for _, batch := range selection.jobs {
			if batch.kind != jobUpdate || len(batch.updateBatch) > 10 || len(batch.desiredBatch) != 0 {
				t.Fatal("expected bounded normal-update batch")
			}
			for _, update := range batch.updateBatch {
				selectedIDs[update.Existing.ID] = true
			}
		}
		for i := range current {
			if selectedIDs[current[i].ID] {
				current[i].Title = desired[i].Title
				mutationCount[current[i].ID]++
			}
		}
		for i := range current {
			if !selectedIDs[current[i].ID] && !reflect.DeepEqual(current[i], before[i]) {
				t.Fatal("mutated unselected issue")
			}
		}
		verified := verifyDrainEffects(selection.jobs, nil, before, current, states)
		for _, op := range selection.selected {
			if !verified[op.WorkKey] {
				t.Fatalf("selected effect not verified: %s", op.WorkKey)
			}
		}
		afterPending := finishDrainPending(selection, pending, verified)
		for _, entry := range afterPending.Entries {
			if entry.SinceGeneration != 1 || entry.UnverifiedGenerations != 0 {
				t.Fatalf("deferred update lost age: %+v", entry)
			}
		}
		evidence, saved, arrivals, err := buildDrainEvidence(pre, drainPreWriteHashes(current, nil), selection.selected, selection.deferred, selection.jobs, verified)
		if err != nil {
			t.Fatal(err)
		}
		if len(arrivals) != 0 || len(evidence.Withheld) != len(selection.deferred) {
			t.Fatal("incorrect withheld partition")
		}
		evidence.Generation = generation
		evidence.ProducerRunID = fmt.Sprintf("run-%d", generation)
		evidence.ProducerRunAttempt = 1
		evidence.FullPlanSHA256 = digest(plan)
		evidence.SelectedOpsSHA256 = digest(selection.selected)
		evidence.DeferredOpsSHA256 = digest(selection.deferred)
		evidence.SettingsSHA256 = plan.Inputs.SettingsSHA256
		evidence.PendingAfterSHA256 = digest(afterPending)
		next := cache.Snapshot{SchemaSignature: initial.SchemaSignature, SnykHashes: maps.Clone(sourceHashes), LinearHashes: saved, BoundedDrainPending: encode(afterPending), BoundedDrainHashEvidence: encode(evidence)}
		if _, _, err := validateDrainSnapshot(next); err != nil {
			t.Fatal(err)
		}
		if err := store.Save(ctx, next); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(sourceHashes, originalSource) {
			t.Fatal("source changed")
		}
	}
	if !reflect.DeepEqual(selectedCounts, []int{100, 100, 1}) {
		t.Fatalf("selected counts = %v", selectedCounts)
	}
	store, err = cache.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	final, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pending, _, err = validateDrainSnapshot(final)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Generation != 3 || len(pending.Entries) != 0 || len(final.LinearHashes) != count {
		t.Fatal("drain did not finish")
	}
	for i, e := range current {
		if mutationCount[e.ID] != 1 || needsUpdate(e, desired[i], states) {
			t.Fatalf("issue %s not reconciled exactly once", e.ID)
		}
		if final.SnykHashes[e.Fingerprint] != sourceHashes[e.Fingerprint] || final.LinearHashes[e.Fingerprint] != existingIssueHash(e) {
			t.Fatalf("completed issue %s not cached", e.ID)
		}
	}
}
