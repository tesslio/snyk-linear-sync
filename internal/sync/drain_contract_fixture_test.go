package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// These are wire fixtures, not proof of an authentic GitHub producer. Consumers
// must authenticate the artifact provenance outside this pure parser boundary.
type drainWireRow struct {
	Pending  string            `json:"pending"`
	Evidence string            `json:"evidence"`
	Linear   map[string]string `json:"linear"`
}
type drainWireReceipts struct {
	Attempt string `json:"attempt"`
	Result  string `json:"result"`
	Plan    string `json:"plan"`
}
type drainWireFixture struct {
	Name     string            `json:"name"`
	Valid    bool              `json:"valid"`
	Reason   string            `json:"reason"`
	Row      drainWireRow      `json:"row"`
	Receipts drainWireReceipts `json:"receipts"`
	Restored *drainWireFixture `json:"restored,omitempty"`
}

func wireEncode(t *testing.T, value any) string {
	t.Helper()
	data, err := canonicalDrainJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func wireDigest(t *testing.T, value any) string {
	t.Helper()
	return planTextDigest(wireEncode(t, value))
}
func wireKeySet(t *testing.T, hashes map[string]string) DrainKeySet {
	t.Helper()
	keys := []string{}
	for key := range hashes {
		keys = append(keys, planTextDigest(key))
	}
	slices.Sort(keys)
	return DrainKeySet{Count: len(keys), SHA256: wireDigest(t, keys)}
}
func wireWithheldSet(t *testing.T, w map[string]DrainWithheld) DrainKeySet {
	hashes := map[string]string{}
	for key := range w {
		hashes[key] = ""
	}
	return wireKeySet(t, hashes)
}
func wireRow(t *testing.T, p DrainPending, e DrainHashEvidence, saved map[string]string) drainWireRow {
	t.Helper()
	row := drainWireRow{wireEncode(t, p), wireEncode(t, e), saved}
	snapshot := cache.Snapshot{SchemaSignature: managedSchemaSignature() + "+drain-v1", LinearHashes: saved, BoundedDrainPending: []byte(row.Pending), BoundedDrainHashEvidence: []byte(row.Evidence)}
	if _, _, err := validateDrainSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	return row
}
func wireInitialization(t *testing.T, pre map[string]string) drainWireFixture {
	t.Helper()
	pending := drainEmptyPending()
	init := DrainInitialization{"source-cache-v2-100-1", planTextDigest("synthetic source cache"), "100", "101"}
	evidence := DrainHashEvidence{Version: 1, ProducerRunID: "101", ProducerRunAttempt: 1, Refreshed: maps.Clone(pre), PreWrite: maps.Clone(pre), Withheld: map[string]DrainWithheld{}, Initialization: &init}
	attempt := DrainInitializationAttempt{Version: 2, Kind: "initialization", Status: "initialization_started", StartedAt: "2026-01-01T00:00:00Z", ProducerRunID: "101", ProducerRunAttempt: 1, Initialization: init}
	result := DrainInitializationResult{Version: 2, Kind: "initialization", Status: "success", FinishedAt: "2026-01-01T00:00:01Z", ProducerRunID: "101", ProducerRunAttempt: 1, InitializationAttemptSHA256: wireDigest(t, attempt), PendingAfterSHA256: wireDigest(t, pending), HashEvidenceSHA256: wireDigest(t, evidence), CacheStatus: "saved", Refreshed: wireKeySet(t, pre), Saved: wireKeySet(t, pre), Withheld: wireKeySet(t, nil), Arrivals: wireKeySet(t, nil)}
	return drainWireFixture{Name: "generation-zero", Valid: true, Reason: "distinct initialization receipt variant; no plan or jobs placeholders", Row: wireRow(t, pending, evidence, maps.Clone(pre)), Receipts: drainWireReceipts{wireEncode(t, attempt), wireEncode(t, result), ""}}
}
func wireNormal(t *testing.T, name string, mixed, absent bool) drainWireFixture {
	t.Helper()
	fp := "snyk:project-a:issue-1"
	other := "snyk:project-a:issue-2"
	drift := "snyk:project-a:issue-drift"
	// Exercises Go HTML and Unicode escapes in a canonical map key.
	escaped := "snyk:project-a:<>&\u2028\u2029"
	pre := map[string]string{fp: planTextDigest("old"), other: planTextDigest("old-other"), drift: planTextDigest("old-drift"), escaped: planTextDigest("old-escaped")}
	initial := wireInitialization(t, pre)
	p, jobs := drainFixture(t, 0)
	count := 1
	if mixed {
		count = 3
	}
	for i := 0; i < count; i++ {
		fingerprint := fp
		if i == 1 {
			fingerprint = other
		}
		id := fmt.Sprintf("issue-%d", i)
		d := model.DesiredIssue{Fingerprint: fingerprint, Title: "Snyk: example", State: model.StateTodo}
		e := model.ExistingIssue{ID: id, Fingerprint: fingerprint, Title: "old"}
		jobs = append(jobs, job{kind: jobUpdate, updateBatch: []model.IssueUpdate{{Existing: e, Desired: d}}})
		p.Records = append(p.Records, PlanRecord{Action: "update", CandidatePresent: true, MutationPlanned: true, ExecutionStatus: "not_attempted", FingerprintSHA256: planTextDigest(fingerprint), IssueID: id, State: PlanState{ProposedModel: model.StateName(d.State)}})
		p.Summary.Updates++
	}
	p.DecisionsSHA256, _ = planDigest(p.Records)
	limits := drainDefaultLimits()
	if mixed {
		limits.MaxIssueChanges = 2
	}
	before := drainEmptyPending()
	selection, err := selectDrain(p, jobs, before, limits, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := drainPlanOperations(p)
	if err != nil {
		t.Fatal(err)
	}
	partition := append(slices.Clone(selection.selected), selection.deferred...)
	slices.SortFunc(partition, func(a, b DrainOperation) int { return strings.Compare(a.WorkKey, b.WorkKey) })
	if !reflect.DeepEqual(ops, partition) {
		t.Fatal("plan projection differs from selected/deferred partition")
	}
	if _, err := drainEvidenceBound(pre, jobs, ops); err != nil {
		t.Fatal(err)
	}
	verified := map[string]bool{}
	if !mixed {
		verified[selection.selected[0].WorkKey] = true
	}
	refreshed := maps.Clone(pre)
	if name == "arrival-excluded" {
		refreshed["snyk:project-a:arrival"] = planTextDigest("concurrent arrival")
	}
	refreshed[fp] = planTextDigest("new")
	if mixed {
		refreshed[drift] = planTextDigest("drifted")
		refreshed[escaped] = planTextDigest("drifted-escaped")
	}
	if absent {
		delete(refreshed, other)
	}
	evidence, saved, arrivals, err := buildDrainEvidence(pre, refreshed, selection.selected, selection.deferred, selection.jobs, verified)
	if err != nil {
		t.Fatal(err)
	}
	pending := finishDrainPending(selection, before, verified)
	// Keep the retained full plan's native field order. Consumers hash these
	// exact bytes and derive operations from its mutation-planned records.
	planBytes, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	planBytes = append(planBytes, '\n')
	full := planTextDigest(string(planBytes))
	jobsDigest, err := boundJobsDigest(selection.jobs)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Generation = 1
	evidence.ProducerRunID = "102"
	evidence.ProducerRunAttempt = 1
	evidence.FullPlanSHA256 = full
	evidence.SelectedOpsSHA256 = wireDigest(t, selection.selected)
	evidence.DeferredOpsSHA256 = wireDigest(t, selection.deferred)
	evidence.SettingsSHA256 = p.Inputs.SettingsSHA256
	evidence.PendingAfterSHA256 = wireDigest(t, pending)
	attempt := DrainAttempt{Version: 2, Status: "attempt_started", StartedAt: "2026-01-01T01:00:00Z", ProducerRunID: "102", ProducerRunAttempt: 1, Generation: 1, RestoredHashEvidenceSHA256: planTextDigest(initial.Row.Evidence), FullPlanSHA256: full, JobsSHA256: jobsDigest, SelectedOpsSHA256: evidence.SelectedOpsSHA256, DeferredOpsSHA256: evidence.DeferredOpsSHA256, SettingsSHA256: evidence.SettingsSHA256, PendingBeforeSHA256: planTextDigest(initial.Row.Pending), FullCounts: DrainCounts{Updates: int64(count)}, SelectedCounts: DrainCounts{Updates: int64(len(selection.selected))}, DeferredCounts: DrainCounts{Updates: int64(len(selection.deferred))}, Limits: limits, Selected: selection.selected, Deferred: selection.deferred, Batches: len(selection.jobs)}
	good, bad := []string{}, []string{}
	for _, op := range selection.selected {
		if verified[op.WorkKey] {
			good = append(good, op.WorkKey)
		} else {
			bad = append(bad, op.WorkKey)
		}
	}
	status := "success"
	if mixed {
		status = "partial_or_uncertain"
	}
	result := DrainResult{Version: 2, Status: status, FinishedAt: "2026-01-01T01:00:01Z", ProducerRunID: "102", ProducerRunAttempt: 1, Generation: 1, FullPlanSHA256: full, JobsSHA256: jobsDigest, SelectedOpsSHA256: evidence.SelectedOpsSHA256, DeferredOpsSHA256: evidence.DeferredOpsSHA256, SettingsSHA256: evidence.SettingsSHA256, PendingAfterSHA256: evidence.PendingAfterSHA256, HashEvidenceSHA256: wireDigest(t, evidence), LinearWritesAttempted: true, BatchesAttempted: len(selection.jobs), BatchesAcknowledged: len(selection.jobs), CacheStatus: "saved", Verified: good, Unverified: bad, Refreshed: wireKeySet(t, evidence.Refreshed), Withheld: wireWithheldSet(t, evidence.Withheld), Saved: wireKeySet(t, saved), Arrivals: DrainKeySet{len(arrivals), wireDigest(t, arrivals)}, Created: map[string]string{}, AuxiliaryComments: DrainAuxiliaryComments{Policy: "disabled"}}
	return drainWireFixture{Name: name, Valid: true, Reason: "real full plan, selected/deferred partition, and exact producer receipt bindings", Row: wireRow(t, pending, evidence, saved), Receipts: drainWireReceipts{wireEncode(t, attempt), wireEncode(t, result), string(planBytes)}, Restored: &initial}
}
func TestDrainProducerWireFixtures(t *testing.T) {
	pre := map[string]string{"snyk:project-a:issue-1": planTextDigest("old")}
	fixtures := []drainWireFixture{wireInitialization(t, pre), wireNormal(t, "successful-update", false, false), wireNormal(t, "mixed-withholding-empty-saved", true, false), wireNormal(t, "missing-refreshed-prewrite-key", false, true), wireNormal(t, "arrival-excluded", false, false)}
	for name, change := range map[string]func(map[string]any){
		"negative-empty-refreshed":     func(e map[string]any) { e["refreshed"] = map[string]string{} },
		"negative-number-run-id":       func(e map[string]any) { e["producer_run_id"] = 101 },
		"negative-leading-zero-run-id": func(e map[string]any) { e["producer_run_id"] = "0101" },
		"negative-withheld-outside-refreshed": func(e map[string]any) {
			e["withheld"] = map[string]DrainWithheld{"absent": {Reason: "drift", WorkKeys: []string{}}}
		},
	} {
		bad := wireInitialization(t, pre)
		bad.Name = name
		bad.Valid = false
		bad.Reason = "must refuse malformed row even when supplied with authentic producer bytes"
		var e map[string]any
		if err := json.Unmarshal([]byte(bad.Row.Evidence), &e); err != nil {
			t.Fatal(err)
		}
		change(e)
		bad.Row.Evidence = wireEncode(t, e)
		snapshot := cache.Snapshot{SchemaSignature: managedSchemaSignature() + "+drain-v1", LinearHashes: bad.Row.Linear, BoundedDrainPending: []byte(bad.Row.Pending), BoundedDrainHashEvidence: []byte(bad.Row.Evidence)}
		if _, _, err := validateDrainSnapshot(snapshot); err == nil {
			t.Fatal("negative row admitted:", name)
		}
		fixtures = append(fixtures, bad)
	}
	for _, fixture := range fixtures {
		data := []byte(wireEncode(t, fixture) + "\n")
		path := filepath.Join("testdata", "drain-v1", fixture.Name+".json")
		if os.Getenv("UPDATE_DRAIN_FIXTURES") == "1" {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0644); err != nil {
				t.Fatal(err)
			}
		}
		current, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v; regenerate with UPDATE_DRAIN_FIXTURES=1", path, err)
		}
		if !bytes.Equal(current, data) {
			t.Fatalf("stale producer fixture %s", path)
		}
	}
}
func TestDrainRunIDAndIssueIDContract(t *testing.T) {
	for _, id := range []string{"", "0", "01", "-1", "+1", " 1", "1 ", "1.0", "1e2", "run-a", "１２", "123456789012345678901"} {
		if drainValidRunID(id) {
			t.Fatalf("accepted run ID %q", id)
		}
	}
	for _, id := range []string{"1", "9007199254740993", "12345678901234567890"} {
		if !drainValidRunID(id) {
			t.Fatalf("rejected decimal string %q", id)
		}
	}
	if !drainValidWorkKey("issue:"+strings.Repeat("a", 64)) || drainValidWorkKey("issue:"+strings.Repeat("a", 65)) {
		t.Fatal("issue ID bound mismatch")
	}
}

func TestDrainPlanProjectionBindsBothAliases(t *testing.T) {
	p, jobs := drainFixture(t, 2)
	old := "snyk:project-old:issue-a"
	jobs[1].updateBatch[0].Existing.Fingerprint = old
	// Missing old alias in the retained plan must refuse even when all other
	// job metadata matches. Otherwise the consumer validates a weaker partition.
	if _, err := selectDrain(p, jobs, drainEmptyPending(), drainDefaultLimits(), nil, nil); err == nil {
		t.Fatal("unbound prior alias accepted")
	}
	p.Records[1].PreviousFingerprintSHA256 = planTextDigest(old)
	p.DecisionsSHA256, _ = planDigest(p.Records)
	if _, err := selectDrain(p, jobs, drainEmptyPending(), drainDefaultLimits(), nil, nil); err != nil {
		t.Fatal(err)
	}
	ops, err := drainPlanOperations(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops[1].FingerprintSHA256s) != 2 {
		t.Fatal("missing previous alias")
	}
	p.Records[1].PreviousFingerprintSHA256 = p.Records[1].FingerprintSHA256
	p.DecisionsSHA256, _ = planDigest(p.Records)
	ops, err = drainPlanOperations(p)
	if err != nil || len(ops[1].FingerprintSHA256s) != 1 {
		t.Fatal("equal prior alias was not deduplicated", err)
	}
}
