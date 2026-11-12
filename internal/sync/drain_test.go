package sync

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/model"
)

func drainFixture(t *testing.T, n int) (*ReconciliationPlan, []job) {
	t.Helper()
	digest := strings.Repeat("a", 64)
	p := &ReconciliationPlan{Version: 2, Complete: true, ReopenHistoryStatus: "not_needed", Records: []PlanRecord{}, Inputs: PlanInputs{SnykSHA256: digest, LinearSHA256: digest, SettingsSHA256: digest, SyncCacheSHA256: digest}}
	jobs := []job{}
	for i := range n {
		kind := []jobKind{jobCreateBatch, jobUpdate, jobResolve, jobCancelDuplicate}[i%4]
		fp := fmt.Sprintf("snyk:project-a:issue-%04d:location", i)
		d := model.DesiredIssue{Fingerprint: fp, Title: "Snyk: example", State: model.StateTodo}
		e := model.ExistingIssue{ID: fmt.Sprintf("issue-%04d", i), Fingerprint: fp}
		r := PlanRecord{Action: string(kind), CandidatePresent: true, MutationPlanned: true, ExecutionStatus: "not_attempted", FingerprintSHA256: planTextDigest(fp), State: PlanState{ProposedModel: model.StateName(d.State)}}
		j := job{kind: kind}
		if kind == jobCreateBatch {
			j.desiredBatch = []model.DesiredIssue{d}
			p.Summary.Creates++
		} else {
			j.updateBatch = []model.IssueUpdate{{Existing: e, Desired: d}}
			r.IssueID = e.ID
			switch kind {
			case jobUpdate:
				p.Summary.Updates++
			case jobResolve:
				p.Summary.Resolves++
			case jobCancelDuplicate:
				p.Summary.CancelDuplicates++
			}
		}
		p.Records = append(p.Records, r)
		jobs = append(jobs, j)
	}
	p.DecisionsSHA256, _ = planDigest(p.Records)
	return p, jobs
}
func drainDefaultLimits() DrainLimits { return DrainLimits{100, 100, 100, 100, 100} }
func drainEmptyPending() DrainPending {
	return DrainPending{Version: 1, Entries: map[string]DrainPendingEntry{}}
}

func TestDrainMixedBudgetBoundaries(t *testing.T) {
	for _, n := range []int{99, 100, 101} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			p, j := drainFixture(t, n)
			got, err := selectDrain(p, j, drainEmptyPending(), drainDefaultLimits(), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := min(n, 100)
			if len(got.selected) != want || len(got.deferred) != n-want {
				t.Fatalf("partition %d/%d", len(got.selected), len(got.deferred))
			}
			for _, b := range got.jobs {
				if len(b.desiredBatch)+len(b.updateBatch) > 10 {
					t.Fatal("oversized batch")
				}
			}
		})
	}
}
func TestDrainOldestPendingSurvivesNewArrival(t *testing.T) {
	p, j := drainFixture(t, 101)
	before := drainEmptyPending()
	before.Generation = 5
	key := "issue:issue-0099"
	before.Entries[key] = DrainPendingEntry{1, []string{p.Records[99].FingerprintSHA256}, 0}
	limits := drainDefaultLimits()
	limits.MaxIssueChanges = 1
	// Other groups are also one operation; age, not action or lexical key, wins.
	got, err := selectDrain(p, j, before, limits, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.selected[0].WorkKey != key {
		t.Fatal(got.selected)
	}
	for _, entry := range got.pending.Entries {
		if entry.SinceGeneration != 6 {
			t.Fatal("new work age incorrect")
		}
	}
}
func TestDrainDuplicateTargetRefuses(t *testing.T) {
	p, j := drainFixture(t, 4)
	j[2].updateBatch[0].Existing.ID = j[1].updateBatch[0].Existing.ID
	p.Records[2].IssueID = p.Records[1].IssueID
	p.DecisionsSHA256, _ = planDigest(p.Records)
	_, err := selectDrain(p, j, drainEmptyPending(), drainDefaultLimits(), nil, nil)
	if err == nil || err.Error() != "duplicate-target" {
		t.Fatal(err)
	}
}
func TestDrainDuplicateGroupNeverSplits(t *testing.T) {
	p, j := drainFixture(t, 4)
	canonical := map[string]model.ExistingIssue{j[3].updateBatch[0].Existing.Fingerprint: j[1].updateBatch[0].Existing}
	limits := drainDefaultLimits()
	limits.MaxIssueChanges = 1
	_, err := selectDrain(p, j, drainEmptyPending(), limits, nil, canonical)
	if err == nil || err.Error() != "drain-oversized-group" {
		t.Fatal(err)
	}
}
func TestDrainPartitionDeterministic(t *testing.T) {
	p, j := drainFixture(t, 101)
	a, err := selectDrain(p, j, drainEmptyPending(), drainDefaultLimits(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(j)
	b, err := selectDrain(p, j, drainEmptyPending(), drainDefaultLimits(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := drainDigest(a.selected)
	y, _ := drainDigest(b.selected)
	if x != y {
		t.Fatal("source ordering changed partition")
	}
}
func TestDrainDeferredAndDriftNeverBecomeCacheHits(t *testing.T) {
	pre := map[string]string{"normal": "old", "drift": "old"}
	fresh := map[string]string{"normal": "new", "drift": "new", "arrival": "new"}
	deferred := []DrainOperation{{"issue:one", "update", []string{planTextDigest("normal")}}}
	evidence, saved, arrivals, err := buildDrainEvidence(pre, fresh, nil, deferred, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 0 || len(evidence.Withheld) != 2 || len(arrivals) != 1 {
		t.Fatal("hash conservation failed")
	}
	if evidence.Withheld["normal"].Reason != "deferred" || evidence.Withheld["drift"].Reason != "drift" {
		t.Fatal(evidence)
	}
	if _, ok := evidence.Refreshed["arrival"]; ok {
		t.Fatal("arrival retained")
	}
}
func TestDrainSharedFingerprintRemainsWithheld(t *testing.T) {
	fp := "snyk:project-a:issue-a"
	digest := planTextDigest(fp)
	selected := []DrainOperation{{"issue:one", "update", []string{digest}}}
	deferred := []DrainOperation{{"issue:two", "update", []string{digest}}}
	e, s, _, err := buildDrainEvidence(map[string]string{fp: "old"}, map[string]string{fp: "new"}, selected, deferred, nil, map[string]bool{"issue:one": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 0 || len(e.Withheld[fp].WorkKeys) != 1 {
		t.Fatal("verified alias released deferred alias")
	}
}
func TestDrainCanonicalJSON(t *testing.T) {
	data, err := canonicalDrainJSON(DrainPending{Version: 1, Generation: 2, Entries: map[string]DrainPendingEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"entries":{},"generation":2,"version":1}` {
		t.Fatal(string(data))
	}
}
func TestDrainEvidenceBoundRefusesLongFingerprint(t *testing.T) {
	_, err := drainEvidenceBound(map[string]string{strings.Repeat("a", drainFingerprintByteCeiling+1): "hash"}, nil, nil)
	if err == nil {
		t.Fatal("oversized key admitted")
	}
}

func TestDrainRepeatedUnverifiedRetainsAgeAndStalls(t *testing.T) {
	p, j := drainFixture(t, 1)
	before := drainEmptyPending()
	for generation := int64(1); generation <= 3; generation++ {
		selected, err := selectDrain(p, j, before, drainDefaultLimits(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		before = finishDrainPending(selected, before, map[string]bool{})
		for _, entry := range before.Entries {
			if entry.SinceGeneration != 1 || entry.UnverifiedGenerations != int(generation) {
				t.Fatal(entry)
			}
		}
	}
	_, err := selectDrain(p, j, before, drainDefaultLimits(), nil, nil)
	if err == nil || err.Error() != "drain-stalled-effect" {
		t.Fatal(err)
	}
}
func TestDrainDisappearedWorkDoesNotRetainAge(t *testing.T) {
	p, j := drainFixture(t, 1)
	prior := drainEmptyPending()
	prior.Generation = 8
	prior.Entries["issue:gone"] = DrainPendingEntry{1, []string{strings.Repeat("a", 64)}, 2}
	selected, err := selectDrain(p, j, prior, drainDefaultLimits(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	after := finishDrainPending(selected, prior, map[string]bool{})
	if _, ok := after.Entries["issue:gone"]; ok {
		t.Fatal("disappeared work retained")
	}
	for _, entry := range after.Entries {
		if entry.SinceGeneration != 9 {
			t.Fatal(entry)
		}
	}
}

func TestDrainRebindLinksOnlySameNonemptyIdentity(t *testing.T) {
	p, j := drainFixture(t, 2)
	a := planFixtureFinding("issue-a")
	b := a
	b.ProjectID = "project-b"
	// Both findings retain the project-independent identity while the durable
	// source fingerprint changes across project recreation.
	a.Fingerprint = j[0].desiredBatch[0].Fingerprint
	b.Fingerprint = j[1].updateBatch[0].Desired.Fingerprint
	if model.FindingIdentity(a) == "" || model.FindingIdentity(a) != model.FindingIdentity(b) {
		t.Fatal("fixture identity")
	}
	p.Records[1].Match = "identity-rebind"
	p.DecisionsSHA256, _ = planDigest(p.Records)
	limit := drainDefaultLimits()
	limit.MaxIssueChanges = 1
	_, err := selectDrain(p, j, drainEmptyPending(), limit, []model.Finding{a, b}, nil)
	if err == nil || err.Error() != "drain-oversized-group" {
		t.Fatal(err)
	}
	b.ProjectClusterUnknown = true
	got, err := selectDrain(p, j, drainEmptyPending(), limit, []model.Finding{a, b}, nil)
	if err != nil || len(got.selected) != 1 {
		t.Fatalf("empty identity invented dependency: %v", err)
	}
}
func TestDrainPerKindCeilingAppliesToSelectedOnly(t *testing.T) {
	p, j := drainFixture(t, 100)
	limits := drainDefaultLimits()
	limits.MaxUpdates = 1
	got, err := selectDrain(p, j, drainEmptyPending(), limits, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	updates := 0
	for _, op := range got.selected {
		if op.Kind == "update" {
			updates++
		}
	}
	if updates != 1 || len(got.selected) != 76 || len(got.deferred) != 24 {
		t.Fatal("per-kind partition mismatch")
	}
}
