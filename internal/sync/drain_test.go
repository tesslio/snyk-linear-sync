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
func TestDrainDisappearedWorkRefuses(t *testing.T) {
	p, j := drainFixture(t, 1)
	prior := drainEmptyPending()
	prior.Generation = 8
	prior.Entries["issue:gone"] = DrainPendingEntry{1, []string{strings.Repeat("a", 64)}, 2}
	_, err := selectDrain(p, j, prior, drainDefaultLimits(), nil, nil)
	if err == nil || err.Error() != "drain-pending-lost" {
		t.Fatalf("disappeared work must refuse: %v", err)
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

func TestDrainEvidenceBoundCountsPendingWorkBeforeFingerprintCollapse(t *testing.T) {
	fp := "snyk:project-a:issue-a"
	digest := planTextDigest(fp)
	operations := make([]DrainOperation, drainEvidenceEntryCeiling+101)
	for i := range operations {
		operations[i] = DrainOperation{fmt.Sprintf("issue:%d", i), "cancel-duplicate", []string{digest}}
	}
	pre := map[string]string{fp: strings.Repeat("a", 64)}
	// Even the 100 selected effects can remain unverified, so the exact
	// admission ceiling applies to all work, not just deferred operations.
	if _, err := drainEvidenceBound(pre, nil, operations[:drainEvidenceEntryCeiling]); err != nil {
		t.Fatalf("ceiling rejected: %v", err)
	}
	for _, n := range []int{drainEvidenceEntryCeiling + 1, len(operations)} {
		if _, err := drainEvidenceBound(pre, nil, operations[:n]); err == nil {
			t.Fatalf("accepted %d potentially pending operations sharing one fingerprint", n)
		}
	}
}

func TestDrainEvidenceBoundIncludesPendingBytesOutsideKnownFingerprints(t *testing.T) {
	operations := make([]DrainOperation, 2000)
	for i := range operations {
		operations[i] = DrainOperation{fmt.Sprintf("issue:%04d", i) + strings.Repeat("x", drainFingerprintByteCeiling-10), "update", []string{strings.Repeat("a", 64)}}
	}
	if _, err := drainEvidenceBound(nil, nil, operations); err == nil {
		t.Fatal("oversized pending row omitted from preflight")
	}
}

func TestDrainCreateToIssueInheritsAgeAndCumulativeCounter(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		t.Run(fmt.Sprintf("deferred=%v", deferred), func(t *testing.T) {
			p, jobs := drainFixture(t, 3)
			key := "issue:" + p.Records[1].IssueID
			fp := p.Records[1].FingerprintSHA256
			oldFingerprint := "snyk:project-old:issue-a:location"
			oldFP := planTextDigest(oldFingerprint)
			jobs[1].updateBatch[0].Existing.Fingerprint = oldFingerprint
			p.Records[1].PreviousFingerprintSHA256 = oldFP
			p.DecisionsSHA256, _ = planDigest(p.Records)
			aliases := []string{fp, oldFP}
			slices.Sort(aliases)
			before := drainEmptyPending()
			before.Generation = 8
			before.Entries[key] = DrainPendingEntry{4, aliases, 1}
			before.Entries["create:"+fp] = DrainPendingEntry{2, []string{fp}, 2}
			before.Entries["create:"+oldFP] = DrainPendingEntry{3, []string{oldFP}, 1}
			limits := drainDefaultLimits()
			limits.MaxIssueChanges = 1
			if deferred {
				// Earlier independent work consumes the one-operation budget.
				before.Entries["issue:"+p.Records[2].IssueID] = DrainPendingEntry{1, []string{p.Records[2].FingerprintSHA256}, 0}
			}
			selection, err := selectDrain(p, jobs, before, limits, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if (selection.selected[0].WorkKey == key) == deferred {
				t.Fatalf("inherited age did not control selection: %+v", selection.selected)
			}
			after := finishDrainPending(selection, before, nil)
			entry := after.Entries[key]
			wantCount := 3
			if deferred {
				wantCount = 2
			}
			if entry.SinceGeneration != 2 || entry.UnverifiedGenerations != wantCount || !slices.Equal(entry.FingerprintSHA256s, aliases) {
				t.Fatalf("continuity lost: %+v", entry)
			}
			if _, retained := after.Entries["create:"+fp]; retained {
				t.Fatal("transferred create retained under its old key")
			}
			verified := finishDrainPending(selection, before, map[string]bool{key: true})
			_, remains := verified.Entries[key]
			if remains != deferred {
				t.Fatal("verification removed deferred work or retained selected work")
			}
			if !deferred {
				_, err = selectDrain(p, jobs, after, drainDefaultLimits(), nil, nil)
				if err == nil || err.Error() != "drain-stalled-effect" {
					t.Fatalf("transferred counter failed to stall: %v", err)
				}
			}
		})
	}
}

func TestDrainPendingAliasesCannotDischargeOtherIssue(t *testing.T) {
	for _, test := range []string{"missing-issue", "narrowed-issue", "missing-create"} {
		t.Run(test, func(t *testing.T) {
			p, jobs := drainFixture(t, 3)
			before := drainEmptyPending()
			before.Generation = 5
			shared := p.Records[2].FingerprintSHA256
			switch test {
			case "missing-issue":
				before.Entries["issue:gone"] = DrainPendingEntry{1, []string{shared}, 1}
			case "narrowed-issue":
				// Another issue still covers the lost alias, but is not its owner.
				before.Entries["issue:"+p.Records[1].IssueID] = DrainPendingEntry{1, []string{p.Records[1].FingerprintSHA256, shared}, 1}
			case "missing-create":
				missing := planTextDigest("snyk:project-missing:issue-missing")
				before.Entries["create:"+missing] = DrainPendingEntry{1, []string{missing}, 1}
			}
			_, err := selectDrain(p, jobs, before, drainDefaultLimits(), nil, nil)
			if err == nil || err.Error() != "drain-pending-lost" {
				t.Fatalf("lost ownership accepted: %v", err)
			}
		})
	}
}

func TestDrainSharedIssueAliasDoesNotInheritOwnership(t *testing.T) {
	p, jobs := drainFixture(t, 3)
	jobs[1].updateBatch[0].Existing.Fingerprint = jobs[2].updateBatch[0].Desired.Fingerprint
	p.Records[1].PreviousFingerprintSHA256 = p.Records[2].FingerprintSHA256
	p.DecisionsSHA256, _ = planDigest(p.Records)
	before := drainEmptyPending()
	before.Generation = 5
	before.Entries["issue:"+p.Records[2].IssueID] = DrainPendingEntry{1, []string{p.Records[2].FingerprintSHA256}, 2}
	selection, err := selectDrain(p, jobs, before, drainDefaultLimits(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	after := finishDrainPending(selection, before, nil)
	entry := after.Entries["issue:"+p.Records[1].IssueID]
	if entry.SinceGeneration != 6 || entry.UnverifiedGenerations != 1 {
		t.Fatalf("unrelated issue ownership inherited: %+v", entry)
	}
}

func TestDrainStalledWorkRefusesBeforeSelection(t *testing.T) {
	for _, keyKind := range []string{"issue", "create", "missing"} {
		t.Run(keyKind, func(t *testing.T) {
			p, jobs := drainFixture(t, 3)
			before := drainEmptyPending()
			before.Generation = 5
			before.Entries["issue:"+p.Records[2].IssueID] = DrainPendingEntry{1, []string{p.Records[2].FingerprintSHA256}, 0}
			key := "issue:" + p.Records[1].IssueID
			if keyKind == "create" {
				key = "create:" + p.Records[1].FingerprintSHA256
			} else if keyKind == "missing" {
				key = "issue:gone"
			}
			before.Entries[key] = DrainPendingEntry{2, []string{p.Records[1].FingerprintSHA256}, 3}
			limits := drainDefaultLimits()
			limits.MaxIssueChanges = 1
			_, err := selectDrain(p, jobs, before, limits, nil, nil)
			if err == nil || err.Error() != "drain-stalled-effect" {
				t.Fatalf("stalled pending work accepted: %v", err)
			}
		})
	}
}

func TestDrainCreateToNewIssueRetainsPendingHistory(t *testing.T) {
	p, jobs := drainFixture(t, 2)
	before := drainEmptyPending()
	before.Generation = 8
	fp := p.Records[1].FingerprintSHA256
	before.Entries["create:"+fp] = DrainPendingEntry{2, []string{fp}, 2}
	limits := drainDefaultLimits()
	limits.MaxIssueChanges = 1
	selection, err := selectDrain(p, jobs, before, limits, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := "issue:" + p.Records[1].IssueID
	if selection.selected[0].WorkKey != key {
		t.Fatal("create history was not transferred to new issue")
	}
	after := finishDrainPending(selection, before, nil)
	if entry := after.Entries[key]; entry.SinceGeneration != 2 || entry.UnverifiedGenerations != 3 {
		t.Fatalf("create history lost: %+v", entry)
	}
}

func TestDrainInheritedPendingUsesMaxNotSum(t *testing.T) {
	a, b := planTextDigest("alias-a"), planTextDigest("alias-b")
	for _, counts := range [][3]int{{2, 1, 0}, {0, 2, 1}, {1, 0, 2}, {1, 1, 1}} {
		before := DrainPending{Version: drainVersion, Generation: 8, Entries: map[string]DrainPendingEntry{
			"issue:one":   {4, []string{a, b}, counts[0]},
			"create:" + a: {2, []string{a}, counts[1]},
			"create:" + b: {3, []string{b}, counts[2]},
		}}
		entry := drainInheritedPending(DrainOperation{"issue:one", "update", []string{a, b}}, before)
		if entry.SinceGeneration != 2 || entry.UnverifiedGenerations != max(counts[0], counts[1], counts[2]) {
			t.Fatalf("incorrect merge for %v: %+v", counts, entry)
		}
	}
}
