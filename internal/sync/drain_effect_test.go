package sync

import (
	"github.com/tesslio/snyk-linear-sync/internal/model"
	"testing"
)

func TestVerifyDrainUpdateRequiresFreshEffect(t *testing.T) {
	cfg := minimalCfg()
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	stale := storedIssue("issue-1", "SNYK-1", cfg.Linear.States.Todo, desired)
	stale.Title = "Snyk: stale title"
	fresh := storedIssue("issue-1", "SNYK-1", cfg.Linear.States.Todo, desired)
	jobs := []job{{kind: jobUpdate, updateBatch: []model.IssueUpdate{{Existing: stale, Desired: desired}}}}
	key := drainWorkKey(jobUpdate, desired, stale)
	for _, tc := range []struct {
		name  string
		after []model.ExistingIssue
		want  bool
	}{
		{"stale acknowledged effect", []model.ExistingIssue{stale}, false},
		{"fresh effect", []model.ExistingIssue{fresh}, true},
		{"missing target", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyDrainEffects(jobs, nil, []model.ExistingIssue{stale}, tc.after, cfg.Linear.States)
			if got[key] != tc.want {
				t.Fatalf("verified=%v want %v", got, tc.want)
			}
		})
	}
}

func TestVerifyDrainCreateRequiresReturnedIDAndSafeCopies(t *testing.T) {
	cfg := minimalCfg()
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	fresh := storedIssue("created-1", "SNYK-2", cfg.Linear.States.Todo, desired)
	terminal := storedIssue("terminal-1", "SNYK-1", cfg.Linear.States.Done, desired)
	terminal.Title = "Snyk: retained terminal"
	drifted := terminal
	drifted.Title = "Snyk: terminal changed"
	openCopy := storedIssue("other-open", "SNYK-3", cfg.Linear.States.Todo, desired)
	wrongID := fresh
	wrongID.ID = "different-id"
	jobs := []job{{kind: jobCreateBatch, desiredBatch: []model.DesiredIssue{desired}}}
	key := drainWorkKey(jobCreateBatch, desired, model.ExistingIssue{})
	for _, tc := range []struct {
		name, id      string
		before, after []model.ExistingIssue
		want          bool
	}{
		{"missing returned ID", "", nil, []model.ExistingIssue{fresh}, false},
		{"exact returned ID", fresh.ID, nil, []model.ExistingIssue{fresh}, true},
		{"fingerprint cannot replace returned ID", fresh.ID, nil, []model.ExistingIssue{wrongID}, false},
		{"extra open copy", fresh.ID, []model.ExistingIssue{openCopy}, []model.ExistingIssue{fresh, openCopy}, false},
		{"unchanged retained terminal", fresh.ID, []model.ExistingIssue{terminal}, []model.ExistingIssue{fresh, terminal}, true},
		{"retained terminal drift", fresh.ID, []model.ExistingIssue{terminal}, []model.ExistingIssue{fresh, drifted}, false},
		{"new terminal copy", fresh.ID, nil, []model.ExistingIssue{fresh, terminal}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyDrainEffects(jobs, map[string]string{key: tc.id}, tc.before, tc.after, cfg.Linear.States)
			if got[key] != tc.want {
				t.Fatalf("verified=%v want %v", got, tc.want)
			}
		})
	}
}

func TestDrainPreWriteHashesCanonicalOverrideAndUnmatched(t *testing.T) {
	cfg := minimalCfg()
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	canonical := storedIssue("canonical", "SNYK-1", cfg.Linear.States.Todo, desired)
	duplicate := storedIssue("duplicate", "SNYK-2", cfg.Linear.States.Todo, desired)
	duplicate.Title = "Snyk: duplicate title"
	otherDesired := desiredIssue(cfg, planFixtureFinding("issue-2"))
	unmatched := storedIssue("unmatched", "SNYK-3", cfg.Linear.States.Todo, otherDesired)
	// The duplicate is intentionally last: the matched-ID override must win.
	got := drainPreWriteHashes([]model.ExistingIssue{canonical, unmatched, duplicate}, map[string]model.ExistingIssue{desired.Fingerprint: canonical})
	if len(got) != 2 || got[desired.Fingerprint] != existingIssueHash(canonical) || got[unmatched.Fingerprint] != existingIssueHash(unmatched) {
		t.Fatalf("wrong overridden map: %v", got)
	}
}

func TestDrainRefreshedHashesPrefersAcknowledgedCreateOverRetainedTerminal(t *testing.T) {
	cfg := minimalCfg()
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	fresh := storedIssue("created-1", "SNYK-2", cfg.Linear.States.Todo, desired)
	terminal := storedIssue("terminal-1", "SNYK-1", cfg.Linear.States.Done, desired)
	terminal.Title = "Snyk: retained terminal"
	jobs := []job{{kind: jobCreateBatch, desiredBatch: []model.DesiredIssue{desired}}}
	created := map[string]string{drainWorkKey(jobCreateBatch, desired, model.ExistingIssue{}): fresh.ID}
	got := drainRefreshedHashes([]model.ExistingIssue{fresh, terminal}, map[string]model.ExistingIssue{desired.Fingerprint: terminal}, jobs, created)
	if got[desired.Fingerprint] != existingIssueHash(fresh) {
		t.Fatalf("cached terminal instead of acknowledged created issue: %v", got)
	}
}

func TestDrainEffectStateVerificationDoesNotUsePlannerReopenSuppression(t *testing.T) {
	cfg := minimalCfg()
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	terminal := storedIssue("created-1", "SNYK-1", cfg.Linear.States.Done, desired)
	if needsUpdate(terminal, desired, cfg.Linear.States) {
		t.Fatal("fixture must exercise planner's terminal-to-open suppression")
	}
	for _, kind := range []jobKind{jobCreateBatch, jobUpdate} {
		j := job{kind: kind}
		key := drainWorkKey(kind, desired, terminal)
		if kind == jobCreateBatch {
			j.desiredBatch = []model.DesiredIssue{desired}
		} else {
			j.updateBatch = []model.IssueUpdate{{Existing: terminal, Desired: desired}}
		}
		got := verifyDrainEffects([]job{j}, map[string]string{key: terminal.ID}, nil, []model.ExistingIssue{terminal}, cfg.Linear.States)
		if got[key] {
			t.Fatalf("%s accepted terminal state for open desired effect", kind)
		}
	}
}

func TestDrainEffectStateTargetsAndPreservation(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	actual := storedIssue("issue-1", "SNYK-1", "Triage", desired)
	if !drainEffectMatches(actual, desired, cfg.Linear.States) {
		t.Fatal("configured target did not verify")
	}
	actual.StateName = "Todo"
	if drainEffectMatches(actual, desired, cfg.Linear.States) {
		t.Fatal("model state name bypassed configured target")
	}
	desired.PreserveState = true
	actual.StateName = "In Progress"
	if !drainEffectMatches(actual, desired, cfg.Linear.States) {
		t.Fatal("preserved state incorrectly compared to model target")
	}
	desired.PreserveState = false
	desired.Reopen = true
	desired.RestoreState = model.WorkflowState{ID: "state-restored", Name: "In Progress"}
	actual.StateID = "state-wrong"
	if drainEffectMatches(actual, desired, cfg.Linear.States) {
		t.Fatal("restore name accepted without exact restore ID")
	}
	actual.StateID = "state-restored"
	if !drainEffectMatches(actual, desired, cfg.Linear.States) {
		t.Fatal("exact restored ID did not verify")
	}
}

func TestDrainEffectRequiresActualManagedLabelsNotOnlyMetadata(t *testing.T) {
	cfg := minimalCfg()
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	desired.ManagedLabels = []string{"security-managed"}
	actual := storedIssue("issue-1", "SNYK-1", cfg.Linear.States.Todo, desired)
	if needsUpdate(actual, desired, cfg.Linear.States) {
		t.Fatal("fixture must exercise managed-label metadata shortcut")
	}
	if drainEffectMatches(actual, desired, cfg.Linear.States) {
		t.Fatal("missing actual managed label verified from metadata")
	}
	actual.Labels = []model.IssueLabel{{ID: "label-1", Name: "Security-Managed"}}
	if !drainEffectMatches(actual, desired, cfg.Linear.States) {
		t.Fatal("normalized actual managed label did not verify")
	}
}

func TestDrainPreservedStateRequiresUnchangedOriginalID(t *testing.T) {
	cfg := minimalCfg()
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	desired.PreserveState = true
	original := storedIssue("issue-1", "SNYK-1", "In Progress", desired)
	original.StateID = "state-in-progress"
	jobs := []job{{kind: jobUpdate, updateBatch: []model.IssueUpdate{{Existing: original, Desired: desired}}}}
	key := drainWorkKey(jobUpdate, desired, original)
	for _, tc := range []struct {
		name, id string
		want     bool
	}{{"unchanged", original.StateID, true}, {"drift", "state-different", false}, {"missing ID", "", false}} {
		t.Run(tc.name, func(t *testing.T) {
			actual := original
			actual.StateID = tc.id
			got := verifyDrainEffects(jobs, nil, []model.ExistingIssue{original}, []model.ExistingIssue{actual}, cfg.Linear.States)
			if got[key] != tc.want {
				t.Fatalf("verified=%v want %v", got, tc.want)
			}
		})
	}
}

func TestDrainCreateRequiresActualCreateOnlyLabels(t *testing.T) {
	cfg := minimalCfg()
	desired := desiredIssue(cfg, planFixtureFinding("issue-1"))
	desired.CreateOnlyLabels = []string{"Initial-Triage"}
	actual := storedIssue("created-1", "SNYK-1", cfg.Linear.States.Todo, desired)
	jobs := []job{{kind: jobCreateBatch, desiredBatch: []model.DesiredIssue{desired}}}
	key := drainWorkKey(jobCreateBatch, desired, model.ExistingIssue{})
	created := map[string]string{key: actual.ID}
	if got := verifyDrainEffects(jobs, created, nil, []model.ExistingIssue{actual}, cfg.Linear.States); got[key] {
		t.Fatal("missing create-only label verified")
	}
	actual.Labels = []model.IssueLabel{{ID: "label-1", Name: "initial-triage"}}
	if got := verifyDrainEffects(jobs, created, nil, []model.ExistingIssue{actual}, cfg.Linear.States); !got[key] {
		t.Fatal("present create-only label did not verify")
	}
}
