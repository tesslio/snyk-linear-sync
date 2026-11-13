package sync

import (
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/model"
)

func TestVerifyDrainMembership(t *testing.T) {
	issue := func(id, fp string) model.ExistingIssue { return model.ExistingIssue{ID: id, Fingerprint: fp} }
	old := issue("issue-1", "fp-old")
	terminal := issue("terminal-1", "fp-new")
	terminal.StateName = "Done"
	create := model.DesiredIssue{Fingerprint: "fp-new"}
	createJob := []job{{kind: jobCreateBatch, desiredBatch: []model.DesiredIssue{create}}}
	createKey := drainWorkKey(jobCreateBatch, create, model.ExistingIssue{})
	rebind := []job{{kind: jobUpdate, updateBatch: []model.IssueUpdate{{Existing: old, Desired: create}}}}
	for _, tc := range []struct {
		name          string
		before, after []model.ExistingIssue
		jobs          []job
		created       map[string]string
		verified      map[string]bool
		wantError     bool
	}{
		{name: "unchanged", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{old}},
		{name: "unrelated arrival", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{old, issue("arrival", "unrelated")}},
		{name: "same fingerprint arrival", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{old, issue("arrival", "fp-old")}, wantError: true},
		{name: "missing member", before: []model.ExistingIssue{old}, wantError: true},
		{name: "moved member", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{issue(old.ID, "unrelated")}, wantError: true},
		{name: "acknowledged create", after: []model.ExistingIssue{issue("created", "fp-new")}, jobs: createJob, created: map[string]string{createKey: "created"}},
		{name: "acknowledged unverified create", after: []model.ExistingIssue{issue("created", "fp-new")}, jobs: createJob, created: map[string]string{createKey: "created"}, verified: map[string]bool{createKey: false}},
		{name: "missing acknowledged create", jobs: createJob, created: map[string]string{createKey: "created"}, wantError: true},
		{name: "unacknowledged create arrival", after: []model.ExistingIssue{issue("created", "fp-new")}, jobs: createJob, wantError: true},
		{name: "retained terminal and create", before: []model.ExistingIssue{terminal}, after: []model.ExistingIssue{terminal, issue("created", "fp-new")}, jobs: createJob, created: map[string]string{createKey: "created"}},
		{name: "extra terminal copy", before: []model.ExistingIssue{terminal}, after: []model.ExistingIssue{terminal, issue("created", "fp-new"), issue("other-terminal", "fp-new")}, jobs: createJob, created: map[string]string{createKey: "created"}, wantError: true},
		{name: "create reused existing ID", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{issue(old.ID, "fp-new")}, jobs: createJob, created: map[string]string{createKey: old.ID}, wantError: true},
		{name: "verified rebind", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{issue(old.ID, "fp-new")}, jobs: rebind, verified: map[string]bool{"issue:" + old.ID: true}},
		{name: "unverified unchanged rebind", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{old}, jobs: rebind},
		{name: "unverified moved rebind", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{issue(old.ID, "fp-new")}, jobs: rebind, wantError: true},
		{name: "prior alias absent", after: []model.ExistingIssue{issue(old.ID, "fp-new")}, jobs: rebind, verified: map[string]bool{"issue:" + old.ID: true}, wantError: true},
		{name: "rebind with extra old alias", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{issue(old.ID, "fp-new"), issue("arrival", "fp-old")}, jobs: rebind, verified: map[string]bool{"issue:" + old.ID: true}, wantError: true},
		{name: "duplicate before ID", before: []model.ExistingIssue{old, old}, after: []model.ExistingIssue{old}, wantError: true},
		{name: "duplicate after ID", before: []model.ExistingIssue{old}, after: []model.ExistingIssue{old, old}, wantError: true},
		{name: "unselected acknowledgement", created: map[string]string{createKey: "created"}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyDrainMembership(tc.before, tc.after, tc.jobs, tc.created, tc.verified)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
}

func TestVerifyDrainMembershipTerminalTransitionKeepsMember(t *testing.T) {
	before := model.ExistingIssue{ID: "issue-1", Fingerprint: "fp-a", StateName: "Todo"}
	after := before
	after.StateName = "Done"
	if err := verifyDrainMembership([]model.ExistingIssue{before}, []model.ExistingIssue{after}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}
