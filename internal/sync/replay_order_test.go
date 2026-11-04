package sync

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// Explicit capability for these synthetic snapshots; the real loader must
// independently prove fresh, strictly validated source reads.
func (s *planSnyk) ValidateFreshSnapshot() error { return nil }

func TestReplayCanonicalInputsPreserveAllRawFields(t *testing.T) {
	f := planFixtureFinding("issue-a")
	f.Classes = []model.IssueClass{{ID: "CWE-2", Source: "z"}, {ID: "CWE-1", Source: "b"}, {ID: "CWE-1", Source: "a"}}
	f.CVEs = []string{"CVE-2", "CVE-1", "CVE-1"}
	issue := model.ExistingIssue{ID: "ticket-a", Labels: []model.IssueLabel{{ID: "label-a", Name: "z", GroupID: "group-b"}, {ID: "label-a", Name: "z", GroupID: "group-a"}}, ManagedLabels: []string{"Z", "a", "a"}}
	snapshot := planSnapshot(f, planFixtureFinding("issue-b"))
	a, ia, err := canonicalReplayInputs(snapshot, []model.ExistingIssue{issue, {ID: "ticket-b"}})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(snapshot.Findings)
	slices.Reverse(f.CVEs)
	slices.Reverse(f.Classes)
	slices.Reverse(issue.Labels)
	slices.Reverse(issue.ManagedLabels)
	b, ib, err := canonicalReplayInputs(snapshot, []model.ExistingIssue{{ID: "ticket-b"}, issue})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(ia, ib) {
		t.Fatal("permutation changed canonical snapshot")
	}
	if len(a.Findings[0].CVEs) != 3 || len(ia[0].ManagedLabels) != 3 {
		t.Fatal("dropped duplicate raw values")
	}
	before, _ := planDigest(a)
	a.Findings[0].Classes[0].Source = "changed"
	after, _ := planDigest(a)
	if before == after {
		t.Fatal("class source not bound")
	}
	before, _ = planDigest(ia)
	ia[0].Labels[0].GroupID = "changed"
	after, _ = planDigest(ia)
	if before == after {
		t.Fatal("label group not bound")
	}
}

func TestReplayRejectsAmbiguousInputs(t *testing.T) {
	f := planFixtureFinding("issue-a")
	for _, test := range []struct {
		name     string
		findings []model.Finding
		issues   []model.ExistingIssue
	}{
		{"duplicate-source", []model.Finding{f, f}, nil},
		{"ambiguous-source", []model.Finding{{Fingerprint: "snyk:p:i:**file**"}, {Fingerprint: "snyk:p:i:__file__"}}, nil},
		{"empty-source", []model.Finding{{}}, nil},
		{"duplicate-linear-id", []model.Finding{f}, []model.ExistingIssue{{ID: "ticket-a"}, {ID: "ticket-a"}}},
		{"empty-linear-id", []model.Finding{f}, []model.ExistingIssue{{}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := planCfg()
			cfg.ReplaySafe = true
			linear := &planLinear{fakeLinear: fakeLinear{snapshot: test.issues}}
			_, err := New(cfg, discardLogger(), &planSnyk{snapshot: planSnapshot(test.findings...)}, linear, nil).Run(t.Context())
			if err == nil {
				t.Fatal("ambiguous input accepted")
			}
			assertNoReviewedWrites(t, linear)
		})
	}
}

func TestReplayV2PermutationsMatchAndBufferDeterministically(t *testing.T) {
	cfg := planCfg()
	cfg.ReplaySafe = true
	var findings []model.Finding
	var issues []model.ExistingIssue
	for i := range 23 {
		f := planFixtureFinding(string(rune('a' + i)))
		f.CVEs = []string{"CVE-2", "CVE-1"}
		f.Classes = []model.IssueClass{{ID: "CWE-2", Source: "source-b"}, {ID: "CWE-1", Source: "source-a"}}
		findings = append(findings, f)
		if i%2 == 0 {
			issue := storedIssue("ticket-"+string(rune('a'+i)), "SNYK-100", "Todo", desiredIssue(cfg, f))
			issue.Title = "old title"
			issue.Labels = []model.IssueLabel{{ID: "label-b", Name: "b"}, {ID: "label-a", Name: "a"}}
			issue.ManagedLabels = []string{"b", "a"}
			issues = append(issues, issue)
		}
	}
	duplicate := issues[0]
	duplicate.ID = "ticket-duplicate"
	issues = append(issues, duplicate)
	absent := storedIssue("ticket-absent", "SNYK-101", "Todo", desiredIssue(cfg, planFixtureFinding("absent")))
	issues = append(issues, absent)
	snapshot := planSnapshot(findings...)
	first, _, _ := runPlan(t, cfg, snapshot, issues, nil)
	if first.Plan.Version != 2 {
		t.Fatal("not v2")
	}
	approved := reviewedServiceCfg(t, cfg, snapshot, issues, nil)
	var baselineCreates [][]model.DesiredIssue
	var baselineUpdates []model.IssueUpdate
	for run := range 8 {
		slices.Reverse(snapshot.Findings)
		slices.Reverse(issues)
		for i := range snapshot.Findings {
			slices.Reverse(snapshot.Findings[i].Classes)
			slices.Reverse(snapshot.Findings[i].CVEs)
		}
		for i := range issues {
			slices.Reverse(issues[i].Labels)
			slices.Reverse(issues[i].ManagedLabels)
		}
		current, _, _ := runPlan(t, cfg, snapshot, issues, nil)
		if !reflect.DeepEqual(first.Plan, current.Plan) {
			t.Fatal("permuted v2 plan differs")
		}
		linear := &planLinear{fakeLinear: fakeLinear{snapshot: issues}}
		_, err := New(approved, discardLogger(), &planSnyk{snapshot: snapshot}, linear, nil).Run(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if run == 0 {
			baselineCreates = linear.createCallBatches
			baselineUpdates = linear.updates
		} else if !reflect.DeepEqual(baselineCreates, linear.createCallBatches) || !reflect.DeepEqual(baselineUpdates, linear.updates) {
			t.Fatal("buffer order changed")
		}
	}
}

func TestReplayVersionsAndStaleRawChangesFailClosed(t *testing.T) {
	for _, mode := range []bool{false, true} {
		for _, change := range []string{"mode", "order", "raw-source", "raw-linear"} {
			t.Run(change+map[bool]string{false: "-v1", true: "-v2"}[mode], func(t *testing.T) {
				cfg := planCfg()
				cfg.ReplaySafe = mode
				snapshot := planSnapshot(planFixtureFinding("issue-a"), planFixtureFinding("issue-b"))
				issues := []model.ExistingIssue{{ID: "ticket-a", StateName: "Done"}}
				cfg = reviewedServiceCfg(t, cfg, snapshot, issues, nil)
				switch change {
				case "mode":
					cfg.ReplaySafe = !mode
				case "order":
					slices.Reverse(snapshot.Findings)
				case "raw-source":
					snapshot.Findings[0].SourceColumnEnd++
				case "raw-linear":
					issues[0].URL = "https://example.test/changed"
				}

				snyk := &planSnyk{snapshot: snapshot}
				linear := &planLinear{fakeLinear: fakeLinear{snapshot: issues}}
				_, err := New(cfg, discardLogger(), snyk, linear, nil).Run(t.Context())
				if change == "order" && mode {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				if err == nil {
					t.Fatal("changed approved inputs accepted")
				}
				assertNoReviewedWrites(t, linear)
				if change == "mode" && (snyk.calls != 0 || linear.calls != 0) {
					t.Fatal("version mismatch loaded snapshots")
				}
			})
		}
	}
}

type unvalidatedReplaySource struct{ snapshot model.SnykSnapshot }

func (s unvalidatedReplaySource) LoadSnapshot(ctx context.Context) (model.SnykSnapshot, error) {
	return s.snapshot, nil
}

type failedFreshReplaySource struct{ planSnyk }

func (s failedFreshReplaySource) ValidateFreshSnapshot() error {
	return errors.New("strict read failed")
}
func TestReplayRequiresFreshSourceProof(t *testing.T) {
	cfg := planCfg()
	cfg.ReplaySafe = true
	for _, source := range []SnykClient{unvalidatedReplaySource{}, &failedFreshReplaySource{}} {
		linear := &planLinear{}
		if _, err := New(cfg, discardLogger(), source, linear, nil).Run(t.Context()); err == nil {
			t.Fatal("accepted source without fresh proof")
		}
		assertNoReviewedWrites(t, linear)
	}
}

func TestReplayV2ExactGuardComparison(t *testing.T) {
	cfg := planCfg()
	cfg.ReplaySafe = true
	result, _, _ := runPlan(t, cfg, planSnapshot(planFixtureFinding("issue-a")), nil, nil)
	changed := *result.Plan
	changed.Guard.Active = !changed.Guard.Active
	if err := verifyReviewedPlan(result.Plan, &changed); err == nil {
		t.Fatal("guard change accepted")
	}
	changed = *result.Plan
	changed.Guard.UntrustedEmptyStart = !changed.Guard.UntrustedEmptyStart
	if err := verifyReviewedPlan(result.Plan, &changed); err == nil {
		t.Fatal("untrusted start change accepted")
	}
}

func TestReplayV2SettingsSetsRemainFullyBound(t *testing.T) {
	cfg := planCfg()
	cfg.ReplaySafe = true
	cfg.Snyk.Scopes = []string{"code", "package"}
	cfg.Linear.Labels.CreateOnly = []string{"z", "a", "a"}
	cfg.Linear.Labels.Protected = []string{"y", "b"}
	snapshot := planSnapshot(planFixtureFinding("issue-a"))
	a, _, _ := runPlan(t, cfg, snapshot, nil, nil)
	slices.Reverse(cfg.Snyk.Scopes)
	slices.Reverse(cfg.Linear.Labels.CreateOnly)
	slices.Reverse(cfg.Linear.Labels.Protected)
	b, _, _ := runPlan(t, cfg, snapshot, nil, nil)
	if !reflect.DeepEqual(a.Plan, b.Plan) {
		t.Fatal("set permutation changed settings or decisions")
	}
	cfg.Linear.Labels.CreateOnly = cfg.Linear.Labels.CreateOnly[1:]
	c, _, _ := runPlan(t, cfg, snapshot, nil, nil)
	if c.Plan.Inputs.SettingsSHA256 == a.Plan.Inputs.SettingsSHA256 {
		t.Fatal("raw duplicate setting was discarded")
	}
}

func TestReplayV2CoarseDuplicateUsesCanonicalWinner(t *testing.T) {
	cfg := planCfg()
	cfg.ReplaySafe = true
	f := planFixtureFinding("issue-a")
	coarse := f
	coarse.Fingerprint = model.CoarseFingerprint(f.Fingerprint)
	a := storedIssue("ticket-a", "SNYK-103", "Todo", desiredIssue(cfg, coarse))
	b := a
	b.ID = "ticket-b"
	b.Identifier = "SNYK-101"
	snapshot := planSnapshot(f)
	first, _, _ := runPlan(t, cfg, snapshot, []model.ExistingIssue{a, b}, nil)
	second, _, _ := runPlan(t, cfg, snapshot, []model.ExistingIssue{b, a}, nil)
	if !reflect.DeepEqual(first.Plan, second.Plan) {
		t.Fatal("coarse winner depended on source order")
	}
	row := planRow(t, first.Plan, b.ID, "update")
	if row.Match != "coarse-migration" {
		t.Fatalf("wrong canonical match: %+v", row)
	}
	planRow(t, first.Plan, a.ID, "cancel-duplicate")
}

func TestPlanSettingsSHA256MatchesCollector(t *testing.T) {
	for _, mode := range []bool{false, true} {
		cfg := planCfg()
		cfg.ReplaySafe = mode
		cfg.Snyk.Scopes = []string{"package", "code"}
		cfg.Linear.Labels.Protected = []string{"z", "a"}
		result, _, _ := runPlan(t, cfg, planSnapshot(planFixtureFinding("issue-a")), nil, nil)
		digest, err := PlanSettingsSHA256(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if digest != result.Plan.Inputs.SettingsSHA256 {
			t.Fatal("receipt settings differ from plan")
		}
		cfg.PlanJSON = "different-path"
		cfg.ReviewedPlanJSON = "another-path"
		cfg.ReviewedPlanSHA256 = "unused-digest"
		cfg.Snyk.ClientSecret = "different-example-token"
		cfg.Linear.APIKey = "different-example-token"
		unchanged, err := PlanSettingsSHA256(cfg)
		if err != nil || unchanged != digest {
			t.Fatal("credentials or operation paths affected settings digest")
		}
	}
}
