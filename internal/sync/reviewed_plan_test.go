package sync

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func reviewedFixture(t *testing.T) *ReconciliationPlan {
	t.Helper()
	result, _, _ := runPlan(t, planCfg(), planSnapshot(planFixtureFinding("issue-a")), nil, nil)
	return result.Plan
}
func reviewedBytes(t *testing.T, p *ReconciliationPlan) []byte {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func reviewedReadBytes(t *testing.T, data []byte, digest string) (*ReconciliationPlan, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return readReviewedPlan(path, digest)
}
func TestReadReviewedPlan(t *testing.T) {
	p := reviewedFixture(t)
	data := reviewedBytes(t, p)
	got, err := reviewedReadBytes(t, data, planTextDigest(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyReviewedPlan(p, got); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pretty = append(pretty, '\n')
	if _, err := reviewedReadBytes(t, pretty, planTextDigest(string(pretty))); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{"", "bad", strings.Repeat("z", 64), strings.Repeat("0", 64), planTextDigest(string(pretty))} {
		if _, err := reviewedReadBytes(t, data, digest); err == nil {
			t.Fatal("accepted invalid artifact digest")
		}
	}
}
func TestReadReviewedPlanStrictJSON(t *testing.T) {
	original := string(reviewedBytes(t, reviewedFixture(t)))
	cases := map[string]string{
		"invalid UTF-8":     strings.Replace(original, `"no-reusable-ticket"`, "\""+string([]byte{0xff})+"\"", 1),
		"trailing document": original + "{}",
		"trailing garbage":  original + "private-value",
		"unknown":           strings.Replace(original, `"version":1`, `"secret-field":"private-value","version":1`, 1),
		"duplicate":         strings.Replace(original, `"version":1`, `"version":1,"version":1`, 1),
		"case alias":        strings.Replace(original, `"version":1`, `"VERSION":1`, 1),
		"nested duplicate":  strings.Replace(original, `"snyk_sha256":`, `"snyk_sha256":"private-value","snyk_sha256":`, 1),
		"escaped duplicate": strings.Replace(original, `"version":1`, `"version":1,"\u0076ersion":1`, 1),
		"missing":           strings.Replace(original, `"version":1,`, "", 1),
		"null":              "null",
		"null records":      strings.Replace(original, `"records":[`, `"records":null,"unused":[`, 1),
		"wrong type":        strings.Replace(original, `"version":1`, `"version":"private-value"`, 1),
		"truncated":         original[:len(original)-1],
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := reviewedReadBytes(t, []byte(data), planTextDigest(data))
			if err == nil {
				t.Fatal("accepted malformed artifact")
			}
			if strings.Contains(err.Error(), "private-value") || strings.Contains(err.Error(), "secret-field") {
				t.Fatal("error disclosed input")
			}
		})
	}
}
func TestReadReviewedPlanFileBoundaries(t *testing.T) {
	digest := strings.Repeat("0", 64)
	dir := t.TempDir()
	for _, path := range []string{dir, filepath.Join(dir, "missing")} {
		if _, err := readReviewedPlan(path, digest); err == nil {
			t.Fatal("accepted invalid file")
		}
	}
	path := filepath.Join(dir, "oversized.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxReviewedPlanBytes + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := readReviewedPlan(path, digest); err == nil {
		t.Fatal("accepted oversized file")
	}
}
func TestVerifyReviewedPlanRejectsInvalid(t *testing.T) {
	cases := map[string]func(*ReconciliationPlan){
		"version":                func(p *ReconciliationPlan) { p.Version++ },
		"incomplete":             func(p *ReconciliationPlan) { p.Complete = false },
		"writes":                 func(p *ReconciliationPlan) { p.LinearWritesAttempted = true },
		"partial history":        func(p *ReconciliationPlan) { p.ReopenHistoryStatus = "partial_or_failed" },
		"missing history":        func(p *ReconciliationPlan) { p.ReopenHistoryStatus = "" },
		"bad input digest":       func(p *ReconciliationPlan) { p.Inputs.LinearSHA256 = "bad" },
		"decision digest":        func(p *ReconciliationPlan) { p.DecisionsSHA256 = strings.Repeat("0", 64) },
		"count":                  func(p *ReconciliationPlan) { p.Summary.Creates++ },
		"coverage":               func(p *ReconciliationPlan) { p.Summary.CoveredFindings = 0 },
		"missing record":         func(p *ReconciliationPlan) { p.Records = []PlanRecord{} },
		"index":                  func(p *ReconciliationPlan) { p.Records[0].FindingIndex = 2 },
		"executed":               func(p *ReconciliationPlan) { p.Records[0].ExecutionStatus = "attempted" },
		"action":                 func(p *ReconciliationPlan) { p.Records[0].Action = "unknown" },
		"mutation":               func(p *ReconciliationPlan) { p.Records[0].MutationPlanned = false },
		"reopen without history": func(p *ReconciliationPlan) { p.Summary.Reopened = 1 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := reviewedFixture(t)
			change(p)
			if err := verifyReviewedPlan(p, p); err == nil {
				t.Fatal("accepted invalid plan")
			}
			data := reviewedBytes(t, p)
			if _, err := reviewedReadBytes(t, data, planTextDigest(string(data))); err == nil {
				t.Fatal("read invalid plan")
			}
		})
	}
	if err := verifyReviewedPlan(nil, nil); err == nil {
		t.Fatal("accepted nil plans")
	}
}
func TestVerifyReviewedPlanComparesAllFields(t *testing.T) {
	cases := map[string]func(*ReconciliationPlan){
		"snyk":          func(p *ReconciliationPlan) { p.Inputs.SnykSHA256 = planTextDigest("other") },
		"linear":        func(p *ReconciliationPlan) { p.Inputs.LinearSHA256 = planTextDigest("other") },
		"settings":      func(p *ReconciliationPlan) { p.Inputs.SettingsSHA256 = planTextDigest("other") },
		"cache":         func(p *ReconciliationPlan) { p.Inputs.SyncCacheSHA256 = planTextDigest("other") },
		"cache enabled": func(p *ReconciliationPlan) { p.Inputs.SyncCacheEnabled = !p.Inputs.SyncCacheEnabled },
		"guard":         func(p *ReconciliationPlan) { p.Guard.Active = !p.Guard.Active },
		"summary":       func(p *ReconciliationPlan) { p.Summary.HeldDueDates++ },
		"local cache":   func(p *ReconciliationPlan) { p.LocalCacheMayChange = !p.LocalCacheMayChange },
		"decision": func(p *ReconciliationPlan) {
			p.Records[0].Reason = "different"
			p.DecisionsSHA256, _ = planDigest(p.Records)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			approved, current := reviewedFixture(t), reviewedFixture(t)
			change(current)
			if err := validateReviewedPlan(current); err != nil {
				t.Fatalf("fixture unexpectedly invalid: %v", err)
			}
			if err := verifyReviewedPlan(approved, current); err == nil {
				t.Fatal("accepted changed plan")
			}
		})
	}
}
func TestReadReviewedPlanDoesNotRereadArtifact(t *testing.T) {
	p := reviewedFixture(t)
	data := reviewedBytes(t, p)
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	approved, err := readReviewedPlan(path, planTextDigest(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyReviewedPlan(approved, p); err != nil {
		t.Fatal(err)
	}
}

func TestReviewedPlanAllActionsAndCoverage(t *testing.T) {
	for _, action := range []string{"create", "update", "resolve", "cancel-duplicate", "defer-create", "retain", "no-op"} {
		t.Run(action, func(t *testing.T) {
			p := reviewedFixture(t)
			p.Summary.Creates = 0
			r := &p.Records[0]
			r.Action = action
			r.MutationPlanned = false
			switch action {
			case "create":
				p.Summary.Creates = 1
				r.MutationPlanned = true
			case "update":
				p.Summary.Updates = 1
				r.MutationPlanned = true
			case "resolve":
				p.Summary.Resolves = 1
				r.MutationPlanned = true
			case "cancel-duplicate":
				p.Summary.CancelDuplicates = 1
				r.MutationPlanned = true
			case "defer-create":
				p.Summary.DeferredCreates = 1
			}
			p.Summary.ExistingIssues = 1
			p.Summary.CoveredExistingIssues = 1
			r.ExistingIndex = 1
			p.DecisionsSHA256, _ = planDigest(p.Records)
			if err := verifyReviewedPlan(p, p); err != nil {
				t.Fatal(err)
			}
			r.ExistingIndex = 0
			p.DecisionsSHA256, _ = planDigest(p.Records)
			if err := verifyReviewedPlan(p, p); err == nil {
				t.Fatal("accepted missing existing coverage")
			}
		})
	}
	result, _, _ := runPlan(t, planCfg(), planSnapshot(), nil, nil)
	data := reviewedBytes(t, result.Plan)
	if _, err := reviewedReadBytes(t, data, planTextDigest(string(data))); err != nil {
		t.Fatal(err)
	}
}
