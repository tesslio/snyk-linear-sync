package sync

import (
	"errors"
	"slices"
)

// drainPlanOperations projects the real retained reconciliation plan, including
// old aliases on identity rebinds. It does not replace that plan with a weaker
// operations-only artifact.
func drainPlanOperations(plan *ReconciliationPlan) ([]DrainOperation, error) {
	if err := validateReviewedPlan(plan); err != nil {
		return nil, err
	}
	if plan.Version != 2 {
		return nil, errors.New("drain-plan-version")
	}
	operations := []DrainOperation{}
	seen := map[string]bool{}
	for _, r := range plan.Records {
		if !r.MutationPlanned {
			continue
		}
		op := DrainOperation{WorkKey: "issue:" + r.IssueID, Kind: r.Action, FingerprintSHA256s: []string{r.FingerprintSHA256}}
		if r.Action == "create" {
			op.WorkKey = "create:" + r.FingerprintSHA256
		}
		if !drainValidWorkKey(op.WorkKey) || !drainSHA256(r.FingerprintSHA256) {
			return nil, errors.New("drain-work-key-invalid")
		}
		if r.PreviousFingerprintSHA256 != "" && r.PreviousFingerprintSHA256 != r.FingerprintSHA256 {
			if r.Action == "create" || !drainSHA256(r.PreviousFingerprintSHA256) {
				return nil, errors.New("drain-work-key-invalid")
			}
			op.FingerprintSHA256s = append(op.FingerprintSHA256s, r.PreviousFingerprintSHA256)
			slices.Sort(op.FingerprintSHA256s)
		}
		if seen[op.WorkKey] {
			return nil, errors.New("duplicate-target")
		}
		seen[op.WorkKey] = true
		operations = append(operations, op)
	}
	if len(operations) > drainEvidenceEntryCeiling {
		return nil, errors.New("drain-evidence-oversized")
	}
	slices.SortFunc(operations, func(a, b DrainOperation) int {
		if a.WorkKey < b.WorkKey {
			return -1
		}
		if a.WorkKey > b.WorkKey {
			return 1
		}
		return 0
	})
	return operations, nil
}
