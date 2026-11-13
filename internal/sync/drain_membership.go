package sync

import (
	"errors"
	"maps"

	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// verifyDrainMembership refuses publication when canonical hash overrides could
// hide a competing or disappeared issue. Only acknowledged selected creates and
// verified selected rebinds explain changes. It does not infer effect success
// from membership, and unrelated new fingerprints remain excluded as arrivals.
func verifyDrainMembership(before, after []model.ExistingIssue, selectedJobs []job, created map[string]string, verified map[string]bool) error {
	invalid := func() error { return errors.New("drain-membership-changed") }
	index := func(issues []model.ExistingIssue) (map[string]string, error) {
		byID := make(map[string]string, len(issues))
		for _, issue := range issues {
			if issue.ID == "" {
				return nil, invalid()
			}
			if _, exists := byID[issue.ID]; exists {
				return nil, invalid()
			}
			byID[issue.ID] = issue.Fingerprint
		}
		return byID, nil
	}
	prior, err := index(before)
	if err != nil {
		return err
	}
	actual, err := index(after)
	if err != nil {
		return err
	}
	expected := maps.Clone(prior)
	known := map[string]bool{}
	for _, fingerprint := range prior {
		if fingerprint != "" {
			known[fingerprint] = true
		}
	}
	selectedCreates := map[string]bool{}
	selectedTargets := map[string]bool{}
	for _, batch := range selectedJobs {
		for _, desired := range batch.desiredBatch {
			if batch.kind != jobCreateBatch || desired.Fingerprint == "" {
				return invalid()
			}
			known[desired.Fingerprint] = true
			key := drainWorkKey(batch.kind, desired, model.ExistingIssue{})
			if selectedCreates[key] {
				return invalid()
			}
			selectedCreates[key] = true
			if id := created[key]; id != "" {
				if _, exists := expected[id]; exists {
					return invalid()
				}
				expected[id] = desired.Fingerprint
			}
		}
		for _, update := range batch.updateBatch {
			id := update.Existing.ID
			if id == "" || update.Desired.Fingerprint == "" || selectedTargets[id] {
				return invalid()
			}
			selectedTargets[id] = true
			known[update.Desired.Fingerprint] = true
			if fingerprint, exists := prior[id]; !exists || fingerprint != update.Existing.Fingerprint {
				return invalid()
			}
			if verified[drainWorkKey(batch.kind, update.Desired, update.Existing)] {
				expected[id] = update.Desired.Fingerprint
			}
		}
	}
	for key := range created {
		if !selectedCreates[key] {
			return invalid()
		}
	}
	// Compare membership in both directions: deletion and movement out of a
	// known key are just as unsafe as a hidden addition under that key.
	for id, fingerprint := range expected {
		if known[fingerprint] && actual[id] != fingerprint {
			return invalid()
		}
	}
	for id, fingerprint := range actual {
		if known[fingerprint] && expected[id] != fingerprint {
			return invalid()
		}
	}
	return nil
}
