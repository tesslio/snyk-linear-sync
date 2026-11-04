package sync

import (
	"fmt"
	"slices"
	"strings"

	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// canonicalReplayInputs orders semantic sets without removing entries or
// rewriting any field. All raw values (including duplicate set entries and
// nil-versus-empty slices) remain bound by the input digests. This must run
// before matching as well as hashing: ordering only an exported plan is unsafe.
func canonicalReplayInputs(snapshot model.SnykSnapshot, existing []model.ExistingIssue) (model.SnykSnapshot, []model.ExistingIssue, error) {
	snapshot.Findings = slices.Clone(snapshot.Findings)
	seen := map[string]bool{}
	for i := range snapshot.Findings {
		f := &snapshot.Findings[i]
		key := model.CanonicalFingerprint(f.Fingerprint)
		if strings.TrimSpace(key) == "" || seen[key] {
			return model.SnykSnapshot{}, nil, fmt.Errorf("replay-safe snapshot requires unique, nonempty source fingerprints; duplicate or ambiguous source at index %d", i+1)
		}
		seen[key] = true
		f.CVEs = sortedReplayStrings(f.CVEs)
		f.Classes = slices.Clone(f.Classes)
		slices.SortFunc(f.Classes, func(a, b model.IssueClass) int {
			if c := strings.Compare(a.ID, b.ID); c != 0 {
				return c
			}
			return strings.Compare(a.Source, b.Source)
		})
	}
	slices.SortFunc(snapshot.Findings, func(a, b model.Finding) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	existing = slices.Clone(existing)
	ids := map[string]bool{}
	for i := range existing {
		issue := &existing[i]
		if strings.TrimSpace(issue.ID) == "" || ids[issue.ID] {
			return model.SnykSnapshot{}, nil, fmt.Errorf("replay-safe snapshot requires unique, nonempty Linear issue IDs at index %d", i+1)
		}
		ids[issue.ID] = true
		issue.ManagedLabels = sortedReplayStrings(issue.ManagedLabels)
		issue.Labels = slices.Clone(issue.Labels)
		slices.SortFunc(issue.Labels, func(a, b model.IssueLabel) int {
			if c := strings.Compare(a.ID, b.ID); c != 0 {
				return c
			}
			if c := strings.Compare(a.Name, b.Name); c != 0 {
				return c
			}
			return strings.Compare(a.GroupID, b.GroupID)
		})
	}
	slices.SortFunc(existing, func(a, b model.ExistingIssue) int { return strings.Compare(a.ID, b.ID) })
	return snapshot, existing, nil
}

func sortedReplayStrings(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return out
}

func replayConfig(cfg config.Config) config.Config {
	if cfg.ReplaySafe {
		cfg.Snyk.Scopes = sortedReplayStrings(cfg.Snyk.Scopes)
		cfg.Linear.Labels.CreateOnly = sortedReplayStrings(cfg.Linear.Labels.CreateOnly)
		cfg.Linear.Labels.Protected = sortedReplayStrings(cfg.Linear.Labels.Protected)
	}
	return cfg
}

func replayMapKeys[V any](values map[string]V, ordered bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	if ordered {
		slices.Sort(keys)
	}
	return keys
}

func replayPlanVersion(cfg config.Config) int {
	if cfg.ReplaySafe {
		return 2
	}
	return 1
}
