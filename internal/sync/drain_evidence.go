package sync

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"

	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

const drainEvidenceEntryCeiling = 100000
const drainEvidenceByteCeiling = 32 << 20
const drainFingerprintByteCeiling = 4096

type DrainWithheld struct {
	Reason   string   `json:"reason"`
	WorkKeys []string `json:"work_keys"`
}

type DrainInitialization struct {
	SourceCacheKey    string `json:"source_cache_key"`
	SourceCacheSHA256 string `json:"source_cache_sha256"`
	V2ProducerRunID   string `json:"v2_producer_run_id"`
	AuthorizingRunID  string `json:"authorizing_run_id"`
}

type DrainHashEvidence struct {
	Version            int                      `json:"version"`
	Generation         int64                    `json:"generation"`
	ProducerRunID      string                   `json:"producer_run_id"`
	ProducerRunAttempt int64                    `json:"producer_run_attempt"`
	FullPlanSHA256     string                   `json:"full_plan_sha256,omitempty"`
	SelectedOpsSHA256  string                   `json:"selected_ops_sha256,omitempty"`
	DeferredOpsSHA256  string                   `json:"deferred_ops_sha256,omitempty"`
	SettingsSHA256     string                   `json:"settings_sha256,omitempty"`
	PendingAfterSHA256 string                   `json:"pending_after_sha256,omitempty"`
	Refreshed          map[string]string        `json:"refreshed"`
	PreWrite           map[string]string        `json:"pre_write"`
	Withheld           map[string]DrainWithheld `json:"withheld"`
	Initialization     *DrainInitialization     `json:"initialization,omitempty"`
}

// canonicalDrainJSON uses recursively sorted object keys, no whitespace or
// trailing newline, UTF-8 and Go JSON escaping. Consumers must match these bytes.
func canonicalDrainJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var object any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err = decoder.Decode(&object); err != nil {
		return nil, err
	}
	return json.Marshal(object)
}
func drainDigest(value any) (string, error) {
	data, err := canonicalDrainJSON(value)
	if err != nil {
		return "", err
	}
	return planTextDigest(string(data)), nil
}

// Preflight sizes a worst-case map using all known keys and all work keys. It
// excludes concurrent arrivals, which are never persisted as trusted hashes.
func drainEvidenceBound(pre map[string]string, jobs []job, operations []DrainOperation) (int, error) {
	known := map[string]bool{}
	for f := range pre {
		known[f] = true
	}
	for _, j := range jobs {
		for _, d := range j.desiredBatch {
			known[d.Fingerprint] = true
		}
		for _, u := range j.updateBatch {
			known[u.Desired.Fingerprint] = true
		}
	}
	if len(known) > drainEvidenceEntryCeiling {
		return 0, errors.New("drain-evidence-oversized")
	}
	// JSON string escaping expands each input byte by no more than six bytes.
	worst := 8192
	keysByFingerprint := map[string]int{}
	for _, op := range operations {
		for _, fp := range op.FingerprintSHA256s {
			keysByFingerprint[fp] += 6*len(op.WorkKey) + 4
		}
	}
	for f := range known {
		if len(f) == 0 || len(f) > drainFingerprintByteCeiling {
			return 0, errors.New("drain-evidence-oversized")
		}
		worst += 18*len(f) + 512 + keysByFingerprint[planTextDigest(f)]
	}
	if worst > drainEvidenceByteCeiling {
		return worst, errors.New("drain-evidence-oversized")
	}
	return worst, nil
}

func drainPreWriteHashes(existing []model.ExistingIssue, matched map[string]model.ExistingIssue) map[string]string {
	hashes := linearHashesByFingerprint(existing)
	for f, e := range matched {
		hashes[f] = existingIssueHash(e)
	}
	return hashes
}

// verifyDrainEffects is based on refreshed IDs, never on an acknowledgement or
// a fingerprint alone. The retained-terminal reopen case is intentionally valid.
func verifyDrainEffects(jobs []job, created map[string]string, before, after []model.ExistingIssue, states config.StateConfig) map[string]bool {
	oldByID := map[string]model.ExistingIssue{}
	newByID := map[string]model.ExistingIssue{}
	for _, e := range before {
		oldByID[e.ID] = e
	}
	for _, e := range after {
		newByID[e.ID] = e
	}
	verified := map[string]bool{}
	for _, j := range jobs {
		for _, u := range j.updateBatch {
			key := drainWorkKey(j.kind, u.Desired, u.Existing)
			actual, ok := newByID[u.Existing.ID]
			preserved := !u.Desired.PreserveState || u.Existing.StateID != "" && actual.StateID == u.Existing.StateID && (u.Existing.ArchivedAt == nil) == (actual.ArchivedAt == nil)
			verified[key] = ok && preserved && actual.Fingerprint == u.Desired.Fingerprint && drainEffectMatches(actual, u.Desired, states)
		}
		for _, d := range j.desiredBatch {
			key := drainWorkKey(j.kind, d, model.ExistingIssue{})
			id := created[key]
			actual, ok := newByID[id]
			// Creates always set a state and their one-time labels; there is no
			// preexisting issue state that could authorize PreserveState.
			valid := ok && id != "" && !d.PreserveState && actual.Fingerprint == d.Fingerprint && drainEffectMatches(actual, d, states) && drainHasActualLabels(actual, d.CreateOnlyLabels)
			for _, other := range after {
				if other.ID == id || other.Fingerprint != d.Fingerprint {
					continue
				}
				prior, existed := oldByID[other.ID]
				canonical, _ := preferCanonicalDuplicate(actual, other, states)
				if !existed || !isTerminalLinearState(other, states) || existingIssueHash(prior) != existingIssueHash(other) || canonical.ID != id {
					valid = false
				}
			}
			verified[key] = valid
		}
	}
	return verified
}

// drainEffectMatches verifies a write's intended state independently of the
// reconciliation diff. ComputeDiff intentionally hides terminal-to-open changes
// to protect the planner; that policy must not turn a stale terminal response
// into proof that a create or update reached its non-terminal target.
func drainEffectMatches(actual model.ExistingIssue, desired model.DesiredIssue, states config.StateConfig) bool {
	if !drainHasActualLabels(actual, desired.ManagedLabels) {
		return false
	}
	if !desired.PreserveState {
		if isNonTerminalModelState(desired.State) && actual.ArchivedAt != nil {
			return false
		}
		if desired.RestoreState.ID != "" {
			if actual.StateID != desired.RestoreState.ID {
				return false
			}
		} else {
			var target string
			switch desired.State {
			case model.StateTodo:
				target = states.Todo
			case model.StateBacklog:
				target = states.Backlog
			case model.StateDone:
				target = states.Done
			case model.StateCancelled:
				target = states.Cancelled
			default:
				return false
			}
			if target == "" {
				target = model.StateName(desired.State)
			}
			if model.NormalizeWorkflowStateName(actual.StateName) != model.NormalizeWorkflowStateName(target) {
				return false
			}
		}
	}
	// State was checked above against the configured target (or deliberately
	// omitted by PreserveState). Reuse only the non-state diff semantics.
	desired.PreserveState = true
	return !needsUpdate(actual, desired, states)
}

// Metadata records label intent, not proof that Linear retained the labels.
func drainHasActualLabels(actual model.ExistingIssue, desired []string) bool {
	for _, label := range model.NormalizeManagedLabelNames(desired) {
		if !model.HasLabelNamed(actual.Labels, label) {
			return false
		}
	}
	return true
}

// buildDrainEvidence filters AFTER canonical matched-ID overrides. Deferred or
// unverified aliases keep the whole fingerprint dirty across saves and reloads.
func buildDrainEvidence(pre, refreshed map[string]string, selected, deferred []DrainOperation, selectedJobs []job, verified map[string]bool) (DrainHashEvidence, map[string]string, []string, error) {
	evidence := DrainHashEvidence{Version: drainVersion, Refreshed: map[string]string{}, PreWrite: pre, Withheld: map[string]DrainWithheld{}}
	saved := map[string]string{}
	arrivals := []string{}
	known := map[string]bool{}
	for f := range pre {
		known[f] = true
	}
	for _, j := range selectedJobs {
		for _, d := range j.desiredBatch {
			known[d.Fingerprint] = true
		}
		for _, u := range j.updateBatch {
			known[u.Desired.Fingerprint] = true
		}
	}
	ops := append(slices.Clone(selected), deferred...)
	touches := map[string]bool{}
	for _, op := range ops {
		for _, fp := range op.FingerprintSHA256s {
			touches[fp] = true
		}
	}
	pending := map[string]DrainWithheld{}
	withhold := func(op DrainOperation, reason string) {
		for _, fp := range op.FingerprintSHA256s {
			w := pending[fp]
			if w.Reason == "" || reason == "deferred" {
				w.Reason = reason
			}
			w.WorkKeys = append(w.WorkKeys, op.WorkKey)
			slices.Sort(w.WorkKeys)
			pending[fp] = w
		}
	}
	for _, op := range deferred {
		withhold(op, "deferred")
	}
	for _, op := range selected {
		if !verified[op.WorkKey] {
			withhold(op, "unverified")
		}
	}
	for f, h := range refreshed {
		if !known[f] {
			arrivals = append(arrivals, planTextDigest(f))
			continue
		}
		evidence.Refreshed[f] = h
		fp := planTextDigest(f)
		if w, ok := pending[fp]; ok {
			evidence.Withheld[f] = w
			continue
		}
		if !touches[fp] && pre[f] != h {
			evidence.Withheld[f] = DrainWithheld{"drift", []string{}}
			continue
		}
		saved[f] = h
	}
	slices.Sort(arrivals)
	data, err := canonicalDrainJSON(evidence)
	if err != nil {
		return evidence, nil, nil, err
	}
	if len(evidence.Refreshed) > drainEvidenceEntryCeiling || len(data) > drainEvidenceByteCeiling {
		return evidence, nil, arrivals, errors.New("drain-evidence-overflow-after-writes")
	}
	if len(evidence.Refreshed) == 0 {
		return evidence, nil, arrivals, errors.New("drain-evidence-empty-refresh")
	}
	return evidence, saved, arrivals, nil
}

// A created ticket's acknowledged ID overrides retained terminal copies just
// as a matched update's ID overrides duplicate copies. A failed verification
// still causes withholding; this function does not authorize a cache hit.
func drainRefreshedHashes(after []model.ExistingIssue, matched map[string]model.ExistingIssue, jobs []job, created map[string]string) map[string]string {
	hashes := linearHashesByFingerprint(after)
	byID := map[string]model.ExistingIssue{}
	for _, e := range after {
		byID[e.ID] = e
	}
	for f, e := range matched {
		if current, ok := byID[e.ID]; ok {
			hashes[f] = existingIssueHash(current)
		}
	}
	for _, j := range jobs {
		for _, d := range j.desiredBatch {
			if current, ok := byID[created[drainWorkKey(j.kind, d, model.ExistingIssue{})]]; ok && current.Fingerprint == d.Fingerprint {
				hashes[d.Fingerprint] = existingIssueHash(current)
			}
		}
	}
	return hashes
}
