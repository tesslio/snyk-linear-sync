package sync

// The drain protocol is deliberately separate from the all-or-nothing bound
// protocol. These helpers never dispatch mutations or initialize a cache.

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tesslio/snyk-linear-sync/internal/model"
)

const drainVersion = 1

type DrainPendingEntry struct {
	SinceGeneration       int64    `json:"since_generation"`
	FingerprintSHA256s    []string `json:"fingerprint_sha256s"`
	UnverifiedGenerations int      `json:"unverified_generations"`
}

type DrainPending struct {
	Version    int                          `json:"version"`
	Generation int64                        `json:"generation"`
	Entries    map[string]DrainPendingEntry `json:"entries"`
}

type DrainOperation struct {
	WorkKey            string   `json:"work_key"`
	Kind               string   `json:"kind"`
	FingerprintSHA256s []string `json:"fingerprint_sha256s"`
}

type DrainLimits struct {
	MaxIssueChanges     int64 `json:"max_issue_changes"`
	MaxCreates          int64 `json:"max_creates"`
	MaxUpdates          int64 `json:"max_updates"`
	MaxResolves         int64 `json:"max_resolves"`
	MaxCancelDuplicates int64 `json:"max_cancel_duplicates"`
}

type drainSelection struct {
	selected, deferred []DrainOperation
	jobs               []job
	pending            DrainPending
}

type drainWork struct {
	op       DrainOperation
	desired  model.DesiredIssue
	existing model.ExistingIssue
	update   model.IssueUpdate
	age      int64
}

func drainWorkKey(kind jobKind, desired model.DesiredIssue, existing model.ExistingIssue) string {
	if kind == jobCreateBatch {
		return "create:" + planTextDigest(desired.Fingerprint)
	}
	return "issue:" + existing.ID
}

// drainInheritedPending carries only this issue's ownership and prior creates
// for its fingerprints. Sharing a fingerprint never transfers another issue's
// pending work. Several create aliases can converge on one issue after rebind.
func drainInheritedPending(op DrainOperation, before DrainPending) DrainPendingEntry {
	entry := DrainPendingEntry{SinceGeneration: before.Generation + 1, FingerprintSHA256s: slices.Clone(op.FingerprintSHA256s)}
	inherit := func(key string) {
		if prior, ok := before.Entries[key]; ok {
			entry.SinceGeneration = min(entry.SinceGeneration, prior.SinceGeneration)
			entry.UnverifiedGenerations = max(entry.UnverifiedGenerations, prior.UnverifiedGenerations)
		}
	}
	inherit(op.WorkKey)
	for _, fingerprint := range op.FingerprintSHA256s {
		inherit("create:" + fingerprint)
	}
	return entry
}

// selectDrain requires full-plan validation first, then partitions whole causal
// components. Neither fingerprint aliases nor source ordering can split a group.
func selectDrain(plan *ReconciliationPlan, jobs []job, before DrainPending, limits DrainLimits, findings []model.Finding, canonical map[string]model.ExistingIssue) (drainSelection, error) {
	out := drainSelection{selected: []DrainOperation{}, deferred: []DrainOperation{}, pending: DrainPending{Version: drainVersion, Generation: before.Generation + 1, Entries: map[string]DrainPendingEntry{}}}
	operations, err := drainPlanOperations(plan)
	if err != nil {
		return out, err
	}
	if err := validateBoundJobs(plan, jobs); err != nil {
		return out, err
	}
	if before.Version != drainVersion || before.Generation < 0 {
		return out, errors.New("drain-pending-invalid")
	}
	// Check every previous entry before selection, including work that may no
	// longer appear in the plan. A replan is not evidence of a verified effect.
	for key, prior := range before.Entries {
		if prior.SinceGeneration < 1 || prior.SinceGeneration > before.Generation || prior.UnverifiedGenerations < 0 || len(prior.FingerprintSHA256s) == 0 {
			return out, errors.New("drain-pending-invalid")
		}
		if !strings.HasPrefix(key, "issue:") && !strings.HasPrefix(key, "create:") {
			return out, errors.New("drain-pending-invalid")
		}
		if strings.HasPrefix(key, "create:") && (len(prior.FingerprintSHA256s) != 1 || key != "create:"+prior.FingerprintSHA256s[0]) {
			return out, errors.New("drain-pending-invalid")
		}
		if prior.UnverifiedGenerations >= 3 {
			return out, errors.New("drain-stalled-effect")
		}
	}
	ceilings := map[string]int64{"create": limits.MaxCreates, "update": limits.MaxUpdates, "resolve": limits.MaxResolves, "cancel-duplicate": limits.MaxCancelDuplicates}
	if limits.MaxIssueChanges < 1 || limits.MaxIssueChanges > 100 {
		return out, errors.New("drain-budget-invalid")
	}
	for _, n := range ceilings {
		if n < 0 {
			return out, errors.New("drain-budget-invalid")
		}
	}
	work := map[string]drainWork{}
	add := func(kind jobKind, d model.DesiredIssue, e model.ExistingIssue, u model.IssueUpdate) error {
		key := drainWorkKey(kind, d, e)
		if (kind != jobCreateBatch && e.ID == "") || d.Fingerprint == "" {
			return errors.New("drain-work-key-invalid")
		}
		if _, ok := work[key]; ok {
			return errors.New("duplicate-target")
		}
		hashes := []string{planTextDigest(d.Fingerprint)}
		if e.Fingerprint != "" && e.Fingerprint != d.Fingerprint {
			hashes = append(hashes, planTextDigest(e.Fingerprint))
			slices.Sort(hashes)
		}
		op := DrainOperation{key, string(kind), hashes}
		prior := drainInheritedPending(op, before)
		work[key] = drainWork{op, d, e, u, prior.SinceGeneration}
		return nil
	}
	for _, j := range jobs {
		for _, d := range j.desiredBatch {
			if err := add(j.kind, d, model.ExistingIssue{}, model.IssueUpdate{}); err != nil {
				return out, err
			}
		}
		for _, u := range j.updateBatch {
			if err := add(j.kind, u.Desired, u.Existing, u); err != nil {
				return out, err
			}
		}
	}
	for _, op := range operations {
		w, ok := work[op.WorkKey]
		if !ok || w.op.Kind != op.Kind || !slices.Equal(w.op.FingerprintSHA256s, op.FingerprintSHA256s) {
			return out, errors.New("drain-plan-operation-mismatch")
		}
	}
	// Issue ownership cannot migrate by fingerprint. Every old alias must
	// still be covered by that same issue operation. Creates may become issue
	// operations, but cannot vanish just because planning now sees a ticket.
	coveredCreates := map[string]bool{}
	for _, w := range work {
		for _, fingerprint := range w.op.FingerprintSHA256s {
			coveredCreates["create:"+fingerprint] = true
		}
	}
	for key, prior := range before.Entries {
		if strings.HasPrefix(key, "create:") {
			if !coveredCreates[key] {
				return out, errors.New("drain-pending-lost")
			}
			continue
		}
		w, ok := work[key]
		if !ok {
			return out, errors.New("drain-pending-lost")
		}
		for _, fingerprint := range prior.FingerprintSHA256s {
			if !slices.Contains(w.op.FingerprintSHA256s, fingerprint) {
				return out, errors.New("drain-pending-lost")
			}
		}
	}
	keys := make([]string, 0, len(work))
	for k := range work {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parent := map[string]string{}
	for _, k := range keys {
		parent[k] = k
	}
	var root func(string) string
	root = func(k string) string {
		if parent[k] != k {
			parent[k] = root(parent[k])
		}
		return parent[k]
	}
	join := func(a, b string) {
		if _, ok := work[a]; !ok {
			return
		}
		if _, ok := work[b]; !ok {
			return
		}
		ra, rb := root(a), root(b)
		if ra < rb {
			parent[rb] = ra
		} else {
			parent[ra] = rb
		}
	}
	identity := map[string]string{}
	for _, f := range findings {
		identity[f.Fingerprint] = model.FindingIdentity(f)
	}
	rebind := map[string]bool{}
	for _, r := range plan.Records {
		if r.MutationPlanned && r.Match == "identity-rebind" {
			rebind["issue:"+r.IssueID] = true
		}
	}
	for _, k := range keys {
		w := work[k]
		if w.op.Kind == "cancel-duplicate" {
			if c, ok := canonical[w.existing.Fingerprint]; ok {
				join(k, "issue:"+c.ID)
			}
		}
		if rebind[k] && identity[w.desired.Fingerprint] != "" {
			for _, other := range keys {
				v := work[other]
				if v.op.Kind == "create" && identity[v.desired.Fingerprint] == identity[w.desired.Fingerprint] {
					join(k, other)
				}
			}
		}
	}
	type group struct {
		keys []string
		age  int64
	}
	byRoot := map[string]*group{}
	for _, k := range keys {
		r := root(k)
		g := byRoot[r]
		if g == nil {
			g = &group{age: work[k].age}
			byRoot[r] = g
		}
		g.keys = append(g.keys, k)
		if work[k].age < g.age {
			g.age = work[k].age
		}
	}
	groups := make([]*group, 0, len(byRoot))
	for _, g := range byRoot {
		groups = append(groups, g)
	}
	slices.SortFunc(groups, func(a, b *group) int {
		if a.age < b.age {
			return -1
		}
		if a.age > b.age {
			return 1
		}
		if a.keys[0] < b.keys[0] {
			return -1
		}
		if a.keys[0] > b.keys[0] {
			return 1
		}
		return 0
	})
	counts := map[string]int64{}
	selected := map[string]bool{}
	for _, g := range groups {
		if int64(len(g.keys)) > limits.MaxIssueChanges {
			return out, errors.New("drain-oversized-group")
		}
		gc := map[string]int64{}
		for _, k := range g.keys {
			gc[work[k].op.Kind]++
		}
		fits := int64(len(selected)+len(g.keys)) <= limits.MaxIssueChanges
		for kind, n := range gc {
			if n > ceilings[kind] {
				return out, errors.New("drain-oversized-group")
			}
			if counts[kind]+n > ceilings[kind] {
				fits = false
			}
		}
		if fits {
			for _, k := range g.keys {
				selected[k] = true
			}
			for kind, n := range gc {
				counts[kind] += n
			}
		}
	}
	if len(work) > 0 && len(selected) == 0 {
		return out, errors.New("drain-no-progress")
	}
	for _, k := range keys {
		w := work[k]
		if selected[k] {
			out.selected = append(out.selected, w.op)
		} else {
			out.deferred = append(out.deferred, w.op)
			out.pending.Entries[k] = drainInheritedPending(w.op, before)
		}
	}
	// Stable action order and sorted targets; batches are always at most ten.
	for _, kind := range []jobKind{jobCreateBatch, jobUpdate, jobResolve, jobCancelDuplicate} {
		var batch job
		batch.kind = kind
		flush := func() {
			if len(batch.desiredBatch)+len(batch.updateBatch) > 0 {
				out.jobs = append(out.jobs, batch)
			}
			batch = job{kind: kind}
		}
		for _, k := range keys {
			w := work[k]
			if !selected[k] || w.op.Kind != string(kind) {
				continue
			}
			if kind == jobCreateBatch {
				batch.desiredBatch = append(batch.desiredBatch, w.desired)
			} else {
				batch.updateBatch = append(batch.updateBatch, w.update)
			}
			if len(batch.desiredBatch)+len(batch.updateBatch) == 10 {
				flush()
			}
		}
		flush()
	}
	selectedPlan := *plan
	selectedPlan.Records = nil
	for _, r := range plan.Records {
		if !r.MutationPlanned {
			continue
		}
		k := "issue:" + r.IssueID
		if r.Action == "create" {
			k = "create:" + r.FingerprintSHA256
		}
		if selected[k] {
			selectedPlan.Records = append(selectedPlan.Records, r)
		}
	}
	if err := validateBoundJobs(&selectedPlan, out.jobs); err != nil {
		return out, fmt.Errorf("selected jobs: %w", err)
	}
	return out, nil
}

// finishDrainPending keeps deferred ages unchanged and advances only the stall
// cumulative counter of selected work whose fresh effect did not verify.
// Only fresh verification removes work; replanning alone cannot discharge it.
func finishDrainPending(selection drainSelection, before DrainPending, verified map[string]bool) DrainPending {
	after := selection.pending
	entries := make(map[string]DrainPendingEntry, len(after.Entries)+len(selection.selected))
	maps.Copy(entries, after.Entries)
	after.Entries = entries
	for _, op := range selection.selected {
		if verified[op.WorkKey] {
			continue
		}
		entry := drainInheritedPending(op, before)
		entry.UnverifiedGenerations++
		after.Entries[op.WorkKey] = entry
	}
	return after
}
