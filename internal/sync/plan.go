package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// ReconciliationPlan describes the decisions of one completed dry run. It is
// private operational data, not a write receipt or a promise that a later run
// will produce the same decisions. Titles, descriptions, source paths, URLs and
// credentials are deliberately absent. Source fingerprints are digested because
// their plaintext can contain source paths.
type ReconciliationPlan struct {
	Version               int          `json:"version"`
	Complete              bool         `json:"complete"`
	LinearWritesAttempted bool         `json:"linear_writes_attempted"`
	LocalCacheMayChange   bool         `json:"local_cache_may_change"`
	Inputs                PlanInputs   `json:"inputs"`
	Guard                 PlanGuard    `json:"cold_start_guard"`
	Summary               PlanSummary  `json:"summary"`
	Records               []PlanRecord `json:"records"`
	ReopenHistoryStatus   string       `json:"reopen_history_status"`
	DecisionsSHA256       string       `json:"decisions_sha256"`
}

type PlanInputs struct {
	// Snapshot hashes preserve input slice order, which can affect matching.
	SnykSHA256       string `json:"snyk_sha256"`
	LinearSHA256     string `json:"linear_sha256"`
	SettingsSHA256   string `json:"settings_sha256"`
	SyncCacheSHA256  string `json:"sync_cache_sha256"`
	SyncCacheEnabled bool   `json:"sync_cache_enabled"`
}

type PlanGuard struct {
	Active              bool `json:"active"`
	UntrustedEmptyStart bool `json:"untrusted_empty_start"`
}

type PlanSummary struct {
	Findings              int   `json:"findings"`
	ExistingIssues        int   `json:"existing_issues"`
	CoveredFindings       int   `json:"covered_findings"`
	CoveredExistingIssues int   `json:"covered_existing_issues"`
	Creates               int64 `json:"creates"`
	Updates               int64 `json:"updates"`
	Resolves              int64 `json:"resolves"`
	CancelDuplicates      int64 `json:"cancel_duplicates"`
	DeferredCreates       int64 `json:"deferred_creates"`
	Rebound               int64 `json:"rebound"`
	Reopened              int64 `json:"reopened"`
	HeldDueDates          int64 `json:"held_due_dates"`
}

type PlanRecord struct {
	// One-based snapshot indexes make coverage independently checkable without
	// including raw Snyk project IDs or location-bearing fingerprints.
	FindingIndex              int         `json:"finding_index,omitempty"`
	ExistingIndex             int         `json:"existing_index,omitempty"`
	FingerprintSHA256         string      `json:"fingerprint_sha256,omitempty"`
	PreviousFingerprintSHA256 string      `json:"previous_fingerprint_sha256,omitempty"`
	IssueID                   string      `json:"issue_id,omitempty"`
	Identifier                string      `json:"identifier,omitempty"`
	Action                    string      `json:"action"`
	Reason                    string      `json:"reason"`
	CandidatePresent          bool        `json:"candidate_present"`
	MutationPlanned           bool        `json:"mutation_planned"`
	ExecutionStatus           string      `json:"execution_status"`
	Match                     string      `json:"match,omitempty"`
	Reopen                    bool        `json:"reopen"`
	HistoryStateFound         bool        `json:"history_state_found"`
	DueDate                   PlanDueDate `json:"due_date"`
	State                     PlanState   `json:"state"`
	Labels                    PlanLabels  `json:"labels"`
	CandidateDiff             PlanDiff    `json:"candidate_diff"`
}

type PlanDueDate struct {
	Before     string `json:"before"`
	Calculated string `json:"calculated"`
	// RawSLADueDate is the deadline before sticky-date and cold-start overrides,
	// not the timestamp from which the SLA is measured.
	RawSLADueDate         string `json:"raw_sla_due_date"`
	Proposed              string `json:"proposed"`
	Planned               string `json:"planned"`
	CalculatedReason      string `json:"calculated_reason"`
	Reason                string `json:"reason"`
	HeldByColdStart       bool   `json:"held_by_cold_start"`
	UsedUpdatedAtFallback bool   `json:"used_updated_at_fallback"`
	CreatedAt             string `json:"created_at,omitempty"`
	UpdatedAt             string `json:"updated_at,omitempty"`
	IgnoreExpiresAt       string `json:"ignore_expires_at,omitempty"`
	IgnoreEndedAt         string `json:"ignore_ended_at,omitempty"`
}

type PlanState struct {
	BeforeID         string `json:"before_id"`
	Before           string `json:"before"`
	ProposedModel    string `json:"proposed_model"`
	ConfiguredTarget string `json:"configured_target"`
	Preserve         bool   `json:"preserve"`
	RestoreID        string `json:"restore_id,omitempty"`
	RestoreName      string `json:"restore_name,omitempty"`
	Reason           string `json:"reason"`
	// State and label IDs are resolved only by the real mutation path. The
	// exporter reports intent, without claiming that resolution succeeded.
	ResolutionStatus string `json:"resolution_status"`
}

type PlanLabels struct {
	BeforeManaged       []string `json:"before_managed"`
	SnapshotNames       []string `json:"snapshot_names"`
	RequestedManaged    []string `json:"requested_managed"`
	RequestedCreateOnly []string `json:"requested_create_only"`
	Protected           []string `json:"protected"`
	Added               []string `json:"added"`
	Removed             []string `json:"removed"`
	ResolutionStatus    string   `json:"resolution_status"`
}

type PlanDiff struct {
	TitleChanged        bool `json:"title_changed"`
	DescriptionChanged  bool `json:"description_changed"`
	MetadataOnly        bool `json:"metadata_only"`
	AwaitingFixBackfill bool `json:"awaiting_fix_backfill"`
	DueDateChanged      bool `json:"due_date_changed"`
	StateChanged        bool `json:"state_changed"`
	PriorityChanged     bool `json:"priority_changed"`
	PriorityBefore      int  `json:"priority_before"`
	PriorityProposed    int  `json:"priority_proposed"`
	LabelsChanged       bool `json:"labels_changed"`
}

type planFinding struct {
	finding model.Finding
	raw     model.DesiredIssue
	index   int
	match   string
	held    bool
}

type planCollector struct {
	plan            *ReconciliationPlan
	cfg             config.Config
	findings        []model.Finding
	existing        []model.ExistingIssue
	contexts        map[string]planFinding
	coveredFindings map[int]bool
	coveredExisting map[int]bool
	existingIndexes map[string]int
	retainedReasons map[string]string
}

func newPlanCollector(cfg config.Config, snapshot model.SnykSnapshot, existing []model.ExistingIssue, cached cache.Snapshot, cacheEnabled bool) (*planCollector, error) {
	if cfg.PlanJSON == "" && cfg.ReviewedPlanJSON == "" {
		return nil, nil
	}
	// Explicit allowlist: never marshal Config, which contains credentials.
	settings := struct {
		Region, Organization, Team                              string
		Scopes                                                  []string
		Source                                                  config.SourceConfig
		States                                                  config.StateConfig
		Labels                                                  config.LabelConfig
		Due                                                     config.DueDateConfig
		ArchiveLookbackDays                                     int
		Comments, UnsubscribeActor, BypassCache, ClearColdStart bool
	}{cfg.Snyk.Region, cfg.Snyk.OrgID, cfg.Linear.TeamID, cfg.Snyk.Scopes,
		cfg.Source, cfg.Linear.States, cfg.Linear.Labels, cfg.Linear.Due,
		cfg.Linear.ArchiveLookbackDays, cfg.Linear.CommentsEnabled, cfg.Linear.UnsubscribeActor,
		cfg.Cache.BypassCache, cfg.Cache.ClearIgnoresColdStart}
	inputs := PlanInputs{SyncCacheEnabled: cacheEnabled}
	var err error
	for _, item := range []struct {
		value any
		dest  *string
	}{
		{snapshot, &inputs.SnykSHA256}, {existing, &inputs.LinearSHA256},
		{settings, &inputs.SettingsSHA256}, {cached, &inputs.SyncCacheSHA256},
	} {
		*item.dest, err = planDigest(item.value)
		if err != nil {
			return nil, fmt.Errorf("fingerprint dry-run inputs: %w", err)
		}
	}
	indexes := make(map[string]int, len(existing))
	for i, issue := range existing {
		// A repeated API row can produce more than one reconciliation action
		// for the same ID. Do not invent per-row provenance or claim retention
		// for a row whose action was attributed elsewhere. Fail export closed;
		// the ordinary sync path is unchanged when export is disabled.
		if issue.ID == "" {
			return nil, fmt.Errorf("dry-run plan requires a Linear issue ID at snapshot index %d", i+1)
		}
		if first, ok := indexes[issue.ID]; ok {
			return nil, fmt.Errorf("dry-run plan cannot attribute repeated Linear issue IDs at snapshot indexes %d and %d", first, i+1)
		}
		indexes[issue.ID] = i + 1
	}
	return &planCollector{
		plan: &ReconciliationPlan{Version: 1, LocalCacheMayChange: true, Inputs: inputs, Records: []PlanRecord{}, ReopenHistoryStatus: "not_needed"},
		cfg:  cfg, findings: snapshot.Findings, existing: existing, existingIndexes: indexes,
		contexts: map[string]planFinding{}, coveredFindings: map[int]bool{}, coveredExisting: map[int]bool{}, retainedReasons: map[string]string{},
	}, nil
}

func (p *planCollector) finding(index int, finding model.Finding, raw model.DesiredIssue) {
	if p == nil {
		return
	}
	// Reconciliation can retain an earlier coarse/rebind match when a later
	// duplicate source fingerprint has already depleted that candidate.
	priorMatch := p.contexts[finding.Fingerprint].match
	p.contexts[finding.Fingerprint] = planFinding{finding: finding, raw: raw, index: index + 1, match: priorMatch}
}
func (p *planCollector) matched(fingerprint string, kind matchKind, held bool) {
	if p == nil {
		return
	}
	c := p.contexts[fingerprint]
	c.match = map[matchKind]string{matchExact: "exact", matchCoarse: "coarse-migration", matchRebind: "identity-rebind"}[kind]
	c.held = held
	p.contexts[fingerprint] = c
}
func (p *planCollector) retained(id, reason string) {
	if p != nil {
		p.retainedReasons[id] = reason
	}
}

func (p *planCollector) add(action, reason, fingerprint string, existing *model.ExistingIssue, desired *model.DesiredIssue) {
	if p == nil {
		return
	}
	r := p.record(action, reason)
	r.MutationPlanned = action == "create" || action == "update" || action == "resolve" || action == "cancel-duplicate"
	if fingerprint != "" {
		r.FingerprintSHA256 = planTextDigest(fingerprint)
	}
	// Resolution and duplicate records must not claim a source finding that
	// belongs to a different canonical ticket.
	c, hasFinding := p.contexts[fingerprint]
	if action == "resolve" || action == "cancel-duplicate" || action == "retain" {
		hasFinding = false
	}
	if hasFinding {
		r.FindingIndex = c.index
		p.coveredFindings[c.index] = true
		r.Match = c.match
		r.DueDate.Calculated = c.raw.DueDate
		r.DueDate.RawSLADueDate = c.raw.DueDateBase
		r.DueDate.CalculatedReason = c.raw.DueDateReason
		r.DueDate.UsedUpdatedAtFallback = c.raw.DueDateUsedUpdatedAtFallback
		r.DueDate.HeldByColdStart = c.held
		r.DueDate.CreatedAt = planTime(c.finding.CreatedAt)
		r.DueDate.UpdatedAt = planTime(c.finding.UpdatedAt)
		r.DueDate.IgnoreExpiresAt = planTime(c.finding.IgnoreExpiresAt)
		r.DueDate.IgnoreEndedAt = planTime(c.finding.IgnoreEndedAt)
	}
	var before model.ExistingIssue
	if existing != nil {
		before = *existing
		r.IssueID = before.ID
		r.Identifier = before.Identifier
		r.ExistingIndex = p.existingIndexes[before.ID]
		if r.ExistingIndex > 0 {
			p.coveredExisting[r.ExistingIndex] = true
		}
		if before.Fingerprint != "" {
			r.PreviousFingerprintSHA256 = planTextDigest(before.Fingerprint)
		}
		r.DueDate.Before = before.DueDate
		r.DueDate.Planned = before.DueDate
		r.State.BeforeID = before.StateID
		r.State.Before = before.StateName
		r.Labels.BeforeManaged = planStrings(before.ManagedLabels)
		var names []string
		for _, label := range before.Labels {
			names = append(names, label.Name)
		}
		r.Labels.SnapshotNames = planStrings(names)
		r.CandidateDiff.PriorityBefore = before.Priority
	}
	if desired != nil {
		r.CandidatePresent = true
		r.Reopen = desired.Reopen
		r.HistoryStateFound = desired.RestoreState.ID != ""
		r.DueDate.Proposed = desired.DueDate
		r.DueDate.Reason = desired.DueDateReason
		if r.MutationPlanned {
			r.DueDate.Planned = desired.DueDate
		}
		r.State.ProposedModel = model.StateName(desired.State)
		r.State.ConfiguredTarget = p.configuredState(desired.State)
		r.State.Preserve = desired.PreserveState
		r.State.RestoreID = desired.RestoreState.ID
		r.State.RestoreName = desired.RestoreState.Name
		r.State.Reason = desired.StateReason
		r.Labels.RequestedManaged = planStrings(desired.ManagedLabels)
		if action == "create" {
			r.Labels.RequestedCreateOnly = planStrings(desired.CreateOnlyLabels)
		}
		diff := ComputeDiff(before, *desired, p.cfg.Linear.States)
		r.Labels.Added = planStrings(diff.LabelsAdded)
		r.Labels.Removed = planStrings(diff.LabelsRemoved)
		r.CandidateDiff = PlanDiff{TitleChanged: diff.TitleChanged, DescriptionChanged: diff.DescriptionChanged,
			MetadataOnly: diff.MetadataOnlyDescriptionChange, DueDateChanged: diff.DueDateChanged, StateChanged: diff.StateChanged,
			PriorityChanged: diff.PriorityChanged, PriorityBefore: before.Priority, PriorityProposed: desired.Priority, LabelsChanged: diff.LabelsNeedUpdate,
			AwaitingFixBackfill: existing != nil && !before.AwaitingFix && hasFinding && c.finding.Status == model.FindingAwaitingFix && diff.DescriptionChanged,
		}
	}
	p.plan.Records = append(p.plan.Records, r)
}

func (p *planCollector) record(action, reason string) PlanRecord {
	return PlanRecord{Action: action, Reason: reason, ExecutionStatus: "not_attempted",
		State:  PlanState{ResolutionStatus: "not_attempted"},
		Labels: PlanLabels{BeforeManaged: []string{}, SnapshotNames: []string{}, RequestedManaged: []string{}, RequestedCreateOnly: []string{}, Protected: planStrings(p.cfg.Linear.Labels.Protected), Added: []string{}, Removed: []string{}, ResolutionStatus: "not_attempted_live_labels_and_groups_not_resolved"},
	}
}

func (p *planCollector) configuredState(state model.IssueState) string {
	switch state {
	case model.StateTodo:
		return p.cfg.Linear.States.Todo
	case model.StateBacklog:
		return p.cfg.Linear.States.Backlog
	case model.StateDone:
		return p.cfg.Linear.States.Done
	case model.StateCancelled:
		return p.cfg.Linear.States.Cancelled
	default:
		return ""
	}
}

func (p *planCollector) finish(result RunResult, guard coldStartGuard) (*ReconciliationPlan, error) {
	if p == nil {
		return nil, nil
	}
	for i, f := range p.findings {
		if !p.coveredFindings[i+1] {
			if p.contexts[f.Fingerprint].index == i+1 {
				return nil, fmt.Errorf("dry-run plan is missing a source finding decision")
			}
			r := p.record("no-op", "superseded-source-fingerprint")
			r.FindingIndex = i + 1
			r.FingerprintSHA256 = planTextDigest(f.Fingerprint)
			p.plan.Records = append(p.plan.Records, r)
			p.coveredFindings[i+1] = true
		}
	}
	for i, issue := range p.existing {
		if !p.coveredExisting[i+1] {
			reason := p.retainedReasons[issue.ID]
			if reason == "" {
				reason = "seen-fingerprint-retained"
			}
			if issue.Fingerprint == "" {
				reason = "no-managed-fingerprint"
			}
			p.add("retain", reason, issue.Fingerprint, &issue, nil)
		}
	}
	slices.SortFunc(p.plan.Records, func(a, b PlanRecord) int {
		if n := strings.Compare(a.FingerprintSHA256, b.FingerprintSHA256); n != 0 {
			return n
		}
		if a.FindingIndex != b.FindingIndex {
			return a.FindingIndex - b.FindingIndex
		}
		if a.ExistingIndex != b.ExistingIndex {
			return a.ExistingIndex - b.ExistingIndex
		}
		return strings.Compare(a.Action, b.Action)
	})
	p.plan.Guard = PlanGuard{Active: guard.active, UntrustedEmptyStart: guard.tableEmpty}
	p.plan.Summary = PlanSummary{Findings: result.Findings, ExistingIssues: result.ExistingIssues,
		CoveredFindings: len(p.coveredFindings), CoveredExistingIssues: len(p.coveredExisting),
		Creates: result.PlannedCreates, Updates: result.PlannedUpdates, Resolves: result.PlannedResolves, CancelDuplicates: result.CancelledDuplicates,
		DeferredCreates: result.DeferredCreates, Rebound: result.Rebound, Reopened: result.Reopened, HeldDueDates: result.HeldDueDates}
	var creates, updates, resolves, duplicates int64
	for _, record := range p.plan.Records {
		switch record.Action {
		case "create":
			creates++
		case "update":
			updates++
		case "resolve":
			resolves++
		case "cancel-duplicate":
			duplicates++
		}
	}
	if creates != result.PlannedCreates || updates != result.PlannedUpdates || resolves != result.PlannedResolves || duplicates != result.CancelledDuplicates {
		return nil, fmt.Errorf("dry-run plan operation coverage does not match reconciliation counters")
	}
	digest, err := planDigest(p.plan.Records)
	if err != nil {
		return nil, err
	}
	p.plan.DecisionsSHA256 = digest
	p.plan.Complete = true
	return p.plan, nil
}

func planTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func planStrings(values []string) []string {
	out := append([]string{}, values...)
	slices.Sort(out)
	return slices.Compact(out)
}
func planTextDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func planDigest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return planTextDigest(string(data)), nil
}

// WritePlanJSON creates a private new artifact, never overwriting an existing
// file or following a final-component symlink. On a write/close error it removes
// the incomplete file. Consumers must require a successful process exit and a
// complete plan before using the artifact.
func WritePlanJSON(path string, plan *ReconciliationPlan) (err error) {
	if plan == nil || !plan.Complete || plan.LinearWritesAttempted {
		return fmt.Errorf("refusing to export an incomplete or non-dry-run plan")
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("encode dry-run plan: %w", err)
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create private dry-run plan: %w", err)
	}
	defer func() {
		if err != nil {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return fmt.Errorf("write dry-run plan: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync dry-run plan: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close dry-run plan: %w", err)
	}
	return nil
}
