package sync

import (
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// DueDateScenario describes one possible due date computation for a finding.
type DueDateScenario struct {
	Name    string `json:"name"`
	DueDate string `json:"due_date"`
	Base    string `json:"base"`
	Reason  string `json:"reason"`
}

// DueDateDiagnostics contains the full picture for a single managed issue and
// its matching Snyk finding.
type DueDateDiagnostics struct {
	Finding                   model.Finding       `json:"finding"`
	Existing                  model.ExistingIssue `json:"existing"`
	Desired                   model.DesiredIssue  `json:"desired"`
	Diff                      *model.IssueDiff    `json:"diff"`
	WouldUpdate               bool                `json:"would_update"`
	Scenarios                 []DueDateScenario   `json:"scenarios"`
	WasAwaitingFix            bool                `json:"was_awaiting_fix"`
	FixAvailabilityScenario   DueDateScenario     `json:"fix_availability_scenario"`
	SnykHash                  string              `json:"snyk_hash"`
	LinearHash                string              `json:"linear_hash"`
	PendingTerminalTransition bool                `json:"pending_terminal_transition"`
}

// DiagnoseDueDate computes the desired issue, the diff against the existing
// Linear issue, and every plausible due date scenario for a single finding.
func DiagnoseDueDate(cfg config.Config, finding model.Finding, existing model.ExistingIssue) DueDateDiagnostics {
	desired := desiredIssue(cfg, finding)

	awaitingFix := wasAwaitingFix(existing, cfg.Linear.Labels.AwaitingFix)

	diff := ComputeDiff(existing, desired, cfg.Linear.States)

	scenarios := make([]DueDateScenario, 0, 2)
	if creationDueDate, creationBase, creationReason := issueDueDateFromCreatedAt(cfg.Linear.Due, finding); creationDueDate != "" {
		scenarios = append(scenarios, DueDateScenario{
			Name:    "issue creation (CreatedAt + severity SLA)",
			DueDate: creationDueDate,
			Base:    creationBase,
			Reason:  creationReason,
		})
	}
	if ignoreExpiryDueDate, ignoreExpiryBase, ignoreExpiryReason := issueDueDateFromIgnoreExpiry(cfg.Linear.Due, finding); ignoreExpiryDueDate != "" {
		scenarios = append(scenarios, DueDateScenario{
			Name:    "ignore expiry (IgnoreExpiresAt + severity SLA)",
			DueDate: ignoreExpiryDueDate,
			Base:    ignoreExpiryBase,
			Reason:  ignoreExpiryReason,
		})
	}

	fixAvailabilityDueDate, fixAvailabilityBase, fixAvailabilityReason := issueDueDateFromIgnoreEnd(cfg.Linear.Due, finding)

	return DueDateDiagnostics{
		Finding:                   finding,
		Existing:                  existing,
		Desired:                   desired,
		Diff:                      diff,
		WouldUpdate:               needsUpdate(existing, desired, cfg.Linear.States),
		WasAwaitingFix:            awaitingFix,
		FixAvailabilityScenario:   dueDateScenario("fix availability (IgnoreEndedAt + severity SLA)", fixAvailabilityDueDate, fixAvailabilityBase, fixAvailabilityReason),
		Scenarios:                 scenarios,
		SnykHash:                  desiredIssueHash(desired),
		LinearHash:                existingIssueHash(existing),
		PendingTerminalTransition: pendingTerminalTransition(existing, desired),
	}
}

func dueDateScenario(name, dueDate, base, reason string) DueDateScenario {
	return DueDateScenario{
		Name:    name,
		DueDate: dueDate,
		Base:    base,
		Reason:  reason,
	}
}

func issueDueDateFromCreatedAt(dueCfg config.DueDateConfig, finding model.Finding) (string, string, string) {
	if finding.CreatedAt.IsZero() {
		return "", "", ""
	}
	return dueDateFromBase(utcDate(finding.CreatedAt), "issue creation", dueCfg, finding)
}

func issueDueDateFromIgnoreExpiry(dueCfg config.DueDateConfig, finding model.Finding) (string, string, string) {
	if finding.IgnoreExpiresAt.IsZero() {
		return "", "", ""
	}
	return dueDateFromBase(utcDate(finding.IgnoreExpiresAt), "ignore expiry", dueCfg, finding)
}

// issueDueDateFromIgnoreEnd is the scenario for an ignore-until-fix-available
// ignore that stopped applying: the SLA from the day the fix arrived (or the
// ignore was revoked), as the ignore cache remembers it. Empty when the
// finding carries no such end.
func issueDueDateFromIgnoreEnd(dueCfg config.DueDateConfig, finding model.Finding) (string, string, string) {
	if finding.IgnoreEndedAt.IsZero() {
		return "", "", ""
	}
	return dueDateFromBase(utcDate(finding.IgnoreEndedAt), "fix availability", dueCfg, finding)
}
