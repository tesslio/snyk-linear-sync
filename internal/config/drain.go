package config

import (
	"encoding/hex"
	"errors"
	"strings"
)

// ValidateDrain checks the opt-in execution boundary before any source access.
// Prior digests bind caller-admitted evidence; they do not authenticate it.
func (c Config) ValidateDrain() error {
	if !c.PlanAndExecuteDrain {
		return errors.New("drain execution requires explicit opt-in")
	}
	if c.PlanAndExecuteBound || !c.ReplaySafe || c.DryRun || c.ReviewedPlanJSON != "" || c.ReviewedPlanSHA256 != "" || c.ObservationCheckpoint != "" || c.ObservationSourceSHA256 != "" || c.Cache.ClearIgnoresColdStart || c.Cache.BypassCache {
		return errors.New("drain execution requires replay-safe mode without another execution mode, bypass, or clearing protection")
	}
	if !IsLinearTeamUUID(c.Linear.TeamID) {
		return errors.New("drain execution requires immutable LINEAR_TEAM_ID UUID")
	}
	if strings.TrimSpace(c.Cache.DBFile) == "" {
		return errors.New("drain execution requires an admitted cache")
	}
	if strings.TrimSpace(c.PlanJSON) == "" || c.PlanJSON == "-" {
		return errors.New("drain execution requires a new private plan path")
	}
	if c.MaxIssueChanges == nil || *c.MaxIssueChanges < 1 || *c.MaxIssueChanges > 100 {
		return errors.New("drain execution requires max-issue-changes from 1 through 100")
	}
	for _, n := range []*int64{c.MaxCreates, c.MaxUpdates, c.MaxResolves, c.MaxCancelDuplicates} {
		if n == nil || *n < 0 || *n > 999999 {
			return errors.New("drain execution requires all four explicit limits between 0 and 999999")
		}
	}
	if len(c.DrainRunID) < 1 || len(c.DrainRunID) > 20 || c.DrainRunID[0] < '1' || c.DrainRunID[0] > '9' {
		return errors.New("drain run ID must be a canonical positive decimal string of at most twenty digits")
	}
	for _, r := range c.DrainRunID {
		if r < '0' || r > '9' {
			return errors.New("drain run ID must contain only decimal digits")
		}
	}
	if c.DrainRunAttempt != 1 {
		return errors.New("drain execution requires producer run attempt one")
	}
	for _, digest := range []string{c.ExpectedSettingsSHA256, c.DrainPriorEvidenceSHA256, c.DrainPriorPendingSHA256} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || strings.ToLower(digest) != digest {
			return errors.New("drain execution requires lowercase SHA-256 settings, prior evidence and prior pending digests")
		}
	}
	if c.Linear.UnsubscribeActor {
		return errors.New("drain execution requires LINEAR_UNSUBSCRIBE_ACTOR=false until cleanup has explicit effect accounting")
	}
	return nil
}
