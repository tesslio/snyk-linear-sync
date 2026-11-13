package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/httpx"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

// A drain run consumes one private output directory. The caller must authenticate
// the prior producer and supply the admitted row digests before invoking it.
// There is deliberately no initializer, legacy fallback or implicit retry here.
type drainRun struct {
	files           *boundRun
	pending         DrainPending
	attempt         DrainAttempt
	result          DrainResult
	selection       drainSelection
	uncertainCreate bool
	commentWorkKeys []string
}

func reserveDrainRun(cfg config.Config) (*drainRun, error) {
	files, err := reserveBoundRun(cfg.PlanJSON)
	if err != nil {
		return nil, err
	}
	return &drainRun{files: files, result: DrainResult{Version: 2, Status: "failed_before_writes", CacheStatus: "not_saved", ProducerRunID: cfg.DrainRunID, ProducerRunAttempt: cfg.DrainRunAttempt, Verified: []string{}, Unverified: []string{}, Created: map[string]string{}, AuxiliaryComments: DrainAuxiliaryComments{Policy: "disabled"}}}, nil
}

func (d *drainRun) admit(cfg config.Config, snapshot cache.Snapshot) error {
	pending, evidence, err := validateDrainSnapshot(snapshot)
	if err != nil {
		return err
	}
	if planTextDigest(string(snapshot.BoundedDrainPending)) != cfg.DrainPriorPendingSHA256 || planTextDigest(string(snapshot.BoundedDrainHashEvidence)) != cfg.DrainPriorEvidenceSHA256 {
		return errors.New("drain-prior-admission-mismatch")
	}
	if evidence.ProducerRunID == cfg.DrainRunID || pending.Generation >= (1<<53)-1 {
		return errors.New("drain-generation-chain")
	}
	for _, e := range pending.Entries {
		if e.UnverifiedGenerations >= 3 {
			return errors.New("drain-stalled-effect")
		}
	}
	d.pending = pending
	d.result.Generation = pending.Generation + 1
	return nil
}

func (d *drainRun) write(name string, value any) ([]byte, error) {
	if err := d.files.unchanged(); err != nil {
		return nil, err
	}
	data, err := canonicalDrainJSON(value)
	limit := drainReceiptByteCeiling
	root, target := d.files.root, name
	if name == "plan.json" {
		data, err = json.MarshalIndent(value, "", "  ")
		data = append(data, '\n')
		limit = drainPlanByteCeiling
		root, target = d.files.planRoot, d.files.planName
	}
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("drain-artifact-oversized")
	}
	f, err := root.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	_, we := f.Write(data)
	se := f.Sync()
	ce := f.Close()
	if err = errors.Join(we, se, ce); err != nil {
		return nil, err
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	se = dir.Sync()
	ce = dir.Close()
	return data, errors.Join(se, ce)
}

func drainCounts(ops []DrainOperation) DrainCounts {
	var c DrainCounts
	for _, op := range ops {
		switch op.Kind {
		case "create":
			c.Creates++
		case "update":
			c.Updates++
		case "resolve":
			c.Resolves++
		case "cancel-duplicate":
			c.CancelDuplicates++
		}
	}
	return c
}
func drainKeySet(keys []string) DrainKeySet {
	slices.Sort(keys)
	digest, _ := drainDigest(keys)
	return DrainKeySet{Count: len(keys), SHA256: digest}
}
func drainMapSet[V any](m map[string]V) DrainKeySet {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, planTextDigest(k))
	}
	return drainKeySet(keys)
}

func (d *drainRun) bind(cfg config.Config, plan *ReconciliationPlan, jobs []job, findings []model.Finding, matched map[string]model.ExistingIssue, before []model.ExistingIssue) error {
	if plan.Inputs.SettingsSHA256 != cfg.ExpectedSettingsSHA256 || plan.Summary.DeferredCreates != 0 {
		return errors.New("drain-settings-or-source-deferral")
	}
	limits := DrainLimits{*cfg.MaxIssueChanges, *cfg.MaxCreates, *cfg.MaxUpdates, *cfg.MaxResolves, *cfg.MaxCancelDuplicates}
	selection, err := selectDrain(plan, jobs, d.pending, limits, findings, matched)
	if err != nil {
		return err
	}
	full := append(slices.Clone(selection.selected), selection.deferred...)
	if _, err = drainEvidenceBound(drainPreWriteHashes(before, matched), jobs, full); err != nil {
		return err
	}
	d.selection = selection
	selectedDigest, err := drainDigest(selection.selected)
	if err != nil {
		return err
	}
	deferredDigest, err := drainDigest(selection.deferred)
	if err != nil {
		return err
	}
	jobsDigest, err := boundJobsDigest(selection.jobs)
	if err != nil {
		return err
	}
	// Check both artifacts' exact size before creating either or attempting writes.
	planBytes, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	planBytes = append(planBytes, '\n')
	if len(planBytes) > drainPlanByteCeiling {
		return errors.New("drain-artifact-oversized")
	}
	d.attempt = DrainAttempt{Version: 2, Status: "attempt_started", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ProducerRunID: cfg.DrainRunID, ProducerRunAttempt: cfg.DrainRunAttempt, Generation: d.pending.Generation + 1, RestoredGeneration: d.pending.Generation, RestoredHashEvidenceSHA256: cfg.DrainPriorEvidenceSHA256, PendingBeforeSHA256: cfg.DrainPriorPendingSHA256, FullPlanSHA256: planTextDigest(string(planBytes)), JobsSHA256: jobsDigest, SelectedOpsSHA256: selectedDigest, DeferredOpsSHA256: deferredDigest, SettingsSHA256: plan.Inputs.SettingsSHA256, FullCounts: drainCounts(full), SelectedCounts: drainCounts(selection.selected), DeferredCounts: drainCounts(selection.deferred), Limits: limits, Selected: selection.selected, Deferred: selection.deferred, Batches: len(selection.jobs)}
	attemptBytes, err := canonicalDrainJSON(d.attempt)
	if err != nil {
		return err
	}
	if len(attemptBytes) > drainReceiptByteCeiling {
		return errors.New("drain-artifact-oversized")
	}
	d.result.FullPlanSHA256 = d.attempt.FullPlanSHA256
	d.result.JobsSHA256 = jobsDigest
	d.result.SelectedOpsSHA256 = selectedDigest
	d.result.DeferredOpsSHA256 = deferredDigest
	d.result.SettingsSHA256 = plan.Inputs.SettingsSHA256
	d.files.planBytes, err = d.write("plan.json", plan)
	if err != nil {
		return err
	}
	d.files.attemptBytes, err = d.write("attempt.json", d.attempt)
	d.files.attempt.JobsSHA256 = jobsDigest
	return err
}

func (d *drainRun) finish(runErr error) error {
	defer d.files.close()
	d.result.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if runErr == nil {
		d.result.Status = "success"
	}
	_, err := d.write("result.json", d.result)
	return errors.Join(runErr, err)
}

// executeDrainJob never retries a mutation. Comment attempts are separate from
// issue batch acknowledgements. Subscription cleanup is forbidden by config.
func (s *Service) executeDrainJob(ctx context.Context, d *drainRun, j job) error {
	ctx = httpx.WithoutRetries(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	d.result.Status = "partial_or_uncertain"
	d.result.LinearWritesAttempted = true
	d.result.BatchesAttempted++
	switch j.kind {
	case jobCreateBatch:
		outcomes, err := s.linear.CreateIssues(ctx, j.desiredBatch)
		failed, shapeErr := failedCreateOutcomes(outcomes, len(j.desiredBatch))
		// A missing ID cannot prove non-creation, even after an empty fresh read.
		// Do not emit a publishable checkpoint that permits a later duplicate.
		d.uncertainCreate = shapeErr != nil || len(failed) > 0
		if shapeErr == nil {
			for _, outcome := range outcomes {
				if outcome.Acknowledged {
					if !drainValidWorkKey("issue:" + outcome.ID) {
						d.uncertainCreate = true
						return errors.New("drain-create-id-invalid")
					}
					d.result.Created[drainWorkKey(j.kind, j.desiredBatch[outcome.Index], model.ExistingIssue{})] = outcome.ID
				}
			}
		}
		if err = errors.Join(err, shapeErr); err != nil {
			return err
		}
		if len(failed) > 0 {
			return errors.New("drain-create-unacknowledged")
		}
	case jobUpdate, jobResolve, jobCancelDuplicate:
		if err := s.linear.UpdateIssues(ctx, j.updateBatch); err != nil {
			return err
		}
	default:
		return errors.New("drain-job-invalid")
	}
	d.result.BatchesAcknowledged++
	if j.kind == jobUpdate && s.cfg.Linear.CommentsEnabled {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, update := range j.updateBatch {
			d.commentWorkKeys = append(d.commentWorkKeys, drainWorkKey(j.kind, update.Desired, update.Existing))
		}
		d.result.AuxiliaryComments.BatchesAttempted++
		failed, err := s.linear.PostComments(ctx, j.updateBatch)
		if err != nil {
			return err
		}
		if len(failed) > 0 {
			return errors.New("drain-comment-unacknowledged")
		}
		d.result.AuxiliaryComments.BatchesAcknowledged++
	}
	return nil
}

func (s *Service) executeDrain(ctx context.Context, d *drainRun, plan *ReconciliationPlan, jobs []job, findings []model.Finding, matched map[string]model.ExistingIssue, before []model.ExistingIssue, snykHashes map[string]string) error {
	if len(snykHashes) == 0 {
		return errors.New("drain-source-empty")
	}
	if err := d.bind(s.cfg, plan, jobs, findings, matched, before); err != nil {
		return err
	}
	if s.cfg.Linear.CommentsEnabled {
		d.result.AuxiliaryComments.Policy = "per-batch-once"
	}
	var mutationErr error
	for _, j := range d.selection.jobs {
		if err := d.files.verify(d.selection.jobs); err != nil {
			return err
		}
		if mutationErr = s.executeDrainJob(ctx, d, j); mutationErr != nil {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(mutationErr, err)
	}
	if d.uncertainCreate {
		return errors.Join(mutationErr, errors.New("drain-create-reconciliation-required"))
	}
	d.result.CacheStatus = "refresh_failed_or_uncertain"
	after, err := s.linear.LoadSnapshot(httpx.WithoutRetries(ctx))
	if err != nil {
		return errors.Join(mutationErr, err)
	}
	_, after, err = canonicalReplayInputs(model.SnykSnapshot{}, after)
	if err != nil {
		return errors.Join(mutationErr, err)
	}
	verified := verifyDrainEffects(d.selection.jobs, d.result.Created, before, after, s.cfg.Linear.States)
	if err = verifyDrainMembership(before, after, d.selection.jobs, d.result.Created, verified); err != nil {
		return errors.Join(mutationErr, err)
	}
	// A later generation must not replay an uncertain comment while retrying
	// an unverified update. Such a batch requires explicit reconciliation.
	for _, key := range d.commentWorkKeys {
		if !verified[key] {
			return errors.Join(mutationErr, errors.New("drain-comment-reconciliation-required"))
		}
	}
	pending := finishDrainPending(d.selection, d.pending, verified)
	evidence, saved, arrivals, err := buildDrainEvidence(drainPreWriteHashes(before, matched), drainRefreshedHashes(after, matched, d.selection.jobs, d.result.Created), d.selection.selected, d.selection.deferred, d.selection.jobs, verified)
	if err != nil {
		return errors.Join(mutationErr, err)
	}
	evidence.Generation = d.attempt.Generation
	evidence.ProducerRunID = d.attempt.ProducerRunID
	evidence.ProducerRunAttempt = d.attempt.ProducerRunAttempt
	evidence.FullPlanSHA256 = d.attempt.FullPlanSHA256
	evidence.SelectedOpsSHA256 = d.attempt.SelectedOpsSHA256
	evidence.DeferredOpsSHA256 = d.attempt.DeferredOpsSHA256
	evidence.SettingsSHA256 = d.attempt.SettingsSHA256
	evidence.PendingAfterSHA256, err = drainDigest(pending)
	if err != nil {
		return err
	}
	pendingBytes, err := canonicalDrainJSON(pending)
	if err != nil {
		return err
	}
	evidenceBytes, err := canonicalDrainJSON(evidence)
	if err != nil {
		return err
	}
	next := cache.Snapshot{SchemaSignature: managedSchemaSignature() + "+drain-v1", SnykHashes: snykHashes, LinearHashes: saved, BoundedDrainPending: pendingBytes, BoundedDrainHashEvidence: evidenceBytes}
	if _, _, err = validateDrainSnapshot(next); err != nil {
		return errors.Join(mutationErr, err)
	}
	for _, op := range d.selection.selected {
		if verified[op.WorkKey] {
			d.result.Verified = append(d.result.Verified, op.WorkKey)
		} else {
			d.result.Unverified = append(d.result.Unverified, op.WorkKey)
		}
	}
	slices.Sort(d.result.Verified)
	slices.Sort(d.result.Unverified)
	d.result.PendingAfterSHA256 = evidence.PendingAfterSHA256
	d.result.HashEvidenceSHA256 = planTextDigest(string(evidenceBytes))
	d.result.Refreshed = drainMapSet(evidence.Refreshed)
	d.result.Withheld = drainMapSet(evidence.Withheld)
	d.result.Saved = drainMapSet(saved)
	d.result.Arrivals = drainKeySet(arrivals)
	if len(d.result.Unverified) > 0 {
		mutationErr = errors.Join(mutationErr, errors.New("drain-effects-unverified"))
	}
	if err = d.files.verify(d.selection.jobs); err != nil {
		return errors.Join(mutationErr, err)
	}
	if err = ctx.Err(); err != nil {
		return errors.Join(mutationErr, err)
	}
	d.result.CacheStatus = "save_failed_or_uncertain"
	if err = s.cache.Save(ctx, next); err != nil {
		return errors.Join(mutationErr, fmt.Errorf("drain cache save: %w", err))
	}
	d.result.CacheStatus = "saved"
	return mutationErr
}
