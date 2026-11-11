package sync

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
)

const maxBoundPlanBytes = 32 << 20
const maxBoundReceiptBytes = 4096

// BoundAttempt contains hashes and aggregate limits, never raw source payloads.
// Its durable existence consumes this receipt directory even if the process dies.
type BoundAttempt struct {
	Version             int    `json:"version"`
	Status              string `json:"status"`
	StartedAt           string `json:"started_at"`
	PlanSHA256          string `json:"plan_sha256"`
	JobsSHA256          string `json:"jobs_sha256"`
	Creates             int64  `json:"creates"`
	Updates             int64  `json:"updates"`
	Resolves            int64  `json:"resolves"`
	CancelDuplicates    int64  `json:"cancel_duplicates"`
	MaxCreates          int64  `json:"max_creates"`
	MaxUpdates          int64  `json:"max_updates"`
	MaxResolves         int64  `json:"max_resolves"`
	MaxCancelDuplicates int64  `json:"max_cancel_duplicates"`
	Batches             int    `json:"batches"`
}

// BoundRefusal records only validated aggregate intent, never an execution attempt.
// It does not authorize execution or reuse of the reserved receipt directory.
type BoundRefusal struct {
	Version             int      `json:"version"`
	Status              string   `json:"status"`
	Creates             int64    `json:"creates"`
	Updates             int64    `json:"updates"`
	Resolves            int64    `json:"resolves"`
	CancelDuplicates    int64    `json:"cancel_duplicates"`
	MaxCreates          int64    `json:"max_creates"`
	MaxUpdates          int64    `json:"max_updates"`
	MaxResolves         int64    `json:"max_resolves"`
	MaxCancelDuplicates int64    `json:"max_cancel_duplicates"`
	Exceeded            []string `json:"exceeded"`
}

// BoundLimitError exposes aggregate diagnostics without source payloads.
type BoundLimitError struct{ Refusal BoundRefusal }

func (e *BoundLimitError) Error() string {
	r := e.Refusal
	return fmt.Sprintf("complete plan exceeds bounded execution limits: creates=%d/%d updates=%d/%d resolves=%d/%d cancel_duplicates=%d/%d exceeded=%v", r.Creates, r.MaxCreates, r.Updates, r.MaxUpdates, r.Resolves, r.MaxResolves, r.CancelDuplicates, r.MaxCancelDuplicates, r.Exceeded)
}

type BoundResult struct {
	Version               int    `json:"version"`
	Status                string `json:"status"`
	FinishedAt            string `json:"finished_at"`
	PlanSHA256            string `json:"plan_sha256"`
	JobsSHA256            string `json:"jobs_sha256"`
	LinearWritesAttempted bool   `json:"linear_writes_attempted"`
	BatchesAttempted      int    `json:"batches_attempted"`
	BatchesAcknowledged   int    `json:"batches_acknowledged"`
	CacheStatus           string `json:"cache_status"`
}

type boundRun struct {
	planRoot                *os.Root
	planName                string
	root                    *os.Root
	path                    string
	info                    os.FileInfo
	attempt                 BoundAttempt
	result                  BoundResult
	planBytes, attemptBytes []byte
}

// Require a physical path and a private parent. Keep a directory handle for all
// operations; replacement or renaming of a parent must never redirect receipts.
func reserveBoundRun(planPath string) (*boundRun, error) {
	absolute, err := filepath.Abs(planPath)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(absolute)
	for current := parent; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("receipt path contains an inaccessible component or symlink")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("receipt parent must be a private mode-0700 directory")
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	keepParent := false
	defer func() {
		if !keepParent {
			parentRoot.Close()
		}
	}()
	planName := filepath.Base(absolute)
	if _, err := parentRoot.Lstat(planName); !os.IsNotExist(err) {
		return nil, errors.New("bound plan already exists or is inaccessible")
	}
	absolute += ".receipts"
	name := filepath.Base(absolute)
	if name == "." || name == string(filepath.Separator) {
		return nil, errors.New("receipt directory must be new")
	}
	if err := parentRoot.Mkdir(name, 0700); err != nil {
		return nil, errors.New("receipt directory already exists or cannot be reserved; never reuse an attempt directory")
	}
	// Persist the reservation in its parent before loading or attempting writes.
	parentFile, err := parentRoot.Open(".")
	if err != nil {
		return nil, err
	}
	err = parentFile.Sync()
	closeErr := parentFile.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	root, err := parentRoot.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	info, err = root.Stat(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	b := &boundRun{root: root, planRoot: parentRoot, planName: planName, path: absolute, info: info, result: BoundResult{Version: 1, Status: "failed_before_writes", CacheStatus: "not_saved"}}
	if err := b.unchanged(); err != nil {
		root.Close()
		return nil, err
	}
	keepParent = true
	return b, nil
}

func (b *boundRun) close() { b.root.Close(); b.planRoot.Close() }

func (b *boundRun) unchanged() error {
	info, err := os.Lstat(b.path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !os.SameFile(info, b.info) {
		return errors.New("receipt directory changed")
	}
	return nil
}

func (b *boundRun) write(name string, value any) ([]byte, error) {
	if err := b.unchanged(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	limit := maxBoundReceiptBytes
	if name == "plan.json" {
		limit = maxBoundPlanBytes
	}
	if len(data) > limit {
		return nil, errors.New("bound artifact exceeds its private retention size limit")
	}
	root := b.root
	if name == "plan.json" {
		root, name = b.planRoot, b.planName
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create bound %s: %w", name, err)
	}
	// Preserve incomplete receipts on failure. No future run can consume this dir.
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return nil, err
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	syncErr = dir.Sync()
	closeErr = dir.Close()
	return data, errors.Join(syncErr, closeErr)
}

func boundJobsDigest(jobs []job) (string, error) {
	// job has private fields; marshal an explicit full-payload representation.
	type payload struct {
		Kind    jobKind
		Creates []model.DesiredIssue
		Updates []model.IssueUpdate
	}
	values := make([]payload, 0, len(jobs))
	for _, j := range jobs {
		values = append(values, payload{j.kind, j.desiredBatch, j.updateBatch})
	}
	return planDigest(values)
}

func (b *boundRun) bind(cfg config.Config, plan *ReconciliationPlan, jobs []job) error {
	if err := validateReviewedPlan(plan); err != nil {
		return err
	}
	s := plan.Summary
	if cfg.ExpectedSettingsSHA256 != "" {
		if plan.Inputs.SettingsSHA256 != cfg.ExpectedSettingsSHA256 {
			return errors.New("bounded plan settings differ from expected settings")
		}
		if s.DeferredCreates != 0 {
			return errors.New("bounded plan contains deferred creates")
		}
	}
	// Validate buffered evidence before describing a refusal as a limit failure.
	if err := validateBoundJobs(plan, jobs); err != nil {
		return err
	}
	refusal := BoundRefusal{Version: 1, Status: "limits_exceeded", Creates: s.Creates, Updates: s.Updates, Resolves: s.Resolves, CancelDuplicates: s.CancelDuplicates, MaxCreates: *cfg.MaxCreates, MaxUpdates: *cfg.MaxUpdates, MaxResolves: *cfg.MaxResolves, MaxCancelDuplicates: *cfg.MaxCancelDuplicates}
	// Each mutation kind has an independent explicit bound; never truncate jobs.
	for _, limit := range []struct {
		name       string
		count, max int64
	}{
		{"creates", refusal.Creates, refusal.MaxCreates},
		{"updates", refusal.Updates, refusal.MaxUpdates},
		{"resolves", refusal.Resolves, refusal.MaxResolves},
		{"cancel_duplicates", refusal.CancelDuplicates, refusal.MaxCancelDuplicates},
	} {
		if limit.count < 0 || limit.max < 0 {
			return errors.New("invalid bounded execution counts or limits")
		}
		if limit.count > limit.max {
			refusal.Exceeded = append(refusal.Exceeded, limit.name)
		}
	}
	if len(refusal.Exceeded) != 0 {
		limitErr := &BoundLimitError{Refusal: refusal}
		if _, err := b.write("refusal.json", refusal); err != nil {
			return errors.Join(limitErr, fmt.Errorf("persist bound refusal: %w", err))
		}
		return limitErr
	}
	digest, err := boundJobsDigest(jobs)
	if err != nil {
		return err
	}
	b.planBytes, err = b.write("plan.json", plan)
	if err != nil {
		return err
	}
	b.attempt = BoundAttempt{Version: 1, Status: "attempt_started", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), PlanSHA256: planTextDigest(string(b.planBytes)), JobsSHA256: digest, Creates: s.Creates, Updates: s.Updates, Resolves: s.Resolves, CancelDuplicates: s.CancelDuplicates, MaxCreates: *cfg.MaxCreates, MaxUpdates: *cfg.MaxUpdates, MaxResolves: *cfg.MaxResolves, MaxCancelDuplicates: *cfg.MaxCancelDuplicates, Batches: len(jobs)}
	b.result.PlanSHA256, b.result.JobsSHA256 = b.attempt.PlanSHA256, digest
	b.attemptBytes, err = b.write("attempt.json", b.attempt)
	return err
}

// Validate an exact correspondence between planned mutations and buffered jobs,
// including candidate decisions. Hashes additionally bind full private payloads.
func validateBoundJobs(plan *ReconciliationPlan, jobs []job) error {
	records := map[string]PlanRecord{}
	key := func(action, fingerprint, id string) string { return action + ":" + fingerprint + ":" + id }
	for _, r := range plan.Records {
		if !r.MutationPlanned {
			continue
		}
		k := key(r.Action, r.FingerprintSHA256, r.IssueID)
		if _, ok := records[k]; ok {
			return errors.New("duplicate planned mutation")
		}
		records[k] = r
	}
	check := func(action string, desired model.DesiredIssue, existing model.ExistingIssue) error {
		k := key(action, planTextDigest(desired.Fingerprint), existing.ID)
		r, ok := records[k]
		if !ok || !r.CandidatePresent || r.Reopen != desired.Reopen || r.DueDate.Planned != desired.DueDate || r.State.ProposedModel != model.StateName(desired.State) || r.State.Preserve != desired.PreserveState || r.State.RestoreID != desired.RestoreState.ID || r.CandidateDiff.PriorityProposed != desired.Priority {
			return errors.New("buffered job differs from complete plan")
		}
		delete(records, k)
		return nil
	}
	for _, j := range jobs {
		switch j.kind {
		case jobCreateBatch:
			if len(j.updateBatch) != 0 || len(j.desiredBatch) == 0 {
				return errors.New("invalid create job")
			}
			for _, d := range j.desiredBatch {
				if err := check(string(j.kind), d, model.ExistingIssue{}); err != nil {
					return err
				}
			}
		case jobUpdate, jobResolve, jobCancelDuplicate:
			if len(j.desiredBatch) != 0 || len(j.updateBatch) == 0 {
				return errors.New("invalid update job")
			}
			for _, u := range j.updateBatch {
				if err := check(string(j.kind), u.Desired, u.Existing); err != nil {
					return err
				}
			}
		default:
			return errors.New("unknown bound job")
		}
	}
	if len(records) != 0 {
		return errors.New("plan has unbuffered mutations")
	}
	return nil
}

func (b *boundRun) verify(jobs []job) error {
	if err := b.unchanged(); err != nil {
		return err
	}
	for _, artifact := range []struct {
		name string
		data []byte
	}{{"plan.json", b.planBytes}, {"attempt.json", b.attemptBytes}} {
		root, name := b.root, artifact.name
		if name == "plan.json" {
			root, name = b.planRoot, b.planName
		}
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(len(artifact.data)) {
			return errors.New("bound artifact changed")
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, int64(len(artifact.data))+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || string(data) != string(artifact.data) {
			return errors.New("bound artifact changed")
		}
	}
	digest, err := boundJobsDigest(jobs)
	if err != nil || digest != b.attempt.JobsSHA256 {
		return errors.New("bound job payload changed")
	}
	return nil
}
