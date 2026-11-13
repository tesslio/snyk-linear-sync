package sync

// Drain receipts are a new version; legacy bounded consumers must refuse them.
// Operation identities are persisted to prove the full = selected + deferred
// partition and to recover selected dirty keys after an uncertain attempt.

type DrainCounts struct {
	Creates          int64 `json:"creates"`
	Updates          int64 `json:"updates"`
	Resolves         int64 `json:"resolves"`
	CancelDuplicates int64 `json:"cancel_duplicates"`
}

type DrainAttempt struct {
	Version                    int              `json:"version"`
	Status                     string           `json:"status"`
	StartedAt                  string           `json:"started_at"`
	ProducerRunID              string           `json:"producer_run_id"`
	ProducerRunAttempt         int64            `json:"producer_run_attempt"`
	Generation                 int64            `json:"generation"`
	RestoredGeneration         int64            `json:"restored_generation"`
	RestoredHashEvidenceSHA256 string           `json:"restored_hash_evidence_sha256"`
	FullPlanSHA256             string           `json:"full_plan_sha256"`
	JobsSHA256                 string           `json:"jobs_sha256"`
	SelectedOpsSHA256          string           `json:"selected_ops_sha256"`
	DeferredOpsSHA256          string           `json:"deferred_ops_sha256"`
	SettingsSHA256             string           `json:"settings_sha256"`
	PendingBeforeSHA256        string           `json:"pending_before_sha256"`
	FullCounts                 DrainCounts      `json:"full_counts"`
	SelectedCounts             DrainCounts      `json:"selected_counts"`
	DeferredCounts             DrainCounts      `json:"deferred_counts"`
	Limits                     DrainLimits      `json:"limits"`
	Selected                   []DrainOperation `json:"selected"`
	Deferred                   []DrainOperation `json:"deferred"`
	Batches                    int              `json:"batches"`
}

type DrainKeySet struct {
	Count  int    `json:"count"`
	SHA256 string `json:"sha256"`
}

type DrainAuxiliaryComments struct {
	Policy              string `json:"policy"`
	BatchesAttempted    int    `json:"batches_attempted"`
	BatchesAcknowledged int    `json:"batches_acknowledged"`
}

type DrainResult struct {
	Version               int                    `json:"version"`
	Status                string                 `json:"status"`
	FinishedAt            string                 `json:"finished_at"`
	ProducerRunID         string                 `json:"producer_run_id"`
	ProducerRunAttempt    int64                  `json:"producer_run_attempt"`
	Generation            int64                  `json:"generation"`
	FullPlanSHA256        string                 `json:"full_plan_sha256"`
	JobsSHA256            string                 `json:"jobs_sha256"`
	SelectedOpsSHA256     string                 `json:"selected_ops_sha256"`
	DeferredOpsSHA256     string                 `json:"deferred_ops_sha256"`
	SettingsSHA256        string                 `json:"settings_sha256"`
	PendingAfterSHA256    string                 `json:"pending_after_sha256"`
	HashEvidenceSHA256    string                 `json:"hash_evidence_sha256"`
	LinearWritesAttempted bool                   `json:"linear_writes_attempted"`
	BatchesAttempted      int                    `json:"batches_attempted"`
	BatchesAcknowledged   int                    `json:"batches_acknowledged"`
	CacheStatus           string                 `json:"cache_status"`
	Verified              []string               `json:"verified"`
	Unverified            []string               `json:"unverified"`
	Refreshed             DrainKeySet            `json:"refreshed"`
	Withheld              DrainKeySet            `json:"withheld"`
	Saved                 DrainKeySet            `json:"saved"`
	Arrivals              DrainKeySet            `json:"arrivals"`
	Created               map[string]string      `json:"created"`
	AuxiliaryComments     DrainAuxiliaryComments `json:"auxiliary_comments"`
}

// Initialization is a separate receipt variant. It never invents an execution
// plan, jobs digest, restored generation, or null placeholders for those fields.
type DrainInitializationAttempt struct {
	Version            int                 `json:"version"`
	Kind               string              `json:"kind"`
	Status             string              `json:"status"`
	StartedAt          string              `json:"started_at"`
	ProducerRunID      string              `json:"producer_run_id"`
	ProducerRunAttempt int64               `json:"producer_run_attempt"`
	Generation         int64               `json:"generation"`
	Initialization     DrainInitialization `json:"initialization"`
}
type DrainInitializationResult struct {
	Version                     int         `json:"version"`
	Kind                        string      `json:"kind"`
	Status                      string      `json:"status"`
	FinishedAt                  string      `json:"finished_at"`
	ProducerRunID               string      `json:"producer_run_id"`
	ProducerRunAttempt          int64       `json:"producer_run_attempt"`
	Generation                  int64       `json:"generation"`
	InitializationAttemptSHA256 string      `json:"initialization_attempt_sha256"`
	PendingAfterSHA256          string      `json:"pending_after_sha256"`
	HashEvidenceSHA256          string      `json:"hash_evidence_sha256"`
	CacheStatus                 string      `json:"cache_status"`
	LinearWritesAttempted       bool        `json:"linear_writes_attempted"`
	Refreshed                   DrainKeySet `json:"refreshed"`
	Withheld                    DrainKeySet `json:"withheld"`
	Saved                       DrainKeySet `json:"saved"`
	Arrivals                    DrainKeySet `json:"arrivals"`
}

const drainReceiptByteCeiling = 32 << 20
const drainPlanByteCeiling = 128 << 20
