package config

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

const (
	defaultSnykRegion           = "SNYK-US-01"
	defaultSourceProvider       = "unknown"
	defaultLinearTodoState      = "Todo"
	defaultLinearBacklogState   = "Backlog"
	defaultLinearDoneState      = "Done"
	defaultLinearCancelledState = "Cancelled"
	defaultManagedLabel         = "snyk-automation"
	defaultAwaitingFixLabel     = "triage-dependency"
	// defaultProtectedLabels are the labels this sync must never assert from
	// its managed set. They belong to the kikimora Dark Factory harness, which
	// uses them as dispatch control state: df:kikimora-snyk enrolls a finding,
	// and the -complete / -invalid variants are terminal gates that stop it
	// being re-dispatched. Stamping one onto a ticket that does not have it
	// would silently re-open or mis-gate a finding, so they are protected by
	// default rather than by opt-in. Override with LINEAR_PROTECTED_LABELS.
	defaultProtectedLabels   = "df:kikimora-snyk,df:kikimora-snyk-complete,df:kikimora-snyk-invalid"
	defaultCriticalDueDays   = 15
	defaultHighDueDays       = 30
	defaultMediumDueDays     = 45
	defaultLowDueDays        = 90
	defaultWorkerCount       = 16
	defaultSnykConcurrency   = 6
	defaultLinearConcurrency = 8
	defaultErrorLogFile      = "logs/snyk-linear-sync-errors.log"
	defaultCacheDBFile       = "data/snyk-linear-sync-cache.db"
	// defaultArchiveLookbackDays is the lookback window for including
	// auto-archived Linear tickets in the sync snapshot. Linear's auto-archive
	// runs after the configured inactivity period (commonly 1 month); the
	// default 35 days (5 weeks) gives a one-week margin so the reopen guard
	// can still see recently-closed tickets.
	defaultArchiveLookbackDays = 35
)

type Config struct {
	DryRun                                                   bool
	PlanAndExecuteBound                                      bool
	MaxCreates, MaxUpdates, MaxResolves, MaxCancelDuplicates *int64
	// PlanJSON exports a private complete plan in dry-run or bounded execution.
	PlanJSON string
	// ReviewedPlanJSON and ReviewedPlanSHA256 gate live writes on exact input/decision equivalence.
	ReviewedPlanJSON   string
	ReviewedPlanSHA256 string
	// ReplaySafe opts into the v2 deterministic, fresh-source plan contract.
	ReplaySafe bool
	// ObservationCheckpoint writes a new private loader-only candidate.
	ObservationCheckpoint   string
	ObservationSourceSHA256 string

	Log    LogConfig
	Cache  CacheConfig
	Snyk   SnykConfig
	Source SourceConfig
	Linear LinearConfig
	Sync   SyncConfig
}

type LogConfig struct {
	ErrorFile string
}

type CacheConfig struct {
	DBFile      string
	BypassCache bool
	// ClearIgnoresColdStart removes the marker the cold-start guard leaves
	// in the cache when it finds the ignore cache empty while Linear holds
	// open tickets with due dates, releasing the due dates it held back.
	ClearIgnoresColdStart bool
}

type SnykConfig struct {
	Region       string
	ClientID     string
	ClientSecret string
	OrgID        string
	Scopes       []string
}

type SourceConfig struct {
	Provider string
}

type LinearConfig struct {
	APIKey              string
	TeamID              string
	UnsubscribeActor    bool
	CommentsEnabled     bool
	States              StateConfig
	Labels              LabelConfig
	Due                 DueDateConfig
	ArchiveLookbackDays int
}

type StateConfig struct {
	Todo      string
	Backlog   string
	Done      string
	Cancelled string
}

type LabelConfig struct {
	Managed       string
	Tool          map[string]string
	ToolDefault   string
	Origin        map[string]string
	OriginDefault string
	AwaitingFix   string
	// CreateOnly holds labels stamped once, when the ticket is created, and
	// never reconciled afterwards. They are deliberately not part of the
	// managed set: they never enter the ticket's managed_labels: metadata and
	// never appear in a desired set, so nothing downstream tries to re-assert
	// them. Because updates carry forward every label the sync does not own,
	// a create-only label already on a ticket is preserved without pairing it
	// with Protected.
	CreateOnly []string
	// Protected holds labels this sync must never assert from its managed set
	// — a guard against a misconfiguration that puts a control label into the
	// managed set and stamps it onto a ticket that does not carry it. A
	// protected label already on the ticket is carried forward like any other
	// unmanaged label.
	Protected []string
}

type DueDateConfig struct {
	CriticalDays int
	HighDays     int
	MediumDays   int
	LowDays      int
}

type SyncConfig struct {
	Workers           int
	SnykConcurrency   int
	LinearConcurrency int
}

func Load(args []string) (Config, error) {
	fs := flag.NewFlagSet("snyk-linear-sync", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	bound := fs.Bool("plan-and-execute-bound", false, "plan once, bind private receipts, then execute within explicit limits")
	maxCreates := boundFlag(fs, "max-creates", "maximum creates for bounded execution (required)")
	maxUpdates := boundFlag(fs, "max-updates", "maximum updates including reopens (required)")
	maxResolves := boundFlag(fs, "max-resolves", "maximum resolves (required)")
	maxCancelDuplicates := boundFlag(fs, "max-cancel-duplicates", "maximum duplicate cancellations for bounded execution (required)")
	dryRun := fs.Bool("dry-run", false, "plan changes without mutating Linear")
	planJSON := fs.String("plan-json", "", "write a private JSON plan to a new file (requires --dry-run or --plan-and-execute-bound)")
	reviewedPlanJSON := fs.String("reviewed-plan-json", "", "require this complete private dry-run reconciliation plan before live writes")
	reviewedPlanSHA256 := fs.String("reviewed-plan-sha256", "", "independently reviewed SHA-256 of the exact approved plan file bytes")
	replaySafe := fs.Bool("replay-safe", false, "use v2 deterministic ordering and mandatory fresh source reads")
	observationCheckpoint := fs.String("observation-checkpoint", "", "write a new private observation-only cache checkpoint; no Linear calls")
	observationSourceSHA256 := fs.String("observation-source-sha256", "", "required SHA-256 of the untouched source cache for observation checkpoint")
	bypassCache := fs.Bool("bypass-cache", false, "ignore the SQLite sync cache and fetch/compare everything directly")
	clearIgnoresColdStart := fs.Bool("clear-ignores-cold-start", false, "clear the ignore-cache cold-start marker so held-back earlier due dates are written again")
	envFile := fs.String("env-file", "", "load configuration from a dotenv-style file before reading the process environment")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	supplied := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { supplied[f.Name] = true })
	if !supplied["max-creates"] {
		maxCreates = nil
	}
	if !supplied["max-updates"] {
		maxUpdates = nil
	}
	if !supplied["max-resolves"] {
		maxResolves = nil
	}
	if !supplied["max-cancel-duplicates"] {
		maxCancelDuplicates = nil
	}
	if fs.NArg() != 0 {
		return Config{}, errors.New("unexpected positional arguments")
	}
	if strings.TrimSpace(*envFile) != "" {
		path := strings.TrimSpace(*envFile)
		if err := godotenv.Overload(path); err != nil {
			return Config{}, fmt.Errorf("load env file %q: %w", path, err)
		}
	}

	toolLabels, err := parseLabelMap("LINEAR_TOOL_LABELS", os.Getenv("LINEAR_TOOL_LABELS"))
	if err != nil {
		return Config{}, err
	}
	originLabels, err := parseLabelMap("LINEAR_ORIGIN_LABELS", os.Getenv("LINEAR_ORIGIN_LABELS"))
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		DryRun:                  *dryRun,
		PlanAndExecuteBound:     *bound,
		MaxCreates:              maxCreates,
		MaxUpdates:              maxUpdates,
		MaxResolves:             maxResolves,
		MaxCancelDuplicates:     maxCancelDuplicates,
		PlanJSON:                strings.TrimSpace(*planJSON),
		ReviewedPlanJSON:        strings.TrimSpace(*reviewedPlanJSON),
		ReviewedPlanSHA256:      strings.ToLower(strings.TrimSpace(*reviewedPlanSHA256)),
		ReplaySafe:              *replaySafe,
		ObservationCheckpoint:   strings.TrimSpace(*observationCheckpoint),
		ObservationSourceSHA256: strings.ToLower(strings.TrimSpace(*observationSourceSHA256)),
		Log: LogConfig{
			ErrorFile: getEnv("ERROR_LOG_FILE", defaultErrorLogFile),
		},
		Cache: CacheConfig{
			DBFile:                getEnv("CACHE_DB_FILE", defaultCacheDBFile),
			BypassCache:           *bypassCache,
			ClearIgnoresColdStart: *clearIgnoresColdStart,
		},
		Snyk: SnykConfig{
			Region:       getEnv("SNYK_REGION", defaultSnykRegion),
			ClientID:     os.Getenv("SNYK_CLIENT_ID"),
			ClientSecret: os.Getenv("SNYK_CLIENT_SECRET"),
			OrgID:        os.Getenv("SNYK_ORG_ID"),
			Scopes:       splitCSV(os.Getenv("SNYK_OAUTH_SCOPES")),
		},
		Source: SourceConfig{
			Provider: normalizeSourceProvider(getEnv("SOURCE_PROVIDER", defaultSourceProvider)),
		},
		Linear: LinearConfig{
			APIKey:           os.Getenv("LINEAR_API_KEY"),
			TeamID:           os.Getenv("LINEAR_TEAM_ID"),
			UnsubscribeActor: getEnvBool("LINEAR_UNSUBSCRIBE_ACTOR", true),
			CommentsEnabled:  getEnvBool("LINEAR_COMMENTS", false),
			States: StateConfig{
				Todo:      getEnv("LINEAR_STATE_TODO", defaultLinearTodoState),
				Backlog:   getEnv("LINEAR_STATE_BACKLOG", defaultLinearBacklogState),
				Done:      getEnv("LINEAR_STATE_DONE", defaultLinearDoneState),
				Cancelled: getEnv("LINEAR_STATE_CANCELLED", defaultLinearCancelledState),
			},
			Labels: LabelConfig{
				Managed:       normalizeManagedLabel(getEnv("LINEAR_MANAGED_LABEL", defaultManagedLabel)),
				Tool:          toolLabels,
				ToolDefault:   normalizeManagedLabel(getEnv("LINEAR_TOOL_LABEL_DEFAULT", defaultManagedLabel)),
				Origin:        originLabels,
				OriginDefault: normalizeManagedLabel(getEnv("LINEAR_ORIGIN_LABEL_DEFAULT", "")),
				AwaitingFix:   normalizeManagedLabel(getEnv("LINEAR_AWAITING_FIX_LABEL", defaultAwaitingFixLabel)),
				CreateOnly:    parseLabelList(os.Getenv("LINEAR_CREATE_ONLY_LABELS")),
				Protected:     parseLabelList(getEnv("LINEAR_PROTECTED_LABELS", defaultProtectedLabels)),
			},
			Due: DueDateConfig{
				CriticalDays: getEnvInt("LINEAR_DUE_DAYS_CRITICAL", defaultCriticalDueDays),
				HighDays:     getEnvInt("LINEAR_DUE_DAYS_HIGH", defaultHighDueDays),
				MediumDays:   getEnvInt("LINEAR_DUE_DAYS_MEDIUM", defaultMediumDueDays),
				LowDays:      getEnvInt("LINEAR_DUE_DAYS_LOW", defaultLowDueDays),
			},
			ArchiveLookbackDays: getEnvInt("LINEAR_ARCHIVE_LOOKBACK_DAYS", defaultArchiveLookbackDays),
		},
		Sync: SyncConfig{
			Workers:           getEnvInt("SYNC_WORKERS", defaultWorkerCount),
			SnykConcurrency:   getEnvInt("SNYK_HTTP_CONCURRENCY", defaultSnykConcurrency),
			LinearConcurrency: getEnvInt("LINEAR_HTTP_CONCURRENCY", defaultLinearConcurrency),
		},
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	var errs []error
	if err := c.ValidateBound(); err != nil {
		errs = append(errs, err)
	}
	if c.ReplaySafe && c.ObservationCheckpoint == "" && c.PlanJSON == "" && c.ReviewedPlanJSON == "" && !c.PlanAndExecuteBound {
		errs = append(errs, errors.New("--replay-safe requires plan export, reviewed execution, bounded execution, or observation checkpoint"))
	}
	if (c.ObservationCheckpoint == "") != (c.ObservationSourceSHA256 == "") {
		errs = append(errs, errors.New("--observation-checkpoint and --observation-source-sha256 must be supplied together"))
	}
	if c.ObservationCheckpoint != "" {
		if !IsLinearTeamUUID(c.Linear.TeamID) {
			errs = append(errs, errors.New("observation checkpoint requires immutable LINEAR_TEAM_ID for its later plan binding"))
		}
		if c.DryRun || c.PlanJSON != "" || c.ReviewedPlanJSON != "" || c.Cache.BypassCache || c.Cache.ClearIgnoresColdStart || c.ObservationCheckpoint == "-" {
			errs = append(errs, errors.New("observation checkpoint cannot reconcile, bypass cache, clear protection, or write stdout"))
		}
		decoded, err := hex.DecodeString(c.ObservationSourceSHA256)
		if err != nil || len(decoded) != 32 {
			errs = append(errs, errors.New("observation checkpoint requires source SHA-256"))
		}
	}
	if c.PlanJSON != "" && !c.DryRun && !c.PlanAndExecuteBound {
		errs = append(errs, errors.New("--plan-json requires --dry-run"))
	}
	if c.PlanJSON == "-" {
		errs = append(errs, errors.New("--plan-json requires a private file path, not stdout"))
	}

	if (c.ReviewedPlanJSON == "") != (c.ReviewedPlanSHA256 == "") {
		errs = append(errs, errors.New("--reviewed-plan-json and --reviewed-plan-sha256 must be supplied together"))
	}
	if c.ReviewedPlanJSON != "" {
		if !IsLinearTeamUUID(c.Linear.TeamID) {
			errs = append(errs, errors.New("reviewed reconciliation guard requires LINEAR_TEAM_ID to be an immutable team UUID, not a team key; regenerate the reviewed plan using that UUID"))
		}
		if c.DryRun || c.PlanJSON != "" {
			errs = append(errs, errors.New("reviewed reconciliation guard requires live mode without --plan-json"))
		}
		if c.ReviewedPlanJSON == "-" {
			errs = append(errs, errors.New("--reviewed-plan-json requires a private file path"))
		}
	}

	if c.Snyk.ClientID == "" {
		errs = append(errs, errors.New("SNYK_CLIENT_ID is required"))
	}
	if c.Snyk.ClientSecret == "" {
		errs = append(errs, errors.New("SNYK_CLIENT_SECRET is required"))
	}
	if c.Snyk.OrgID == "" {
		errs = append(errs, errors.New("SNYK_ORG_ID is required"))
	}
	if c.Linear.APIKey == "" && c.ObservationCheckpoint == "" {
		errs = append(errs, errors.New("LINEAR_API_KEY is required"))
	}
	if c.Linear.TeamID == "" && c.ObservationCheckpoint == "" {
		errs = append(errs, errors.New("LINEAR_TEAM_ID is required"))
	}
	switch c.Source.Provider {
	case "unknown", "github":
	default:
		errs = append(errs, fmt.Errorf("SOURCE_PROVIDER must be one of unknown, github; got %q", c.Source.Provider))
	}
	if strings.TrimSpace(c.Log.ErrorFile) == "" {
		errs = append(errs, errors.New("ERROR_LOG_FILE must not be empty"))
	}
	if strings.TrimSpace(c.Cache.DBFile) == "" {
		errs = append(errs, errors.New("CACHE_DB_FILE must not be empty"))
	}
	if c.Sync.Workers <= 0 {
		errs = append(errs, fmt.Errorf("SYNC_WORKERS must be > 0, got %d", c.Sync.Workers))
	}
	if c.Sync.SnykConcurrency <= 0 {
		errs = append(errs, fmt.Errorf("SNYK_HTTP_CONCURRENCY must be > 0, got %d", c.Sync.SnykConcurrency))
	}
	if c.Sync.LinearConcurrency <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_HTTP_CONCURRENCY must be > 0, got %d", c.Sync.LinearConcurrency))
	}
	if c.Linear.Due.CriticalDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_CRITICAL must be > 0, got %d", c.Linear.Due.CriticalDays))
	}
	if c.Linear.Due.HighDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_HIGH must be > 0, got %d", c.Linear.Due.HighDays))
	}
	if c.Linear.Due.MediumDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_MEDIUM must be > 0, got %d", c.Linear.Due.MediumDays))
	}
	if c.Linear.Due.LowDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_LOW must be > 0, got %d", c.Linear.Due.LowDays))
	}
	if c.Linear.ArchiveLookbackDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_ARCHIVE_LOOKBACK_DAYS must be > 0, got %d", c.Linear.ArchiveLookbackDays))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// IsLinearTeamUUID identifies the direct immutable-ID form accepted by the
// Linear client. A team key can resolve to another team after credentials or
// workspace configuration change, so it cannot identify a guarded destination.
func IsLinearTeamUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}

	return n
}

func getEnvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}

	return v
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}

	return out
}

func normalizeSourceProvider(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return defaultSourceProvider
	}
	return value
}

func normalizeManagedLabel(raw string) string {
	value := strings.TrimSpace(raw)
	switch strings.ToLower(value) {
	case "", "off", "false", "disabled", "none":
		return ""
	default:
		return value
	}
}

// parseLabelList parses a comma-separated list of label names, dropping empty
// entries and honouring the same "off"/"none" disable words as
// normalizeManagedLabel (so LINEAR_PROTECTED_LABELS=off disables protection
// entirely). Unlike parseLabelMap it cannot fail: there is no key:value shape
// to get wrong, so an absent value simply means "no labels".
func parseLabelList(raw string) []string {
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		if label := normalizeManagedLabel(part); label != "" {
			out = append(out, label)
		}
	}
	return out
}

func parseLabelMap(envName, raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	out := make(map[string]string)
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		issueType, label, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("%s entry %q must use key:label format", envName, part)
		}

		issueType = strings.ToLower(strings.TrimSpace(issueType))
		label = normalizeManagedLabel(label)
		if issueType == "" {
			return nil, fmt.Errorf("%s entry %q is missing the key", envName, part)
		}
		if label == "" {
			return nil, fmt.Errorf("%s entry %q is missing the label name", envName, part)
		}

		out[issueType] = label
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// ValidateBound is also called by Service.Run, before any loader or cache access.
func (c Config) ValidateBound() error {
	if !c.PlanAndExecuteBound {
		if c.MaxCreates != nil || c.MaxUpdates != nil || c.MaxResolves != nil || c.MaxCancelDuplicates != nil {
			return errors.New("bounded options require --plan-and-execute-bound")
		}
		return nil
	}
	if !c.ReplaySafe || c.DryRun || c.ReviewedPlanJSON != "" || c.ReviewedPlanSHA256 != "" || c.ObservationCheckpoint != "" || c.ObservationSourceSHA256 != "" || c.Cache.ClearIgnoresColdStart {
		return errors.New("bounded execution requires --replay-safe live mode without other plan modes or clearing cold-start protection")
	}
	if !IsLinearTeamUUID(c.Linear.TeamID) {
		return errors.New("bounded execution requires immutable LINEAR_TEAM_ID UUID")
	}
	if strings.TrimSpace(c.PlanJSON) == "" || c.PlanJSON == "-" {
		return errors.New("bounded execution requires --plan-json with a new private file path")
	}
	for _, limit := range []*int64{c.MaxCreates, c.MaxUpdates, c.MaxResolves, c.MaxCancelDuplicates} {
		if limit == nil || *limit < 0 || *limit > 1000000 {
			return errors.New("bounded execution requires all four explicit limits between 0 and 1000000")
		}
	}
	return nil
}

func boundFlag(fs *flag.FlagSet, name, usage string) *int64 {
	value := new(int64)
	fs.Func(name, usage, func(raw string) error {
		if raw == "" || (len(raw) > 1 && raw[0] == '0') {
			return errors.New("requires a canonical nonnegative decimal integer")
		}
		for _, digit := range raw {
			if digit < '0' || digit > '9' {
				return errors.New("requires a canonical nonnegative decimal integer")
			}
		}
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return errors.New("bound integer overflows")
		}
		*value = parsed
		return nil
	})
	return value
}
