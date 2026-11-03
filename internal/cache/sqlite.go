package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	_ "modernc.org/sqlite"
)

const schemaVersion = "v1"

// IgnoreMeta stores the v1 ignore fields that must survive a flaky Snyk API.
// It is kept in the cache package to avoid an import cycle with the snyk package.
//
// The cache is the sync's only memory of an ignore once the Snyk v1 ignores
// endpoint stops returning it, which it does for expired ignores after an
// undocumented period. Rows are therefore never aged out here on read; the
// Snyk loader decides at the end of each snapshot load, with the REST issue
// data in hand, which rows Snyk has contradicted (see the retention rule in
// internal/snyk).
type IgnoreMeta struct {
	IssueKey           string
	ExpiresAt          time.Time
	DisregardIfFixable bool
	CreatedAt          time.Time
	// UpdatedAt is when the v1 API last confirmed the ignore. Zero when the
	// row predates the column or its value could not be parsed: the
	// confirmation time is then unknown, and the next write stamps the row
	// with the time of that write.
	UpdatedAt time.Time
	// UnignoredAt is set on an ignore-until-fix-available row the first run
	// on which every REST issue it applies to reports ignored=false: the
	// fix arrived (or the ignore was revoked) and the SLA clock starts. It
	// is the base of the due date from then on, so it is kept. Zero while
	// Snyk still reports the ignore, and for rows without the
	// disregard-if-fixable flag.
	UnignoredAt time.Time
	// ObservedIssues remembers which REST issue IDs were actually ignored.
	// Each observation retains its own metadata and first observed end.
	// Rule keys alone cannot establish a historical association to a sibling.
	ObservedIssues map[string]IgnoreObservation
}

// IgnoreObservation is the effective ignore seen for one REST finding.
// Rule-key summaries may change for a sibling; its historical expiry and end
// must not replace the SLA memory of a finding that is already actionable.
type IgnoreObservation struct {
	ExpiresAt          time.Time
	CreatedAt          time.Time
	DisregardIfFixable bool
	EndedAt            time.Time
}

type Snapshot struct {
	SchemaSignature string
	SnykHashes      map[string]string
	LinearHashes    map[string]string
}

type Store struct {
	db      *sql.DB
	builder sq.StatementBuilderType
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite cache: %w", err)
	}

	store := &Store{
		db:      db,
		builder: sq.StatementBuilder.PlaceholderFormat(sq.Question),
	}
	if err := store.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Load(ctx context.Context) (Snapshot, error) {
	snapshot := Snapshot{
		SnykHashes:   map[string]string{},
		LinearHashes: map[string]string{},
	}

	query, args, err := s.builder.
		Select("value").
		From("sync_meta").
		Where(sq.Eq{"key": "schema_signature"}).
		ToSql()
	if err != nil {
		return Snapshot{}, fmt.Errorf("build cache schema signature query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Snapshot{}, fmt.Errorf("load cache schema signature: %w", err)
	}
	for rows.Next() {
		if err := rows.Scan(&snapshot.SchemaSignature); err != nil {
			_ = rows.Close()
			return Snapshot{}, fmt.Errorf("scan cache schema signature: %w", err)
		}
	}
	if err := rows.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("close cache schema signature rows: %w", err)
	}

	query, args, err = s.builder.
		Select("fingerprint", "hash").
		From("snyk_findings").
		ToSql()
	if err != nil {
		return Snapshot{}, fmt.Errorf("build Snyk cache rows query: %w", err)
	}

	snykRows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Snapshot{}, fmt.Errorf("load Snyk cache rows: %w", err)
	}
	for snykRows.Next() {
		var fingerprint string
		var hash string
		if err := snykRows.Scan(&fingerprint, &hash); err != nil {
			_ = snykRows.Close()
			return Snapshot{}, fmt.Errorf("scan Snyk cache row: %w", err)
		}
		snapshot.SnykHashes[fingerprint] = hash
	}
	if err := snykRows.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("close Snyk cache rows: %w", err)
	}

	query, args, err = s.builder.
		Select("fingerprint", "hash").
		From("linear_issues").
		ToSql()
	if err != nil {
		return Snapshot{}, fmt.Errorf("build Linear cache rows query: %w", err)
	}

	linearRows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Snapshot{}, fmt.Errorf("load Linear cache rows: %w", err)
	}
	for linearRows.Next() {
		var fingerprint string
		var hash string
		if err := linearRows.Scan(&fingerprint, &hash); err != nil {
			_ = linearRows.Close()
			return Snapshot{}, fmt.Errorf("scan Linear cache row: %w", err)
		}
		snapshot.LinearHashes[fingerprint] = hash
	}
	if err := linearRows.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("close Linear cache rows: %w", err)
	}

	return snapshot, nil
}

func (s *Store) Save(ctx context.Context, snapshot Snapshot) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cache transaction: %w", err)
	}
	// Rollback also runs on shadowed error paths; after Commit it is a no-op.
	defer func() { _ = tx.Rollback() }()

	query, args, err := s.builder.
		Insert("sync_meta").
		Columns("key", "value").
		Values("schema_signature", snapshot.SchemaSignature).
		Suffix("ON CONFLICT(key) DO UPDATE SET value = excluded.value").
		ToSql()
	if err != nil {
		return fmt.Errorf("build cache schema signature upsert: %w", err)
	}
	if _, err = tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("save cache schema signature: %w", err)
	}

	query, args, err = s.builder.Delete("snyk_findings").ToSql()
	if err != nil {
		return fmt.Errorf("build clear Snyk cache rows query: %w", err)
	}
	if _, err = tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("clear Snyk cache rows: %w", err)
	}
	for fingerprint, hash := range snapshot.SnykHashes {
		query, args, err = s.builder.
			Insert("snyk_findings").
			Columns("fingerprint", "hash").
			Values(fingerprint, hash).
			ToSql()
		if err != nil {
			return fmt.Errorf("build insert Snyk cache row: %w", err)
		}
		if _, err = tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert Snyk cache row: %w", err)
		}
	}

	query, args, err = s.builder.Delete("linear_issues").ToSql()
	if err != nil {
		return fmt.Errorf("build clear Linear cache rows query: %w", err)
	}
	if _, err = tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("clear Linear cache rows: %w", err)
	}
	for fingerprint, hash := range snapshot.LinearHashes {
		query, args, err = s.builder.
			Insert("linear_issues").
			Columns("fingerprint", "hash").
			Values(fingerprint, hash).
			ToSql()
		if err != nil {
			return fmt.Errorf("build insert Linear cache row: %w", err)
		}
		if _, err = tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert Linear cache row: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit cache transaction: %w", err)
	}

	return nil
}

func (s *Store) init(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS sync_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS snyk_findings (
			fingerprint TEXT PRIMARY KEY,
			hash TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS linear_issues (
			fingerprint TEXT PRIMARY KEY,
			hash TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS snyk_ignores (
			project_id TEXT NOT NULL,
			issue_key TEXT NOT NULL,
			expires_at TEXT,
			disregard_if_fixable INTEGER NOT NULL DEFAULT 0,
			created_at TEXT,
			updated_at TEXT,
			unignored_at TEXT,
			PRIMARY KEY (project_id, issue_key)
		)`,
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize sqlite cache: %w", err)
		}
	}

	if err := s.migrateSnykIgnoresCache(ctx); err != nil {
		return fmt.Errorf("migrate snyk ignores cache: %w", err)
	}

	query, args, err := s.builder.
		Insert("sync_meta").
		Columns("key", "value").
		Values("schema_version", schemaVersion).
		Suffix("ON CONFLICT(key) DO UPDATE SET value = excluded.value").
		ToSql()
	if err != nil {
		return fmt.Errorf("build initialize sqlite schema version upsert: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("initialize sqlite cache: %w", err)
	}

	return nil
}

func (s *Store) migrateSnykIgnoresCache(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info(snyk_ignores)")
	if err != nil {
		return fmt.Errorf("check snyk_ignores columns: %w", err)
	}
	defer rows.Close()

	columns := map[string]bool{}
	for rows.Next() {
		var cid, notNull, pk int
		var name string
		var typ, dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("scan table_info: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate table_info: %w", err)
	}

	if !columns["updated_at"] {
		if _, err := s.db.ExecContext(ctx, "ALTER TABLE snyk_ignores ADD COLUMN updated_at TEXT"); err != nil {
			return fmt.Errorf("add updated_at column: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, "UPDATE snyk_ignores SET updated_at = CURRENT_TIMESTAMP"); err != nil {
			return fmt.Errorf("seed updated_at column: %w", err)
		}
	}
	if !columns["unignored_at"] {
		// Left empty for existing rows: the next run stamps the rows whose
		// findings are already un-ignored.
		if _, err := s.db.ExecContext(ctx, "ALTER TABLE snyk_ignores ADD COLUMN unignored_at TEXT"); err != nil {
			return fmt.Errorf("add unignored_at column: %w", err)
		}
	}
	if !columns["observed_issues"] {
		if _, err := s.db.ExecContext(ctx, "ALTER TABLE snyk_ignores ADD COLUMN observed_issues TEXT"); err != nil {
			return fmt.Errorf("add observed_issues column: %w", err)
		}
	}
	return nil
}

// HasIgnoreRows reports whether the cache holds any v1 ignore row for any
// project. The sync reads it at the start of a run: an empty table means
// the sync has no memory of expired ignores, so an earlier due date it
// computes may only reflect that gap (see the cold-start guard).
func (s *Store) HasIgnoreRows(ctx context.Context) (bool, error) {
	query, args, err := s.builder.
		Select("1").
		From("snyk_ignores").
		Limit(1).
		ToSql()
	if err != nil {
		return false, fmt.Errorf("build cache ignores presence query: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return false, fmt.Errorf("check cache ignores presence: %w", err)
	}
	defer rows.Close()
	present := rows.Next()
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("check cache ignores presence: %w", err)
	}
	return present, nil
}

// GetMeta returns the value stored under a sync_meta key, and whether the
// key exists.
func (s *Store) GetMeta(ctx context.Context, key string) (string, bool, error) {
	query, args, err := s.builder.
		Select("value").
		From("sync_meta").
		Where(sq.Eq{"key": key}).
		ToSql()
	if err != nil {
		return "", false, fmt.Errorf("build cache meta query: %w", err)
	}
	var value string
	switch err := s.db.QueryRowContext(ctx, query, args...).Scan(&value); {
	case err == nil:
		return value, true, nil
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	default:
		return "", false, fmt.Errorf("load cache meta %q: %w", key, err)
	}
}

// SetMeta stores a value under a sync_meta key, replacing any existing one.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	query, args, err := s.builder.
		Insert("sync_meta").
		Columns("key", "value").
		Values(key, value).
		Suffix("ON CONFLICT(key) DO UPDATE SET value = excluded.value").
		ToSql()
	if err != nil {
		return fmt.Errorf("build cache meta upsert: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("save cache meta %q: %w", key, err)
	}
	return nil
}

// DeleteMeta removes a sync_meta key. Removing an absent key is not an error.
func (s *Store) DeleteMeta(ctx context.Context, key string) error {
	query, args, err := s.builder.
		Delete("sync_meta").
		Where(sq.Eq{"key": key}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build cache meta delete: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("delete cache meta %q: %w", key, err)
	}
	return nil
}

// sqliteTimestampLayout is the format of SQLite's CURRENT_TIMESTAMP, which
// the updated_at migration used to seed existing rows. Unlike RFC3339 it
// carries no timezone; CURRENT_TIMESTAMP is always UTC.
const sqliteTimestampLayout = "2006-01-02 15:04:05"

// parseTimestamp parses a cache timestamp column value. Values are written as
// RFC3339, but rows seeded by the updated_at migration carry SQLite's
// CURRENT_TIMESTAMP format instead, so both are accepted and the result is
// normalised to UTC. An empty or unparsable value yields the zero time: the
// value is then unknown, never a reason to discard the row.
func parseTimestamp(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, sqliteTimestampLayout} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

// LoadIgnores returns the cached v1 ignore metadata for a project. Every row
// is returned: the cache does not age rows out on read, because for an
// expired ignore it is the only record of the expiry that the due date is
// based on. Retention is decided by the Snyk loader, which knows what the
// REST API currently says about each finding.
func (s *Store) LoadIgnores(ctx context.Context, projectID string) (map[string]IgnoreMeta, error) {
	out := make(map[string]IgnoreMeta)

	query, args, err := s.builder.
		Select("issue_key", "expires_at", "disregard_if_fixable", "created_at", "updated_at", "unignored_at", "observed_issues").
		From("snyk_ignores").
		Where(sq.Eq{"project_id": projectID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build cache ignores query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("load cache ignores: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var issueKey string
		var expiresAtRaw, createdAtRaw, updatedAtRaw string
		var unignoredAtRaw, observedRaw sql.NullString
		var disregardIfFixable int
		if err := rows.Scan(&issueKey, &expiresAtRaw, &disregardIfFixable, &createdAtRaw, &updatedAtRaw, &unignoredAtRaw, &observedRaw); err != nil {
			return nil, fmt.Errorf("scan cache ignore row: %w", err)
		}

		var observed map[string]IgnoreObservation
		if observedRaw.String != "" {
			if err := json.Unmarshal([]byte(observedRaw.String), &observed); err != nil {
				return nil, fmt.Errorf("decode cached ignore associations: %w", err)
			}
		}
		out[issueKey] = IgnoreMeta{
			IssueKey:           issueKey,
			DisregardIfFixable: disregardIfFixable != 0,
			ExpiresAt:          parseTimestamp(expiresAtRaw),
			CreatedAt:          parseTimestamp(createdAtRaw),
			UpdatedAt:          parseTimestamp(updatedAtRaw),
			UnignoredAt:        parseTimestamp(unignoredAtRaw.String),
			ObservedIssues:     observed,
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cache ignores rows: %w", err)
	}

	return out, nil
}

// SaveIgnores stores v1 ignore metadata for a project, replacing any existing rows.
func (s *Store) SaveIgnores(ctx context.Context, projectID string, ignores map[string]IgnoreMeta) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cache ignores transaction: %w", err)
	}
	// Rollback also runs on shadowed error paths; after Commit it is a no-op.
	defer func() { _ = tx.Rollback() }()

	query, args, err := s.builder.
		Delete("snyk_ignores").
		Where(sq.Eq{"project_id": projectID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build clear cache ignores query: %w", err)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("clear cache ignores: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for issueKey, meta := range ignores {
		expiresAtRaw := ""
		if !meta.ExpiresAt.IsZero() {
			expiresAtRaw = meta.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		createdAtRaw := ""
		if !meta.CreatedAt.IsZero() {
			createdAtRaw = meta.CreatedAt.UTC().Format(time.RFC3339Nano)
		}
		updatedAtRaw := now
		if !meta.UpdatedAt.IsZero() {
			updatedAtRaw = meta.UpdatedAt.UTC().Format(time.RFC3339Nano)
		}
		unignoredAtRaw := ""
		if !meta.UnignoredAt.IsZero() {
			unignoredAtRaw = meta.UnignoredAt.UTC().Format(time.RFC3339Nano)
		}
		var observedRaw []byte
		observedRaw, err = json.Marshal(meta.ObservedIssues)
		if err != nil {
			return fmt.Errorf("encode ignore associations: %w", err)
		}
		var disregard int64
		if meta.DisregardIfFixable {
			disregard = 1
		}

		query, args, err = s.builder.
			Insert("snyk_ignores").
			Columns("project_id", "issue_key", "expires_at", "disregard_if_fixable", "created_at", "updated_at", "unignored_at", "observed_issues").
			Values(projectID, issueKey, expiresAtRaw, disregard, createdAtRaw, updatedAtRaw, unignoredAtRaw, string(observedRaw)).
			ToSql()
		if err != nil {
			return fmt.Errorf("build insert cache ignore row: %w", err)
		}
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert cache ignore row: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cache ignores transaction: %w", err)
	}
	return nil
}
