package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
	snykclient "github.com/tesslio/snyk-linear-sync/internal/snyk"
	syncsvc "github.com/tesslio/snyk-linear-sync/internal/sync"
)

const checkpointProtocol = "observation-checkpoint-v1"
const maxCheckpointBytes = 1 << 30

type observationLoader interface {
	SetCache(*cache.Store)
	LoadSnapshot(context.Context) (model.SnykSnapshot, error)
	ValidateFreshSnapshot() error
	FreshSourceReads() (snykclient.SourceReads, error)
}
type protectedCheckpointState struct {
	Meta          map[string]string `json:"meta"`
	Snyk          map[string]string `json:"snyk"`
	Linear        map[string]string `json:"linear"`
	Schema        map[string]string `json:"schema"`
	IgnoreRows    int               `json:"-"`
	IgnoreColumns int               `json:"-"`
}
type checkpointReceipt struct {
	Protocol         string                 `json:"protocol"`
	Complete         bool                   `json:"complete"`
	SourceSHA256     string                 `json:"source_sha256"`
	CheckpointSHA256 string                 `json:"checkpoint_sha256"`
	ProtectedSHA256  string                 `json:"protected_sha256"`
	SettingsSHA256   string                 `json:"settings_sha256"`
	StartedAt        string                 `json:"started_at"`
	CompletedAt      string                 `json:"completed_at"`
	Findings         int                    `json:"findings"`
	FreshSourceReads snykclient.SourceReads `json:"fresh_source_reads"`
}

// prepareObservationCheckpoint never constructs a Linear client or reconciles.
// The new DB is usable only together with its complete digest-bound receipt.
func prepareObservationCheckpoint(ctx context.Context, cfg config.Config, loader observationLoader) (err error) {
	if cfg.ObservationCheckpoint == "" || cfg.ObservationSourceSHA256 == "" {
		return errors.New("observation checkpoint requires output and source digest")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	source, err := readCheckpointFile(cfg.Cache.DBFile)
	if err != nil {
		return err
	}
	if checkpointDigest(source) != cfg.ObservationSourceSHA256 {
		return errors.New("observation source digest mismatch")
	}
	// cache.Open consumes a SQLite DSN. Use an absolute filesystem path so
	// a relative "file:" name cannot become a URI, and reject query syntax
	// which the driver would strip from the actual filename before opening.
	output, err := filepath.Abs(cfg.ObservationCheckpoint)
	if err != nil {
		return err
	}
	if strings.Contains(output, "?") {
		return errors.New("observation checkpoint output must not contain SQLite query syntax")
	}
	if err := privateCheckpointParent(output); err != nil {
		return err
	}
	if err := noCheckpointSidecars(output); err != nil {
		return err
	}
	receiptPath := output + ".json"
	if _, err := os.Lstat(receiptPath); !os.IsNotExist(err) {
		return errors.New("observation receipt already exists or is inaccessible")
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create new observation checkpoint: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			err = errors.Join(err, removeCheckpoint(output))
		}
	}()
	if _, err = f.Write(source); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	before, err := inspectCheckpoint(ctx, output)
	if err != nil {
		return err
	}
	store, err := cache.Open(output)
	if err != nil {
		return err
	}
	loader.SetCache(store)
	startedAt := time.Now().UTC().Format(time.RFC3339Nano)
	snapshot, loadErr := loader.LoadSnapshot(ctx)
	if loadErr == nil {
		loadErr = loader.ValidateFreshSnapshot()
	}
	reads, readErr := loader.FreshSourceReads()
	closeErr := store.Close()
	if err = errors.Join(loadErr, readErr, closeErr); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	after, err := inspectCheckpoint(ctx, output)
	if err != nil {
		return err
	}
	// The loader preserves an existing trust decision. A legacy source without
	// one may gain only the same pending/trusted marker PrepareIgnoreMemory sets.
	if _, ok := before.Meta[cache.IgnoreMemoryStateKey]; !ok {
		state := "pending"
		if before.IgnoreRows > 0 {
			state = cache.IgnoreMemoryTrusted
		}
		before.Meta[cache.IgnoreMemoryStateKey] = state
	}
	// Only the reviewed nullable-column additions may change schema SQL. In
	// particular, a source without updated_at is rejected before cache.Open can
	// run its timestamp-backfill migration. Bind the receipt to the final SQL.
	if after.IgnoreColumns != 8 {
		return errors.New("incomplete observation checkpoint schema")
	}
	if before.IgnoreColumns == 6 || before.IgnoreColumns == 7 {
		expected, err := upgradedCheckpointIgnoreSQL(ctx, before.Schema["snyk_ignores"], before.IgnoreColumns)
		if err != nil {
			return err
		}
		if after.Schema["snyk_ignores"] != expected {
			return errors.New("unreviewed checkpoint schema migration")
		}
		before.Schema["snyk_ignores"] = expected
	}
	before.IgnoreColumns = 0
	after.IgnoreColumns = 0
	before.IgnoreRows = 0
	after.IgnoreRows = 0
	if !reflect.DeepEqual(before, after) {
		return errors.New("observation checkpoint changed protected cache state")
	}
	currentSource, err := readCheckpointFile(cfg.Cache.DBFile)
	if err != nil {
		return err
	}
	if checkpointDigest(currentSource) != cfg.ObservationSourceSHA256 {
		return errors.New("observation source changed during preparation")
	}
	candidate, err := readCheckpointFile(output)
	if err != nil {
		return err
	}
	protected, err := json.Marshal(after)
	if err != nil {
		return err
	}
	planCfg := cfg
	planCfg.ReplaySafe = true
	settingsSHA, err := syncsvc.PlanSettingsSHA256(planCfg)
	if err != nil {
		return err
	}

	receipt := checkpointReceipt{Protocol: checkpointProtocol, Complete: true, SourceSHA256: cfg.ObservationSourceSHA256, CheckpointSHA256: checkpointDigest(candidate), ProtectedSHA256: checkpointDigest(protected), SettingsSHA256: settingsSHA, StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), Findings: len(snapshot.Findings), FreshSourceReads: reads}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := ctx.Err(); err != nil {
		return err
	}
	rf, err := os.OpenFile(receiptPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = rf.Write(data); err == nil {
		err = rf.Sync()
	}
	err = errors.Join(err, rf.Close())
	if err != nil {
		_ = os.Remove(receiptPath)
		return err
	}
	directory, err := os.OpenRoot(filepath.Dir(output))
	if err == nil {
		var dir *os.File
		dir, err = directory.Open(".")
		if err == nil {
			err = errors.Join(dir.Sync(), dir.Close())
		}
		err = errors.Join(err, directory.Close())
	}
	if err != nil {
		_ = os.Remove(receiptPath)
		return err
	}
	complete = true
	return nil
}
func checkpointDigest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
func noCheckpointSidecars(path string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			return errors.New("SQLite sidecar exists or is inaccessible")
		}
	}
	return nil
}
func noCheckpointSymlinks(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink in checkpoint path")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}
func privateCheckpointParent(path string) error {
	parent := filepath.Dir(path)
	if err := noCheckpointSymlinks(parent); err != nil {
		return err
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("checkpoint output parent must be a private mode-0700 directory")
	}
	return nil
}

// The operator selects the source path, but the leaf must never escape its
// opened parent directory, including if a symlink changes during the read.
func readCheckpointFile(path string) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := noCheckpointSymlinks(absolute); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, opened, err := readCheckpointRoot(root, filepath.Base(absolute))
	if err != nil {
		return nil, err
	}
	if err := noCheckpointSymlinks(absolute); err != nil {
		return nil, err
	}
	after, err := os.Lstat(absolute)
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(data)) || !after.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("checkpoint path changed during read")
	}
	return data, nil
}

func readCheckpointRoot(root *os.Root, name string) ([]byte, os.FileInfo, error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name {
		return nil, nil, errors.New("checkpoint must name one file within its parent")
	}
	checkSidecars := func() error {
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			if _, err := root.Lstat(name + suffix); !os.IsNotExist(err) {
				return errors.New("SQLite sidecar exists or is inaccessible")
			}
		}
		return nil
	}
	if err := checkSidecars(); err != nil {
		return nil, nil, err
	}
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCheckpointBytes {
		return nil, nil, errors.New("checkpoint must be a regular bounded non-symlink file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > maxCheckpointBytes {
		_ = file.Close()
		return nil, nil, errors.New("checkpoint replaced before read")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxCheckpointBytes+1))
	finished, statErr := file.Stat()
	if err = errors.Join(readErr, statErr, file.Close()); err != nil || len(data) > maxCheckpointBytes {
		return nil, nil, errors.New("cannot read bounded checkpoint")
	}
	if !os.SameFile(opened, finished) || opened.Size() != finished.Size() || !opened.ModTime().Equal(finished.ModTime()) {
		return nil, nil, errors.New("checkpoint changed through read descriptor")
	}
	after, err := root.Lstat(name)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(info, after) || after.Size() != int64(len(data)) || !after.ModTime().Equal(info.ModTime()) {
		return nil, nil, errors.New("checkpoint changed during rooted read")
	}
	if err := checkSidecars(); err != nil {
		return nil, nil, err
	}
	return data, opened, nil
}
func removeCheckpoint(path string) error {
	var errs []error
	for _, name := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func inspectCheckpoint(ctx context.Context, path string) (protectedCheckpointState, error) {
	state := protectedCheckpointState{Schema: map[string]string{}}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return state, err
	}
	u := url.URL{Scheme: "file", Path: absolute}
	q := url.Values{"mode": {"ro"}, "immutable": {"1"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return state, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
	if err != nil {
		return state, err
	}
	allowed := map[string]bool{"sync_meta": true, "snyk_findings": true, "linear_issues": true, "snyk_ignores": true}
	for rows.Next() {
		var kind, name, table string
		var definition sql.NullString
		if err := rows.Scan(&kind, &name, &table, &definition); err != nil {
			rows.Close()
			return state, err
		}
		if kind == "index" && !definition.Valid && allowed[table] && name == "sqlite_autoindex_"+table+"_1" {
			continue
		}
		if kind != "table" || !allowed[name] || !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(definition.String)), "CREATE TABLE") {
			rows.Close()
			return state, errors.New("unreviewed checkpoint schema object")
		}
		state.Schema[name] = definition.String
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return state, err
	}
	if len(state.Schema) != 4 {
		return state, errors.New("incomplete checkpoint schema")
	}
	// table_xinfo includes generated/hidden columns, unlike table_info. Literal
	// queries keep database-derived identifiers out of executable SQL.
	type column struct {
		name, kind  string
		notNull, pk int
	}
	for _, table := range []struct {
		name, query string
		columns     []column
	}{
		{"sync_meta", "PRAGMA table_xinfo(sync_meta)", []column{{"key", "TEXT", 0, 1}, {"value", "TEXT", 1, 0}}},
		{"snyk_findings", "PRAGMA table_xinfo(snyk_findings)", []column{{"fingerprint", "TEXT", 0, 1}, {"hash", "TEXT", 1, 0}}},
		{"linear_issues", "PRAGMA table_xinfo(linear_issues)", []column{{"fingerprint", "TEXT", 0, 1}, {"hash", "TEXT", 1, 0}}},
		{"snyk_ignores", "PRAGMA table_xinfo(snyk_ignores)", []column{
			{"project_id", "TEXT", 1, 1}, {"issue_key", "TEXT", 1, 2},
			{"expires_at", "TEXT", 0, 0}, {"disregard_if_fixable", "INTEGER", 1, 0},
			{"created_at", "TEXT", 0, 0}, {"updated_at", "TEXT", 0, 0},
			{"unignored_at", "TEXT", 0, 0}, {"observed_issues", "TEXT", 0, 0},
		}},
	} {
		rows, err := db.QueryContext(ctx, table.query)
		if err != nil {
			return state, err
		}
		count := 0
		for rows.Next() {
			var cid, hidden int
			var actual column
			var defaultValue sql.NullString
			if err := rows.Scan(&cid, &actual.name, &actual.kind, &actual.notNull, &defaultValue, &actual.pk, &hidden); err != nil {
				rows.Close()
				return state, err
			}
			if count >= len(table.columns) || cid != count || hidden != 0 || actual != table.columns[count] {
				rows.Close()
				return state, errors.New("unreviewed checkpoint columns")
			}
			count++
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return state, err
		}
		if table.name == "snyk_ignores" {
			if count < 6 {
				return state, errors.New("unsupported checkpoint ignore migration")
			}
			state.IgnoreColumns = count
		} else if count != len(table.columns) {
			return state, errors.New("incomplete checkpoint columns")
		}
	}
	for _, item := range []struct {
		query       string
		destination *map[string]string
	}{
		{"SELECT key,value FROM sync_meta ORDER BY key", &state.Meta},
		{"SELECT fingerprint,hash FROM snyk_findings ORDER BY fingerprint", &state.Snyk},
		{"SELECT fingerprint,hash FROM linear_issues ORDER BY fingerprint", &state.Linear},
	} {
		rows, err := db.QueryContext(ctx, item.query)
		if err != nil {
			return state, err
		}
		*item.destination = map[string]string{}
		for rows.Next() {
			var key, value string
			if err := rows.Scan(&key, &value); err != nil {
				rows.Close()
				return state, err
			}
			if _, duplicate := (*item.destination)[key]; duplicate {
				rows.Close()
				return state, errors.New("duplicate protected checkpoint key")
			}
			(*item.destination)[key] = value
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return state, err
		}
	}
	if state.Meta["schema_version"] != "v1" {
		return state, errors.New("unsupported checkpoint cache schema version")
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM snyk_ignores").Scan(&state.IgnoreRows); err != nil {
		return state, err
	}
	return state, nil
}

// Reproduce SQLite's own SQL rewriting in an isolated database: ADD COLUMN
// inserts before table constraints, rather than necessarily before the last ')'.
// definition comes only from a table already checked by inspectCheckpoint.
func upgradedCheckpointIgnoreSQL(ctx context.Context, definition string, columns int) (string, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return "", err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, definition); err != nil {
		return "", err
	}
	if columns == 6 {
		if _, err := db.ExecContext(ctx, "ALTER TABLE snyk_ignores ADD COLUMN unignored_at TEXT"); err != nil {
			return "", err
		}
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE snyk_ignores ADD COLUMN observed_issues TEXT"); err != nil {
		return "", err
	}
	var expected string
	err = db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='snyk_ignores'").Scan(&expected)
	return expected, err
}
