package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
	"github.com/tesslio/snyk-linear-sync/internal/config"
	"github.com/tesslio/snyk-linear-sync/internal/model"
	snykclient "github.com/tesslio/snyk-linear-sync/internal/snyk"
	syncsvc "github.com/tesslio/snyk-linear-sync/internal/sync"
)

type checkpointTestLoader struct {
	store     *cache.Store
	calls     int
	failure   string
	afterLoad func()
}

func (l *checkpointTestLoader) SetCache(s *cache.Store) { l.store = s }
func (l *checkpointTestLoader) LoadSnapshot(ctx context.Context) (model.SnykSnapshot, error) {
	l.calls++
	if _, err := cache.PrepareIgnoreMemory(ctx, l.store); err != nil {
		return model.SnykSnapshot{}, err
	}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := l.store.SaveIgnores(ctx, "project-a", map[string]cache.IgnoreMeta{"issue-1": {DisregardIfFixable: true, CreatedAt: now.Add(-time.Hour), UpdatedAt: now, UnignoredAt: now}}); err != nil {
		return model.SnykSnapshot{}, err
	}
	if l.afterLoad != nil {
		l.afterLoad()
	}
	switch l.failure {
	case "partial":
		return model.SnykSnapshot{}, errors.New("incomplete source read")
	case "hashes":
		_ = l.store.Save(ctx, cache.Snapshot{SnykHashes: map[string]string{"changed": "value"}, LinearHashes: map[string]string{}})
	case "trust":
		_ = l.store.SetMeta(ctx, "ignores_cold_start_at", "changed")
	}
	return model.SnykSnapshot{Findings: []model.Finding{{Fingerprint: "example"}}}, nil
}
func (l *checkpointTestLoader) ValidateFreshSnapshot() error {
	if l.failure == "stale" {
		return errors.New("not fresh")
	}
	return nil
}
func (l *checkpointTestLoader) FreshSourceReads() (snykclient.SourceReads, error) {
	if l.failure == "stale" {
		return snykclient.SourceReads{}, errors.New("not fresh")
	}
	return snykclient.SourceReads{Organization: true, ProjectPages: 1, IssuePages: 1, IgnoreProjects: 1, Complete: true}, nil
}
func checkpointTestConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source.db")
	s, err := cache.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(t.Context(), cache.Snapshot{SchemaSignature: "example", SnykHashes: map[string]string{"source": "hash"}, LinearHashes: map[string]string{"ticket": "hash"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta(t.Context(), "ignores_cold_start_at", "2029-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CACHE_DB_FILE", source)
	for _, key := range []string{"SNYK_CLIENT_ID", "SNYK_CLIENT_SECRET", "SNYK_ORG_ID"} {
		t.Setenv(key, "example")
	}
	t.Setenv("LINEAR_API_KEY", "")
	t.Setenv("LINEAR_TEAM_ID", "11111111-1111-4111-8111-111111111111")
	cfg, err := config.Load([]string{"--observation-checkpoint", filepath.Join(dir, "candidate.db"), "--observation-source-sha256", checkpointDigest(data)})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
func TestObservationCheckpointCreatesBoundPrivateCandidate(t *testing.T) {
	cfg := checkpointTestConfig(t)
	loader := &checkpointTestLoader{}
	if err := prepareObservationCheckpoint(t.Context(), cfg, loader); err != nil {
		t.Fatal(err)
	}
	if loader.calls != 1 {
		t.Fatal("loader not called once")
	}
	source, err := os.ReadFile(cfg.Cache.DBFile)
	if err != nil || checkpointDigest(source) != cfg.ObservationSourceSHA256 {
		t.Fatal("source changed")
	}
	candidate, err := os.ReadFile(cfg.ObservationCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfg.ObservationCheckpoint + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt checkpointReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.Complete || receipt.SourceSHA256 != cfg.ObservationSourceSHA256 || receipt.CheckpointSHA256 != checkpointDigest(candidate) || !receipt.FreshSourceReads.Complete {
		t.Fatal("receipt not bound")
	}
	v2Cfg := cfg
	v2Cfg.ReplaySafe = true
	settingsSHA, err := syncsvc.PlanSettingsSHA256(v2Cfg)
	if err != nil || receipt.SettingsSHA256 != settingsSHA {
		t.Fatal("checkpoint settings differ from v2 plan")
	}
	for _, p := range []string{cfg.ObservationCheckpoint, cfg.ObservationCheckpoint + ".json"} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("output is not private")
		}
	}
	state, err := inspectCheckpoint(t.Context(), cfg.ObservationCheckpoint)
	if err != nil || state.Meta[cache.IgnoreMemoryStateKey] != "pending" {
		t.Fatal("lost untrusted empty start")
	}
}
func TestObservationCheckpointDiscardsIncompleteOrMutatedState(t *testing.T) {
	for _, failure := range []string{"partial", "stale", "hashes", "trust"} {
		t.Run(failure, func(t *testing.T) {
			cfg := checkpointTestConfig(t)
			loader := &checkpointTestLoader{failure: failure}
			if err := prepareObservationCheckpoint(t.Context(), cfg, loader); err == nil || loader.calls != 1 {
				t.Fatalf("accepted invalid checkpoint or did not reach loader: %v, %d", err, loader.calls)
			}
			for _, p := range []string{cfg.ObservationCheckpoint, cfg.ObservationCheckpoint + ".json"} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatal("failed checkpoint left publishable output")
				}
			}
			source, err := os.ReadFile(cfg.Cache.DBFile)
			if err != nil || checkpointDigest(source) != cfg.ObservationSourceSHA256 {
				t.Fatal("source changed")
			}
		})
	}
}
func TestObservationCheckpointRejectsUnsafeInputsBeforeLoading(t *testing.T) {
	for _, failure := range []string{"wrong-digest", "existing-output", "source-sidecar", "public-directory"} {
		t.Run(failure, func(t *testing.T) {
			cfg := checkpointTestConfig(t)
			loader := &checkpointTestLoader{}
			switch failure {
			case "wrong-digest":
				cfg.ObservationSourceSHA256 = checkpointDigest([]byte("other"))
			case "existing-output":
				_ = os.WriteFile(cfg.ObservationCheckpoint, []byte("keep"), 0600)
			case "source-sidecar":
				_ = os.WriteFile(cfg.Cache.DBFile+"-wal", []byte("pending"), 0600)
			case "public-directory":
				_ = os.Chmod(filepath.Dir(cfg.ObservationCheckpoint), 0755)
			}
			if err := prepareObservationCheckpoint(t.Context(), cfg, loader); err == nil || loader.calls != 0 {
				t.Fatalf("unsafe input loaded: %v", err)
			}
			if failure == "existing-output" {
				b, _ := os.ReadFile(cfg.ObservationCheckpoint)
				if string(b) != "keep" {
					t.Fatal("overwrote existing file")
				}
			}
		})
	}
}

const checkpointIgnoreBase = `CREATE TABLE snyk_ignores (
 project_id TEXT NOT NULL, issue_key TEXT NOT NULL, expires_at TEXT,
 disregard_if_fixable INTEGER NOT NULL DEFAULT 0, created_at TEXT, updated_at TEXT%s,
 PRIMARY KEY (project_id, issue_key))`

func rewriteCheckpointSource(t *testing.T, cfg *config.Config, statements ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", cfg.Cache.DBFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.Cache.DBFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ObservationSourceSHA256 = checkpointDigest(data)
}

func TestObservationCheckpointReviewedSchemaUpgrades(t *testing.T) {
	for _, count := range []int{6, 7, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			cfg := checkpointTestConfig(t)
			suffix := ""
			if count >= 7 {
				suffix += ", unignored_at TEXT"
			}
			if count == 8 {
				suffix += ", observed_issues TEXT"
			}
			rewriteCheckpointSource(t, &cfg, "DROP TABLE snyk_ignores", fmt.Sprintf(checkpointIgnoreBase, suffix),
				`INSERT INTO snyk_ignores(project_id,issue_key,expires_at,disregard_if_fixable,created_at,updated_at) VALUES('history','old','2035-01-01T00:00:00Z',1,'2020-01-01T00:00:00Z','2021-01-01T00:00:00Z')`)
			rewriteCheckpointSource(t, &cfg, `INSERT INTO snyk_ignores(project_id,issue_key,disregard_if_fixable) VALUES('history','null-times',0)`)
			if count >= 7 {
				rewriteCheckpointSource(t, &cfg, `UPDATE snyk_ignores SET unignored_at='2022-01-01T00:00:00Z' WHERE issue_key='old'`)
			}
			if count == 8 {
				rewriteCheckpointSource(t, &cfg, `UPDATE snyk_ignores SET observed_issues='["old"]' WHERE issue_key='old'`)
			}
			before, err := inspectCheckpoint(t.Context(), cfg.Cache.DBFile)
			if err != nil {
				t.Fatal(err)
			}
			if before.IgnoreColumns != count {
				t.Fatal("wrong fixture schema")
			}
			if err := prepareObservationCheckpoint(t.Context(), cfg, &checkpointTestLoader{}); err != nil {
				t.Fatal(err)
			}
			source, err := os.ReadFile(cfg.Cache.DBFile)
			if err != nil || checkpointDigest(source) != cfg.ObservationSourceSHA256 {
				t.Fatal("source bytes changed")
			}
			after, err := inspectCheckpoint(t.Context(), cfg.ObservationCheckpoint)
			if err != nil || after.IgnoreColumns != 8 || after.Meta[cache.IgnoreMemoryStateKey] != cache.IgnoreMemoryTrusted {
				t.Fatalf("invalid upgraded state: %v", err)
			}
			db, err := sql.Open("sqlite", cfg.ObservationCheckpoint)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var expires, created, updated string
			var disregard int
			var unignored, observed sql.NullString
			err = db.QueryRow(`SELECT expires_at,disregard_if_fixable,created_at,updated_at,unignored_at,observed_issues FROM snyk_ignores WHERE project_id='history' AND issue_key='old'`).Scan(&expires, &disregard, &created, &updated, &unignored, &observed)
			if err != nil || expires != "2035-01-01T00:00:00Z" || disregard != 1 || created != "2020-01-01T00:00:00Z" || updated != "2021-01-01T00:00:00Z" || unignored.Valid != (count >= 7) || observed.Valid != (count == 8) || (unignored.Valid && unignored.String != "2022-01-01T00:00:00Z") || (observed.Valid && observed.String != `["old"]`) {
				t.Fatalf("history changed: %v", err)
			}
			var untouched int
			err = db.QueryRow(`SELECT count(*) FROM snyk_ignores WHERE project_id='history' AND issue_key='null-times' AND created_at IS NULL AND updated_at IS NULL AND unignored_at IS NULL AND observed_issues IS NULL`).Scan(&untouched)
			if err != nil || untouched != 1 {
				t.Fatalf("null timestamps backfilled: %v", err)
			}
			protected, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(cfg.ObservationCheckpoint + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var receipt checkpointReceipt
			if err := json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.ProtectedSHA256 != checkpointDigest(protected) {
				t.Fatal("receipt does not bind final schema")
			}
		})
	}
}

func TestObservationCheckpointRejectsUnreviewedSchema(t *testing.T) {
	base := fmt.Sprintf(checkpointIgnoreBase, "")
	cases := map[string][]string{
		"extra":                    {"ALTER TABLE snyk_ignores ADD COLUMN arbitrary TEXT"},
		"missing-updated-backfill": {"DROP TABLE snyk_ignores", strings.Replace(base, ", updated_at TEXT", "", 1)},
		"missing-intermediate":     {"DROP TABLE snyk_ignores", fmt.Sprintf(checkpointIgnoreBase, ", observed_issues TEXT")},
		"wrong-type":               {"DROP TABLE snyk_ignores", strings.Replace(base, "updated_at TEXT", "updated_at BLOB", 1)},
		"wrong-pk":                 {"DROP TABLE snyk_ignores", strings.Replace(base, "PRIMARY KEY (project_id, issue_key)", "PRIMARY KEY (issue_key, project_id)", 1)},
		"wrong-nullability":        {"DROP TABLE snyk_ignores", strings.Replace(base, "updated_at TEXT", "updated_at TEXT NOT NULL", 1)},
		"wrong-order":              {"DROP TABLE snyk_ignores", strings.Replace(base, "created_at TEXT, updated_at TEXT", "updated_at TEXT, created_at TEXT", 1)},
		"generated":                {"DROP TABLE snyk_ignores", fmt.Sprintf(checkpointIgnoreBase, ", unignored_at TEXT GENERATED ALWAYS AS (updated_at) VIRTUAL")},
		"trigger":                  {"CREATE TRIGGER bad AFTER INSERT ON snyk_ignores BEGIN DELETE FROM snyk_findings; END"},
		"extra-table":              {"CREATE TABLE extra (id TEXT)"},
	}
	for _, table := range []string{"sync_meta", "snyk_findings", "linear_issues"} {
		cases[table+"-extra"] = []string{"ALTER TABLE " + table + " ADD COLUMN extra TEXT"}
		key := "fingerprint"
		value := "hash"
		if table == "sync_meta" {
			key, value = "key", "value"
		}
		cases[table+"-type"] = []string{"DROP TABLE " + table, "CREATE TABLE " + table + " (" + key + " TEXT PRIMARY KEY, " + value + " BLOB NOT NULL)"}
		cases[table+"-pk"] = []string{"DROP TABLE " + table, "CREATE TABLE " + table + " (" + key + " TEXT, " + value + " TEXT NOT NULL)"}
		cases[table+"-missing"] = []string{"DROP TABLE " + table, "CREATE TABLE " + table + " (" + key + " TEXT PRIMARY KEY)"}
		cases[table+"-generated"] = []string{"ALTER TABLE " + table + " ADD COLUMN extra TEXT GENERATED ALWAYS AS ('x') VIRTUAL"}
	}
	for name, statements := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := checkpointTestConfig(t)
			rewriteCheckpointSource(t, &cfg, statements...)
			loader := &checkpointTestLoader{}
			if err := prepareObservationCheckpoint(t.Context(), cfg, loader); err == nil || loader.calls != 0 {
				t.Fatalf("unreviewed schema loaded: %v", err)
			}
			for _, p := range []string{cfg.ObservationCheckpoint, cfg.ObservationCheckpoint + ".json"} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatal("rejected schema left output")
				}
			}
			source, err := os.ReadFile(cfg.Cache.DBFile)
			if err != nil || checkpointDigest(source) != cfg.ObservationSourceSHA256 {
				t.Fatal("source bytes changed")
			}
		})
	}
}

func TestObservationCheckpointRejectsOtherSchemaChangesDuringUpgrade(t *testing.T) {
	for _, count := range []int{6, 7, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			cfg := checkpointTestConfig(t)
			suffix := ""
			if count >= 7 {
				suffix += ", unignored_at TEXT"
			}
			if count == 8 {
				suffix += ", observed_issues TEXT"
			}
			rewriteCheckpointSource(t, &cfg, "DROP TABLE snyk_ignores", fmt.Sprintf(checkpointIgnoreBase, suffix))
			loader := &checkpointTestLoader{afterLoad: func() {
				db, err := sql.Open("sqlite", cfg.ObservationCheckpoint)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				// Exact reviewed column metadata still matches, but raw schema changed in
				// addition to the permitted migrations. This must not earn a receipt.
				if _, err := db.Exec("DROP TABLE snyk_ignores"); err != nil {
					t.Fatal(err)
				}
				altered := fmt.Sprintf(checkpointIgnoreBase, ", unignored_at TEXT, observed_issues TEXT DEFAULT 'unexpected'")
				if _, err := db.Exec(altered); err != nil {
					t.Fatal(err)
				}
			}}
			if err := prepareObservationCheckpoint(t.Context(), cfg, loader); err == nil || loader.calls != 1 {
				t.Fatalf("accepted extra schema change: %v", err)
			}
			for _, p := range []string{cfg.ObservationCheckpoint, cfg.ObservationCheckpoint + ".json"} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatal("failed migration left output")
				}
			}
		})
	}
}

func TestObservationCheckpointRelativePaths(t *testing.T) {
	for _, output := range []string{"candidate.db", "private-observation/candidate.db", "private-observation/candidate #.db", "file:candidate.db", ":memory:", "candidate%3F.db", "candidate%23.db", "source.db%3Fmode=rw", "source.db#fragment"} {
		t.Run(output, func(t *testing.T) {
			cfg := checkpointTestConfig(t)
			t.Chdir(filepath.Dir(cfg.Cache.DBFile))
			cfg.Cache.DBFile = "source.db"
			cfg.ObservationCheckpoint = output
			if parent := filepath.Dir(output); parent != "." {
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
			}
			loader := &checkpointTestLoader{}
			if err := prepareObservationCheckpoint(t.Context(), cfg, loader); err != nil {
				t.Fatal(err)
			}
			if loader.calls != 1 {
				t.Fatal("relative checkpoint did not reach loader")
			}
			source, err := os.ReadFile(cfg.Cache.DBFile)
			if err != nil || checkpointDigest(source) != cfg.ObservationSourceSHA256 {
				t.Fatal("source bytes changed through filename interpretation")
			}
			relative, err := inspectCheckpoint(t.Context(), output)
			if err != nil {
				t.Fatal(err)
			}
			absolute, err := filepath.Abs(output)
			if err != nil {
				t.Fatal(err)
			}
			full, err := inspectCheckpoint(t.Context(), absolute)
			if err != nil || !reflect.DeepEqual(relative, full) {
				t.Fatalf("relative and absolute inspection differ: %v", err)
			}
			candidate, err := readCheckpointFile(output)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(output + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var receipt checkpointReceipt
			if err := json.Unmarshal(raw, &receipt); err != nil || !receipt.Complete || receipt.CheckpointSHA256 != checkpointDigest(candidate) {
				t.Fatalf("relative candidate receipt does not bind bytes: %v", err)
			}
		})
	}
}

func TestCheckpointRootRejectsTraversalAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.db")
	for _, path := range []string{outside, filepath.Join(parent, "source.db")} {
		if err := os.WriteFile(path, []byte("example checkpoint"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"outside-link.db": "../outside.db", "inside-link.db": "source.db"} {
		if err := os.Symlink(target, filepath.Join(parent, name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"../outside.db", outside, "sub/../source.db", "sub/source.db", "outside-link.db", "inside-link.db", ".", ""} {
		t.Run(name, func(t *testing.T) {
			if data, _, err := readCheckpointRoot(root, name); err == nil || data != nil {
				t.Fatalf("read unsafe rooted checkpoint %q: %q, %v", name, data, err)
			}
		})
	}
	data, _, err := readCheckpointRoot(root, "source.db")
	if err != nil || string(data) != "example checkpoint" {
		t.Fatalf("safe leaf rejected: %q, %v", data, err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readCheckpointFile(filepath.Join(alias, "source.db")); err == nil {
		t.Fatal("accepted symlink in parent path")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.WriteFile(filepath.Join(parent, "source.db"+suffix), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readCheckpointRoot(root, "source.db"); err == nil {
			t.Fatal("accepted SQLite sidecar")
		}
		if err := os.Remove(filepath.Join(parent, "source.db"+suffix)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCheckpointRootRemainsBoundToOpenedParent(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "source.db"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(parent, filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "source.db"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	data, _, err := readCheckpointRoot(root, "source.db")
	if err != nil || string(data) != "original" {
		t.Fatalf("root followed replaced parent: %q, %v", data, err)
	}
}

func TestObservationCheckpointRejectsOutputDSNQueryBeforeLoading(t *testing.T) {
	cfg := checkpointTestConfig(t)
	// If passed to SQLite unchanged, this would open the existing source DB,
	// not the distinct literal filename checked and created by os.OpenFile.
	cfg.ObservationCheckpoint = cfg.Cache.DBFile + "?mode=rw"
	loader := &checkpointTestLoader{}
	if err := prepareObservationCheckpoint(t.Context(), cfg, loader); err == nil || loader.calls != 0 {
		t.Fatalf("accepted SQLite query syntax: %v", err)
	}
	if _, err := os.Lstat(cfg.ObservationCheckpoint); !os.IsNotExist(err) {
		t.Fatal("created query-shaped output")
	}
	source, err := os.ReadFile(cfg.Cache.DBFile)
	if err != nil || checkpointDigest(source) != cfg.ObservationSourceSHA256 {
		t.Fatal("source bytes changed")
	}
}

func TestObservationCheckpointRejectsSourceOutputAliases(t *testing.T) {
	for _, alias := range []string{"exact", "relative", "hardlink", "symlink"} {
		t.Run(alias, func(t *testing.T) {
			cfg := checkpointTestConfig(t)
			switch alias {
			case "exact":
				cfg.ObservationCheckpoint = cfg.Cache.DBFile
			case "relative":
				t.Chdir(filepath.Dir(cfg.Cache.DBFile))
				cfg.ObservationCheckpoint = "./source.db"
			case "hardlink":
				if err := os.Link(cfg.Cache.DBFile, cfg.ObservationCheckpoint); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(cfg.Cache.DBFile, cfg.ObservationCheckpoint); err != nil {
					t.Fatal(err)
				}
			}
			loader := &checkpointTestLoader{}
			if err := prepareObservationCheckpoint(t.Context(), cfg, loader); err == nil || loader.calls != 0 {
				t.Fatalf("source/output alias reached loader: %v", err)
			}
			source, err := os.ReadFile(cfg.Cache.DBFile)
			if err != nil || checkpointDigest(source) != cfg.ObservationSourceSHA256 {
				t.Fatal("source bytes changed")
			}
			if _, err := os.Stat(cfg.ObservationCheckpoint + ".json"); !os.IsNotExist(err) {
				t.Fatal("alias received a receipt")
			}
		})
	}
}
