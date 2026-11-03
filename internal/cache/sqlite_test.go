package cache

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "test-cache.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestLoadIgnoresKeepsRowsNotConfirmedForWeeks pins that the cache no longer
// ages rows out on read. Once the Snyk v1 ignores endpoint stops returning an
// expired ignore, the cached row is the only record of the expiry the due
// date is based on, so a row that has not been reconfirmed for a long time is
// returned like any other; retention is decided by the Snyk loader instead.
func TestLoadIgnoresKeepsRowsNotConfirmedForWeeks(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	projectID := "project-a"
	issueKey := "SNYK-100"

	staleUpdatedAt := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	expiresAt := time.Now().UTC().Add(-20 * 24 * time.Hour).Truncate(time.Second)
	if err := store.SaveIgnores(ctx, projectID, map[string]IgnoreMeta{
		issueKey: {
			IssueKey:  issueKey,
			ExpiresAt: expiresAt,
			CreatedAt: time.Now().UTC().Add(-60 * 24 * time.Hour),
			UpdatedAt: staleUpdatedAt,
		},
	}); err != nil {
		t.Fatalf("SaveIgnores() error = %v", err)
	}

	loaded, err := store.LoadIgnores(ctx, projectID)
	if err != nil {
		t.Fatalf("LoadIgnores() error = %v", err)
	}
	row, ok := loaded[issueKey]
	if !ok {
		t.Fatalf("ignore row %q not confirmed for 30 days was evicted on read", issueKey)
	}
	if !row.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("ExpiresAt = %v, want %v", row.ExpiresAt, expiresAt)
	}
	if !row.UpdatedAt.Equal(staleUpdatedAt) {
		t.Fatalf("UpdatedAt = %v, want %v (unchanged on read)", row.UpdatedAt, staleUpdatedAt)
	}
}

// TestLoadIgnoresKeepsLegacyAndUnparsableUpdatedAt covers rows written before
// updated_at existed (the migration seeds them with SQLite's CURRENT_TIMESTAMP
// format, which is not RFC3339) and rows whose updated_at is corrupt. Both are
// kept; the confirmation time is unknown (zero) rather than a reason to drop
// the row, and the legacy format is parsed when it can be.
func TestLoadIgnoresKeepsLegacyAndUnparsableUpdatedAt(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	projectID := "project-a"

	rows := []struct {
		key       string
		updatedAt string
	}{
		{"SNYK-100", "2026-01-02 03:04:05"}, // migration-seeded format
		{"SNYK-101", "not-a-timestamp"},
		{"SNYK-102", ""},
	}
	for _, row := range rows {
		if _, err := store.db.ExecContext(ctx,
			`INSERT INTO snyk_ignores (project_id, issue_key, expires_at, disregard_if_fixable, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)`,
			projectID, row.key, "2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z", row.updatedAt,
		); err != nil {
			t.Fatalf("insert %s: %v", row.key, err)
		}
	}

	loaded, err := store.LoadIgnores(ctx, projectID)
	if err != nil {
		t.Fatalf("LoadIgnores() error = %v", err)
	}
	if len(loaded) != len(rows) {
		t.Fatalf("LoadIgnores() returned %d rows, want %d: %+v", len(loaded), len(rows), loaded)
	}
	for _, row := range rows {
		meta, ok := loaded[row.key]
		if !ok {
			t.Fatalf("row %q (updated_at %q) was dropped", row.key, row.updatedAt)
		}
		if meta.ExpiresAt.IsZero() {
			t.Fatalf("row %q lost its expiry", row.key)
		}
	}
	legacy := loaded["SNYK-100"].UpdatedAt
	if want := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC); !legacy.Equal(want) {
		t.Fatalf("legacy updated_at parsed as %v, want %v", legacy, want)
	}
	if !loaded["SNYK-101"].UpdatedAt.IsZero() || !loaded["SNYK-102"].UpdatedAt.IsZero() {
		t.Fatalf("unparsable or empty updated_at should read as unknown (zero), got %v and %v", loaded["SNYK-101"].UpdatedAt, loaded["SNYK-102"].UpdatedAt)
	}
}

// TestSaveIgnoresStampsUnknownConfirmationTime pins the write-side half of
// the unknown-confirmation rule: a row saved with a zero UpdatedAt is stamped
// with the time of the write, so a legacy row starts its grace clock on the
// first run that touches it instead of staying unaged forever.
func TestSaveIgnoresStampsUnknownConfirmationTime(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	before := time.Now().UTC().Add(-time.Second)
	if err := store.SaveIgnores(ctx, "project-a", map[string]IgnoreMeta{
		"SNYK-100": {IssueKey: "SNYK-100", ExpiresAt: time.Now().UTC().Add(24 * time.Hour)},
	}); err != nil {
		t.Fatalf("SaveIgnores() error = %v", err)
	}
	loaded, err := store.LoadIgnores(ctx, "project-a")
	if err != nil {
		t.Fatalf("LoadIgnores() error = %v", err)
	}
	if got := loaded["SNYK-100"].UpdatedAt; got.Before(before) {
		t.Fatalf("UpdatedAt = %v, want stamped at save time (after %v)", got, before)
	}
}

// TestIgnoreRowsPresenceAndMeta covers the helpers the cold-start guard
// relies on: whether the ignore cache holds any row, and the sync_meta
// marker round trip.
func TestIgnoreRowsPresenceAndMeta(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	present, err := store.HasIgnoreRows(ctx)
	if err != nil || present {
		t.Fatalf("HasIgnoreRows() on an empty cache = %v, %v; want false, nil", present, err)
	}
	if err := store.SaveIgnores(ctx, "project-a", map[string]IgnoreMeta{
		"SNYK-100": {IssueKey: "SNYK-100", ExpiresAt: time.Now().UTC().Add(24 * time.Hour)},
	}); err != nil {
		t.Fatalf("SaveIgnores() error = %v", err)
	}
	present, err = store.HasIgnoreRows(ctx)
	if err != nil || !present {
		t.Fatalf("HasIgnoreRows() after a save = %v, %v; want true, nil", present, err)
	}

	if _, ok, err := store.GetMeta(ctx, "ignores_cold_start_at"); err != nil || ok {
		t.Fatalf("GetMeta() before set = ok %v, err %v; want absent", ok, err)
	}
	if err := store.SetMeta(ctx, "ignores_cold_start_at", "2026-03-01T12:00:00Z"); err != nil {
		t.Fatalf("SetMeta() error = %v", err)
	}
	value, ok, err := store.GetMeta(ctx, "ignores_cold_start_at")
	if err != nil || !ok || value != "2026-03-01T12:00:00Z" {
		t.Fatalf("GetMeta() = %q, %v, %v; want the stored value", value, ok, err)
	}
	// The sync snapshot save must not disturb other meta keys.
	if err := store.Save(ctx, Snapshot{SchemaSignature: "sig", SnykHashes: map[string]string{}, LinearHashes: map[string]string{}}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if _, ok, _ := store.GetMeta(ctx, "ignores_cold_start_at"); !ok {
		t.Fatal("marker lost on snapshot save")
	}
	if err := store.DeleteMeta(ctx, "ignores_cold_start_at"); err != nil {
		t.Fatalf("DeleteMeta() error = %v", err)
	}
	if _, ok, _ := store.GetMeta(ctx, "ignores_cold_start_at"); ok {
		t.Fatal("marker still present after delete")
	}
	if err := store.DeleteMeta(ctx, "ignores_cold_start_at"); err != nil {
		t.Fatalf("DeleteMeta() of an absent key error = %v, want nil", err)
	}
}
