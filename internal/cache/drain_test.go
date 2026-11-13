package cache

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func drainSnapshot(generation int) Snapshot {
	pending, _ := json.Marshal(map[string]any{"version": 1, "generation": generation, "entries": map[string]any{}})
	evidence, _ := json.Marshal(map[string]any{"version": 1, "generation": generation})
	return Snapshot{SchemaSignature: "v1+drain-v1", SnykHashes: map[string]string{"finding-a": "source-hash"}, LinearHashes: map[string]string{}, BoundedDrainPending: pending, BoundedDrainHashEvidence: evidence}
}

func TestDrainSnapshotRoundTripEmptyLinearMap(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	for generation := range 3 {
		want := drainSnapshot(generation)
		if err := store.Save(ctx, want); err != nil {
			t.Fatal(err)
		}
		got, err := store.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("roundtrip = %#v, want %#v", got, want)
		}
	}
}

func TestDrainSnapshotRejectsInconsistentMetadata(t *testing.T) {
	tests := map[string]func(*Snapshot){
		"missing pending":  func(s *Snapshot) { s.BoundedDrainPending = nil },
		"missing evidence": func(s *Snapshot) { s.BoundedDrainHashEvidence = nil },
		"legacy signature": func(s *Snapshot) { s.SchemaSignature = "v1" },
		"empty pending":    func(s *Snapshot) { s.BoundedDrainPending = json.RawMessage{} },
		"invalid evidence": func(s *Snapshot) { s.BoundedDrainHashEvidence = json.RawMessage("{") },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			store := openTestStore(t)
			snapshot := drainSnapshot(1)
			change(&snapshot)
			if err := store.Save(context.Background(), snapshot); err == nil {
				t.Fatal("accepted inconsistent metadata")
			}
		})
	}
}

func TestDrainSnapshotLoadRejectsDamagedMetadata(t *testing.T) {
	for _, statement := range []string{
		`DELETE FROM sync_meta WHERE key = 'bounded_drain_pending'`,
		`DELETE FROM sync_meta WHERE key = 'bounded_drain_hash_evidence'`,
		`UPDATE sync_meta SET value = 'v1' WHERE key = 'schema_signature'`,
		`UPDATE sync_meta SET value = '' WHERE key = 'bounded_drain_pending'`,
	} {
		t.Run(statement, func(t *testing.T) {
			store := openTestStore(t)
			ctx := context.Background()
			if err := store.Save(ctx, drainSnapshot(1)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(ctx); err == nil {
				t.Fatal("accepted damaged metadata")
			}
			if err := store.Save(ctx, Snapshot{SchemaSignature: "v1"}); err == nil {
				t.Fatal("downgraded damaged drain cache")
			}
		})
	}
}

func TestDrainSnapshotAtomicRollback(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	want := drainSnapshot(1)
	want.LinearHashes["finding-a"] = "old-linear-hash"
	if err := store.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_hash BEFORE INSERT ON linear_issues BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
		t.Fatal(err)
	}
	next := drainSnapshot(2)
	next.SchemaSignature = "v2+drain-v1"
	next.SnykHashes["finding-a"] = "new-source-hash"
	next.LinearHashes["finding-b"] = "new-linear-hash"
	if err := store.Save(ctx, next); err == nil {
		t.Fatal("expected insert failure")
	}
	got, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("failed transaction changed snapshot: %#v, want %#v", got, want)
	}
}

func TestDrainSnapshotCannotBeOverwrittenByLegacy(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	want := drainSnapshot(1)
	if err := store.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, Snapshot{SchemaSignature: "v1"}); err == nil {
		t.Fatal("legacy save overwrote drain cache")
	}
	got, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("refused save changed snapshot")
	}
}
