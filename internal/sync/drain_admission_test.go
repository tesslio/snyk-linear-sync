package sync

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
)

func admissionFixture(generation int64) (DrainPending, DrainHashEvidence, cache.Snapshot) {
	hash := strings.Repeat("a", 64)
	p := DrainPending{Version: 1, Generation: generation, Entries: map[string]DrainPendingEntry{}}
	e := DrainHashEvidence{Version: 1, Generation: generation, ProducerRunID: "101", ProducerRunAttempt: 1, Refreshed: map[string]string{"finding-a": hash}, PreWrite: map[string]string{"finding-a": hash}, Withheld: map[string]DrainWithheld{}}
	if generation == 0 {
		e.Initialization = &DrainInitialization{"cache-a", hash, "100", "101"}
	} else {
		e.FullPlanSHA256 = hash
		e.SelectedOpsSHA256 = hash
		e.DeferredOpsSHA256 = hash
		e.SettingsSHA256 = hash
	}
	s := cache.Snapshot{SchemaSignature: managedSchemaSignature() + "+drain-v1", LinearHashes: map[string]string{"finding-a": hash}}
	return p, e, s
}

func admissionEncode(t *testing.T, p DrainPending, e DrainHashEvidence, s cache.Snapshot) cache.Snapshot {
	t.Helper()
	var err error
	if p.Generation > 0 {
		e.PendingAfterSHA256, err = drainDigest(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	s.BoundedDrainPending, err = canonicalDrainJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	s.BoundedDrainHashEvidence, err = canonicalDrainJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDrainAdmissionRoundTrip(t *testing.T) {
	for _, gen := range []int64{0, 1, 2} {
		p, e, s := admissionFixture(gen)
		s = admissionEncode(t, p, e, s)
		gotP, gotE, err := validateDrainSnapshot(s)
		if err != nil || gotP.Generation != gen || gotE.Generation != gen {
			t.Fatalf("generation %d: %v", gen, err)
		}
	}
}

func TestDrainAdmissionEmptySavedMap(t *testing.T) {
	p, e, s := admissionFixture(2)
	p.Entries["issue:issue-1"] = DrainPendingEntry{1, []string{planTextDigest("finding-a")}, 1}
	e.Withheld["finding-a"] = DrainWithheld{"unverified", []string{"issue:issue-1"}}
	s.LinearHashes = map[string]string{}
	s = admissionEncode(t, p, e, s)
	if _, _, err := validateDrainSnapshot(s); err != nil {
		t.Fatal(err)
	}
	e.Withheld = map[string]DrainWithheld{}
	if _, _, err := validateDrainSnapshot(admissionEncode(t, p, e, s)); err == nil {
		t.Fatal("accepted missing withheld alias")
	}
}

func TestDrainAdmissionRejectsStructuralChanges(t *testing.T) {
	cases := map[string]func(*DrainPending, *DrainHashEvidence, *cache.Snapshot){
		"version":         func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) { p.Version = 2 },
		"generation":      func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) { e.Generation = 3 },
		"missing entries": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) { p.Entries = nil },
		"missing map":     func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) { e.PreWrite = nil },
		"signature":       func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) { s.SchemaSignature = "v1" },
		"bad hash":        func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) { e.FullPlanSHA256 = "bad" },
		"extra saved": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) {
			s.LinearHashes["extra"] = strings.Repeat("a", 64)
		},
		"wrong saved value": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) {
			s.LinearHashes["finding-a"] = strings.Repeat("b", 64)
		},
		"withheld outside R": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) {
			e.Withheld["other"] = DrainWithheld{"drift", []string{}}
		},
		"false drift": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) {
			e.Withheld["finding-a"] = DrainWithheld{"drift", []string{}}
			s.LinearHashes = map[string]string{}
		},
		"unknown pending work": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) {
			e.Withheld["finding-a"] = DrainWithheld{"deferred", []string{"issue:unknown"}}
			s.LinearHashes = map[string]string{}
		},
		"bad work key": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) {
			p.Entries["unknown:key"] = DrainPendingEntry{1, []string{planTextDigest("finding-a")}, 0}
		},
		"future age": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) {
			p.Entries["issue:a"] = DrainPendingEntry{3, []string{planTextDigest("finding-a")}, 0}
		},
		"negative stall": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) {
			p.Entries["issue:a"] = DrainPendingEntry{1, []string{planTextDigest("finding-a")}, -1}
		},
		"late init": func(p *DrainPending, e *DrainHashEvidence, s *cache.Snapshot) {
			e.Initialization = &DrainInitialization{}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p, e, s := admissionFixture(2)
			change(&p, &e, &s)
			if _, _, err := validateDrainSnapshot(admissionEncode(t, p, e, s)); err == nil {
				t.Fatal("accepted invalid snapshot")
			}
		})
	}
}

func TestDrainAdmissionRejectsNonCanonicalJSON(t *testing.T) {
	p, e, s := admissionFixture(1)
	s = admissionEncode(t, p, e, s)
	for name, data := range map[string][]byte{
		"whitespace": append([]byte(" "), s.BoundedDrainPending...),
		"duplicate":  bytes.Replace(s.BoundedDrainPending, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"unknown":    bytes.Replace(s.BoundedDrainPending, []byte(`"version":1`), []byte(`"version":1,"extra":0`), 1),
		"reordered":  []byte(`{"version":1,"generation":1,"entries":{}}`),
		"missing":    []byte(`{"entries":{},"generation":1}`),
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			changed.BoundedDrainPending = data
			if _, _, err := validateDrainSnapshot(changed); err == nil {
				t.Fatal("accepted noncanonical data")
			}
		})
	}
	changed := s
	changed.BoundedDrainHashEvidence = bytes.Replace(s.BoundedDrainHashEvidence, []byte(e.SettingsSHA256), []byte(strings.Repeat("c", 64)), 1)
	// A syntactically valid differing producer-plan digest cannot be rejected by
	// local structure alone. External producer receipt binding remains mandatory.
	if _, _, err := validateDrainSnapshot(changed); err != nil {
		t.Fatalf("structural reader inferred producer proof: %v", err)
	}
}

func TestDrainAdmissionGenerationZeroRejectsInvalidInitialization(t *testing.T) {
	for name, change := range map[string]func(*DrainHashEvidence){
		"missing":       func(e *DrainHashEvidence) { e.Initialization = nil },
		"source digest": func(e *DrainHashEvidence) { e.Initialization.SourceCacheSHA256 = "bad" },
		"plan digest":   func(e *DrainHashEvidence) { e.FullPlanSHA256 = strings.Repeat("a", 64) },
		"different pre": func(e *DrainHashEvidence) { e.PreWrite["finding-a"] = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			p, e, s := admissionFixture(0)
			change(&e)
			if _, _, err := validateDrainSnapshot(admissionEncode(t, p, e, s)); err == nil {
				t.Fatal("accepted invalid init")
			}
		})
	}
}

func TestDrainAdmissionDriftAndDigestBinding(t *testing.T) {
	p, e, s := admissionFixture(2)
	e.PreWrite["finding-a"] = strings.Repeat("b", 64)
	e.Withheld["finding-a"] = DrainWithheld{"drift", []string{}}
	s.LinearHashes = map[string]string{}
	s = admissionEncode(t, p, e, s)
	if _, _, err := validateDrainSnapshot(s); err != nil {
		t.Fatal(err)
	}
	var decoded DrainHashEvidence
	if err := decodeCanonicalDrain(s.BoundedDrainHashEvidence, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.PendingAfterSHA256 = strings.Repeat("c", 64)
	s.BoundedDrainHashEvidence, _ = canonicalDrainJSON(decoded)
	if _, _, err := validateDrainSnapshot(s); err == nil {
		t.Fatal("accepted pending digest mismatch")
	}
}

func TestDrainAdmissionSharedAliasRequiresEveryPendingKey(t *testing.T) {
	p, e, s := admissionFixture(2)
	fp := planTextDigest("finding-a")
	for _, key := range []string{"issue:a", "issue:b"} {
		p.Entries[key] = DrainPendingEntry{1, []string{fp}, 0}
	}
	e.Withheld["finding-a"] = DrainWithheld{"deferred", []string{"issue:a", "issue:b"}}
	s.LinearHashes = map[string]string{}
	if _, _, err := validateDrainSnapshot(admissionEncode(t, p, e, s)); err != nil {
		t.Fatal(err)
	}
	for _, keys := range [][]string{{"issue:a"}, {"issue:b", "issue:a"}, {"issue:a", "issue:a"}, nil} {
		e.Withheld["finding-a"] = DrainWithheld{"deferred", keys}
		if _, _, err := validateDrainSnapshot(admissionEncode(t, p, e, s)); err == nil {
			t.Fatalf("accepted invalid aliases %v", keys)
		}
	}
}

func TestDrainAdmissionRejectsDifferentManagedSchema(t *testing.T) {
	p, e, s := admissionFixture(1)
	snapshot := admissionEncode(t, p, e, s)
	snapshot.SchemaSignature = "different-managed-schema+drain-v1"
	if _, _, err := validateDrainSnapshot(snapshot); err == nil {
		t.Fatal("different managed schema admitted")
	}
}
