package sync

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/tesslio/snyk-linear-sync/internal/cache"
)

func drainSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func drainValidWorkKey(key string) bool {
	if after, ok := strings.CutPrefix(key, "create:"); ok {
		return drainSHA256(after)
	}
	if !strings.HasPrefix(key, "issue:") || len(key) <= len("issue:") || len(key) > drainFingerprintByteCeiling {
		return false
	}
	for _, c := range strings.TrimPrefix(key, "issue:") {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func drainSortedUnique(values []string) bool {
	if values == nil {
		return false
	}
	for i := 1; i < len(values); i++ {
		if values[i-1] >= values[i] {
			return false
		}
	}
	return true
}

func decodeCanonicalDrain(data []byte, target any) error {
	if len(data) == 0 || len(data) > drainEvidenceByteCeiling {
		return errors.New("drain-evidence-invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("drain-evidence-invalid")
	}
	canonical, err := canonicalDrainJSON(target)
	if err != nil || !bytes.Equal(data, canonical) {
		return errors.New("drain-evidence-invalid")
	}
	return nil
}

// validateDrainSnapshot proves only structural and internal consistency. The
// caller must separately admit the exact producer's artifacts and cache bytes;
// self-consistent digests in a cache are not proof of producer acknowledgement.
// Full-plan operation/partition and unchanged-key drift checks require that
// producer's plan and are deliberately not inferred from pending entries.
func validateDrainSnapshot(snapshot cache.Snapshot) (DrainPending, DrainHashEvidence, error) {
	var pending DrainPending
	var evidence DrainHashEvidence
	invalid := func() (DrainPending, DrainHashEvidence, error) {
		return DrainPending{}, DrainHashEvidence{}, errors.New("drain-evidence-invalid")
	}
	if snapshot.SchemaSignature != managedSchemaSignature()+"+drain-v1" {
		return invalid()
	}
	if err := decodeCanonicalDrain(snapshot.BoundedDrainPending, &pending); err != nil {
		return invalid()
	}
	if err := decodeCanonicalDrain(snapshot.BoundedDrainHashEvidence, &evidence); err != nil {
		return invalid()
	}
	if pending.Version != drainVersion || evidence.Version != drainVersion || pending.Generation < 0 || pending.Generation != evidence.Generation || pending.Entries == nil || evidence.Refreshed == nil || evidence.PreWrite == nil || evidence.Withheld == nil || snapshot.LinearHashes == nil {
		return invalid()
	}
	if strings.TrimSpace(evidence.ProducerRunID) == "" || evidence.ProducerRunAttempt < 1 || len(evidence.Refreshed) == 0 || len(evidence.Refreshed) > drainEvidenceEntryCeiling || len(evidence.PreWrite) > drainEvidenceEntryCeiling || len(pending.Entries) > drainEvidenceEntryCeiling {
		return invalid()
	}
	for key, entry := range pending.Entries {
		if !drainValidWorkKey(key) || entry.SinceGeneration < 1 || entry.SinceGeneration > pending.Generation || entry.UnverifiedGenerations < 0 || len(entry.FingerprintSHA256s) == 0 || !drainSortedUnique(entry.FingerprintSHA256s) {
			return invalid()
		}
		for _, hash := range entry.FingerprintSHA256s {
			if !drainSHA256(hash) {
				return invalid()
			}
		}
		if strings.HasPrefix(key, "create:") && !slices.Contains(entry.FingerprintSHA256s, strings.TrimPrefix(key, "create:")) {
			return invalid()
		}
	}
	for _, hashes := range []map[string]string{evidence.Refreshed, evidence.PreWrite} {
		for fingerprint, hash := range hashes {
			if len(fingerprint) == 0 || len(fingerprint) > drainFingerprintByteCeiling || !drainSHA256(hash) {
				return invalid()
			}
		}
	}
	for fingerprint, withheld := range evidence.Withheld {
		refreshed, exists := evidence.Refreshed[fingerprint]
		if !exists || !drainSortedUnique(withheld.WorkKeys) {
			return invalid()
		}
		switch withheld.Reason {
		case "deferred", "unverified":
			if len(withheld.WorkKeys) == 0 {
				return invalid()
			}
			for _, key := range withheld.WorkKeys {
				entry, exists := pending.Entries[key]
				if !exists || !slices.Contains(entry.FingerprintSHA256s, planTextDigest(fingerprint)) {
					return invalid()
				}
			}
		case "drift":
			pre, exists := evidence.PreWrite[fingerprint]
			if len(withheld.WorkKeys) != 0 || !exists || pre == refreshed {
				return invalid()
			}
		default:
			return invalid()
		}
	}
	// Each pending alias present in R must be withheld, even when multiple work
	// keys share a fingerprint and only one was deferred.
	refreshedByDigest := make(map[string]string, len(evidence.Refreshed))
	for fingerprint := range evidence.Refreshed {
		refreshedByDigest[planTextDigest(fingerprint)] = fingerprint
	}
	for key, entry := range pending.Entries {
		for _, hash := range entry.FingerprintSHA256s {
			if fingerprint, exists := refreshedByDigest[hash]; exists {
				w, exists := evidence.Withheld[fingerprint]
				if !exists || w.Reason == "drift" || !slices.Contains(w.WorkKeys, key) {
					return invalid()
				}
			}
		}
	}
	expectedSaved := 0
	for fingerprint, hash := range evidence.Refreshed {
		if _, withheld := evidence.Withheld[fingerprint]; withheld {
			if _, exists := snapshot.LinearHashes[fingerprint]; exists {
				return invalid()
			}
			continue
		}
		expectedSaved++
		if saved, exists := snapshot.LinearHashes[fingerprint]; !exists || saved != hash {
			return invalid()
		}
	}
	if len(snapshot.LinearHashes) != expectedSaved {
		return invalid()
	}
	digests := []string{evidence.FullPlanSHA256, evidence.SelectedOpsSHA256, evidence.DeferredOpsSHA256, evidence.SettingsSHA256, evidence.PendingAfterSHA256}
	if pending.Generation == 0 {
		if len(pending.Entries) != 0 || len(evidence.Withheld) != 0 || evidence.Initialization == nil {
			return invalid()
		}
		for _, digest := range digests {
			if digest != "" {
				return invalid()
			}
		}
		init := evidence.Initialization
		if strings.TrimSpace(init.SourceCacheKey) == "" || !drainSHA256(init.SourceCacheSHA256) || strings.TrimSpace(init.V2ProducerRunID) == "" || strings.TrimSpace(init.AuthorizingRunID) == "" {
			return invalid()
		}
		if len(evidence.PreWrite) != len(evidence.Refreshed) {
			return invalid()
		}
		for key, value := range evidence.Refreshed {
			if evidence.PreWrite[key] != value {
				return invalid()
			}
		}
	} else {
		if evidence.Initialization != nil {
			return invalid()
		}
		for _, digest := range digests {
			if !drainSHA256(digest) {
				return invalid()
			}
		}
		digest, err := drainDigest(pending)
		if err != nil || digest != evidence.PendingAfterSHA256 {
			return invalid()
		}
	}
	return pending, evidence, nil
}
