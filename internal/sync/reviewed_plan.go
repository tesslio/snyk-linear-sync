package sync

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"unicode/utf8"
)

const maxReviewedPlanBytes = 64 << 20

// readReviewedPlan binds one immutable read to an independently accepted digest.
// A v1 or v2 plan commits to reconciliation decisions, not resolved API payloads.
func readReviewedPlan(path, expectedSHA256 string) (*ReconciliationPlan, error) {
	expected, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("reviewed plan requires a SHA-256 digest")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("reviewed plan must be a readable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open reviewed plan")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxReviewedPlanBytes {
		return nil, errors.New("reviewed plan file is invalid or too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReviewedPlanBytes+1))
	if err != nil || len(data) > maxReviewedPlanBytes {
		return nil, errors.New("cannot read reviewed plan within size limit")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("reviewed plan JSON is not valid UTF-8")
	}
	actual := sha256.Sum256(data)
	if !bytes.Equal(actual[:], expected) {
		return nil, errors.New("reviewed plan artifact digest mismatch")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := reviewedJSONValue(dec, reflect.TypeFor[ReconciliationPlan]()); err != nil {
		return nil, errors.New("reviewed plan JSON does not match the strict schema")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("reviewed plan has trailing data")
	}
	var plan ReconciliationPlan
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&plan); err != nil {
		return nil, errors.New("reviewed plan JSON is invalid")
	}
	if err := validateReviewedPlan(&plan); err != nil {
		return nil, err
	}
	return &plan, nil
}

// Enforce exact field spelling, presence, and uniqueness at every nesting level.
// encoding/json alone accepts duplicate keys and case-insensitive field aliases.
func reviewedJSONValue(dec *json.Decoder, typ reflect.Type) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	invalid := errors.New("invalid schema")
	if token == nil {
		return invalid
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return invalid
		}
		fields := map[string]reflect.StructField{}
		required := map[string]bool{}
		for field := range typ.Fields() {
			parts := strings.Split(field.Tag.Get("json"), ",")
			fields[parts[0]] = field
			required[parts[0]] = len(parts) == 1
		}
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return invalid
			}
			field, ok := fields[name]
			if !ok {
				return invalid
			}
			seen[name] = true
			if err := reviewedJSONValue(dec, field.Type); err != nil {
				return err
			}
		}
		for key, needed := range required {
			if needed && !seen[key] {
				return invalid
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return invalid
		}
	case reflect.Slice:
		if token != json.Delim('[') {
			return invalid
		}
		for dec.More() {
			if err := reviewedJSONValue(dec, typ.Elem()); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return invalid
		}
	default:
		if _, compound := token.(json.Delim); compound {
			return invalid
		}
	}
	return nil
}

func validateReviewedPlan(p *ReconciliationPlan) error {
	invalid := errors.New("reviewed plan is incomplete or inconsistent")
	if p == nil || (p.Version != 1 && p.Version != 2) || !p.Complete || p.LinearWritesAttempted || p.Records == nil {
		return invalid
	}
	if p.ReopenHistoryStatus != "complete" && p.ReopenHistoryStatus != "not_needed" {
		return errors.New("reviewed plan requires complete reopen history")
	}
	for _, digest := range []string{p.Inputs.SnykSHA256, p.Inputs.LinearSHA256, p.Inputs.SettingsSHA256, p.Inputs.SyncCacheSHA256, p.DecisionsSHA256} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size {
			return invalid
		}
	}
	s := p.Summary
	if s.Findings < 0 || s.ExistingIssues < 0 || s.CoveredFindings != s.Findings || s.CoveredExistingIssues != s.ExistingIssues || s.Rebound < 0 || s.Reopened < 0 || s.HeldDueDates < 0 {
		return invalid
	}
	findings, existing := map[int]bool{}, map[int]bool{}
	var creates, updates, resolves, duplicates int64
	deferred := map[string]bool{}
	for _, r := range p.Records {
		if r.FindingIndex < 0 || r.FindingIndex > s.Findings || r.ExistingIndex < 0 || r.ExistingIndex > s.ExistingIssues {
			return invalid
		}
		if r.FindingIndex > 0 {
			findings[r.FindingIndex] = true
		}
		if r.ExistingIndex > 0 {
			existing[r.ExistingIndex] = true
		}
		if r.ExecutionStatus != "not_attempted" {
			return invalid
		}
		mutation := false
		switch r.Action {
		case "create":
			creates++
			mutation = true
		case "update":
			updates++
			mutation = true
		case "resolve":
			resolves++
			mutation = true
		case "cancel-duplicate":
			duplicates++
			mutation = true
		case "defer-create":
			deferred[r.FingerprintSHA256] = true
		case "retain", "no-op":
		default:
			return invalid
		}
		if r.MutationPlanned != mutation {
			return invalid
		}
	}
	if len(findings) != s.Findings || len(existing) != s.ExistingIssues || creates != s.Creates || updates != s.Updates || resolves != s.Resolves || duplicates != s.CancelDuplicates || int64(len(deferred)) != s.DeferredCreates {
		return invalid
	}
	if s.Reopened > 0 && p.ReopenHistoryStatus != "complete" || s.Reopened == 0 && p.ReopenHistoryStatus != "not_needed" {
		return invalid
	}
	digest, err := planDigest(p.Records)
	if err != nil || digest != p.DecisionsSHA256 {
		return errors.New("reviewed plan decisions digest mismatch")
	}
	return nil
}

func verifyReviewedPlan(approved, current *ReconciliationPlan) error {
	if err := validateReviewedPlan(approved); err != nil {
		return err
	}
	if err := validateReviewedPlan(current); err != nil {
		return err
	}
	before, err := json.Marshal(approved)
	if err != nil {
		return errors.New("cannot encode reviewed plan")
	}
	after, err := json.Marshal(current)
	if err != nil {
		return errors.New("cannot encode current plan")
	}
	if !bytes.Equal(before, after) {
		return errors.New("current reconciliation differs from reviewed plan")
	}
	return nil
}
