package config

import (
	"strings"
	"testing"
)

func TestBoundOptionsFailClosed(t *testing.T) {
	n := int64(5)
	valid := Config{PlanAndExecuteBound: true, ReplaySafe: true, PlanJSON: "private/plan.json", MaxCreates: &n, MaxUpdates: &n, MaxResolves: &n, MaxCancelDuplicates: &n, Linear: LinearConfig{TeamID: "11111111-1111-4111-8111-111111111111"}}
	max := int64(999999)
	valid.MaxCreates = &max
	if err := valid.ValidateBound(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing-create", "missing-update", "missing-resolve", "missing-cancel", "negative", "huge", "dry-run", "reviewed", "export", "checkpoint", "clear", "team-alias", "stdout", "missing-directory", "non-replay", "no-mode"} {
		t.Run(kind, func(t *testing.T) {
			c := valid
			switch kind {
			case "missing-create":
				c.MaxCreates = nil
			case "missing-update":
				c.MaxUpdates = nil
			case "missing-cancel":
				c.MaxCancelDuplicates = nil
			case "missing-resolve":
				c.MaxResolves = nil
			case "negative":
				v := int64(-1)
				c.MaxCreates = &v
			case "huge":
				v := int64(1000000)
				c.MaxCreates = &v
			case "dry-run":
				c.DryRun = true
			case "reviewed":
				c.ReviewedPlanJSON = "plan.json"
			case "export":
				c.PlanJSON = ""
			case "checkpoint":
				c.ObservationCheckpoint = "candidate.db"
			case "clear":
				c.Cache.ClearIgnoresColdStart = true
			case "team-alias":
				c.Linear.TeamID = "TEAM"
			case "stdout":
				c.PlanJSON = "-"
			case "missing-directory":
				c.PlanJSON = ""
			case "non-replay":
				c.ReplaySafe = false
			case "no-mode":
				c.PlanAndExecuteBound = false
			}
			if err := c.ValidateBound(); err == nil {
				t.Fatal("accepted unsafe bounded options")
			}
		})
	}
	for _, value := range []string{"unlimited", "NaN", "1.5", "9223372036854775808", "+1", "01", "0x10", "-1", " 1", "1 "} {
		t.Run(value, func(t *testing.T) {
			_, err := Load([]string{"--max-creates", value})
			if err == nil || !strings.Contains(err.Error(), "max-creates") {
				t.Fatal("accepted malformed bound")
			}
		})
	}
	if _, err := Load([]string{"unexpected-positional"}); err == nil {
		t.Fatal("ignored positional arguments")
	}
}

func TestExpectedSettingsOptions(t *testing.T) {
	n := int64(5)
	valid := Config{PlanAndExecuteBound: true, ReplaySafe: true, PlanJSON: "private/plan.json", MaxCreates: &n, MaxUpdates: &n, MaxResolves: &n, MaxCancelDuplicates: &n, Linear: LinearConfig{TeamID: "11111111-1111-4111-8111-111111111111"}}
	for _, digest := range []string{strings.Repeat("a", 64), ""} {
		c := valid
		c.ExpectedSettingsSHA256 = digest
		if err := c.ValidateBound(); err != nil {
			t.Fatal(err)
		}
	}
	for _, digest := range []string{"x", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64), strings.Repeat("A", 64), " " + strings.Repeat("a", 64)} {
		c := valid
		c.ExpectedSettingsSHA256 = digest
		if c.ValidateBound() == nil {
			t.Fatal("accepted malformed digest")
		}
	}
	if (Config{ExpectedSettingsSHA256: strings.Repeat("a", 64)}).ValidateBound() == nil {
		t.Fatal("accepted outside bound mode")
	}
	if _, err := Load([]string{"--expected-settings-sha256="}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatal("accepted empty supplied digest")
	}
}
