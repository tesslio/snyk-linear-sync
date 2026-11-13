package config

import (
	"strings"
	"testing"
)

func drainConfigFixture() Config {
	n := int64(100)
	return Config{PlanAndExecuteDrain: true, ReplaySafe: true, PlanJSON: "private/plan.json", MaxIssueChanges: &n,
		MaxCreates: &n, MaxUpdates: &n, MaxResolves: &n, MaxCancelDuplicates: &n,
		DrainRunID: "123", DrainRunAttempt: 1, ExpectedSettingsSHA256: strings.Repeat("a", 64),
		DrainPriorEvidenceSHA256: strings.Repeat("b", 64), DrainPriorPendingSHA256: strings.Repeat("c", 64),
		Cache: CacheConfig{DBFile: "private/cache.db"}, Linear: LinearConfig{TeamID: "11111111-1111-4111-8111-111111111111"}}
}

func TestDrainOptionsFailClosed(t *testing.T) {
	valid := drainConfigFixture()
	if err := valid.ValidateBound(); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*Config){
		"no-opt-in":         func(c *Config) { c.PlanAndExecuteDrain = false },
		"bound":             func(c *Config) { c.PlanAndExecuteBound = true },
		"dry-run":           func(c *Config) { c.DryRun = true },
		"non-replay":        func(c *Config) { c.ReplaySafe = false },
		"reviewed":          func(c *Config) { c.ReviewedPlanJSON = "prior.json" },
		"reviewed-digest":   func(c *Config) { c.ReviewedPlanSHA256 = strings.Repeat("a", 64) },
		"checkpoint":        func(c *Config) { c.ObservationCheckpoint = "checkpoint.db" },
		"checkpoint-digest": func(c *Config) { c.ObservationSourceSHA256 = strings.Repeat("a", 64) },
		"clear":             func(c *Config) { c.Cache.ClearIgnoresColdStart = true },
		"bypass":            func(c *Config) { c.Cache.BypassCache = true },
		"cache":             func(c *Config) { c.Cache.DBFile = " " },
		"stdout":            func(c *Config) { c.PlanJSON = "-" },
		"no-plan":           func(c *Config) { c.PlanJSON = "" },
		"team":              func(c *Config) { c.Linear.TeamID = "TEAM" },
		"cleanup":           func(c *Config) { c.Linear.UnsubscribeActor = true },
		"attempt-zero":      func(c *Config) { c.DrainRunAttempt = 0 },
		"attempt-two":       func(c *Config) { c.DrainRunAttempt = 2 },
		"missing-total":     func(c *Config) { c.MaxIssueChanges = nil },
		"missing-create":    func(c *Config) { c.MaxCreates = nil },
		"missing-update":    func(c *Config) { c.MaxUpdates = nil },
		"missing-resolve":   func(c *Config) { c.MaxResolves = nil },
		"missing-cancel":    func(c *Config) { c.MaxCancelDuplicates = nil },
		"missing-settings":  func(c *Config) { c.ExpectedSettingsSHA256 = "" },
		"missing-evidence":  func(c *Config) { c.DrainPriorEvidenceSHA256 = "" },
		"missing-pending":   func(c *Config) { c.DrainPriorPendingSHA256 = "" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c := valid
			change(&c)
			if c.ValidateBound() == nil {
				t.Fatal("unsafe drain options accepted")
			}
		})
	}
	for _, value := range []int64{-1, 0, 101, 1000000} {
		c := valid
		c.MaxIssueChanges = &value
		if c.ValidateBound() == nil {
			t.Fatalf("accepted total %d", value)
		}
	}
	for _, value := range []int64{1, 100} {
		c := valid
		c.MaxIssueChanges = &value
		if err := c.ValidateBound(); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"", "0", "01", "+1", "1 ", " 1", "1e2", strings.Repeat("1", 21), "１２"} {
		c := valid
		c.DrainRunID = value
		if c.ValidateBound() == nil {
			t.Fatalf("accepted ID %q", value)
		}
	}
	for _, value := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63), " " + strings.Repeat("a", 64)} {
		for _, field := range []string{"settings", "evidence", "pending"} {
			c := valid
			switch field {
			case "settings":
				c.ExpectedSettingsSHA256 = value
			case "evidence":
				c.DrainPriorEvidenceSHA256 = value
			case "pending":
				c.DrainPriorPendingSHA256 = value
			}
			if c.ValidateBound() == nil {
				t.Fatalf("accepted %s digest %q", field, value)
			}
		}
	}
}

func TestDrainFlagsAreExplicitAndCanonical(t *testing.T) {
	for _, key := range []string{"SNYK_CLIENT_ID", "SNYK_CLIENT_SECRET", "SNYK_ORG_ID", "LINEAR_API_KEY"} {
		t.Setenv(key, "example")
	}
	t.Setenv("LINEAR_TEAM_ID", "11111111-1111-4111-8111-111111111111")
	t.Setenv("LINEAR_UNSUBSCRIBE_ACTOR", "false")
	args := []string{"--plan-and-execute-drain", "--replay-safe", "--plan-json", "private/plan.json", "--max-issue-changes", "100", "--max-creates", "100", "--max-updates", "100", "--max-resolves", "100", "--max-cancel-duplicates", "0", "--drain-run-id", "123", "--drain-run-attempt", "1", "--expected-settings-sha256", strings.Repeat("a", 64), "--drain-prior-evidence-sha256", strings.Repeat("b", 64), "--drain-prior-pending-sha256", strings.Repeat("c", 64)}
	cfg, err := Load(args)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PlanAndExecuteDrain || cfg.DrainRunID != "123" || cfg.DrainRunAttempt != 1 || *cfg.MaxIssueChanges != 100 {
		t.Fatalf("wrong parsed config: %+v", cfg)
	}
	for _, flag := range []string{"--max-issue-changes", "--drain-run-attempt"} {
		for _, value := range []string{"01", "+1", "-1", "1.5", " 1", "9223372036854775808"} {
			bad := append(append([]string{}, args...), flag, value)
			if _, err := Load(bad); err == nil {
				t.Fatalf("accepted %s %q", flag, value)
			}
		}
	}
	for _, flag := range []string{"--drain-run-id=", "--drain-prior-evidence-sha256=", "--drain-prior-pending-sha256=", "--drain-run-attempt=0", "--max-issue-changes=0"} {
		if _, err := Load([]string{flag}); err == nil {
			t.Fatalf("accepted standalone %s", flag)
		}
	}
}
