package config

import (
	"strings"
	"testing"
)

func TestReplaySafeAndObservationFlags(t *testing.T) {
	for _, key := range []string{"SNYK_CLIENT_ID", "SNYK_CLIENT_SECRET", "SNYK_ORG_ID", "LINEAR_API_KEY"} {
		t.Setenv(key, "example")
	}
	t.Setenv("LINEAR_TEAM_ID", "11111111-1111-4111-8111-111111111111")
	if _, err := Load([]string{"--replay-safe"}); err == nil {
		t.Fatal("unguarded replay safe run accepted")
	}
	cfg, err := Load([]string{"--replay-safe", "--dry-run", "--plan-json", "private.json"})
	if err != nil || !cfg.ReplaySafe {
		t.Fatalf("v2 preview rejected: %v", err)
	}
	for _, extra := range []string{"--dry-run", "--bypass-cache", "--clear-ignores-cold-start"} {
		if _, err := Load([]string{"--observation-checkpoint", "new.db", "--observation-source-sha256", strings.Repeat("1", 64), extra}); err == nil {
			t.Fatal("unsafe checkpoint combination accepted")
		}
	}
	if _, err := Load([]string{"--observation-checkpoint", "new.db"}); err == nil {
		t.Fatal("unbound checkpoint accepted")
	}
	t.Setenv("LINEAR_API_KEY", "")
	t.Setenv("LINEAR_TEAM_ID", "11111111-1111-4111-8111-111111111111")
	cfg, err = Load([]string{"--observation-checkpoint", "new.db", "--observation-source-sha256", strings.Repeat("1", 64)})
	if err != nil || cfg.ObservationCheckpoint != "new.db" {
		t.Fatalf("observation required Linear credentials: %v", err)
	}
}
