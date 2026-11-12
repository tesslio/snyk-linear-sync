package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/tesslio/snyk-linear-sync/internal/model"
)

func TestOrdinaryCreateDoesNotRetryUncertainOutcome(t *testing.T) {
	linear := &reviewedFailureLinear{createErr: errors.New("uncertain transport outcome"), failed: []int{0}}
	service := &Service{linear: linear, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	result := &RunResult{}
	err := service.executeJob(t.Context(), job{kind: jobCreateBatch, desiredBatch: []model.DesiredIssue{{Fingerprint: "snyk:project-a:issue-1"}}}, result)
	if err == nil || linear.createCalls != 1 || result.FailedOps != 1 {
		t.Fatalf("calls=%d failed=%d error=%v", linear.createCalls, result.FailedOps, err)
	}
}

func TestCreateOutcomeShapeFailsClosed(t *testing.T) {
	for _, outcomes := range [][]model.CreateOutcome{
		nil,
		{{Index: 1, ID: "issue-1", Acknowledged: true}},
		{{Index: 0, Acknowledged: true}},
		{{Index: 0, ID: "issue-1", Acknowledged: true}, {Index: 1, ID: "issue-2", Acknowledged: true}},
	} {
		if _, err := failedCreateOutcomes(outcomes, 1); err == nil {
			t.Fatalf("accepted %+v", outcomes)
		}
	}
}

func TestOrdinaryRunUncertainCreateUnblocksProducer(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprint(replay), func(t *testing.T) {
			cfg := minimalCfg()
			cfg.DryRun = false
			cfg.Sync.Workers = 1
			cfg.ReplaySafe = replay
			findings := make([]model.Finding, 11)
			for i := range findings {
				findings[i] = planFixtureFinding(fmt.Sprintf("issue-%d", i))
			}
			cause := errors.New("uncertain transport outcome")
			linear := &reviewedFailureLinear{createErr: cause, failed: []int{0}}
			cacheStore := &fakeCache{}
			service := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &planSnyk{snapshot: model.SnykSnapshot{
				Findings: findings, ProjectIDs: map[string]struct{}{"project-a": {}},
			}}, linear, cacheStore)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := service.Run(ctx); done <- err }()
			select {
			case err := <-done:
				if !errors.Is(err, cause) {
					t.Fatalf("lost create failure: %v", err)
				}
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("uncertain create stranded producer")
			}
			if linear.createCalls != 1 {
				t.Fatalf("retried or dispatched later create: %d", linear.createCalls)
			}
			if cacheStore.saved.SchemaSignature != "" {
				t.Fatal("published cache after uncertain create")
			}
		})
	}
}
