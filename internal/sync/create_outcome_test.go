package sync

import (
	"errors"
	"github.com/tesslio/snyk-linear-sync/internal/model"
	"io"
	"log/slog"
	"testing"
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
