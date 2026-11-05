package logx

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// newBufferHandler returns a text handler at level, plus the buffer it writes
// to, so a test can say what actually reached that child.
func newBufferHandler(level slog.Level) (slog.Handler, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level}), buf
}

// stubHandler is a child a test can watch: it reports one fixed level, counts
// the records it is asked to handle, and can be made to fail.
type stubHandler struct {
	level   slog.Level
	wantErr error
	calls   int
}

func (h *stubHandler) Enabled(_ context.Context, level slog.Level) bool { return level >= h.level }

func (h *stubHandler) Handle(context.Context, slog.Record) error {
	h.calls++
	return h.wantErr
}

func (h *stubHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *stubHandler) WithGroup(string) slog.Handler { return h }

func testRecord(level slog.Level, message string) slog.Record {
	return slog.NewRecord(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), level, message, 0)
}

// A failing child must not stop the remaining children: Handle calls every
// enabled child and joins the failures, so a broken console handler cannot
// keep records from reaching the file.
func TestMultiHandlerHandleCallsEveryChildAndJoinsErrors(t *testing.T) {
	firstErr := errors.New("first child failed")
	secondErr := errors.New("second child failed")
	first := &stubHandler{level: slog.LevelInfo, wantErr: firstErr}
	second := &stubHandler{level: slog.LevelInfo, wantErr: secondErr}

	err := NewMultiHandler(first, second).Handle(context.Background(), testRecord(slog.LevelInfo, "boom"))

	if !errors.Is(err, firstErr) {
		t.Errorf("Handle error = %v; want it to wrap %v", err, firstErr)
	}
	if !errors.Is(err, secondErr) {
		t.Errorf("Handle error = %v; want it to wrap %v", err, secondErr)
	}
	if first.calls != 1 {
		t.Errorf("first child calls = %d; want 1", first.calls)
	}
	if second.calls != 1 {
		t.Errorf("second child calls = %d; want 1: a failing sibling must not stop the remaining children", second.calls)
	}

	// A failing console handler must still let the record reach the file.
	console := &stubHandler{level: slog.LevelInfo, wantErr: secondErr}
	fileHandler, file := newBufferHandler(slog.LevelInfo)
	err = NewMultiHandler(console, fileHandler).Handle(context.Background(), testRecord(slog.LevelInfo, "boom"))
	if !errors.Is(err, secondErr) {
		t.Errorf("Handle error = %v; want it to wrap %v", err, secondErr)
	}
	if console.calls != 1 {
		t.Errorf("console child calls = %d; want 1", console.calls)
	}
	if !strings.Contains(file.String(), "msg=boom") {
		t.Errorf("file child should still receive the record after the console child failed, got:\n%s", file.String())
	}
}

func TestMultiHandlerSkipsChildrenBelowTheirLevel(t *testing.T) {
	child := &stubHandler{level: slog.LevelError}

	slog.New(NewMultiHandler(child)).Info("hello")

	if child.calls != 0 {
		t.Errorf("child calls = %d; want 0: an info record must not reach a child at error level", child.calls)
	}
}
