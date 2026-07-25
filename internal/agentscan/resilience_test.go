package agentscan

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// concurrencyAdapter records the peak number of simultaneous Invoke calls.
type concurrencyAdapter struct {
	mu       sync.Mutex
	cur, max int
	payload  string
}

func (a *concurrencyAdapter) Name() string { return "conc" }

func (a *concurrencyAdapter) Invoke(_ context.Context, _, _ string) (InvokeResult, error) {
	a.mu.Lock()
	a.cur++
	if a.cur > a.max {
		a.max = a.cur
	}
	a.mu.Unlock()
	time.Sleep(25 * time.Millisecond) // hold the slot so overlap is observable
	a.mu.Lock()
	a.cur--
	a.mu.Unlock()
	return InvokeResult{Raw: a.payload}, nil
}

func (a *concurrencyAdapter) maxSeen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.max
}

func TestRunPipeline_ConcurrencyLimit(t *testing.T) {
	files := map[string]string{
		"a.go": "package p\n\nfunc A() {}\n",
		"b.go": "package p\n\nfunc B() {}\n",
	}
	dir := initStagedRepo(t, files)
	a := &concurrencyAdapter{payload: payloadJSON(t, nil, "clean")}
	// 2 per-file chunks x 3 lenses = 6 invocations, bounded to 2 at a time.
	cfg := PipelineConfig{Root: dir, Adapter: a, SoftLimit: 3, HardLimit: 100000, Concurrency: 2}
	if _, err := RunPipeline(context.Background(), cfg, stagedCS(t, dir)); err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if got := a.maxSeen(); got > 2 {
		t.Errorf("peak concurrent invocations = %d, want <= 2 (the limiter)", got)
	}
	if got := a.maxSeen(); got < 2 {
		t.Errorf("peak concurrent = %d; expected to reach the limit of 2 (parallelism within the bound)", got)
	}
}

func TestIsRetryableLensErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"timeout is retryable", fmt.Errorf("lens go: claude: %w after 180s", ErrAgentTimeout), true},
		{"unavailable is not", fmt.Errorf("lens go: %w", ErrAgentUnavailable), false},
		{"canceled is not", context.Canceled, false},
		{"generic transient is retryable", errors.New("rate limited"), true},
	}
	for _, c := range cases {
		if got := isRetryableLensErr(c.err); got != c.want {
			t.Errorf("%s: isRetryableLensErr = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRunLensResilient_RetriesOnceThenSucceeds(t *testing.T) {
	cs := goChangeSet()
	l := goLens(t)
	payload := findingsJSON(t, []Finding{validFinding()}, "ok")

	var attempts int32
	fa := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			return InvokeResult{}, fmt.Errorf("claude: %w after 180s (model sonnet)", ErrAgentTimeout)
		}
		return InvokeResult{Raw: payload}, nil
	}}

	r := runLensResilient(context.Background(), fa, l, cs, "/tmp/snap")
	if r.Err != nil {
		t.Fatalf("expected success after one retry, got %v", r.Err)
	}
	if !r.Retried {
		t.Error("Retried should be true")
	}
	if fa.callCount() != 2 {
		t.Errorf("expected exactly 2 invocations (fail + retry), got %d", fa.callCount())
	}
}

func TestRunLensResilient_NoRetryOnSuccess(t *testing.T) {
	payload := findingsJSON(t, []Finding{validFinding()}, "ok")
	fa := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{Raw: payload}, nil
	}}
	r := runLensResilient(context.Background(), fa, goLens(t), goChangeSet(), "/tmp/snap")
	if r.Retried || fa.callCount() != 1 {
		t.Errorf("success must not retry: retried=%v calls=%d", r.Retried, fa.callCount())
	}
}

func TestRunLensResilient_NoRetryOnUnavailable(t *testing.T) {
	fa := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{}, fmt.Errorf("%w: %q", ErrAgentUnavailable, "claude")
	}}
	r := runLensResilient(context.Background(), fa, goLens(t), goChangeSet(), "/tmp/snap")
	if r.Err == nil {
		t.Fatal("expected an error")
	}
	if r.Retried || fa.callCount() != 1 {
		t.Errorf("systematic ErrAgentUnavailable must not retry: retried=%v calls=%d", r.Retried, fa.callCount())
	}
}

// A retry that also fails keeps the (retried) error rather than blanking it.
func TestRunLensResilient_RetryAlsoFails(t *testing.T) {
	fa := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{}, fmt.Errorf("claude: %w after 180s", ErrAgentTimeout)
	}}
	r := runLensResilient(context.Background(), fa, goLens(t), goChangeSet(), "/tmp/snap")
	if r.Err == nil || !errors.Is(r.Err, ErrAgentTimeout) {
		t.Errorf("expected the timeout error to survive, got %v", r.Err)
	}
	if !r.Retried || fa.callCount() != 2 {
		t.Errorf("expected one retry: retried=%v calls=%d", r.Retried, fa.callCount())
	}
}
