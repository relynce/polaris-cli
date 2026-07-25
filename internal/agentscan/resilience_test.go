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

// noBackoff zeros the retry backoff for the duration of a test.
func noBackoff(t *testing.T) {
	t.Helper()
	prev := lensRetryBackoff
	lensRetryBackoff = 0
	t.Cleanup(func() { lensRetryBackoff = prev })
}

func TestIsRetryableLensErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"timeout is retryable", fmt.Errorf("lens go: claude: %w after 180s", ErrAgentTimeout), true},
		{"api error is retryable", fmt.Errorf("claude: %w (status 500)", ErrAgentAPI), true},
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

func TestRunLensResilient_RetriesTransientThenSucceeds(t *testing.T) {
	noBackoff(t)
	payload := findingsJSON(t, []Finding{validFinding()}, "ok")
	var attempts int32
	fa := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			return InvokeResult{}, fmt.Errorf("claude: %w (status 500): server error", ErrAgentAPI)
		}
		return InvokeResult{Raw: payload}, nil
	}}
	r := runLensResilient(context.Background(), fa, goLens(t), goChangeSet(), "/tmp/snap", 30*time.Second)
	if r.Err != nil {
		t.Fatalf("expected success after retry, got %v", r.Err)
	}
	if !r.Retried {
		t.Error("Retried should be true")
	}
	if fa.callCount() != 2 {
		t.Errorf("expected 2 invocations (fail + retry), got %d", fa.callCount())
	}
}

func TestRunLensResilient_NoRetryOnSuccess(t *testing.T) {
	noBackoff(t)
	payload := findingsJSON(t, []Finding{validFinding()}, "ok")
	fa := &fakeAdapter{fn: func(string) (InvokeResult, error) { return InvokeResult{Raw: payload}, nil }}
	r := runLensResilient(context.Background(), fa, goLens(t), goChangeSet(), "/tmp/snap", 30*time.Second)
	if r.Retried || fa.callCount() != 1 {
		t.Errorf("success must not retry: retried=%v calls=%d", r.Retried, fa.callCount())
	}
}

func TestRunLensResilient_NoRetryOnUnavailable(t *testing.T) {
	noBackoff(t)
	fa := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{}, fmt.Errorf("%w: %q", ErrAgentUnavailable, "claude")
	}}
	r := runLensResilient(context.Background(), fa, goLens(t), goChangeSet(), "/tmp/snap", 30*time.Second)
	if r.Err == nil {
		t.Fatal("expected an error")
	}
	if r.Retried || fa.callCount() != 1 {
		t.Errorf("systematic ErrAgentUnavailable must not retry: retried=%v calls=%d", r.Retried, fa.callCount())
	}
}

// A persistently-failing transient error retries up to the cap, then stops.
func TestRunLensResilient_RetriesUpToMax(t *testing.T) {
	noBackoff(t)
	fa := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{}, fmt.Errorf("claude: %w (status 500)", ErrAgentAPI)
	}}
	r := runLensResilient(context.Background(), fa, goLens(t), goChangeSet(), "/tmp/snap", 30*time.Second)
	if r.Err == nil || !errors.Is(r.Err, ErrAgentAPI) {
		t.Errorf("expected the API error to survive, got %v", r.Err)
	}
	if !r.Retried || fa.callCount() != 1+maxLensRetries {
		t.Errorf("expected %d attempts (1 + %d retries), got %d", 1+maxLensRetries, maxLensRetries, fa.callCount())
	}
}

// When the first attempt consumes more than half the budget, the retry is
// skipped — it would not have time to finish (the "died at 120s of 180s" case).
func TestRunLensResilient_NoRetryWhenBudgetExhausted(t *testing.T) {
	noBackoff(t)
	budget := 100 * time.Millisecond
	fa := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		time.Sleep(70 * time.Millisecond) // > budget/2
		return InvokeResult{}, fmt.Errorf("claude: %w (status 500)", ErrAgentAPI)
	}}
	r := runLensResilient(context.Background(), fa, goLens(t), goChangeSet(), "/tmp/snap", budget)
	if r.Err == nil {
		t.Fatal("expected an error")
	}
	if r.Retried || fa.callCount() != 1 {
		t.Errorf("must not retry with <half budget left: retried=%v calls=%d", r.Retried, fa.callCount())
	}
}

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
	time.Sleep(25 * time.Millisecond)
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
		t.Errorf("peak concurrent = %d; expected to reach the limit of 2", got)
	}
}
