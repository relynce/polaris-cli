package agentscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
)

// fakeAdapter is an in-process Adapter fake. fn decides the outcome per
// invocation; calls and prompts are recorded for assertions.
type fakeAdapter struct {
	mu      sync.Mutex
	calls   int
	prompts []string
	fn      func(prompt string) (InvokeResult, error)
}

func (s *fakeAdapter) Name() string { return "stub" }

func (s *fakeAdapter) Invoke(_ context.Context, prompt, _ string) (InvokeResult, error) {
	s.mu.Lock()
	s.calls++
	s.prompts = append(s.prompts, prompt)
	s.mu.Unlock()
	return s.fn(prompt)
}

func (s *fakeAdapter) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *fakeAdapter) allPrompts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.prompts...)
}

// fakeProbeAdapter is a fakeAdapter that also implements
// AvailabilityChecker with a fixed probe result.
type fakeProbeAdapter struct {
	fakeAdapter
	avail error
}

func (s *fakeProbeAdapter) CheckAvailability() error { return s.avail }

// payloadJSON marshals a findings payload the way a lens is instructed
// to emit it.
func payloadJSON(t *testing.T, findings []Finding, summary string) string {
	t.Helper()
	b, err := json.Marshal(findingsPayload{Findings: findings, Summary: summary})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// initStagedRepo builds a repo with the given files committed as a base,
// then stages a modification appending to each so StagedChangeSet sees
// every file as modified.
func initStagedRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := initGitRepo(t)
	for rel, content := range files {
		writeFile(t, dir, rel, content)
	}
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	for rel, content := range files {
		writeFile(t, dir, rel, content+"// staged change\n")
	}
	gitIn(t, dir, "add", ".")
	return dir
}

func stagedCS(t *testing.T, dir string) ChangeSet {
	t.Helper()
	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatalf("StagedChangeSet: %v", err)
	}
	return cs
}

func TestComputeGate(t *testing.T) {
	find := func(sev string) Finding {
		return Finding{Rule: "missing-timeout", Severity: sev, File: "a.go", Line: 1, Title: "t"}
	}
	infra := func(n int) []error {
		var out []error
		for i := 0; i < n; i++ {
			out = append(out, fmt.Errorf("lens go: %w", ErrAgentTimeout))
		}
		return out
	}
	cases := []struct {
		name          string
		findings      []Finding
		failOn        string
		mode          string
		strict        bool
		infra         []error
		wantBlocked   bool
		wantBlockedOn int
		wantBanner    bool
	}{
		{name: "high finding blocks at defaults", findings: []Finding{find("high")}, wantBlocked: true, wantBlockedOn: 1},
		{name: "critical blocks at fail_on high", findings: []Finding{find("critical")}, failOn: "high", mode: "enforce", wantBlocked: true, wantBlockedOn: 1},
		{name: "medium does not block at fail_on high", findings: []Finding{find("medium")}, failOn: "high", mode: "enforce"},
		{name: "high does not block at fail_on critical", findings: []Finding{find("high")}, failOn: "critical", mode: "enforce"},
		{name: "medium blocks at fail_on medium", findings: []Finding{find("medium")}, failOn: "medium", mode: "enforce", wantBlocked: true, wantBlockedOn: 1},
		{name: "low blocks at fail_on low", findings: []Finding{find("low")}, failOn: "low", mode: "enforce", wantBlocked: true, wantBlockedOn: 1},
		{name: "eval never blocks on findings", findings: []Finding{find("critical")}, failOn: "high", mode: "eval", wantBlockedOn: 1},
		{name: "eval with strict infra never blocks", mode: "eval", strict: true, infra: infra(2), wantBanner: true},
		{name: "infra fail-open carries banner", mode: "enforce", infra: infra(2), wantBanner: true},
		{name: "infra strict fails closed", mode: "enforce", strict: true, infra: infra(1), wantBlocked: true},
		{name: "unknown severity never gates", findings: []Finding{find("bogus")}, mode: "enforce"},
		{name: "strict infra plus findings blocks with both", findings: []Finding{find("high")}, mode: "enforce", strict: true, infra: infra(1), wantBlocked: true, wantBlockedOn: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := PipelineConfig{FailOn: c.failOn, Mode: c.mode, StrictErrors: c.strict}
			res := PipelineResult{Findings: c.findings, InfraErrors: c.infra}
			d := ComputeGate(cfg, res)
			if d.Blocked != c.wantBlocked {
				t.Errorf("Blocked = %v, want %v (reason %q)", d.Blocked, c.wantBlocked, d.Reason)
			}
			if len(d.BlockedOn) != c.wantBlockedOn {
				t.Errorf("len(BlockedOn) = %d, want %d", len(d.BlockedOn), c.wantBlockedOn)
			}
			if c.wantBanner {
				want := fmt.Sprintf("AGENT SCAN INCOMPLETE (%d lens errors)", len(c.infra))
				if !strings.Contains(d.Banner, want) {
					t.Errorf("Banner = %q, want it to contain %q", d.Banner, want)
				}
			} else if d.Banner != "" {
				t.Errorf("Banner = %q, want empty", d.Banner)
			}
			if c.wantBlocked && d.Reason == "" {
				t.Error("blocked decision must carry a Reason")
			}
		})
	}
}

func TestDedupeFindings(t *testing.T) {
	in := []Finding{
		{Rule: "missing-timeout", Severity: "high", File: "a.go", Line: 10, Title: "first"},
		{Rule: "missing-timeout", Severity: "critical", File: "a.go", Line: 10, Title: "dupe-higher"},
		{Rule: "missing-timeout", Severity: "low", File: "a.go", Line: 11, Title: "other-line"},
	}
	out := dedupeFindings(in)
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(out), out)
	}
	// Highest severity wins for the duplicate key; sort is severity-desc.
	if out[0].Severity != "critical" || out[0].Line != 10 {
		t.Errorf("out[0] = %+v, want the critical line-10 finding", out[0])
	}
	if out[1].Line != 11 {
		t.Errorf("out[1] = %+v, want the line-11 finding", out[1])
	}
}

func TestRunPipelineHappyPathAggregation(t *testing.T) {
	dir := initStagedRepo(t, map[string]string{"a.go": "package p\n"})
	perLens := []Finding{
		{Rule: "missing-timeout", Severity: "high", File: "a.go", Line: 10, Title: "go finding", Description: "d"},
		{Rule: "missing-audit-signal", Severity: "medium", File: "a.go", Line: 12, Title: "obs finding", Description: "d"},
		{Rule: "migration-safety", Severity: "low", File: "a.go", Line: 14, Title: "general finding", Description: "d"},
	}
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{Raw: payloadJSON(t, perLens, "ok"), CostUSD: 0.5}, nil
	}}
	res, err := RunPipeline(context.Background(), PipelineConfig{Root: dir, Adapter: stub}, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if res.Skipped {
		t.Fatalf("unexpectedly skipped: %s", res.SkipNotice)
	}
	// a.go selects go + observability + general.
	if stub.callCount() != 3 {
		t.Errorf("adapter calls = %d, want 3", stub.callCount())
	}
	if len(res.LensResults) != 3 {
		t.Fatalf("len(LensResults) = %d, want 3", len(res.LensResults))
	}
	// Each lens keeps its own vocab finding and drops the two others.
	for _, lr := range res.LensResults {
		if lr.Err != nil {
			t.Fatalf("lens %s errored: %v", lr.Lens.ID, lr.Err)
		}
		if len(lr.Findings) != 1 {
			t.Errorf("lens %s kept %d findings, want 1", lr.Lens.ID, len(lr.Findings))
		}
		if len(lr.Dropped) != 2 {
			t.Errorf("lens %s dropped %d findings, want 2", lr.Lens.ID, len(lr.Dropped))
		}
	}
	if len(res.Findings) != 3 {
		t.Fatalf("aggregated findings = %d, want 3: %+v", len(res.Findings), res.Findings)
	}
	// Sorted severity-desc: high, medium, low.
	if res.Findings[0].Rule != "missing-timeout" || res.Findings[0].Lens != LensGo {
		t.Errorf("Findings[0] = %+v, want the go missing-timeout", res.Findings[0])
	}
	if math.Abs(res.TotalCostUSD-1.5) > 1e-9 {
		t.Errorf("TotalCostUSD = %v, want 1.5", res.TotalCostUSD)
	}
	// Default gate: enforce, fail_on high; the high finding blocks.
	if !res.Blocked || len(res.BlockedOn) != 1 {
		t.Errorf("Blocked=%v BlockedOn=%d, want blocked on 1 finding", res.Blocked, len(res.BlockedOn))
	}
	if res.Degraded || len(res.InfraErrors) != 0 || res.Banner != "" {
		t.Errorf("clean run must not be degraded: %+v", res.InfraErrors)
	}
}

func TestRunPipelineRangeMode(t *testing.T) {
	dir := initRangeRepo(t)
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{Raw: payloadJSON(t, nil, "clean")}, nil
	}}
	cs, err := RangeChangeSet(dir, "main")
	if err != nil {
		t.Fatalf("RangeChangeSet: %v", err)
	}
	res, err := RunPipeline(context.Background(), PipelineConfig{Root: dir, Adapter: stub}, cs)
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if res.Skipped {
		t.Fatalf("unexpectedly skipped: %s", res.SkipNotice)
	}
	if stub.callCount() != 3 {
		t.Errorf("adapter calls = %d, want 3", stub.callCount())
	}
	if res.Blocked {
		t.Error("clean range scan must not block")
	}
}

func TestRunPipelineChunkFanOutAndCap(t *testing.T) {
	files := map[string]string{
		"a.go": "package p\n\nfunc A() {}\n",
		"b.go": "package p\n\nfunc B() {}\n",
	}
	dir := initStagedRepo(t, files)
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{Raw: payloadJSON(t, nil, "clean")}, nil
	}}
	cfg := PipelineConfig{Root: dir, Adapter: stub, SoftLimit: 3, HardLimit: 100000}
	res, err := RunPipeline(context.Background(), cfg, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	// Two per-file chunks x 3 lenses (go, observability, general).
	if stub.callCount() != 6 {
		t.Errorf("adapter calls = %d, want 6", stub.callCount())
	}
	joinedPrompts := strings.Join(stub.allPrompts(), "\n===\n")
	if !strings.Contains(joinedPrompts, "chunk 1/2") || !strings.Contains(joinedPrompts, "chunk 2/2") {
		t.Error("prompts must carry the chunked BaseDesc")
	}
	if len(res.Notices) == 0 {
		t.Error("chunked run must carry the budget notice")
	}

	// Same setup capped at 4 invocations.
	stub2 := &fakeAdapter{fn: stub.fn}
	cfg2 := PipelineConfig{Root: dir, Adapter: stub2, SoftLimit: 3, HardLimit: 100000, MaxInvocations: 4}
	res2, err := RunPipeline(context.Background(), cfg2, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline capped: %v", err)
	}
	if stub2.callCount() != 4 {
		t.Errorf("capped adapter calls = %d, want 4", stub2.callCount())
	}
	joined := strings.Join(res2.Notices, "\n")
	if !strings.Contains(joined, "4 of 6") {
		t.Errorf("cap notice missing from notices: %q", joined)
	}
}

func TestRunPipelineFileListMode(t *testing.T) {
	dir := initStagedRepo(t, map[string]string{"a.go": "package p\n\nfunc A() {}\n"})
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{Raw: payloadJSON(t, nil, "clean")}, nil
	}}
	cfg := PipelineConfig{Root: dir, Adapter: stub, SoftLimit: 1, HardLimit: 1}
	res, err := RunPipeline(context.Background(), cfg, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if !res.FileListMode {
		t.Fatal("FileListMode must be set for an over-hard-limit diff")
	}
	prompts := stub.allPrompts()
	if len(prompts) != 3 {
		t.Fatalf("adapter calls = %d, want 3", len(prompts))
	}
	if !strings.Contains(prompts[0], "[FILE-LIST MODE") {
		t.Error("prompt must carry the file-list-mode summary instead of the diff")
	}
	if !strings.Contains(strings.Join(res.Notices, "\n"), "FILE-LIST MODE") {
		t.Error("file-list degrade must be surfaced in Notices")
	}
}

func TestRunPipelineInfraErrorsFailOpenAndStrict(t *testing.T) {
	dir := initStagedRepo(t, map[string]string{"a.go": "package p\n"})
	timeoutFn := func(string) (InvokeResult, error) {
		return InvokeResult{CostUSD: 0.25}, fmt.Errorf("boom: %w", ErrAgentTimeout)
	}

	stub := &fakeAdapter{fn: timeoutFn}
	res, err := RunPipeline(context.Background(), PipelineConfig{Root: dir, Adapter: stub}, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if len(res.InfraErrors) != 3 {
		t.Fatalf("InfraErrors = %d, want 3", len(res.InfraErrors))
	}
	for _, e := range res.InfraErrors {
		if !errors.Is(e, ErrAgentTimeout) {
			t.Errorf("infra error lost taxonomy: %v", e)
		}
	}
	if !res.Degraded {
		t.Error("Degraded must be set when lenses errored")
	}
	if res.Blocked {
		t.Error("default (non-strict) infra errors must fail open")
	}
	if !strings.Contains(res.Banner, "AGENT SCAN INCOMPLETE (3 lens errors)") {
		t.Errorf("Banner = %q", res.Banner)
	}
	// Cost is summed across errored lenses too.
	if math.Abs(res.TotalCostUSD-0.75) > 1e-9 {
		t.Errorf("TotalCostUSD = %v, want 0.75", res.TotalCostUSD)
	}

	stubStrict := &fakeAdapter{fn: timeoutFn}
	resStrict, err := RunPipeline(context.Background(),
		PipelineConfig{Root: dir, Adapter: stubStrict, StrictErrors: true}, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline strict: %v", err)
	}
	if !resStrict.Blocked {
		t.Error("strict_errors must fail the gate closed on infra errors")
	}
	if resStrict.Banner != "" {
		t.Errorf("blocked run must not carry the fail-open banner: %q", resStrict.Banner)
	}
}

func TestRunPipelineAvailabilityProbe(t *testing.T) {
	dir := initStagedRepo(t, map[string]string{"a.go": "package p\n"})
	stub := &fakeProbeAdapter{avail: fmt.Errorf("%w: no claude on PATH", ErrAgentUnavailable)}
	stub.fn = func(string) (InvokeResult, error) {
		t.Error("Invoke must not be called when the availability probe fails")
		return InvokeResult{}, nil
	}
	res, err := RunPipeline(context.Background(), PipelineConfig{Root: dir, Adapter: stub}, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if stub.callCount() != 0 {
		t.Errorf("adapter calls = %d, want 0", stub.callCount())
	}
	if len(res.InfraErrors) != 1 {
		t.Fatalf("InfraErrors = %d, want exactly 1 (single probe, not N per lens)", len(res.InfraErrors))
	}
	if !errors.Is(res.InfraErrors[0], ErrAgentUnavailable) {
		t.Errorf("probe error lost taxonomy: %v", res.InfraErrors[0])
	}
	if !res.Degraded || res.Blocked {
		t.Errorf("probe failure must degrade + fail open: degraded=%v blocked=%v", res.Degraded, res.Blocked)
	}
	if !strings.Contains(res.Banner, "AGENT SCAN INCOMPLETE (1 lens errors)") {
		t.Errorf("Banner = %q", res.Banner)
	}
}

func TestRunPipelineSecretsRefusal(t *testing.T) {
	dir := initStagedRepo(t, map[string]string{
		"a.go": "package p\n\nvar password = \"hunter2hunter2\"\n",
	})
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		t.Error("Invoke must never run on a secrets refusal")
		return InvokeResult{}, nil
	}}
	_, err := RunPipeline(context.Background(), PipelineConfig{Root: dir, Adapter: stub}, stagedCS(t, dir))
	if !errors.Is(err, ErrSecretsDetected) {
		t.Fatalf("err = %v, want ErrSecretsDetected", err)
	}
	if !strings.Contains(err.Error(), "a.go:") {
		t.Errorf("refusal must name file:line, got %q", err.Error())
	}
	if stub.callCount() != 0 {
		t.Errorf("adapter calls = %d, want 0", stub.callCount())
	}
}

func TestRunPipelineGeneratedOnlySkip(t *testing.T) {
	dir := initStagedRepo(t, map[string]string{"go.sum": "example.com v1.0.0 h1:abc\n"})
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		t.Error("Invoke must not run for a generated-only change set")
		return InvokeResult{}, nil
	}}
	res, err := RunPipeline(context.Background(), PipelineConfig{Root: dir, Adapter: stub}, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if !res.Skipped {
		t.Fatal("generated-only change set must skip")
	}
	if !strings.Contains(res.SkipNotice, "generated") {
		t.Errorf("SkipNotice = %q, want it to explain the generated filter", res.SkipNotice)
	}
	if stub.callCount() != 0 {
		t.Errorf("adapter calls = %d, want 0", stub.callCount())
	}
}

func TestRunPipelineEmptyChangeSetSkip(t *testing.T) {
	dir := initGitRepo(t)
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		t.Error("Invoke must not run for an empty change set")
		return InvokeResult{}, nil
	}}
	res, err := RunPipeline(context.Background(), PipelineConfig{Root: dir, Adapter: stub},
		ChangeSet{BaseDesc: "staged", Files: []ChangedFile{}})
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if !res.Skipped || res.SkipNotice == "" {
		t.Errorf("empty change set must skip with an explicit notice, got %+v", res)
	}
}

func TestRunPipelineMergeStateSkip(t *testing.T) {
	dir := initStagedRepo(t, map[string]string{"a.go": "package p\n"})
	writeFile(t, dir, ".git/MERGE_HEAD", "0123456789012345678901234567890123456789\n")
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		t.Error("Invoke must not run during a merge")
		return InvokeResult{}, nil
	}}
	res, err := RunPipeline(context.Background(), PipelineConfig{Root: dir, Adapter: stub}, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if !res.Skipped || !strings.Contains(res.SkipNotice, "merge") {
		t.Errorf("merge state must skip with notice, got %+v", res)
	}
}

func TestRunPipelineBudgetWarnNotice(t *testing.T) {
	dir := initStagedRepo(t, map[string]string{"a.go": "package p\n"})
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{Raw: payloadJSON(t, nil, "clean"), CostUSD: 1.0}, nil
	}}
	cfg := PipelineConfig{Root: dir, Adapter: stub, BudgetWarnUSD: 2.0}
	res, err := RunPipeline(context.Background(), cfg, stagedCS(t, dir))
	if err != nil {
		t.Fatalf("RunPipeline: %v", err)
	}
	if math.Abs(res.TotalCostUSD-3.0) > 1e-9 {
		t.Errorf("TotalCostUSD = %v, want 3.0", res.TotalCostUSD)
	}
	if !strings.Contains(strings.Join(res.Notices, "\n"), "budget_warn") {
		t.Errorf("budget warning missing from notices: %q", res.Notices)
	}
}

func TestRunPipelineCanceledContext(t *testing.T) {
	dir := initStagedRepo(t, map[string]string{"a.go": "package p\n"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stub := &fakeAdapter{fn: func(string) (InvokeResult, error) {
		return InvokeResult{}, nil
	}}
	_, err := RunPipeline(ctx, PipelineConfig{Root: dir, Adapter: stub}, stagedCS(t, dir))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled (user abort)", err)
	}
}
