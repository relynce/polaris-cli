package agentscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// envelopeJSON builds a claude -p --output-format json envelope via
// json.Marshal so result strings never need hand escaping.
func envelopeJSON(t *testing.T, result string, cost float64, isError bool) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"result":         result,
		"total_cost_usd": cost,
		"is_error":       isError,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeFakeAgent writes an executable shell script standing in for the
// claude binary and returns its path. Every script must consume stdin
// (the prompt) before producing output.
func writeFakeAgent(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-claude")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeAgentEmitting returns a fake agent that swallows stdin and prints
// the given envelope from a file (avoiding shell-escaping the JSON).
func fakeAgentEmitting(t *testing.T, envelope string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "envelope.json")
	if err := os.WriteFile(out, []byte(envelope), 0o644); err != nil {
		t.Fatal(err)
	}
	return writeFakeAgent(t, "cat >/dev/null\ncat '"+out+"'")
}

func TestClaudeAdapterHappyPath(t *testing.T) {
	payload := findingsJSON(t, []Finding{validFinding()}, "one risk")
	bin := fakeAgentEmitting(t, envelopeJSON(t, payload, 1.25, false))
	a := NewClaudeAdapter(AdapterConfig{Binary: bin})

	res, err := a.Invoke(context.Background(), "prompt text", t.TempDir())
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.Raw != payload {
		t.Fatalf("Raw = %q, want the envelope result", res.Raw)
	}
	if res.CostUSD != 1.25 {
		t.Fatalf("CostUSD = %v, want 1.25", res.CostUSD)
	}
	if res.Model != DefaultModel {
		t.Fatalf("Model = %q, want default %q", res.Model, DefaultModel)
	}

	findings, summary, err := ExtractFindings(res.Raw)
	if err != nil {
		t.Fatalf("ExtractFindings: %v", err)
	}
	if len(findings) != 1 || summary != "one risk" {
		t.Fatalf("got %d findings, summary %q", len(findings), summary)
	}
}

func TestClaudeAdapterFencedResult(t *testing.T) {
	payload := findingsJSON(t, []Finding{validFinding()}, "fenced result")
	fenced := "```json\n" + payload + "\n```"
	bin := fakeAgentEmitting(t, envelopeJSON(t, fenced, 0.5, false))
	a := NewClaudeAdapter(AdapterConfig{Binary: bin})

	res, err := a.Invoke(context.Background(), "prompt", t.TempDir())
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	findings, summary, err := ExtractFindings(res.Raw)
	if err != nil {
		t.Fatalf("ExtractFindings: %v", err)
	}
	if len(findings) != 1 || summary != "fenced result" {
		t.Fatalf("got %d findings, summary %q", len(findings), summary)
	}
}

func TestClaudeAdapterIsErrorEnvelope(t *testing.T) {
	bin := fakeAgentEmitting(t, envelopeJSON(t, "credit balance too low", 0, true))
	a := NewClaudeAdapter(AdapterConfig{Binary: bin})

	_, err := a.Invoke(context.Background(), "prompt", t.TempDir())
	if err == nil {
		t.Fatal("want error for is_error=true envelope")
	}
	if !strings.Contains(err.Error(), "credit balance too low") {
		t.Fatalf("err = %v, want the agent's error text included", err)
	}
}

func TestClaudeAdapterNonJSONOutput(t *testing.T) {
	bin := writeFakeAgent(t, "cat >/dev/null\necho 'not json at all'")
	a := NewClaudeAdapter(AdapterConfig{Binary: bin})

	if _, err := a.Invoke(context.Background(), "prompt", t.TempDir()); err == nil {
		t.Fatal("want error for non-JSON envelope")
	}
}

func TestClaudeAdapterExitFailure(t *testing.T) {
	bin := writeFakeAgent(t, "cat >/dev/null\necho 'auth expired' >&2\nexit 1")
	a := NewClaudeAdapter(AdapterConfig{Binary: bin})

	_, err := a.Invoke(context.Background(), "prompt", t.TempDir())
	if err == nil {
		t.Fatal("want error for non-zero exit")
	}
	if !strings.Contains(err.Error(), "auth expired") {
		t.Fatalf("err = %v, want stderr included", err)
	}
}

func TestClaudeAdapterTimeout(t *testing.T) {
	bin := writeFakeAgent(t, "cat >/dev/null\nexec sleep 30")
	a := NewClaudeAdapter(AdapterConfig{Binary: bin, Timeout: 150 * time.Millisecond})

	start := time.Now()
	_, err := a.Invoke(context.Background(), "prompt", t.TempDir())
	elapsed := time.Since(start)
	if !errors.Is(err, ErrAgentTimeout) {
		t.Fatalf("err = %v, want errors.Is ErrAgentTimeout", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Invoke took %v; process not killed on timeout", elapsed)
	}
}

func TestClaudeAdapterMissingBinary(t *testing.T) {
	a := NewClaudeAdapter(AdapterConfig{Binary: "rvl-test-no-such-agent-binary"})
	_, err := a.Invoke(context.Background(), "prompt", t.TempDir())
	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("err = %v, want errors.Is ErrAgentUnavailable", err)
	}

	a = NewClaudeAdapter(AdapterConfig{Binary: filepath.Join(t.TempDir(), "absent")})
	_, err = a.Invoke(context.Background(), "prompt", t.TempDir())
	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("err = %v, want errors.Is ErrAgentUnavailable for absolute path", err)
	}
}

func TestClaudeAdapterPromptOnStdin(t *testing.T) {
	// The fake reports how many bytes it received on stdin; asserting
	// the exact prompt length proves stdin transport (never argv).
	bin := writeFakeAgent(t, `n=$(wc -c)
n=$(echo $n)
printf '{"result":"stdin-bytes:%s","total_cost_usd":0,"is_error":false}' "$n"`)
	a := NewClaudeAdapter(AdapterConfig{Binary: bin})

	prompt := "line one\nline two with unicode é\n"
	res, err := a.Invoke(context.Background(), prompt, t.TempDir())
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	want := fmt.Sprintf("stdin-bytes:%d", len(prompt))
	if res.Raw != want {
		t.Fatalf("Raw = %q, want %q", res.Raw, want)
	}
}

func TestClaudeAdapterRunsInSnapshotDir(t *testing.T) {
	bin := writeFakeAgent(t, `cat >/dev/null
printf '{"result":"pwd:%s","total_cost_usd":0,"is_error":false}' "$PWD"`)
	a := NewClaudeAdapter(AdapterConfig{Binary: bin})

	snap := t.TempDir()
	res, err := a.Invoke(context.Background(), "prompt", snap)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	got := strings.TrimPrefix(res.Raw, "pwd:")
	// Resolve symlinks: on some systems TMPDIR is a symlink and $PWD
	// reports the resolved path.
	wantResolved, _ := filepath.EvalSymlinks(snap)
	if got != snap && got != wantResolved {
		t.Fatalf("agent cwd = %q, want snapshot dir %q", got, snap)
	}
}

func TestClaudeAdapterInvocationArgs(t *testing.T) {
	bin := writeFakeAgent(t, `cat >/dev/null
printf '{"result":"args:%s","total_cost_usd":0,"is_error":false}' "$*"`)
	a := NewClaudeAdapter(AdapterConfig{Binary: bin, Model: "opus"})

	res, err := a.Invoke(context.Background(), "prompt", t.TempDir())
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	want := "args:-p --output-format json --allowedTools Read --model opus"
	if res.Raw != want {
		t.Fatalf("Raw = %q, want %q", res.Raw, want)
	}
}

func TestClaudeAdapterName(t *testing.T) {
	if got := NewClaudeAdapter(AdapterConfig{}).Name(); got != "claude" {
		t.Fatalf("Name = %q, want claude", got)
	}
}

func TestRunLensWithClaudeAdapterEndToEnd(t *testing.T) {
	cs := goChangeSet()
	l := goLens(t)
	payload := findingsJSON(t, []Finding{validFinding()}, "end to end")
	bin := fakeAgentEmitting(t, envelopeJSON(t, payload, 0.33, false))
	a := NewClaudeAdapter(AdapterConfig{Binary: bin})

	res := RunLens(context.Background(), a, l, cs, t.TempDir())
	if res.Err != nil {
		t.Fatalf("RunLens Err = %v", res.Err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Lens != LensGo {
		t.Fatalf("Findings = %+v, want one stamped %q", res.Findings, LensGo)
	}
	if res.CostUSD != 0.33 {
		t.Fatalf("CostUSD = %v, want 0.33", res.CostUSD)
	}
}

func TestRunLensClaudeTimeoutCarriesLensContext(t *testing.T) {
	bin := writeFakeAgent(t, "cat >/dev/null\nexec sleep 30")
	a := NewClaudeAdapter(AdapterConfig{Binary: bin, Timeout: 150 * time.Millisecond})

	res := RunLens(context.Background(), a, goLens(t), goChangeSet(), t.TempDir())
	if !errors.Is(res.Err, ErrAgentTimeout) {
		t.Fatalf("Err = %v, want errors.Is ErrAgentTimeout", res.Err)
	}
	if !strings.Contains(res.Err.Error(), LensGo) {
		t.Fatalf("Err = %v, want lens id in message for gate-policy reporting", res.Err)
	}
}
