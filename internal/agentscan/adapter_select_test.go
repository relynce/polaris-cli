package agentscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelectAdapterDefaultsToClaude(t *testing.T) {
	a, err := SelectAdapter(AdapterChoice{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "claude" {
		t.Errorf("empty preset must default to claude, got %s", a.Name())
	}
}

func TestSelectAdapterUnknownPreset(t *testing.T) {
	if _, err := SelectAdapter(AdapterChoice{Preset: "gpt5"}); err == nil {
		t.Fatal("unknown preset must error")
	}
}

// TestSelectAdapterCustomRequiresTrustedCommand is the trust-boundary
// test: preset=custom with no user-level command fails closed, and the
// error makes clear repo config cannot supply one.
func TestSelectAdapterCustomRequiresTrustedCommand(t *testing.T) {
	_, err := SelectAdapter(AdapterChoice{Preset: "custom"})
	if err == nil {
		t.Fatal("custom preset with no trusted command must fail closed")
	}
	if !strings.Contains(err.Error(), "repo config cannot supply") {
		t.Errorf("error must explain the trust boundary, got: %v", err)
	}
}

func TestSelectAdapterCustomWithTrustedCommand(t *testing.T) {
	a, err := SelectAdapter(AdapterChoice{
		Preset:         "custom",
		TrustedCommand: []string{"myagent", "--prompt", promptFileToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "custom" {
		t.Errorf("name = %s, want custom", a.Name())
	}
}

func TestNewCustomAdapterRequiresPromptFileToken(t *testing.T) {
	// A command that never references {promptfile} would force the prompt
	// onto argv, which the transport rules forbid.
	if _, err := NewCustomAdapter(CustomAdapterConfig{Command: []string{"agent", "run"}}); err == nil {
		t.Fatal("command without {promptfile} must be rejected")
	}
	if _, err := NewCustomAdapter(CustomAdapterConfig{Command: nil}); err == nil {
		t.Fatal("empty command must be rejected")
	}
}

// TestCustomAdapterInvokeEndToEnd runs a fake agent that reads the
// prompt file and echoes findings JSON, proving the placeholder
// substitution, off-argv prompt delivery, and cwd all work.
func TestCustomAdapterInvokeEndToEnd(t *testing.T) {
	binDir := t.TempDir()
	fake := filepath.Join(binDir, "fakeagent")
	// The fake asserts it received a real prompt file path (arg 2) whose
	// contents include our marker, that cwd is the snapshot dir, then
	// prints a findings JSON object.
	script := "#!/bin/sh\n" +
		"pf=\"$2\"\n" +
		"grep -q PROMPT_MARKER \"$pf\" || { echo 'missing prompt marker' >&2; exit 3; }\n" +
		"echo \"cwd=$(pwd)\" >&2\n" +
		"echo '{\"findings\":[{\"rule\":\"missing-timeout\",\"severity\":\"high\",\"file\":\"a.go\",\"line\":1,\"title\":\"t\",\"description\":\"d\"}],\"summary\":\"ok\"}'\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	snap := t.TempDir()
	a, err := NewCustomAdapter(CustomAdapterConfig{
		Command: []string{"fakeagent", "--prompt", promptFileToken, "--dir", snapshotDirToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Invoke(context.Background(), "PROMPT_MARKER body", snap)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	findings, _, perr := ExtractFindings(res.Raw)
	if perr != nil {
		t.Fatalf("extract: %v (raw=%q)", perr, res.Raw)
	}
	if len(findings) != 1 || findings[0].Rule != "missing-timeout" {
		t.Errorf("findings = %+v", findings)
	}
}

func TestCustomAdapterUnavailableBinary(t *testing.T) {
	a, err := NewCustomAdapter(CustomAdapterConfig{Command: []string{"definitely-not-a-real-binary-xyz", promptFileToken}})
	if err != nil {
		t.Fatal(err)
	}
	_, ierr := a.Invoke(context.Background(), "p", t.TempDir())
	if ierr == nil {
		t.Fatal("missing binary must error")
	}
	if got := ierr.Error(); !strings.Contains(got, "agent unavailable") {
		t.Errorf("want ErrAgentUnavailable, got %v", ierr)
	}
}
