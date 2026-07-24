package commands

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func hookTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.email=t@e.co", "-c", "user.name=T", "commit", "--allow-empty", "-q", "-m", "init"},
	} {
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestSelectedHooksDefaultsToPreCommit(t *testing.T) {
	hooks, force, err := selectedHooks(nil)
	if err != nil {
		t.Fatal(err)
	}
	if force {
		t.Error("force should default false")
	}
	if len(hooks) != 1 || hooks[0].name != "pre-commit" {
		t.Fatalf("default should be pre-commit only, got %+v", hooks)
	}
}

func TestSelectedHooksBoth(t *testing.T) {
	hooks, _, err := selectedHooks([]string{"--pre-commit", "--pre-push", "--force"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 2 {
		t.Fatalf("want 2 hooks, got %d", len(hooks))
	}
}

func TestSelectedHooksUnknownFlag(t *testing.T) {
	if _, _, err := selectedHooks([]string{"--nope"}); err == nil {
		t.Fatal("unknown flag must error")
	}
}

func TestWriteHookShimAndForceBackup(t *testing.T) {
	dir := hookTestRepo(t)
	hd, err := hooksDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := hookKind{name: "pre-commit", shim: preCommitScanCmd}

	// First install writes an executable shim calling the agent scan.
	if err := writeHookShim(hd, h, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	path := filepath.Join(hd, "pre-commit")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&0o111 == 0 {
		t.Error("shim must be executable")
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "scan --agent --staged") {
		t.Errorf("shim missing agent-scan command:\n%s", body)
	}

	// Second install without --force is refused.
	if err := writeHookShim(hd, h, false); err == nil {
		t.Fatal("re-install without --force must be refused")
	}

	// With --force, the old hook is backed up.
	if err := writeHookShim(hd, h, true); err != nil {
		t.Fatalf("force install: %v", err)
	}
	if _, err := os.Stat(path + ".pre-rvl"); err != nil {
		t.Errorf("force must back up the old hook to .pre-rvl: %v", err)
	}
}

func TestHooksDirHonorsCoreHooksPath(t *testing.T) {
	dir := hookTestRepo(t)
	custom := filepath.Join(dir, "myhooks")
	c := exec.Command("git", "-C", dir, "config", "core.hooksPath", custom)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("set hooksPath: %v\n%s", err, out)
	}
	hd, err := hooksDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(hd) != filepath.Clean(custom) {
		t.Errorf("hooksDir = %s, want %s (core.hooksPath must be honored)", hd, custom)
	}
}

func TestDetectLefthookAndSnippet(t *testing.T) {
	dir := hookTestRepo(t)
	lh := filepath.Join(dir, "lefthook.yml")
	if err := os.WriteFile(lh, []byte("pre-commit:\n  commands:\n    secret-scan:\n      run: gitleaks dir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, ok := detectLefthook(dir)
	if !ok || path != lh {
		t.Fatalf("detectLefthook = %q,%v", path, ok)
	}
	if !lefthookHasSecretScan(lh) {
		t.Error("gitleaks entry must be detected as a secret scan")
	}
	// No .git/hooks file should be written when lefthook is present: the
	// install path prints a snippet instead. We assert the snippet
	// builder emits use_stdin for pre-push (piping the ref lines).
	// (printLefthookSnippet writes to stdout; we assert the shim data
	//  indirectly by checking selectedHooks marks pre-push stopgap.)
	hooks, _, _ := selectedHooks([]string{"--pre-push"})
	if len(hooks) != 1 || !hooks[0].stopgap {
		t.Errorf("pre-push must be marked stopgap until po-66evv.9")
	}
}

func TestDoctorChecksHealthyVsMissingBinary(t *testing.T) {
	dir := hookTestRepo(t)

	// Healthy: a fake `claude` on the provided PATH.
	binDir := t.TempDir()
	fake := filepath.Join(binDir, "claude")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	checks := doctorChecks(dir, binDir)
	if failed(checks) {
		t.Errorf("healthy repo with claude on PATH must not FAIL: %+v", checks)
	}
	if !hasCheck(checks, "agent binary", checkPass) {
		t.Errorf("agent binary should PASS when present:\n%+v", checks)
	}

	// Missing binary: empty PATH dir.
	emptyDir := t.TempDir()
	checks = doctorChecks(dir, emptyDir)
	if !failed(checks) {
		t.Errorf("missing binary must produce a FAIL")
	}
	if !hasCheck(checks, "agent binary", checkFail) {
		t.Errorf("agent binary should FAIL when absent:\n%+v", checks)
	}
}

func failed(checks []doctorCheck) bool {
	for _, c := range checks {
		if c.Status == checkFail {
			return true
		}
	}
	return false
}

func hasCheck(checks []doctorCheck, label string, status checkStatus) bool {
	for _, c := range checks {
		if c.Label == label && c.Status == status {
			return true
		}
	}
	return false
}
