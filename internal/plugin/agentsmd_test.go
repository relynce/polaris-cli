package plugin

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newTempGitRepo creates a temp directory initialized as a git repo.
func newTempGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("git", "init", "-q", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return dir
}

func readAgentsMd(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	return string(data)
}

func TestInstallContextFiles_CreatesBlockInGitRepo(t *testing.T) {
	// Simulates the post-install step every editor (claude or not) runs.
	repo := newTempGitRepo(t)
	var buf bytes.Buffer

	installContextFiles(repo, InstallOptions{}, &buf)

	content := readAgentsMd(t, repo)
	if !strings.Contains(content, agentsMdBlockStart) || !strings.Contains(content, agentsMdBlockEnd) {
		t.Fatalf("AGENTS.md missing managed-block markers:\n%s", content)
	}
	for _, want := range []string{
		"rvl risk context R-XXX --format=json",
		"rvl control show RC-XXX",
		"rvl knowledge search",
		"rvl evidence submit --control=RC-XXX",
		"/rvl:scan",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("AGENTS.md block missing %q", want)
		}
	}
	if !strings.Contains(buf.String(), "AGENTS.md: created") {
		t.Errorf("expected creation notice, got: %s", buf.String())
	}
}

func TestInstallContextFiles_OptOut(t *testing.T) {
	repo := newTempGitRepo(t)
	var buf bytes.Buffer

	installContextFiles(repo, InstallOptions{SkipContextFiles: true}, &buf)

	if _, err := os.Stat(filepath.Join(repo, "AGENTS.md")); !os.IsNotExist(err) {
		t.Fatalf("AGENTS.md should not exist with SkipContextFiles, stat err: %v", err)
	}
	// The skip is silent: rvl init sets SkipContextFiles programmatically
	// (its Steps 4/5 own the context files interactively), so a notice here
	// would be misleading. The --no-context-files flag prints its own notice
	// at parse time in CmdPlugin.
	if buf.Len() != 0 {
		t.Errorf("expected silent skip, got: %s", buf.String())
	}
}

func TestInstallContextFiles_NonGitRepoSkipsWithNotice(t *testing.T) {
	dir := t.TempDir() // not a git repo
	var buf bytes.Buffer

	installContextFiles(dir, InstallOptions{}, &buf)

	if _, err := os.Stat(filepath.Join(dir, "AGENTS.md")); !os.IsNotExist(err) {
		t.Fatalf("AGENTS.md should not exist outside a git repo, stat err: %v", err)
	}
	if !strings.Contains(buf.String(), "not inside a git repository") {
		t.Errorf("expected non-git-repo notice, got: %s", buf.String())
	}
}

func TestEnsureAgentsMd_UpdateIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	action, err := EnsureAgentsMd(dir, true)
	if err != nil || action != "created" {
		t.Fatalf("first ensure: action=%q err=%v", action, err)
	}
	first := readAgentsMd(t, dir)

	action, err = EnsureAgentsMd(dir, true)
	if err != nil || action != "updated" {
		t.Fatalf("second ensure: action=%q err=%v", action, err)
	}
	second := readAgentsMd(t, dir)

	if first != second {
		t.Errorf("repeated ensure changed content:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if got := strings.Count(second, agentsMdBlockStart); got != 1 {
		t.Errorf("expected exactly 1 managed block, got %d", got)
	}
}

func TestEnsureAgentsMd_ReplacesStaleBlock(t *testing.T) {
	dir := t.TempDir()
	stale := "# My Project\n\nUser notes.\n\n" +
		agentsMdBlockStart + "\nold stale content\n" + agentsMdBlockEnd + "\n\n## Other Section\n"
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(stale), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureAgentsMd(dir, true)
	if err != nil || action != "updated" {
		t.Fatalf("ensure: action=%q err=%v", action, err)
	}

	content := readAgentsMd(t, dir)
	if strings.Contains(content, "old stale content") {
		t.Error("stale block content survived update")
	}
	if !strings.Contains(content, "# My Project") || !strings.Contains(content, "## Other Section") {
		t.Errorf("surrounding user content lost:\n%s", content)
	}
	if got := strings.Count(content, agentsMdBlockStart); got != 1 {
		t.Errorf("expected exactly 1 managed block, got %d", got)
	}
}

func TestEnsureAgentsMd_AppendsToUnmanagedFile(t *testing.T) {
	dir := t.TempDir()
	existing := "# My Project\n\nBuild with make.\n"
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureAgentsMd(dir, true)
	if err != nil || action != "appended" {
		t.Fatalf("ensure: action=%q err=%v", action, err)
	}

	content := readAgentsMd(t, dir)
	if !strings.HasPrefix(content, existing) {
		t.Errorf("existing content not preserved at top:\n%s", content)
	}
	if !strings.Contains(content, agentsMdBlockStart) {
		t.Error("managed block not appended")
	}
}

func TestEnsureAgentsMd_SkipsUnmanagedWithoutYesAll(t *testing.T) {
	dir := t.TempDir()
	existing := "# My Project\n"
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureAgentsMd(dir, false)
	if err != nil || action != "skipped" {
		t.Fatalf("ensure: action=%q err=%v", action, err)
	}
	if got := readAgentsMd(t, dir); got != existing {
		t.Errorf("file changed despite skip:\n%s", got)
	}
}

func TestEnsureAgentsMd_MigratesLegacySection(t *testing.T) {
	dir := t.TempDir()
	// Shape written by older `rvl init` (heading + ### subsections, no markers).
	legacy := "# My Project\n\n## Revelara\n\nThis project uses Revelara for reliability risk analysis. The following skills are available:\n\n### Core Skills\n- `/rvl:scan` old entry\n\n### Quick Reference\n- Run `rvl risk list` to see current risks\n\n## Build\n\nRun make.\n"
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureAgentsMd(dir, true)
	if err != nil || action != "updated" {
		t.Fatalf("ensure: action=%q err=%v", action, err)
	}

	content := readAgentsMd(t, dir)
	if strings.Contains(content, "old entry") {
		t.Error("legacy section content survived migration")
	}
	if !strings.Contains(content, "# My Project") || !strings.Contains(content, "## Build") {
		t.Errorf("non-Revelara sections lost:\n%s", content)
	}
	if got := strings.Count(content, agentsMdBlockStart); got != 1 {
		t.Errorf("expected exactly 1 managed block, got %d", got)
	}
	if got := strings.Count(content, "## Revelara\n"); got != 1 {
		t.Errorf("expected exactly 1 Revelara heading, got %d", got)
	}

	// Migration must be stable: a second run keeps content identical.
	if action, err = EnsureAgentsMd(dir, true); err != nil || action != "updated" {
		t.Fatalf("re-ensure: action=%q err=%v", action, err)
	}
	if again := readAgentsMd(t, dir); again != content {
		t.Errorf("second ensure after migration changed content")
	}
}

func TestEnsureAgentsMd_MalformedMarkersError(t *testing.T) {
	dir := t.TempDir()
	malformed := agentsMdBlockStart + "\ncontent without end marker\n"
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(malformed), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureAgentsMd(dir, true)
	if err == nil {
		t.Fatal("expected error for start marker without end marker")
	}
	if action != "skipped" {
		t.Errorf("expected skipped action, got %q", action)
	}
	if got := readAgentsMd(t, dir); got != malformed {
		t.Errorf("malformed file was modified:\n%s", got)
	}
}

func TestAgentsMdState(t *testing.T) {
	dir := t.TempDir()
	if got := AgentsMdState(dir); got != AgentsMdStateMissing {
		t.Errorf("missing: got %q", got)
	}

	path := filepath.Join(dir, "AGENTS.md")
	if err := os.WriteFile(path, []byte("# Notes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := AgentsMdState(dir); got != AgentsMdStateUnmanaged {
		t.Errorf("unmanaged: got %q", got)
	}

	if err := os.WriteFile(path, []byte("## Revelara\n\nlegacy\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := AgentsMdState(dir); got != AgentsMdStateManaged {
		t.Errorf("legacy managed: got %q", got)
	}

	if _, err := EnsureAgentsMd(dir, true); err != nil {
		t.Fatal(err)
	}
	if got := AgentsMdState(dir); got != AgentsMdStateManaged {
		t.Errorf("marker managed: got %q", got)
	}
}

func TestAgentsMdTemplate_NoInternalCodename(t *testing.T) {
	// The AGENTS.md block is client-visible: the internal codename must not leak.
	if strings.Contains(strings.ToLower(agentsMdTemplate), "polaris") {
		t.Error("agentsMdTemplate contains the internal codename")
	}
	if strings.Contains(agentsMdTemplate, "Task tool") {
		t.Error("agentsMdTemplate contains Claude-specific Task-tool wording")
	}
}
