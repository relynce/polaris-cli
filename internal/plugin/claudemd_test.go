package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// po-dhtnw: EnsureClaudeMd had no test coverage at all, which let init's
// reporting bugs go unnoticed. These tests lock in the writer's contract.
// po-pw4p6: the block is now composed from the shared agentsMdTemplate plus
// Claude-specific extras, single-sourcing everything the two files share.

func readClaudeMd(t *testing.T, gitRoot string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(gitRoot, "CLAUDE.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The single-source guarantee: every byte of the agent-neutral AGENTS.md
// template appears verbatim in the CLAUDE.md block, and the Claude-specific
// extras never leak back into AGENTS.md.
func TestClaudeMdTemplate_SingleSourcesSharedContent(t *testing.T) {
	tmpl := claudeMdTemplate()
	if !strings.Contains(tmpl, strings.TrimSpace(agentsMdTemplate)) {
		t.Error("CLAUDE.md template must embed the AGENTS.md template verbatim")
	}
	if !strings.Contains(tmpl, "### Expert Routing (ambient invocation)") {
		t.Error("CLAUDE.md template missing Claude-specific expert routing section")
	}
	if !strings.Contains(tmpl, "Task tool") {
		t.Error("CLAUDE.md extras should describe Task-tool expert routing")
	}
	if strings.Contains(agentsMdTemplate, "Expert Routing") || strings.Contains(agentsMdTemplate, "Task tool") {
		t.Error("Claude-specific extras must not leak into the agent-neutral AGENTS.md template")
	}
}

func TestEnsureClaudeMd_CreatesWhenMissing(t *testing.T) {
	gitRoot := t.TempDir()

	action, err := EnsureClaudeMd(gitRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	if action != "created" {
		t.Errorf("action = %q, want created", action)
	}
	content := readClaudeMd(t, gitRoot)
	if !strings.Contains(content, claudeMdBlockStart) || !strings.Contains(content, claudeMdBlockEnd) {
		t.Errorf("created CLAUDE.md missing managed block markers:\n%s", content)
	}
	if !strings.Contains(content, strings.TrimSpace(agentsMdTemplate)) {
		t.Error("created CLAUDE.md missing shared AGENTS.md content")
	}
	if !strings.Contains(content, "### Expert Routing (ambient invocation)") {
		t.Error("created CLAUDE.md missing Claude-specific extras")
	}
}

func TestEnsureClaudeMd_AppendsToExistingWithoutBlock(t *testing.T) {
	gitRoot := t.TempDir()
	existing := "# My project\nuser content\n"
	if err := os.WriteFile(filepath.Join(gitRoot, "CLAUDE.md"), []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureClaudeMd(gitRoot, true)
	if err != nil {
		t.Fatal(err)
	}
	if action != "appended" {
		t.Errorf("action = %q, want appended", action)
	}
	content := readClaudeMd(t, gitRoot)
	if !strings.HasPrefix(content, existing) {
		t.Errorf("append must preserve user content at the top:\n%s", content)
	}
	if !strings.Contains(content, claudeMdBlockStart) {
		t.Errorf("appended CLAUDE.md missing managed block:\n%s", content)
	}
}

func TestEnsureClaudeMd_SkipsExistingWithoutBlockWhenNotYesAll(t *testing.T) {
	gitRoot := t.TempDir()
	existing := "# My project\n"
	if err := os.WriteFile(filepath.Join(gitRoot, "CLAUDE.md"), []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureClaudeMd(gitRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	if action != "skipped" {
		t.Errorf("action = %q, want skipped", action)
	}
	if got := readClaudeMd(t, gitRoot); got != existing {
		t.Errorf("skip must not modify the file, got:\n%s", got)
	}
}

func TestEnsureClaudeMd_UpdatesExistingBlock(t *testing.T) {
	gitRoot := t.TempDir()
	stale := "# Mine\n" + claudeMdBlockStart + "\nstale block content\n" + claudeMdBlockEnd + "\n"
	if err := os.WriteFile(filepath.Join(gitRoot, "CLAUDE.md"), []byte(stale), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureClaudeMd(gitRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	if action != "updated" {
		t.Errorf("action = %q, want updated", action)
	}
	content := readClaudeMd(t, gitRoot)
	if strings.Contains(content, "stale block content") {
		t.Errorf("update must replace block content:\n%s", content)
	}
	if !strings.HasPrefix(content, "# Mine\n") {
		t.Errorf("update must preserve user content outside the block:\n%s", content)
	}
	if !strings.Contains(content, "### Expert Routing (ambient invocation)") {
		t.Error("updated block missing current template content")
	}
}

func TestEnsureClaudeMd_MigratesOldRelynceMarkers(t *testing.T) {
	gitRoot := t.TempDir()
	legacy := "# Mine\n" + claudeMdBlockStartOld + "\nlegacy\n" + claudeMdBlockEndOld + "\n"
	if err := os.WriteFile(filepath.Join(gitRoot, "CLAUDE.md"), []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureClaudeMd(gitRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	if action != "updated" {
		t.Errorf("action = %q, want updated", action)
	}
	content := readClaudeMd(t, gitRoot)
	if strings.Contains(content, claudeMdBlockStartOld) {
		t.Errorf("old markers must be migrated:\n%s", content)
	}
	if strings.Contains(content, "legacy") {
		t.Errorf("migrated block must carry new content:\n%s", content)
	}
}

func TestEnsureClaudeMd_MalformedBlockErrors(t *testing.T) {
	gitRoot := t.TempDir()
	malformed := claudeMdBlockStart + "\nno end marker\n"
	if err := os.WriteFile(filepath.Join(gitRoot, "CLAUDE.md"), []byte(malformed), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureClaudeMd(gitRoot, true)
	if err == nil {
		t.Error("want error for start marker without end marker")
	}
	if action != "skipped" {
		t.Errorf("action = %q, want skipped", action)
	}
}
