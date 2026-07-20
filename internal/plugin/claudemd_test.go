package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// po-dhtnw: EnsureClaudeMd had no test coverage at all, which let init's
// reporting bugs go unnoticed. These tests lock in the writer's contract.

func writeTemplate(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "CLAUDE.md")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readClaudeMd(t *testing.T, gitRoot string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(gitRoot, "CLAUDE.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEnsureClaudeMd_CreatesWhenMissing(t *testing.T) {
	gitRoot := t.TempDir()
	tmpl := writeTemplate(t, "## Revelara\ncontext here")

	action, err := EnsureClaudeMd(gitRoot, tmpl, false)
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
	if !strings.Contains(content, "context here") {
		t.Errorf("created CLAUDE.md missing template content:\n%s", content)
	}
}

func TestEnsureClaudeMd_AppendsToExistingWithoutBlock(t *testing.T) {
	gitRoot := t.TempDir()
	tmpl := writeTemplate(t, "## Revelara")
	existing := "# My project\nuser content\n"
	if err := os.WriteFile(filepath.Join(gitRoot, "CLAUDE.md"), []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureClaudeMd(gitRoot, tmpl, true)
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
	tmpl := writeTemplate(t, "## Revelara")
	existing := "# My project\n"
	if err := os.WriteFile(filepath.Join(gitRoot, "CLAUDE.md"), []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureClaudeMd(gitRoot, tmpl, false)
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
	tmpl := writeTemplate(t, "old content")
	if _, err := EnsureClaudeMd(gitRoot, tmpl, false); err != nil {
		t.Fatal(err)
	}

	tmpl2 := writeTemplate(t, "new content")
	action, err := EnsureClaudeMd(gitRoot, tmpl2, false)
	if err != nil {
		t.Fatal(err)
	}
	if action != "updated" {
		t.Errorf("action = %q, want updated", action)
	}
	content := readClaudeMd(t, gitRoot)
	if strings.Contains(content, "old content") || !strings.Contains(content, "new content") {
		t.Errorf("update must replace block content:\n%s", content)
	}
}

func TestEnsureClaudeMd_MigratesOldRelynceMarkers(t *testing.T) {
	gitRoot := t.TempDir()
	tmpl := writeTemplate(t, "new content")
	legacy := "# Mine\n" + claudeMdBlockStartOld + "\nlegacy\n" + claudeMdBlockEndOld + "\n"
	if err := os.WriteFile(filepath.Join(gitRoot, "CLAUDE.md"), []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureClaudeMd(gitRoot, tmpl, false)
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
	if !strings.Contains(content, "new content") || strings.Contains(content, "legacy") {
		t.Errorf("migrated block must carry new content:\n%s", content)
	}
}

func TestEnsureClaudeMd_MalformedBlockErrors(t *testing.T) {
	gitRoot := t.TempDir()
	tmpl := writeTemplate(t, "content")
	malformed := claudeMdBlockStart + "\nno end marker\n"
	if err := os.WriteFile(filepath.Join(gitRoot, "CLAUDE.md"), []byte(malformed), 0644); err != nil {
		t.Fatal(err)
	}

	action, err := EnsureClaudeMd(gitRoot, tmpl, true)
	if err == nil {
		t.Error("want error for start marker without end marker")
	}
	if action != "skipped" {
		t.Errorf("action = %q, want skipped", action)
	}
}
