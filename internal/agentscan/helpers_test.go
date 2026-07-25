package agentscan

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// initGitRepo creates a temp git repo with an initial empty commit on
// main. Same fixture pattern as internal/scanner/git_test.go, kept
// local to this package.
func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "--allow-empty", "-q", "-m", "init"},
	} {
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// gitIn runs a git command in dir, failing the test on error.
func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-c", "user.email=test@example.com", "-c", "user.name=Test"}, args...)
	c := exec.Command("git", full...)
	c.Dir = dir
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
}

// findFile returns the ChangedFile with the given path, if present.
func findFile(cs ChangeSet, path string) (ChangedFile, bool) {
	for _, f := range cs.Files {
		if f.Path == path {
			return f, true
		}
	}
	return ChangedFile{}, false
}

// initRangeRepo builds a repo where main has a.go and b.go, and a
// feature branch (checked out) modifies a.go, adds c.go, and deletes
// b.go. main...HEAD therefore spans exactly those three changes.
func initRangeRepo(t *testing.T) string {
	t.Helper()
	dir := initGitRepo(t)
	writeFile(t, dir, "a.go", "package p\n\nfunc A() {}\n")
	writeFile(t, dir, "b.go", "package p\n\nfunc B() {}\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "base files")
	gitIn(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, dir, "a.go", "package p\n\nfunc A() {}\n\nfunc A2() {}\n")
	writeFile(t, dir, "c.go", "package p\n\nfunc C() {}\n")
	gitIn(t, dir, "rm", "-q", "b.go")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "feature changes")
	return dir
}
