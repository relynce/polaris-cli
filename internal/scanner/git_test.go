package scanner

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

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

func TestResolveBaseRefFromFlagWins(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{
		Root:        dir,
		FlagBaseRef: "main",
		Env:         map[string]string{"RVL_BASE_REF": "feature/x"},
	}
	res, err := ResolveBaseRef(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ref != "main" {
		t.Errorf("got %q, want main", res.Ref)
	}
	if res.Source != BaseRefFromFlag {
		t.Errorf("source=%q, want flag", res.Source)
	}
}

func TestResolveBaseRefFromRVLEnv(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{
		Root: dir,
		Env:  map[string]string{"RVL_BASE_REF": "main"},
	}
	res, err := ResolveBaseRef(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != BaseRefFromRVLEnv {
		t.Errorf("source=%q, want RVL_BASE_REF", res.Source)
	}
}

func TestResolveBaseRefFromGitHub(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{
		Root: dir,
		Env:  map[string]string{"GITHUB_BASE_REF": "main"},
	}
	res, err := ResolveBaseRef(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != BaseRefFromGitHub {
		t.Errorf("source=%q, want GITHUB_BASE_REF", res.Source)
	}
}

func TestResolveBaseRefHardFailsWhenAllMissing(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{Root: dir}
	res, err := ResolveBaseRef(cfg)
	if !errors.Is(err, ErrNoBaseRef) {
		t.Fatalf("got err=%v, want ErrNoBaseRef", err)
	}
	if res.Ref != "" {
		t.Errorf("expected empty Ref, got %q", res.Ref)
	}
	msg := FormatNoBaseRefDiagnostic(res)
	if !strings.Contains(msg, "Tried") {
		t.Errorf("diagnostic missing 'Tried' summary: %s", msg)
	}
	if !strings.Contains(msg, "--scan-all-on-missing-base") {
		t.Errorf("diagnostic missing the opt-in flag mention: %s", msg)
	}
}

func TestResolveBaseRefSkipsUnreachableThenContinues(t *testing.T) {
	dir := initGitRepo(t)
	cfg := ChangedOnlyConfig{
		Root:        dir,
		FlagBaseRef: "no-such-ref",
		Env:         map[string]string{"RVL_BASE_REF": "main"},
	}
	res, err := ResolveBaseRef(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != BaseRefFromRVLEnv {
		t.Errorf("source=%q, want RVL_BASE_REF after flag was unreachable", res.Source)
	}
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

// initGitRepoWithChanges builds a repo where main has a.go and b.go,
// and a feature branch (checked out) modifies a.go and adds c.go.
// main...HEAD therefore contains exactly a.go and c.go.
func initGitRepoWithChanges(t *testing.T) string {
	t.Helper()
	dir := initGitRepo(t)
	writeFile(t, dir, "a.go", "package p\n\nfunc A() {}\n")
	writeFile(t, dir, "b.go", "package p\n\nfunc B() {}\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "base files")
	gitIn(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, dir, "a.go", "package p\n\nfunc A() {}\n\nfunc A2() {}\n")
	writeFile(t, dir, "c.go", "package p\n\nfunc C() {}\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "feature changes")
	return dir
}

func TestResolveChangedFilesReturnsChangedSet(t *testing.T) {
	dir := initGitRepoWithChanges(t)
	files, err := ResolveChangedFiles(dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(files, ",")
	if got != "a.go,c.go" {
		t.Errorf("changed files = %q, want %q (pathspec-vs-range regression, po-t8acf)", got, "a.go,c.go")
	}
}

func TestResolveChangedFilesEmptyDiffReturnsNonNilEmpty(t *testing.T) {
	dir := initGitRepoWithChanges(t)
	// A branch pointing at the same commit as HEAD: diff is genuinely empty.
	gitIn(t, dir, "branch", "same-as-head")
	files, err := ResolveChangedFiles(dir, "same-as-head")
	if err != nil {
		t.Fatal(err)
	}
	if files == nil {
		t.Fatal("empty diff with a set base ref must return a non-nil empty slice (nil means 'no base: scan everything')")
	}
	if len(files) != 0 {
		t.Errorf("expected no changed files, got %v", files)
	}
}

func TestResolveChangedFilesRejectsDashRef(t *testing.T) {
	dir := initGitRepoWithChanges(t)
	if _, err := ResolveChangedFiles(dir, "-U5"); err == nil {
		t.Fatal("baseRef with leading dash must be rejected (argument injection guard)")
	}
	if _, err := ResolveChangedHunks(dir, "--exit-code"); err == nil {
		t.Fatal("baseRef with leading dash must be rejected in ResolveChangedHunks too")
	}
}

func TestResolveChangedHunksReturnsRangesForChangedFile(t *testing.T) {
	dir := initGitRepoWithChanges(t)
	hunks, err := ResolveChangedHunks(dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(hunks["a.go"]) == 0 {
		t.Fatalf("no hunks for a.go (pathspec-vs-range regression, po-t8acf); hunks=%v", hunks)
	}
	if len(hunks["c.go"]) == 0 {
		t.Fatalf("no hunks for new file c.go; hunks=%v", hunks)
	}
}

// TestChangedOnlyGateFiresOnNewFinding is the end-to-end vacuous-gate
// regression for po-t8acf: a high-impact finding on a line changed
// vs the base ref must classify as new and gate. Before the fix,
// ResolveChangedHunks returned an empty (non-nil) map, so every
// finding classified pre-existing and the gate never fired.
func TestChangedOnlyGateFiresOnNewFinding(t *testing.T) {
	dir := initGitRepoWithChanges(t)
	hunks, err := ResolveChangedHunks(dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	findings := []ScanFinding{{
		Impact:   "high",
		Evidence: []ScanEvidence{{Path: "a.go", LineNumber: 5}}, // func A2 line, inside the changed hunk
	}}
	findings = ClassifyFindings(findings, hunks)
	if findings[0].Status != StatusNew {
		t.Fatalf("finding on changed line classified %q, want %q", findings[0].Status, StatusNew)
	}
	if !HasGatingFindings(findings) {
		t.Fatal("high-impact finding on changed line must gate")
	}
}
