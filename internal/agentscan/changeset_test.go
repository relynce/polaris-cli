package agentscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagedChangeSetClassifiesAddModifyDelete(t *testing.T) {
	dir := initGitRepo(t)
	writeFile(t, dir, "a.go", "package p\n\nfunc A() {}\n")
	writeFile(t, dir, "b.go", "package p\n\nfunc B() {}\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "base")

	writeFile(t, dir, "a.go", "package p\n\nfunc A() {}\n\nfunc A2() {}\n")
	writeFile(t, dir, "pkg/nested/new.go", "package nested\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "rm", "-q", "b.go")

	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cs.BaseDesc != "staged" {
		t.Errorf("BaseDesc = %q, want %q", cs.BaseDesc, "staged")
	}
	if !strings.Contains(cs.Diff, "func A2") {
		t.Errorf("Diff does not contain the staged modification:\n%s", cs.Diff)
	}
	if len(cs.Files) != 3 {
		t.Fatalf("got %d files, want 3: %+v", len(cs.Files), cs.Files)
	}
	if f, ok := findFile(cs, "a.go"); !ok || f.Kind != ChangeModified {
		t.Errorf("a.go = %+v, want modified", f)
	}
	if f, ok := findFile(cs, "pkg/nested/new.go"); !ok || f.Kind != ChangeAdded {
		t.Errorf("pkg/nested/new.go = %+v, want added", f)
	}
	if f, ok := findFile(cs, "b.go"); !ok || f.Kind != ChangeDeleted {
		t.Errorf("b.go = %+v, want deleted", f)
	}
	if del := cs.Deleted(); len(del) != 1 || del[0] != "b.go" {
		t.Errorf("Deleted() = %v, want [b.go]", del)
	}
	if got := len(cs.Present()); got != 2 {
		t.Errorf("Present() has %d entries, want 2", got)
	}
}

func TestStagedChangeSetDetectsRename(t *testing.T) {
	dir := initGitRepo(t)
	writeFile(t, dir, "old.go", "package p\n\n// enough distinctive content for similarity matching\nfunc Old() {}\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "base")

	gitIn(t, dir, "mv", "old.go", "new.go")

	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Files) != 1 {
		t.Fatalf("got %d files, want 1 rename entry: %+v", len(cs.Files), cs.Files)
	}
	f := cs.Files[0]
	if f.Kind != ChangeRenamed {
		t.Errorf("Kind = %q, want %q", f.Kind, ChangeRenamed)
	}
	if f.Path != "new.go" {
		t.Errorf("Path = %q, want new.go", f.Path)
	}
	if f.OldPath != "old.go" {
		t.Errorf("OldPath = %q, want old.go", f.OldPath)
	}
}

func TestStagedChangeSetEmptyIsNonNilEmptyFiles(t *testing.T) {
	dir := initGitRepo(t)
	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Files == nil {
		t.Fatal("empty staged set must return non-nil empty Files")
	}
	if len(cs.Files) != 0 {
		t.Errorf("expected no files, got %+v", cs.Files)
	}
	if cs.Diff != "" {
		t.Errorf("expected empty diff, got %q", cs.Diff)
	}
}

// TestStagedChangeSetHonorsGitIndexFile asserts the temp-index
// guarantee: when git runs a pre-commit hook for `git commit -a` or a
// pathspec commit, it exports GIT_INDEX_FILE pointing at the temporary
// index the commit will use. Our git subprocesses must inherit that
// variable so the diff and snapshot reflect the index being committed,
// not .git/index.
func TestStagedChangeSetHonorsGitIndexFile(t *testing.T) {
	dir := initGitRepo(t)
	writeFile(t, dir, "a.go", "package p\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "base")

	// Build an alternate index: copy the real one, then stage extra.go
	// into the alternate only (via GIT_INDEX_FILE on the subprocess).
	altIndex := filepath.Join(t.TempDir(), "alt-index")
	copyFile(t, filepath.Join(dir, ".git", "index"), altIndex)
	writeFile(t, dir, "extra.go", "package p\n\n// staged content\n")
	cmd := exec.Command("git", "-C", dir, "add", "extra.go")
	cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+altIndex)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add with GIT_INDEX_FILE: %v\n%s", err, out)
	}
	// The worktree moves on; the alternate index keeps the staged blob.
	writeFile(t, dir, "extra.go", "package p\n\n// worktree content\n")

	// Without GIT_INDEX_FILE the default index is diffed: extra.go is
	// untracked there, so the staged set is empty.
	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Files) != 0 {
		t.Fatalf("default index should have nothing staged, got %+v", cs.Files)
	}

	// With GIT_INDEX_FILE set (as inside a hook), the alternate index
	// must be the one diffed and snapshotted.
	t.Setenv("GIT_INDEX_FILE", altIndex)
	cs, err = StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findFile(cs, "extra.go")
	if !ok || f.Kind != ChangeAdded {
		t.Fatalf("extra.go = %+v, want added via alternate index; files=%+v", f, cs.Files)
	}
	if !strings.Contains(cs.Diff, "staged content") {
		t.Errorf("Diff must show the alternate index content:\n%s", cs.Diff)
	}

	snapDir, cleanup, err := SnapshotIndex(dir, cs.Present())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got := readFile(t, filepath.Join(snapDir, "extra.go"))
	if !strings.Contains(got, "staged content") {
		t.Errorf("snapshot content = %q, want the alternate index blob", got)
	}
	if strings.Contains(got, "worktree content") {
		t.Errorf("snapshot leaked worktree content: %q", got)
	}
}

func TestRangeChangeSetAgainstBase(t *testing.T) {
	dir := initRangeRepo(t)
	cs, err := RangeChangeSet(dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	if cs.BaseDesc != "main...HEAD" {
		t.Errorf("BaseDesc = %q, want main...HEAD", cs.BaseDesc)
	}
	if len(cs.Files) != 3 {
		t.Fatalf("got %d files, want 3: %+v", len(cs.Files), cs.Files)
	}
	if f, ok := findFile(cs, "a.go"); !ok || f.Kind != ChangeModified {
		t.Errorf("a.go = %+v, want modified", f)
	}
	if f, ok := findFile(cs, "c.go"); !ok || f.Kind != ChangeAdded {
		t.Errorf("c.go = %+v, want added", f)
	}
	if f, ok := findFile(cs, "b.go"); !ok || f.Kind != ChangeDeleted {
		t.Errorf("b.go = %+v, want deleted", f)
	}
	if !strings.Contains(cs.Diff, "func A2") {
		t.Errorf("Diff missing the range change (pathspec-vs-range regression, po-t8acf):\n%s", cs.Diff)
	}
}

func TestRangeChangeSetRejectsDashBaseRef(t *testing.T) {
	dir := initRangeRepo(t)
	if _, err := RangeChangeSet(dir, "-U5"); err == nil {
		t.Fatal("baseRef with leading dash must be rejected (argument injection guard)")
	}
	if _, err := RangeChangeSet(dir, ""); err == nil {
		t.Fatal("empty baseRef must be rejected: a range change set requires a base")
	}
}

func TestRangeChangeSetEmptyDiffNonNilEmptyFiles(t *testing.T) {
	dir := initRangeRepo(t)
	gitIn(t, dir, "branch", "same-as-head")
	cs, err := RangeChangeSet(dir, "same-as-head")
	if err != nil {
		t.Fatal(err)
	}
	if cs.Files == nil {
		t.Fatal("genuinely empty range diff must return non-nil empty Files")
	}
	if len(cs.Files) != 0 {
		t.Errorf("expected no files, got %+v", cs.Files)
	}
}
