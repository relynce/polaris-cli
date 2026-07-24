package agentscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSnapshotIndexMaterializesStagedContentNotWorktree is the core
// partial-staging correctness test (git add -p): the snapshot must
// contain the INDEX content that will be committed, never the worktree
// file, which may have moved on since staging.
func TestSnapshotIndexMaterializesStagedContentNotWorktree(t *testing.T) {
	dir := initGitRepo(t)
	writeFile(t, dir, "a.go", "package p\n\n// v1\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "v1")

	writeFile(t, dir, "a.go", "package p\n\n// v2 staged\n")
	gitIn(t, dir, "add", "a.go")
	// Worktree drifts past the staged state without staging.
	writeFile(t, dir, "a.go", "package p\n\n// v3 worktree only\n")

	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapDir, cleanup, err := SnapshotIndex(dir, cs.Present())
	if err != nil {
		t.Fatal(err)
	}
	got := readFile(t, filepath.Join(snapDir, "a.go"))
	if !strings.Contains(got, "// v2 staged") {
		t.Errorf("snapshot = %q, want the staged (index) content", got)
	}
	if strings.Contains(got, "v3 worktree") {
		t.Errorf("snapshot leaked worktree content: %q", got)
	}

	cleanup()
	if _, err := os.Stat(snapDir); !os.IsNotExist(err) {
		t.Errorf("cleanup did not remove snapshot dir %s", snapDir)
	}
}

func TestSnapshotIndexPreservesNestedPaths(t *testing.T) {
	dir := initGitRepo(t)
	writeFile(t, dir, "pkg/nested/deep.go", "package nested\n")
	gitIn(t, dir, "add", ".")

	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapDir, cleanup, err := SnapshotIndex(dir, cs.Present())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got := readFile(t, filepath.Join(snapDir, "pkg", "nested", "deep.go"))
	if got != "package nested\n" {
		t.Errorf("nested file content = %q", got)
	}
}

func TestSnapshotSkipsDeletedFilesDefensively(t *testing.T) {
	dir := initGitRepo(t)
	writeFile(t, dir, "keep.go", "package p\n")
	writeFile(t, dir, "gone.go", "package p\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	gitIn(t, dir, "rm", "-q", "gone.go")
	writeFile(t, dir, "keep.go", "package p\n\n// changed\n")
	gitIn(t, dir, "add", "keep.go")

	cs, err := StagedChangeSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Pass the FULL file list, including the deletion: the snapshot
	// must skip it even when the caller forgot to filter via Present().
	snapDir, cleanup, err := SnapshotIndex(dir, cs.Files)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(snapDir, "gone.go")); !os.IsNotExist(err) {
		t.Error("deleted file was materialized into the snapshot")
	}
	if _, err := os.Stat(filepath.Join(snapDir, "keep.go")); err != nil {
		t.Errorf("modified file missing from snapshot: %v", err)
	}
}

func TestSnapshotFailsClosedOnMissingFile(t *testing.T) {
	dir := initGitRepo(t)
	_, _, err := SnapshotIndex(dir, []ChangedFile{{Path: "nope.go", Kind: ChangeAdded}})
	if err == nil {
		t.Fatal("snapshot of a file absent from the index must fail the whole snapshot (partial snapshots silently narrow the scan)")
	}
	if !strings.Contains(err.Error(), "nope.go") {
		t.Errorf("error must name the failing file: %v", err)
	}
}

func TestSnapshotTreeMaterializesHeadSideContent(t *testing.T) {
	dir := initRangeRepo(t)
	// Worktree drifts after the commit: the tree snapshot must show the
	// committed HEAD content, not the drift.
	writeFile(t, dir, "a.go", "package p\n\n// uncommitted drift\n")

	cs, err := RangeChangeSet(dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	snapDir, cleanup, err := SnapshotTree(dir, "HEAD", cs.Present())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got := readFile(t, filepath.Join(snapDir, "a.go"))
	if !strings.Contains(got, "func A2") {
		t.Errorf("a.go = %q, want committed HEAD content", got)
	}
	if strings.Contains(got, "uncommitted drift") {
		t.Errorf("snapshot leaked worktree content: %q", got)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "c.go")); err != nil {
		t.Errorf("added file missing from tree snapshot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "b.go")); !os.IsNotExist(err) {
		t.Error("deleted file was materialized into the tree snapshot")
	}
}

func TestSnapshotTreeRejectsDashTreeish(t *testing.T) {
	dir := initRangeRepo(t)
	if _, _, err := SnapshotTree(dir, "-x", nil); err == nil {
		t.Fatal("treeish with leading dash must be rejected (argument injection guard)")
	}
	if _, _, err := SnapshotTree(dir, "", nil); err == nil {
		t.Fatal("empty treeish must be rejected")
	}
}
