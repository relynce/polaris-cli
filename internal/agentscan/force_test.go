package agentscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestForceStateEnv(t *testing.T) {
	dir := initGitRepo(t)
	t.Setenv("RVL_FORCE", "1")
	mech, forced, err := ForceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !forced || mech != "env" {
		t.Fatalf("env force: mech=%q forced=%v, want env/true", mech, forced)
	}
}

func TestForceStateMarker(t *testing.T) {
	dir := initGitRepo(t)
	t.Setenv("RVL_FORCE", "") // ensure env is off
	if _, err := WriteForceMarker(dir); err != nil {
		t.Fatal(err)
	}
	mech, forced, err := ForceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !forced || mech != "marker" {
		t.Fatalf("marker force: mech=%q forced=%v, want marker/true", mech, forced)
	}
}

func TestForceStateEnvWinsButMarkerStillConsumable(t *testing.T) {
	dir := initGitRepo(t)
	t.Setenv("RVL_FORCE", "1")
	if _, err := WriteForceMarker(dir); err != nil {
		t.Fatal(err)
	}
	mech, forced, err := ForceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !forced || mech != "env" {
		t.Fatalf("both set: mech=%q, want env (env wins as reported mechanism)", mech)
	}
	// The marker must still be present and consumable, so it cannot
	// silently apply to a later run.
	present, err := MarkerPresent(dir)
	if err != nil || !present {
		t.Fatalf("marker must remain present when env also set; present=%v err=%v", present, err)
	}
	if err := ConsumeForceMarker(dir); err != nil {
		t.Fatalf("consume: %v", err)
	}
	present, _ = MarkerPresent(dir)
	if present {
		t.Fatal("marker must be gone after consume")
	}
}

func TestForceStateNeither(t *testing.T) {
	dir := initGitRepo(t)
	t.Setenv("RVL_FORCE", "")
	mech, forced, err := ForceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if forced || mech != "" {
		t.Fatalf("no force: mech=%q forced=%v, want empty/false", mech, forced)
	}
}

func TestMarkerLifecycle(t *testing.T) {
	dir := initGitRepo(t)
	path, err := WriteForceMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Marker lives in the git dir.
	if filepath.Base(path) != ForceMarkerName {
		t.Errorf("marker name = %s, want %s", filepath.Base(path), ForceMarkerName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Errorf("marker should be a non-empty JSON line")
	}
	// Consume twice: second is a no-op, not an error.
	if err := ConsumeForceMarker(dir); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := ConsumeForceMarker(dir); err != nil {
		t.Fatalf("second consume must be idempotent, got: %v", err)
	}
}

// TestMarkerInLinkedWorktreeGitDir locks that the marker lands in the
// per-worktree git dir (git rev-parse --git-dir), not the main repo's,
// so a force in one worktree does not leak to another.
func TestMarkerInLinkedWorktreeGitDir(t *testing.T) {
	main := initGitRepo(t)
	// A commit is needed before adding a worktree.
	writeFile(t, main, "f.txt", "x\n")
	gitIn(t, main, "add", ".")
	gitIn(t, main, "commit", "-q", "-m", "base")
	wt := t.TempDir()
	gitIn(t, main, "worktree", "add", "-q", wt)

	path, err := WriteForceMarker(wt)
	if err != nil {
		t.Fatal(err)
	}
	// The worktree's git dir is <main>/.git/worktrees/<name>, so the
	// marker path must be under that, not directly under <main>/.git.
	if !filepath.IsAbs(path) {
		t.Fatalf("marker path not absolute: %s", path)
	}
	present, err := MarkerPresent(wt)
	if err != nil || !present {
		t.Fatalf("marker must be present in the worktree; present=%v err=%v", present, err)
	}
	// The MAIN repo must NOT see the worktree's marker.
	mainPresent, err := MarkerPresent(main)
	if err != nil {
		t.Fatal(err)
	}
	if mainPresent {
		t.Errorf("worktree marker leaked into main repo git dir: %s", path)
	}
}
