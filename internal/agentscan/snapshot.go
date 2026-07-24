package agentscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SnapshotIndex materializes the staged (index) content of the given
// non-deleted files into a fresh temp directory, preserving relative
// paths. Content comes from the index blob (`git show :<path>`) —
// never the worktree file: with partial staging (git add -p) the two
// differ, and the gate must see exactly what will be committed.
// Because git subprocesses inherit the environment (see runGit), a
// GIT_INDEX_FILE exported by git for temp-index commits is honored
// here too.
//
// Deleted files are skipped defensively even if passed. Any per-file
// failure fails the whole snapshot with an error naming the file: a
// partial snapshot would silently narrow the scan. On success, cleanup
// removes the temp directory; on error, dir is "" and cleanup is nil.
func SnapshotIndex(root string, files []ChangedFile) (dir string, cleanup func(), err error) {
	return snapshot(root, "", files)
}

// SnapshotTree is SnapshotIndex with content read from treeish instead
// of the index (`git show <treeish>:<path>`), for range scans that
// gate the committed side (e.g. the pushed sha in the pre-push
// protocol). treeish must be non-empty and must not start with a dash
// (argument injection guard).
func SnapshotTree(root, treeish string, files []ChangedFile) (dir string, cleanup func(), err error) {
	treeish = strings.TrimSpace(treeish)
	if treeish == "" {
		return "", nil, fmt.Errorf("snapshot: treeish is empty")
	}
	if strings.HasPrefix(treeish, "-") {
		return "", nil, fmt.Errorf("snapshot: invalid treeish %q: leading dash", treeish)
	}
	return snapshot(root, treeish, files)
}

// snapshot materializes files from `git show <treeish>:<path>`; an
// empty treeish selects the index (stage 0). The object spec always
// starts with treeish or ":", so a path can never be parsed as a git
// flag.
func snapshot(root, treeish string, files []ChangedFile) (string, func(), error) {
	dir, err := os.MkdirTemp("", "rvl-agentscan-*")
	if err != nil {
		return "", nil, fmt.Errorf("snapshot: create temp dir: %w", err)
	}
	remove := func() { _ = os.RemoveAll(dir) }
	for _, f := range files {
		if f.Kind == ChangeDeleted {
			// Deletions are listed in prompts but never materialized.
			continue
		}
		rel := filepath.Clean(filepath.FromSlash(f.Path))
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			remove()
			return "", nil, fmt.Errorf("snapshot %s: path escapes snapshot root", f.Path)
		}
		content, err := runGit(root, "show", treeish+":"+f.Path)
		if err != nil {
			remove()
			return "", nil, fmt.Errorf("snapshot %s: %w", f.Path, err)
		}
		dest := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			remove()
			return "", nil, fmt.Errorf("snapshot %s: %w", f.Path, err)
		}
		if err := os.WriteFile(dest, content, 0o644); err != nil {
			remove()
			return "", nil, fmt.Errorf("snapshot %s: %w", f.Path, err)
		}
	}
	return dir, remove, nil
}
