package agentscan

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// runGit runs a git subcommand in root and returns its stdout.
//
// The subprocess DELIBERATELY inherits the parent environment (cmd.Env
// is left nil). When git invokes a hook for a temp-index commit
// (`git commit -a`, pathspec commits like `git commit -- file`), it
// exports GIT_INDEX_FILE pointing at the temporary index that commit
// will actually use; our git subprocesses must inherit it so we diff
// and snapshot the same index the commit sees (spec: "Execution model:
// staged snapshot"). Never scrub or replace the environment here.
func runGit(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, msg)
		}
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// StagedChangeSet computes the staged change set: the unified diff and
// classified file list of the index versus HEAD. This is the
// pre-commit gate's view; with partial staging (git add -p) it
// reflects the index content that will be committed, not the worktree.
func StagedChangeSet(root string) (ChangeSet, error) {
	return changeSet(root, "staged", "--cached")
}

// RangeChangeSet computes the change set for baseRef...HEAD (changes
// on HEAD's side since the merge base), the --changed-only / range
// scan view. baseRef must be non-empty and must not start with a dash
// (argument injection guard, po-t8acf).
func RangeChangeSet(root, baseRef string) (ChangeSet, error) {
	return RangeChangeSetBetween(root, baseRef, "HEAD")
}

// RangeChangeSetBetween computes the change set for base...head (changes
// on head's side since the merge base of base and head). Pre-push uses
// it with head = the pushed sha, not HEAD, since the pushed ref may not
// be the checked-out branch (po-66evv.9). Both refs must be non-empty
// and dash-free (argument injection guard, po-t8acf).
func RangeChangeSetBetween(root, base, head string) (ChangeSet, error) {
	base = strings.TrimSpace(base)
	head = strings.TrimSpace(head)
	if base == "" || head == "" {
		return ChangeSet{}, fmt.Errorf("range change set: base or head is empty")
	}
	if strings.HasPrefix(base, "-") {
		return ChangeSet{}, fmt.Errorf("invalid base ref %q: leading dash", base)
	}
	if strings.HasPrefix(head, "-") {
		return ChangeSet{}, fmt.Errorf("invalid head ref %q: leading dash", head)
	}
	rng := base + "..." + head
	return changeSet(root, rng, rng)
}

// changeSet runs the two diff invocations that make up a ChangeSet.
// selector is either "--cached" or a "<base>...HEAD" revision range.
//
// po-t8acf: the revision range must precede `--`; placed after it, git
// parses the range as a pathspec and the diff is silently empty. -M
// forces rename detection on regardless of user diff.renames config so
// both invocations classify renames identically.
func changeSet(root, baseDesc, selector string) (ChangeSet, error) {
	diffOut, err := runGit(root, "diff", "--no-color", "-M", selector, "--")
	if err != nil {
		return ChangeSet{}, fmt.Errorf("change set %s: %w", baseDesc, err)
	}
	statusOut, err := runGit(root, "diff", "--name-status", "-z", "-M", selector, "--")
	if err != nil {
		return ChangeSet{}, fmt.Errorf("change set %s: %w", baseDesc, err)
	}
	files, err := parseNameStatusZ(statusOut)
	if err != nil {
		return ChangeSet{}, fmt.Errorf("change set %s: %w", baseDesc, err)
	}
	return ChangeSet{Diff: string(diffOut), Files: files, BaseDesc: baseDesc}, nil
}

// parseNameStatusZ parses `git diff --name-status -z` output: NUL-
// separated tokens of `<status> <path>`, where rename and copy entries
// (`R<score>`, `C<score>`) carry two paths (`<old> <new>`). Returns a
// non-nil slice even when empty: a computed change set always has a
// Files list, and "genuinely empty diff" must be distinguishable from
// "not computed" (same semantics as scanner.ResolveChangedFiles).
func parseNameStatusZ(out []byte) ([]ChangedFile, error) {
	files := []ChangedFile{}
	tokens := strings.Split(string(out), "\x00")
	for i := 0; i < len(tokens); {
		status := tokens[i]
		if status == "" { // trailing NUL yields a final empty token
			i++
			continue
		}
		switch status[0] {
		case 'R', 'C':
			if i+2 >= len(tokens) {
				return nil, fmt.Errorf("truncated rename/copy entry %q in --name-status -z output", status)
			}
			oldPath, newPath := tokens[i+1], tokens[i+2]
			if status[0] == 'R' {
				files = append(files, ChangedFile{
					Path:    normalizePath(newPath),
					OldPath: normalizePath(oldPath),
					Kind:    ChangeRenamed,
				})
			} else {
				// A copy creates a new file; the source is unchanged.
				files = append(files, ChangedFile{Path: normalizePath(newPath), Kind: ChangeAdded})
			}
			i += 3
		default:
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("truncated entry %q in --name-status -z output", status)
			}
			files = append(files, ChangedFile{Path: normalizePath(tokens[i+1]), Kind: kindForStatus(status[0])})
			i += 2
		}
	}
	return files, nil
}

func kindForStatus(s byte) ChangeKind {
	switch s {
	case 'A':
		return ChangeAdded
	case 'D':
		return ChangeDeleted
	default:
		// M (modified), T (typechange), and anything unexpected: the
		// file exists on the new side, so treat it as modified - it
		// gets snapshotted and reviewed, which is the safe default.
		return ChangeModified
	}
}

// normalizePath returns the repo-relative path in forward-slash form.
// One-line duplicate of scanner.NormalizePath, kept local so agentscan
// does not depend on the scanner package.
func normalizePath(p string) string {
	return filepath.ToSlash(p)
}
