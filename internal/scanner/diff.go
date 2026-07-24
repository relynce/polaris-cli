package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Finding status values used by ClassifyFindings.
const (
	StatusNew         = "new"
	StatusPreExisting = "pre-existing"
)

// LineRange is an inclusive 1-based line range in a file. Used by
// change-aware scanning to classify findings against changed hunks.
type LineRange struct {
	Start int
	End   int
}

// Contains reports whether n falls inside the range (inclusive).
func (r LineRange) Contains(n int) bool {
	return n >= r.Start && n <= r.End
}

// ResolveChangedHunks returns the changed line ranges per file in the
// new-file (HEAD) side of `git diff baseRef...HEAD`. Used by
// change-aware scanning to classify findings as new vs pre-existing.
//
// Empty baseRef returns (nil, nil) so callers can short-circuit
// classification cleanly.
func ResolveChangedHunks(root, baseRef string) (map[string][]LineRange, error) {
	if baseRef == "" {
		return nil, nil
	}
	if strings.HasPrefix(baseRef, "-") {
		return nil, fmt.Errorf("invalid base ref %q: leading dash", baseRef)
	}
	// -U0 strips context lines so hunks shrink to just the touched
	// lines. Cleaner range data; same hunk-header semantics.
	// po-t8acf: the range must precede `--` or git parses it as a pathspec.
	cmd := exec.Command("git", "-C", root, "diff", "-U0", baseRef+"...HEAD", "--")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff against %s: %w", baseRef, err)
	}
	return parseChangedHunks(string(out)), nil
}

// ClassifyFindings tags each finding's Status field as "new" (line
// inside a changed hunk) or "pre-existing" (line outside any hunk for
// that file, or the file is not in the diff at all).
//
// Mutates findings in place. Returns the same slice for chaining.
//
// When hunks is nil (no base ref resolved), findings retain their
// existing Status (typically empty). Callers MUST treat empty status
// as "gate normally" for back-compat with non-change-aware scans.
func ClassifyFindings(findings []ScanFinding, hunks map[string][]LineRange) []ScanFinding {
	if hunks == nil {
		return findings
	}
	for i := range findings {
		f := &findings[i]
		if len(f.Evidence) == 0 {
			f.Status = StatusPreExisting
			continue
		}
		ev := f.Evidence[0]
		ranges, ok := hunks[ev.Path]
		if !ok {
			f.Status = StatusPreExisting
			continue
		}
		inHunk := false
		for _, r := range ranges {
			if r.Contains(ev.LineNumber) {
				inHunk = true
				break
			}
		}
		if inHunk {
			f.Status = StatusNew
		} else {
			f.Status = StatusPreExisting
		}
	}
	return findings
}

// HasGatingFindings reports whether any finding in the slice should
// cause the scanner to exit non-zero. A finding gates when its Impact
// is critical or high AND its Status is not "pre-existing". Empty
// Status (no classification ran) is treated as gating, matching the
// pre-change-aware behavior.
func HasGatingFindings(findings []ScanFinding) bool {
	for _, f := range findings {
		if f.Status == StatusPreExisting {
			continue
		}
		switch strings.ToLower(f.Impact) {
		case "critical", "high":
			return true
		}
	}
	return false
}

// hunkHeaderRE captures the new-file range from a unified diff hunk
// header. Example: `@@ -10,2 +10,3 @@` -> start=10, count=3 (count
// defaults to 1 when the comma form is absent).
var hunkHeaderRE = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// hunkDiffPathRE matches the new-file path line of a unified diff,
// e.g. `+++ b/path/to/file.go`. Captures the path with the `b/` prefix
// stripped.
var hunkDiffPathRE = regexp.MustCompile(`^\+\+\+ b/(.+)$`)

// parseChangedHunks walks unified diff output and returns the new-file
// line ranges grouped by path. Ranges with zero-length new content
// (pure deletions) are dropped because there are no current-file lines
// for findings to land on.
func parseChangedHunks(diff string) map[string][]LineRange {
	out := map[string][]LineRange{}
	if diff == "" {
		return out
	}
	var currentFile string
	for line := range strings.SplitSeq(diff, "\n") {
		if m := hunkDiffPathRE.FindStringSubmatch(line); m != nil {
			currentFile = NormalizePath(m[1])
			continue
		}
		if !strings.HasPrefix(line, "@@ ") || currentFile == "" {
			continue
		}
		m := hunkHeaderRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		start, _ := strconv.Atoi(m[1])
		count := 1
		if m[2] != "" {
			count, _ = strconv.Atoi(m[2])
		}
		if count == 0 {
			continue
		}
		out[currentFile] = append(out[currentFile], LineRange{
			Start: start,
			End:   start + count - 1,
		})
	}
	return out
}
