package agentscan

import (
	"bufio"
	"strconv"
	"strings"
)

// newcode.go implements new-code gating: only findings on (or within a small
// tolerance of) lines the change added/modified GATE; findings on pre-existing
// / context lines in a touched file are marked Advisory (reported, never
// gated). This bounds the treadmill's detection-variance layer — the agent
// still samples real issues non-deterministically, but re-litigating old code
// in files you merely touched stops moving the goalposts.

// newCodeTolerance is how far (in lines) a finding may sit from a changed line
// and still count as in-scope. Absorbs agent line-number drift and
// change-adjacent context lines.
const newCodeTolerance = 3

// GateScopeChanged (default) gates only on changed-line findings; GateScopeAll
// disables new-code gating (every finding gates).
const (
	GateScopeChanged = "changed"
	GateScopeAll     = "all"
)

// classifyNewCode marks each finding Advisory when it does not fall on a
// changed line (within tolerance). With GateScope="all" it is a no-op (every
// finding gates). Returns the same slice for chaining.
func classifyNewCode(cfg PipelineConfig, cs ChangeSet, findings []Finding) []Finding {
	if strings.EqualFold(cfg.GateScope, GateScopeAll) {
		return findings
	}
	changed := changedLineSet(cs.Diff)
	for i := range findings {
		if !inChangedScope(findings[i], changed, newCodeTolerance) {
			findings[i].Advisory = true
		}
	}
	return findings
}

// changedLineSet parses a unified diff into per-file sets of ADDED post-change
// line numbers. Deletions do not advance the post-change counter; context and
// added lines do; only added ('+') lines are recorded.
func changedLineSet(diff string) map[string]map[int]bool {
	out := map[string]map[int]bool{}
	var file string
	var line int // current post-change line number within a hunk
	sc := bufio.NewScanner(strings.NewReader(diff))
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024) // tolerate large diffs
	for sc.Scan() {
		t := sc.Text()
		switch {
		case strings.HasPrefix(t, "+++ "):
			file = parseDiffNewPath(t)
			if file != "" && out[file] == nil {
				out[file] = map[int]bool{}
			}
			line = 0
		case strings.HasPrefix(t, "--- "), strings.HasPrefix(t, "diff --git "),
			strings.HasPrefix(t, "index "), strings.HasPrefix(t, "\\ "),
			strings.HasPrefix(t, "rename "), strings.HasPrefix(t, "similarity "),
			strings.HasPrefix(t, "new file"), strings.HasPrefix(t, "deleted file"),
			strings.HasPrefix(t, "old mode"), strings.HasPrefix(t, "new mode"):
			// metadata: ignore
		case strings.HasPrefix(t, "@@"):
			line = parseHunkNewStart(t)
		case file == "" || line == 0:
			// not inside a hunk yet
		case strings.HasPrefix(t, "+"):
			out[file][line] = true
			line++
		case strings.HasPrefix(t, "-"):
			// deletion: no post-change advance
		default:
			// context line (leading space) advances the post-change counter
			line++
		}
	}
	return out
}

// inChangedScope reports whether f falls on (or within tol of) a changed line.
// A file-level finding (Line <= 0) is in scope if the file has any changed
// lines at all.
func inChangedScope(f Finding, changed map[string]map[int]bool, tol int) bool {
	lines := changed[normalizePath(f.File)]
	if len(lines) == 0 {
		return false
	}
	if f.Line <= 0 {
		return true
	}
	for d := -tol; d <= tol; d++ {
		if lines[f.Line+d] {
			return true
		}
	}
	return false
}

// parseDiffNewPath extracts the post-change path from a "+++ b/<path>" header.
// Returns "" for /dev/null (a deletion has no post-change side).
func parseDiffNewPath(t string) string {
	p := strings.TrimPrefix(t, "+++ ")
	if i := strings.IndexByte(p, '\t'); i >= 0 { // strip trailing tab-metadata
		p = p[:i]
	}
	if p == "/dev/null" {
		return ""
	}
	p = strings.TrimPrefix(p, "b/")
	return normalizePath(p)
}

// parseHunkNewStart extracts c from a "@@ -a,b +c,d @@" hunk header.
func parseHunkNewStart(t string) int {
	i := strings.IndexByte(t, '+')
	if i < 0 {
		return 0
	}
	rest := t[i+1:]
	if end := strings.IndexAny(rest, ", "); end >= 0 {
		rest = rest[:end]
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0
	}
	return n
}
