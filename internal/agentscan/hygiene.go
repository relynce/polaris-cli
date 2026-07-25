package agentscan

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// This file implements diff hygiene (spec: "Diff hygiene (before prompt
// rendering)"): the generated-content filter, the size budget, secret
// refusal, and the in-progress-git-state skip check. Pipeline order for
// callers (po-66evv.5): SkipReason first (cheapest, decides whether to
// scan at all), then compute the ChangeSet, then FilterGenerated →
// CheckSecrets → ApplyBudget → RenderPrompt per chunk.

// DroppedFile records one file removed by the generated-content filter
// and why, so the scan output can list what was excluded (no silent
// filtering).
type DroppedFile struct {
	Path   string
	Reason string
}

// builtinGeneratedGlobs is the built-in generated/vendored file list
// (spec: Diff hygiene item 1). Matched only when .gitattributes says
// nothing about the path.
var builtinGeneratedGlobs = []string{
	"*.gen.go",
	"*.pb.go",
	"*_generated.go",
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	"go.sum",
	"vendor/**",
	"node_modules/**",
	"*.min.js",
	"*.min.css",
}

// FilterGenerated drops generated content from a change set before any
// prompt is rendered. Resolution order per file (spec: Diff hygiene):
//
//  1. .gitattributes `linguist-generated` - queried in one batch
//     `git check-attr` subprocess. An explicit true/set drops the file;
//     an explicit false/unset KEEPS it even when a glob below matches
//     (.gitattributes is the first authority in both directions).
//  2. Built-in globs (builtinGeneratedGlobs).
//  3. extraGlobs from repo config.
//
// Dropped files are removed from BOTH the Files list and the unified
// diff text (their `diff --git` sections are stripped). The returned
// DroppedFile list names every exclusion and its reason.
func FilterGenerated(root string, cs ChangeSet, extraGlobs []string) (ChangeSet, []DroppedFile, error) {
	if len(cs.Files) == 0 {
		return cs, nil, nil
	}
	paths := make([]string, len(cs.Files))
	for i, f := range cs.Files {
		paths[i] = f.Path
	}
	attrs, err := linguistGenerated(root, paths)
	if err != nil {
		return ChangeSet{}, nil, err
	}

	var kept []ChangedFile
	var dropped []DroppedFile
	droppedSet := map[string]bool{}
	for _, f := range cs.Files {
		reason := ""
		switch attrs[f.Path] {
		case "true", "set":
			reason = ".gitattributes linguist-generated=true"
		case "false", "unset":
			// Explicitly marked not-generated: keep, skip globs.
		default: // "unspecified" or absent
			if g, ok := matchAnyGlob(builtinGeneratedGlobs, f.Path); ok {
				reason = "built-in generated glob " + g
			} else if g, ok := matchAnyGlob(extraGlobs, f.Path); ok {
				reason = "config generated glob " + g
			}
		}
		if reason != "" {
			dropped = append(dropped, DroppedFile{Path: f.Path, Reason: reason})
			droppedSet[f.Path] = true
			continue
		}
		kept = append(kept, f)
	}
	if len(dropped) == 0 {
		return cs, nil, nil
	}

	prefix, sections := splitDiffSections(cs.Diff)
	var sb strings.Builder
	sb.WriteString(prefix)
	for _, sec := range sections {
		if droppedSet[sec.NewPath] {
			continue
		}
		sb.WriteString(sec.Text)
	}
	out := cs
	out.Diff = sb.String()
	out.Files = kept
	return out, dropped, nil
}

// linguistGenerated returns the linguist-generated attribute value for
// each path ("set", "unset", "unspecified", or a value like "true"),
// resolved by git in a single batch subprocess.
func linguistGenerated(root string, paths []string) (map[string]string, error) {
	if len(paths) == 0 {
		return map[string]string{}, nil
	}
	stdin := []byte(strings.Join(paths, "\x00") + "\x00")
	out, err := runGitStdin(root, stdin, "check-attr", "--stdin", "-z", "linguist-generated")
	if err != nil {
		return nil, fmt.Errorf("query .gitattributes linguist-generated: %w", err)
	}
	// -z output: <path> NUL <attribute> NUL <value> NUL, repeated.
	vals := map[string]string{}
	tokens := strings.Split(string(out), "\x00")
	for i := 0; i+2 < len(tokens); i += 3 {
		vals[normalizePath(tokens[i])] = tokens[i+2]
	}
	return vals, nil
}

// runGitStdin is runGit with input on stdin (used for batch check-attr).
// Like runGit, it deliberately inherits the parent environment so a
// GIT_INDEX_FILE exported for temp-index commits is honored.
func runGitStdin(root string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
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

// matchAnyGlob returns the first glob in globs matching p.
func matchAnyGlob(globs []string, p string) (string, bool) {
	for _, g := range globs {
		if matchGlob(g, p) {
			return g, true
		}
	}
	return "", false
}

// matchGlob matches a repo-relative forward-slash path against a
// generated-content glob. Semantics (documented, deliberately simple -
// not full doublestar):
//
//   - "dir/**"     - the path is inside a dir/ directory at any depth
//     (vendor/**, node_modules/** must catch nested trees like
//     frontend/node_modules/...).
//   - "**/pat"     - pat matched against the basename.
//   - no slash     - matched against the basename (so *.gen.go matches
//     api/openapi.gen.go).
//   - otherwise    - path.Match against the full path.
func matchGlob(pattern, p string) bool {
	switch {
	case strings.HasSuffix(pattern, "/**"):
		dir := strings.TrimSuffix(pattern, "/**")
		return p == dir || strings.HasPrefix(p, dir+"/") || strings.Contains(p, "/"+dir+"/")
	case strings.HasPrefix(pattern, "**/"):
		ok, err := path.Match(strings.TrimPrefix(pattern, "**/"), path.Base(p))
		return err == nil && ok
	case !strings.Contains(pattern, "/"):
		ok, err := path.Match(pattern, path.Base(p))
		return err == nil && ok
	default:
		ok, err := path.Match(pattern, p)
		return err == nil && ok
	}
}

// diffSection is one file's slice of a unified diff, from its
// `diff --git` header up to the next header (or end of diff).
type diffSection struct {
	NewPath string // b/ side of the header, repo-relative
	Text    string // full section text including the header line
}

// splitDiffSections splits a unified diff into per-file sections keyed
// on `diff --git a/... b/...` headers. prefix is any content before the
// first header (normally empty), preserved so filtering is lossless.
func splitDiffSections(diff string) (prefix string, sections []diffSection) {
	lines := strings.SplitAfter(diff, "\n")
	var cur *diffSection
	var sb strings.Builder
	flush := func() {
		if cur != nil {
			cur.Text = sb.String()
			sections = append(sections, *cur)
		} else {
			prefix = sb.String()
		}
		sb.Reset()
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
			cur = &diffSection{NewPath: newPathFromHeader(line)}
		}
		sb.WriteString(line)
	}
	flush()
	return prefix, sections
}

// newPathFromHeader extracts the new (b/) path from a
// `diff --git a/OLD b/NEW` header line. Paths containing specials are
// C-quoted by git (`diff --git "a/x y" "b/x y"`); both forms are
// handled by splitting on the last b/ marker.
func newPathFromHeader(line string) string {
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if i := strings.LastIndex(line, ` "b/`); i >= 0 {
		return normalizePath(strings.TrimSuffix(line[i+len(` "b/`):], `"`))
	}
	if i := strings.LastIndex(line, " b/"); i >= 0 {
		return normalizePath(line[i+len(" b/"):])
	}
	return ""
}

// Default size-budget limits, measured against the filtered diff's line
// count (spec: Diff hygiene item 2).
const (
	DefaultSoftLimitLines = 1500
	DefaultHardLimitLines = 6000
	// DefaultChunkMaxFiles bounds how many changed files a single lens
	// invocation reasons over. Per-lens runtime scales with file count
	// (not diff line count); grouping keeps each invocation well under the
	// per-lens timeout. Groups of this size retain enough cross-file
	// context to summarize repeated patterns — per-file (1) does not and
	// explodes the finding count (measured). See the per-file-chunking
	// benchmark.
	DefaultChunkMaxFiles = 4
)

// BudgetResult is the outcome of applying the size budget.
//
//   - Under the soft limit: ChangeSet is the input, Chunks is empty.
//   - Over soft, under hard: Chunks holds per-file groupings to scan as
//     separate lens invocations; ChangeSet still holds the full input
//     for reference.
//   - Over the hard limit: FileListMode is true and ChangeSet.Diff is
//     replaced by a file-list summary - the diff content is NOT sent.
//
// Notices lists every degrade in human-readable form; callers MUST
// surface them (spec: oversized diffs must never silently fail open,
// and a degraded scan must never look like a successful full scan).
type BudgetResult struct {
	ChangeSet    ChangeSet
	Chunks       []ChangeSet
	FileListMode bool
	Notices      []string
}

// ApplyBudget enforces the size budget on a filtered change set.
// Non-positive limits fall back to the defaults. A change set is chunked
// when it is over the soft line limit OR spans more than chunkMaxFiles
// changed files: per-lens runtime scales with file count, so many small
// files still need splitting even under the line limit.
func ApplyBudget(cs ChangeSet, softLimit, hardLimit, chunkMaxFiles int) BudgetResult {
	if softLimit <= 0 {
		softLimit = DefaultSoftLimitLines
	}
	if hardLimit <= 0 {
		hardLimit = DefaultHardLimitLines
	}
	if hardLimit < softLimit {
		hardLimit = softLimit
	}
	if chunkMaxFiles <= 0 {
		chunkMaxFiles = DefaultChunkMaxFiles
	}
	total := lineCount(cs.Diff)
	if total > hardLimit {
		degraded := cs
		degraded.Diff = fileListSummary(cs, total, hardLimit)
		return BudgetResult{
			ChangeSet:    degraded,
			FileListMode: true,
			Notices: []string{fmt.Sprintf(
				"DEGRADED TO FILE-LIST MODE: the filtered diff is %d lines, over the hard limit of %d. "+
					"Diff content was NOT sent to any lens; only file names were. "+
					"This is NOT a full scan of the change - split the change or scan smaller ranges to restore coverage.",
				total, hardLimit)},
		}
	}
	if total <= softLimit && len(cs.Files) <= chunkMaxFiles {
		return BudgetResult{ChangeSet: cs}
	}
	return chunkBySection(cs, softLimit, chunkMaxFiles, total)
}

// chunkBySection splits a change set into chunks, greedily grouping
// consecutive diff sections so each chunk stays under the soft LINE limit
// AND holds at most chunkMaxFiles files. A single section that alone
// exceeds the line limit gets its own chunk (it cannot be split further at
// file granularity) and its own notice.
func chunkBySection(cs ChangeSet, softLimit, chunkMaxFiles, total int) BudgetResult {
	if chunkMaxFiles <= 0 {
		chunkMaxFiles = DefaultChunkMaxFiles
	}
	prefix, sections := splitDiffSections(cs.Diff)
	fileByPath := map[string]ChangedFile{}
	for _, f := range cs.Files {
		fileByPath[f.Path] = f
	}

	var notices []string
	var chunks []ChangeSet
	var curDiff strings.Builder
	var curFiles []ChangedFile
	curLines := 0
	curDiff.WriteString(prefix)
	flush := func() {
		if curLines == 0 && len(curFiles) == 0 {
			return
		}
		chunks = append(chunks, ChangeSet{Diff: curDiff.String(), Files: curFiles, BaseDesc: cs.BaseDesc})
		curDiff.Reset()
		curFiles = nil
		curLines = 0
	}
	matched := map[string]bool{}
	for _, sec := range sections {
		n := lineCount(sec.Text)
		// Flush before adding this section if the current chunk is full on
		// either axis: too many lines, or already at the file cap.
		if curLines > 0 && (curLines+n > softLimit || len(curFiles) >= chunkMaxFiles) {
			flush()
		}
		curDiff.WriteString(sec.Text)
		curLines += n
		if f, ok := fileByPath[sec.NewPath]; ok && !matched[sec.NewPath] {
			curFiles = append(curFiles, f)
			matched[sec.NewPath] = true
		}
		if n > softLimit {
			notices = append(notices, fmt.Sprintf(
				"file %s alone is %d diff lines (over the soft limit of %d); it gets its own chunk and cannot be reduced further at file granularity",
				sec.NewPath, n, softLimit))
			flush()
		}
	}
	flush()

	// Files with no diff section (defensive: should not happen for a
	// git-produced diff) still get grouped into chunks under the file cap.
	for _, f := range cs.Files {
		if !matched[f.Path] {
			if len(chunks) == 0 || len(chunks[len(chunks)-1].Files) >= chunkMaxFiles {
				chunks = append(chunks, ChangeSet{BaseDesc: cs.BaseDesc})
			}
			last := &chunks[len(chunks)-1]
			last.Files = append(last.Files, f)
			matched[f.Path] = true
		}
	}
	for i := range chunks {
		chunks[i].BaseDesc = fmt.Sprintf("%s (chunk %d/%d)", cs.BaseDesc, i+1, len(chunks))
	}
	notices = append([]string{fmt.Sprintf(
		"change set (%d diff lines, %d files) split into %d chunks of at most %d files / %d lines each, "+
			"scanned as separate lens invocations; cross-file interactions between chunks may be missed",
		total, len(cs.Files), len(chunks), chunkMaxFiles, softLimit)}, notices...)
	return BudgetResult{ChangeSet: cs, Chunks: chunks, Notices: notices}
}

// fileListSummary renders the degraded file-list-mode replacement for
// the diff. It states loudly that diff content is omitted so no lens
// output built on it can read as a full review.
func fileListSummary(cs ChangeSet, total, hardLimit int) string {
	var sb strings.Builder
	sb.WriteString("[FILE-LIST MODE - DIFF CONTENT OMITTED]\n")
	fmt.Fprintf(&sb, "The filtered diff is %d lines, exceeding the hard limit of %d lines.\n", total, hardLimit)
	sb.WriteString("Only the changed file list follows; the diff itself was not included.\n")
	sb.WriteString("Findings are limited to what file names imply. This is NOT a full review of the change.\n\n")
	fmt.Fprintf(&sb, "Changed files (%d):\n", len(cs.Files))
	for _, f := range cs.Files {
		if f.Kind == ChangeRenamed && f.OldPath != "" {
			fmt.Fprintf(&sb, "- %s: %s -> %s\n", f.Kind, f.OldPath, f.Path)
			continue
		}
		fmt.Fprintf(&sb, "- %s: %s\n", f.Kind, f.Path)
	}
	return sb.String()
}

// lineCount counts lines in s, counting a trailing unterminated line.
func lineCount(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

// ErrSecretsDetected is the sentinel wrapped by SecretsError; callers
// use errors.Is(err, ErrSecretsDetected) to distinguish secret refusal
// from infra errors (refusal must never fail open).
var ErrSecretsDetected = errors.New("potential secrets detected in change set")

// SecretHit locates one potential secret. The matched value is
// deliberately NOT retained anywhere - file, line, and pattern kind
// only.
type SecretHit struct {
	Path string
	Line int
	Kind string
}

// SecretsError reports why the scan refused to invoke any agent. Its
// message names files and lines but never echoes secret values.
type SecretsError struct {
	Hits []SecretHit
}

func (e *SecretsError) Error() string {
	var sb strings.Builder
	sb.WriteString("refusing to invoke any agent: potential secrets detected in the outgoing diff (values withheld): ")
	for i, h := range e.Hits {
		if i > 0 {
			sb.WriteString("; ")
		}
		fmt.Fprintf(&sb, "%s:%d (%s)", h.Path, h.Line, h.Kind)
	}
	sb.WriteString(". Remove or unstage the secret - verify with your secret scanner (e.g. gitleaks) - then rerun.")
	return sb.String()
}

func (e *SecretsError) Unwrap() error { return ErrSecretsDetected }

// secretPatterns are gitleaks-style detectors run over outgoing diff
// content lines. Detection-only: v1 policy is refusal, not
// redact-and-continue (spec: Diff hygiene item 3), so these are
// separate from internal/scanner's redactSecrets masker (which rewrites
// snippets in place and reports no locations). Kind strings appear in
// the error message and must never resemble the secret itself.
var secretPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"private key material", regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}`)},
	{"credential assignment", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password)\s*[:=]+\s*['"][^'"]{8,}`)},
}

// hunkHeader captures the old and new start lines of a @@ hunk header.
var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// CheckSecrets scans the outgoing diff for secret material. On any hit
// it returns a *SecretsError (wrapping ErrSecretsDetected) naming each
// file:line - never the value - and the caller must refuse to invoke
// any agent. Line numbers are new-file lines for added/context lines
// and old-file lines for removed lines (removed content still leaves
// the machine in the prompt, so it is checked too).
func CheckSecrets(cs ChangeSet) error {
	var hits []SecretHit
	curPath := ""
	oldLine, newLine := 0, 0
	inHunk := false
	check := func(content string, line int) {
		for _, p := range secretPatterns {
			if p.re.MatchString(content) {
				hits = append(hits, SecretHit{Path: curPath, Line: line, Kind: p.kind})
				return // one hit per line is enough to refuse
			}
		}
	}
	for _, raw := range strings.Split(cs.Diff, "\n") {
		switch {
		case strings.HasPrefix(raw, "diff --git "):
			curPath = newPathFromHeader(raw)
			inHunk = false
		case strings.HasPrefix(raw, "@@"):
			if m := hunkHeader.FindStringSubmatch(raw); m != nil {
				oldLine, _ = strconv.Atoi(m[1])
				newLine, _ = strconv.Atoi(m[2])
				inHunk = true
			}
		case !inHunk:
			// Section metadata (index, ---, +++, mode lines): skip.
		case strings.HasPrefix(raw, "+"):
			check(raw[1:], newLine)
			newLine++
		case strings.HasPrefix(raw, "-"):
			check(raw[1:], oldLine)
			oldLine++
		case strings.HasPrefix(raw, " "):
			check(raw[1:], newLine)
			oldLine++
			newLine++
		}
	}
	if len(hits) > 0 {
		return &SecretsError{Hits: hits}
	}
	return nil
}

// SkipReason reports whether the scan should be skipped because a
// merge, rebase, or cherry-pick is in progress (spec: Diff hygiene
// item 5 - these are out of scope in v1). The git dir is resolved via
// `git rev-parse --git-dir` because in linked worktrees .git is a file
// and the hook-relevant state lives in the worktree's private git dir.
// If the git dir cannot be resolved, no skip state is reported; the
// change-set stages will surface the real error.
func SkipReason(root string) (string, bool) {
	out, err := runGit(root, "rev-parse", "--git-dir")
	if err != nil {
		return "", false
	}
	gitDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	exists := func(rel string) bool {
		_, err := os.Stat(filepath.Join(gitDir, rel))
		return err == nil
	}
	switch {
	case exists("MERGE_HEAD"):
		return "merge in progress (MERGE_HEAD present)", true
	case exists("rebase-merge") || exists("rebase-apply"):
		return "rebase in progress (rebase state dir present)", true
	case exists("CHERRY_PICK_HEAD"):
		return "cherry-pick in progress (CHERRY_PICK_HEAD present)", true
	}
	return "", false
}
