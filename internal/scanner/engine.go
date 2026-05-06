package scanner

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// defaultExcludeDirs are walked-but-skipped by every scan. These never need
// reliability findings and dominate file counts in real repos.
var defaultExcludeDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"venv":         true,
	".venv":        true,
	"env":          true,
	"target":       true,
	"build":        true,
	"dist":         true,
	".git":         true,
	"__pycache__":  true,
	".tox":         true,
}

// generatedFileSuffixes catches typical generated-code patterns. Matchers
// can opt back in via FilePatterns if they want to match these.
var generatedFileSuffixes = []string{
	".pb.go", "_generated.go", ".gen.go",
}

// LanguageDetector returns the proper-case names of languages present
// in rootDir. The signature matches project.DetectLanguages so the
// caller can pass it directly. Used to drive matcher auto-selection
// without coupling the scanner package to project detection.
type LanguageDetector func(rootDir string) []string

// Scan walks opts.Root, runs all applicable matchers from registry, and
// returns the candidate findings plus stats. The caller (typically
// CmdScan) translates Candidates into ScanFindings via convert.go.
//
// The engine emits paths in forward-slash form (PRD §Deterministic
// Fingerprinting / Path normalization) regardless of host OS.
//
// Language auto-selection: when opts.Languages is non-empty (caller
// pre-resolved via project.DetectLanguages or --matchers) those drive
// filtering. When empty, no language filter is applied — all matchers
// run, restricted only by their FilePatterns. Pass project.DetectLanguages
// from the caller and assign the result into opts.Languages before
// calling Scan to enable auto-selection.
func Scan(matchers []Matcher, opts ScanOptions) ([]Candidate, ScanStats, error) {
	start := time.Now()
	if opts.Root == "" {
		return nil, ScanStats{}, fmt.Errorf("scanner: ScanOptions.Root is required")
	}
	rootAbs, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, ScanStats{}, fmt.Errorf("resolve root: %w", err)
	}

	for _, m := range matchers {
		for _, p := range m.Patterns {
			if err := p.NegateScope.Validate(); err != nil {
				return nil, ScanStats{}, fmt.Errorf("matcher %s: %w", m.Slug, err)
			}
		}
	}

	matchers = filterMatchersByOptions(matchers, opts)

	// Build the work list of files to scan.
	files, totalBytes, err := walkFiles(rootAbs, opts)
	if err != nil {
		return nil, ScanStats{}, err
	}

	type fileWork struct {
		relPath string // forward-slash, relative to rootAbs
		absPath string
		size    int64
	}
	work := make([]fileWork, 0, len(files))
	for _, f := range files {
		work = append(work, fileWork{relPath: f.rel, absPath: f.abs, size: f.size})
	}

	// Worker pool. Files are independent; matchers within a file are
	// sequential because they share the file's content buffer.
	workers := 8
	if len(work) < workers {
		workers = max(1, len(work))
	}

	var (
		mu         sync.Mutex
		candidates []Candidate
	)
	jobs := make(chan fileWork)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				localCands, err := scanFile(w.relPath, w.absPath, matchers, opts.IncludeTests)
				if err != nil {
					// Soft-fail per file: warn but continue.
					fmt.Fprintf(os.Stderr, "scanner: skip %s: %v\n", w.relPath, err)
					continue
				}
				if len(localCands) == 0 {
					continue
				}
				mu.Lock()
				candidates = append(candidates, localCands...)
				mu.Unlock()
			}
		}()
	}
	for _, w := range work {
		jobs <- w
	}
	close(jobs)
	wg.Wait()

	stats := ScanStats{
		FilesScanned: len(work),
		BytesScanned: totalBytes,
		MatchersRun:  len(matchers),
		DurationMS:   time.Since(start).Milliseconds(),
	}
	return candidates, stats, nil
}

func filterMatchersByOptions(in []Matcher, opts ScanOptions) []Matcher {
	out := make([]Matcher, 0, len(in))
	confidenceRank := map[string]int{"low": 1, "medium": 2, "high": 3}
	minConf := confidenceRank[strings.ToLower(opts.ConfidenceMin)]

	onlySet := map[string]bool{}
	for _, s := range opts.OnlyMatchers {
		onlySet[s] = true
	}

	// Build a set of detected languages for fast lookup. When
	// opts.Languages is empty we skip the language filter entirely
	// (every matcher with empty Languages always runs anyway).
	langSet := map[string]bool{}
	for _, l := range opts.Languages {
		langSet[strings.ToLower(l)] = true
	}

	for _, m := range in {
		if len(onlySet) > 0 && !onlySet[m.Slug] {
			continue
		}
		if opts.ExcludeMatchers[m.Slug] {
			continue
		}
		if minConf > 0 && confidenceRank[strings.ToLower(m.Confidence)] < minConf {
			continue
		}
		if !matcherLanguagesIntersect(m, langSet) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// matcherLanguagesIntersect reports whether m should run given the
// detected language set. Matchers with empty Languages are
// language-agnostic (typically IaC). Matchers with explicit Languages
// run only when at least one is present in detected (case-insensitive).
// When detected is empty (caller did not pre-resolve), all matchers
// pass — the engine falls back to FilePatterns alone.
func matcherLanguagesIntersect(m Matcher, detected map[string]bool) bool {
	if len(m.Languages) == 0 {
		return true
	}
	if len(detected) == 0 {
		return true
	}
	for _, l := range m.Languages {
		if detected[strings.ToLower(l)] {
			return true
		}
	}
	return false
}

type walkedFile struct {
	rel  string
	abs  string
	size int64
}

func walkFiles(root string, opts ScanOptions) ([]walkedFile, int64, error) {
	onlyFiles := map[string]bool{}
	for _, f := range opts.OnlyFiles {
		onlyFiles[NormalizePath(f)] = true
	}
	useOnly := len(onlyFiles) > 0

	excludePaths := opts.ExcludePaths

	var (
		out   []walkedFile
		bytes int64
	)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if defaultExcludeDirs[name] {
				return fs.SkipDir
			}
			rel, _ := filepath.Rel(root, path)
			rel = NormalizePath(rel)
			for _, ex := range excludePaths {
				ex = strings.TrimSuffix(NormalizePath(ex), "/")
				if rel == ex || strings.HasPrefix(rel, ex+"/") {
					return fs.SkipDir
				}
			}
			return nil
		}

		// Skip generated files by default.
		for _, suf := range generatedFileSuffixes {
			if strings.HasSuffix(name, suf) {
				return nil
			}
		}

		rel, _ := filepath.Rel(root, path)
		rel = NormalizePath(rel)
		if useOnly && !onlyFiles[rel] {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		out = append(out, walkedFile{rel: rel, abs: path, size: info.Size()})
		bytes += info.Size()
		return nil
	})
	return out, bytes, err
}

func scanFile(relPath, absPath string, matchers []Matcher, includeTests bool) ([]Candidate, error) {
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	lineStarts := computeLineStarts(src)
	isTest := looksLikeTestFile(relPath)

	var cands []Candidate
	for _, m := range matchers {
		if !matcherAppliesToFile(m, relPath, isTest, includeTests) {
			continue
		}
		switch m.Impl {
		case ImplRegex, "":
			cands = append(cands, runRegexMatcher(m, relPath, src, lineStarts)...)
		case ImplAST, ImplHeuristic:
			if m.Check != nil {
				cands = append(cands, m.Check(absPath, relPath, src)...)
			}
		}
	}
	return cands, nil
}

func runRegexMatcher(m Matcher, relPath string, src []byte, lineStarts []int) []Candidate {
	var out []Candidate
	for _, p := range m.Patterns {
		if p.Regex == nil {
			continue
		}
		matches := p.Regex.FindAllIndex(src, -1)
		for _, idx := range matches {
			start, end := idx[0], idx[1]
			line := byteOffsetToLine(start, lineStarts)
			if p.NegateRegex != nil && negationMatchesNear(p, src, start, end, lineStarts, line) {
				continue
			}
			snippet := snippetFromOffsets(src, start, end)
			out = append(out, Candidate{
				Slug:        m.Slug,
				File:        relPath,
				LineNumber:  line,
				Snippet:     snippet,
				Description: p.Label,
			})
		}
	}
	return out
}

func negationMatchesNear(p Pattern, src []byte, matchStart, matchEnd int, lineStarts []int, matchLine int) bool {
	scope := p.NegateScope
	if scope.Kind == "" {
		scope = DefaultNegateScope
	}
	switch scope.Kind {
	case "line":
		lineFrom := lineStartOffset(matchLine, lineStarts)
		lineTo := lineEndOffset(matchLine, lineStarts, len(src))
		return p.NegateRegex.Match(src[lineFrom:lineTo])
	case "window":
		w := scope.Window
		if w <= 0 {
			w = DefaultNegateScope.Window
		}
		fromLine := matchLine - w
		if fromLine < 1 {
			fromLine = 1
		}
		toLine := matchLine + w
		fromOff := lineStartOffset(fromLine, lineStarts)
		toOff := lineEndOffset(toLine, lineStarts, len(src))
		return p.NegateRegex.Match(src[fromOff:toOff])
	case "block":
		// AST-only; regex matchers should not declare block scope.
		return false
	}
	return false
}

func computeLineStarts(src []byte) []int {
	starts := []int{0}
	for i, b := range src {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func byteOffsetToLine(offset int, starts []int) int {
	// Binary search would be faster but linear is fine for MB-scale files.
	for i := len(starts) - 1; i >= 0; i-- {
		if starts[i] <= offset {
			return i + 1
		}
	}
	return 1
}

func lineStartOffset(line int, starts []int) int {
	if line < 1 {
		return 0
	}
	if line-1 >= len(starts) {
		return starts[len(starts)-1]
	}
	return starts[line-1]
}

func lineEndOffset(line int, starts []int, total int) int {
	if line < 1 {
		return 0
	}
	if line >= len(starts) {
		return total
	}
	return starts[line] - 1
}

func snippetFromOffsets(src []byte, start, end int) string {
	const maxLen = 200
	if start < 0 {
		start = 0
	}
	if end > len(src) {
		end = len(src)
	}
	// Expand to the surrounding line for readability.
	lineStart := bytes.LastIndexByte(src[:start], '\n') + 1
	lineEnd := start + bytes.IndexByte(src[start:], '\n')
	if lineEnd < start {
		lineEnd = len(src)
	}
	s := strings.TrimSpace(string(src[lineStart:lineEnd]))
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return s
}

func matcherAppliesToFile(m Matcher, relPath string, isTest, includeTests bool) bool {
	// Test-file gating: per-matcher AppliesToTests, with a global
	// IncludeTests override. The override lets the user opt-in
	// repo-wide via .revelara.yaml scanner.include_tests=true while
	// still allowing per-matcher control to be the default.
	if isTest && !m.AppliesToTests && !includeTests {
		return false
	}
	// Excluded patterns first.
	for _, ex := range m.ExcludePatterns {
		if ok, _ := filepath.Match(ex, relPath); ok {
			return false
		}
		if ok, _ := filepath.Match(ex, filepath.Base(relPath)); ok {
			return false
		}
	}
	// File-pattern intersection. If FilePatterns is empty, language list
	// alone drives selection; the engine assumes the registry sets at
	// least one of them.
	if len(m.FilePatterns) > 0 {
		var matched bool
		for _, fp := range m.FilePatterns {
			if globMatch(fp, relPath) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func globMatch(pattern, path string) bool {
	// filepath.Match doesn't support **/, expand by hand: a leading "**/"
	// matches at any depth.
	if strings.HasPrefix(pattern, "**/") {
		bare := strings.TrimPrefix(pattern, "**/")
		// Match against the bare suffix at any depth.
		if ok, _ := filepath.Match(bare, filepath.Base(path)); ok {
			return true
		}
		// Match against any ancestor segment.
		parts := strings.Split(path, "/")
		for i := 0; i < len(parts); i++ {
			if ok, _ := filepath.Match(bare, strings.Join(parts[i:], "/")); ok {
				return true
			}
		}
		return false
	}
	if ok, _ := filepath.Match(pattern, path); ok {
		return true
	}
	if ok, _ := filepath.Match(pattern, filepath.Base(path)); ok {
		return true
	}
	return false
}

func looksLikeTestFile(relPath string) bool {
	base := filepath.Base(relPath)
	switch {
	case strings.HasSuffix(base, "_test.go"):
		return true
	case strings.HasSuffix(base, ".test.js"), strings.HasSuffix(base, ".test.ts"):
		return true
	case strings.HasSuffix(base, ".spec.js"), strings.HasSuffix(base, ".spec.ts"):
		return true
	case strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"):
		return true
	case strings.HasSuffix(base, "Test.java"), strings.HasSuffix(base, "Tests.java"):
		return true
	}
	if strings.Contains("/"+relPath+"/", "/tests/") || strings.Contains("/"+relPath+"/", "/__tests__/") {
		return true
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// MatcherFiresOnSource is a unit-test helper that runs a matcher's regex
// patterns (with their negation scopes applied) against an in-memory
// source buffer and reports whether any candidate fires. Used by matcher
// unit tests in the matchers/ package to avoid setting up filesystem
// fixtures for every assertion.
//
// The helper handles regex impl only; AST and heuristic matchers must be
// tested with their own dispatch.
func MatcherFiresOnSource(m Matcher, relPath string, src []byte) bool {
	if m.Impl != ImplRegex && m.Impl != "" {
		return false
	}
	starts := computeLineStarts(src)
	cands := runRegexMatcher(m, relPath, src, starts)
	return len(cands) > 0
}
