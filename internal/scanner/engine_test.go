package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// stubMatcher returns a single-pattern regex matcher for "BAD" with
// optional negation regex. Useful for testing engine behavior without
// importing the matchers package (which would create a cycle).
func stubMatcher(slug, neg string) Matcher {
	m := Matcher{
		Slug:         slug,
		Description:  "stub for tests",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-000"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "high",
		Severity:     "high",
		Impl:         ImplRegex,
		Source:       "curated",
		Patterns: []Pattern{
			{
				Regex: regexp.MustCompile(`BAD`),
				Label: "BAD pattern",
			},
		},
	}
	if neg != "" {
		m.Patterns[0].NegateRegex = regexp.MustCompile(neg)
		m.Patterns[0].NegateScope = NegateScope{Kind: "window", Window: 5}
	}
	return m
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanFiresOnMatch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n// has BAD here\n")

	cands, _, err := Scan([]Matcher{stubMatcher("bad", "")}, ScanOptions{Root: root, Service: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(cands), cands)
	}
	if cands[0].File != "main.go" {
		t.Errorf("file=%q, want main.go (forward-slash, relative)", cands[0].File)
	}
	if cands[0].LineNumber != 2 {
		t.Errorf("line=%d, want 2", cands[0].LineNumber)
	}
}

func TestScanSkipsDefaultExcludeDirs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "vendor/x.go", "BAD")
	writeFile(t, root, "node_modules/y.go", "BAD")
	writeFile(t, root, ".git/z.go", "BAD")
	writeFile(t, root, "main.go", "BAD")

	cands, _, err := Scan([]Matcher{stubMatcher("bad", "")}, ScanOptions{Root: root, Service: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Errorf("expected 1 candidate (only main.go), got %d: %+v", len(cands), cands)
	}
}

func TestScanRespectsExcludeMatchers(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "BAD")

	cands, _, err := Scan([]Matcher{stubMatcher("bad", "")}, ScanOptions{
		Root:            root,
		Service:         "test",
		ExcludeMatchers: map[string]bool{"bad": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 0 {
		t.Errorf("expected 0 candidates (matcher excluded), got %d", len(cands))
	}
}

func TestScanRespectsOnlyMatchers(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "BAD")

	cands, _, err := Scan([]Matcher{stubMatcher("bad", ""), stubMatcher("other", "")}, ScanOptions{
		Root:         root,
		Service:      "test",
		OnlyMatchers: []string{"other"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || cands[0].Slug != "other" {
		t.Errorf("expected 1 'other' candidate, got %+v", cands)
	}
}

func TestScanWindowNegationSuppressesNearbyMatch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "GOOD\nBAD\n")

	// negate=GOOD within 5 lines of BAD; should suppress.
	cands, _, err := Scan([]Matcher{stubMatcher("bad", "GOOD")}, ScanOptions{Root: root, Service: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 0 {
		t.Errorf("expected 0 candidates (negation in window), got %d: %+v", len(cands), cands)
	}
}

func TestScanWindowNegationDoesNotSuppressFarMatch(t *testing.T) {
	root := t.TempDir()
	// 20 lines apart — outside the default window:5 used by stubMatcher.
	body := "BAD\n"
	for i := 0; i < 20; i++ {
		body += "filler\n"
	}
	body += "GOOD\n"
	writeFile(t, root, "main.go", body)

	cands, _, err := Scan([]Matcher{stubMatcher("bad", "GOOD")}, ScanOptions{Root: root, Service: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Errorf("expected 1 candidate (negation outside window), got %d", len(cands))
	}
}

func TestScanRejectsFileScopeAtValidation(t *testing.T) {
	m := stubMatcher("bad", "GOOD")
	m.Patterns[0].NegateScope = NegateScope{Kind: "file"}

	root := t.TempDir()
	writeFile(t, root, "main.go", "BAD")

	_, _, err := Scan([]Matcher{m}, ScanOptions{Root: root, Service: "test"})
	if err == nil {
		t.Fatal("Scan accepted file-scope negation; PRD forbids it")
	}
}

func TestScanSkipsTestFilesByDefault(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "BAD")
	writeFile(t, root, "main_test.go", "BAD")

	cands, _, err := Scan([]Matcher{stubMatcher("bad", "")}, ScanOptions{Root: root, Service: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Errorf("expected 1 candidate (test file skipped), got %d: %+v", len(cands), cands)
	}
}

func TestScanIncludesTestFilesWhenMatcherOptsIn(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main_test.go", "BAD")

	m := stubMatcher("bad", "")
	m.AppliesToTests = true
	cands, _, err := Scan([]Matcher{m}, ScanOptions{Root: root, Service: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Errorf("expected 1 candidate (matcher opted in to tests), got %d", len(cands))
	}
}

func TestConvertProducesFingerprint(t *testing.T) {
	c := Candidate{Slug: "bad", File: "main.go", LineNumber: 7, Description: "match"}
	findings := Convert([]Candidate{c}, []Matcher{stubMatcher("bad", "")}, "svc")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Fingerprint == "" {
		t.Error("finding has empty fingerprint")
	}
	if findings[0].ControlCodes[0] != "RC-000" {
		t.Errorf("control codes not propagated: %v", findings[0].ControlCodes)
	}
}

func TestConvertDedupesByLocation(t *testing.T) {
	cands := []Candidate{
		{Slug: "bad", File: "main.go", LineNumber: 7},
		{Slug: "bad", File: "main.go", LineNumber: 7}, // dup
		{Slug: "bad", File: "main.go", LineNumber: 8},
	}
	findings := Convert(cands, []Matcher{stubMatcher("bad", "")}, "svc")
	if len(findings) != 2 {
		t.Errorf("expected 2 deduped findings, got %d", len(findings))
	}
}

func TestConvertSortsStably(t *testing.T) {
	cands := []Candidate{
		{Slug: "bad", File: "z.go", LineNumber: 1},
		{Slug: "bad", File: "a.go", LineNumber: 5},
		{Slug: "bad", File: "a.go", LineNumber: 1},
	}
	findings := Convert(cands, []Matcher{stubMatcher("bad", "")}, "svc")
	if findings[0].Evidence[0].Path != "a.go" || findings[0].Evidence[0].LineNumber != 1 {
		t.Errorf("sort order wrong; got %+v", findings)
	}
}

func TestConvertRollupByProjectCollapsesAllCandidates(t *testing.T) {
	m := stubMatcher("global", "")
	m.RollupKey = RollupByProject
	cands := []Candidate{
		{Slug: "global", File: "a.go", LineNumber: 1, Description: "a"},
		{Slug: "global", File: "b.go", LineNumber: 9, Description: "b"},
		{Slug: "global", File: "c/d.go", LineNumber: 42, Description: "c"},
	}
	findings := Convert(cands, []Matcher{m}, "svc")
	if len(findings) != 1 {
		t.Fatalf("expected 1 rolled-up finding, got %d", len(findings))
	}
	if len(findings[0].Evidence) != 3 {
		t.Errorf("expected 3 evidence entries on rolled-up finding, got %d", len(findings[0].Evidence))
	}
}

func TestConvertRollupByFileCollapsesPerFile(t *testing.T) {
	m := stubMatcher("inFile", "")
	m.RollupKey = RollupByFile
	cands := []Candidate{
		{Slug: "inFile", File: "a.go", LineNumber: 1},
		{Slug: "inFile", File: "a.go", LineNumber: 5},
		{Slug: "inFile", File: "a.go", LineNumber: 9},
		{Slug: "inFile", File: "b.go", LineNumber: 2},
	}
	findings := Convert(cands, []Matcher{m}, "svc")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (per file), got %d", len(findings))
	}
	byPath := map[string]int{}
	for _, f := range findings {
		byPath[f.Evidence[0].Path] = len(f.Evidence)
	}
	if byPath["a.go"] != 3 {
		t.Errorf("expected 3 evidence entries for a.go, got %d", byPath["a.go"])
	}
	if byPath["b.go"] != 1 {
		t.Errorf("expected 1 evidence entry for b.go, got %d", byPath["b.go"])
	}
}

func TestConvertRollupByFunctionFallsBackWhenFunctionEmpty(t *testing.T) {
	// If a matcher declares RollupByFunction but the Candidate has no
	// EnclosingFunction set, the helper returns "" and convert falls
	// back to per-location grouping. Two candidates in the same file at
	// different lines must produce two Findings, not one.
	m := stubMatcher("fn", "")
	m.RollupKey = RollupByFunction
	cands := []Candidate{
		{Slug: "fn", File: "a.go", LineNumber: 1}, // no EnclosingFunction
		{Slug: "fn", File: "a.go", LineNumber: 5}, // no EnclosingFunction
	}
	findings := Convert(cands, []Matcher{m}, "svc")
	if len(findings) != 2 {
		t.Errorf("expected per-location fallback when EnclosingFunction empty, got %d findings", len(findings))
	}
}

func TestConvertRollupByFunctionGroupsByEnclosingFunction(t *testing.T) {
	m := stubMatcher("fn", "")
	m.RollupKey = RollupByFunction
	cands := []Candidate{
		{Slug: "fn", File: "a.go", LineNumber: 1, EnclosingFunction: "Run"},
		{Slug: "fn", File: "a.go", LineNumber: 5, EnclosingFunction: "Run"},
		{Slug: "fn", File: "a.go", LineNumber: 9, EnclosingFunction: "Other"},
	}
	findings := Convert(cands, []Matcher{m}, "svc")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (Run, Other), got %d", len(findings))
	}
}

func TestConvertRollupFingerprintStableAcrossFileOrder(t *testing.T) {
	// A rolled-up Finding's fingerprint should depend on the rollup key,
	// not on which Candidate happens to be at the head of the group.
	// Otherwise adding a new k8s overlay would shift the Finding's id.
	m := stubMatcher("k8s", "")
	m.RollupKey = RollupByK8sWorkload
	a := Candidate{Slug: "k8s", File: "dev.yml", LineNumber: 2, K8sKind: "Deployment", K8sName: "backend"}
	b := Candidate{Slug: "k8s", File: "prod.yml", LineNumber: 2, K8sKind: "Deployment", K8sName: "backend"}

	findingsAB := Convert([]Candidate{a, b}, []Matcher{m}, "svc")
	findingsBA := Convert([]Candidate{b, a}, []Matcher{m}, "svc")
	if len(findingsAB) != 1 || len(findingsBA) != 1 {
		t.Fatalf("expected 1 finding each, got %d and %d", len(findingsAB), len(findingsBA))
	}
	if findingsAB[0].Fingerprint != findingsBA[0].Fingerprint {
		t.Errorf("rolled-up fingerprint must be order-independent; got %q vs %q",
			findingsAB[0].Fingerprint, findingsBA[0].Fingerprint)
	}
}

func TestConvertWithoutRollupKeyPreservesLegacyBehavior(t *testing.T) {
	// Matchers that don't set RollupKey must keep emitting one Finding
	// per location (the pre-W2 behavior). This guards against accidental
	// changes that would silently roll up unrelated matchers.
	m := stubMatcher("legacy", "")
	cands := []Candidate{
		{Slug: "legacy", File: "a.go", LineNumber: 1},
		{Slug: "legacy", File: "a.go", LineNumber: 5},
		{Slug: "legacy", File: "b.go", LineNumber: 2},
	}
	findings := Convert(cands, []Matcher{m}, "svc")
	if len(findings) != 3 {
		t.Errorf("expected 3 per-location findings with no RollupKey, got %d", len(findings))
	}
}

// po-t8acf: OnlyFiles nil-vs-empty contract. Nil walks everything;
// a non-nil empty slice (change-scoped scan with zero changed files)
// must scan nothing rather than fall back to a full walk.
func TestWalkFilesOnlyFilesNilVsEmpty(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", "package p\n")

	got, _, err := walkFiles(root, ScanOptions{OnlyFiles: nil})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("nil OnlyFiles must walk everything; walked 0 files")
	}

	got, _, err = walkFiles(root, ScanOptions{OnlyFiles: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("non-nil empty OnlyFiles must scan nothing; walked %d files", len(got))
	}
}
