package scanner

import (
	"regexp"
	"strings"
	"testing"
)

func TestRedactSecretsMasksConnectionStringPassword(t *testing.T) {
	in := `dsn := "postgres://appuser:sup3rS3cret@db.internal:5432/prod"`
	got := redactSecrets(in)
	if strings.Contains(got, "sup3rS3cret") {
		t.Fatalf("password not redacted: %q", got)
	}
	if !strings.Contains(got, "***REDACTED***") {
		t.Fatalf("expected redaction marker, got: %q", got)
	}
	// Scheme and username are preserved for triage.
	if !strings.Contains(got, "postgres://appuser:") {
		t.Fatalf("scheme/username should be preserved, got: %q", got)
	}
}

func TestRedactSecretsMasksApiKeyToken(t *testing.T) {
	in := `const key = "sk-live-abcdef0123456789ABCDEF"`
	got := redactSecrets(in)
	if strings.Contains(got, "abcdef0123456789ABCDEF") {
		t.Fatalf("api key not redacted: %q", got)
	}
	if !strings.Contains(got, "***REDACTED***") {
		t.Fatalf("expected redaction marker, got: %q", got)
	}
}

func TestRedactSecretsLeavesOrdinaryTextAlone(t *testing.T) {
	in := `count := selectFromTable // no secrets here`
	if got := redactSecrets(in); got != in {
		t.Fatalf("ordinary text was altered: %q -> %q", in, got)
	}
}

// TestScanRedactsConnectionStringInSubmittedNarrative proves the redaction
// happens in the engine, so the credential never reaches the finding
// Narrative that `scan --submit` posts to the API. A stub matcher stands in
// for the real hardcoded-connection-string matcher to avoid an import cycle
// with the matchers package.
func TestScanRedactsConnectionStringInSubmittedNarrative(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go",
		"package main\n\nvar dsn = \"postgres://appuser:sup3rS3cret@db.internal:5432/prod\"\n")

	m := Matcher{
		Slug:         "hardcoded-connection-string",
		Description:  "Hardcoded DB connection string with credentials",
		Category:     "service_fragility",
		ControlCodes: []string{"RC-039"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "high",
		Severity:     "high",
		Impl:         ImplRegex,
		Source:       "curated",
		Patterns: []Pattern{{
			Regex: regexp.MustCompile(`"postgres://[^@\s"]*@[^"]+"`),
			Label: "connection string literal",
		}},
	}

	cands, _, err := Scan([]Matcher{m}, ScanOptions{Root: root, Service: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(cands), cands)
	}
	if strings.Contains(cands[0].Snippet, "sup3rS3cret") {
		t.Fatalf("candidate snippet leaks password: %q", cands[0].Snippet)
	}
	// The Narrative is what scan --submit posts to the API.
	narrative := narrativeFor(m, cands[0])
	if strings.Contains(narrative, "sup3rS3cret") {
		t.Fatalf("submitted narrative leaks password: %q", narrative)
	}
	if !strings.Contains(narrative, "***REDACTED***") {
		t.Fatalf("expected redaction marker in narrative, got: %q", narrative)
	}
}
