//go:build acceptance

// Package scanner_test (acceptance) drives the rvl binary against a fixture
// repo and asserts the Phase 1 PRD's integration acceptance criteria.
//
// Run with:
//
//	make scanner-acceptance
//
// or
//
//	go test -tags=acceptance -v ./internal/scanner/...
//
// The test builds the rvl binary, runs `rvl scan --local --target <fixture>`
// against testdata/phase1_acceptance, and asserts the expected findings.
package scanner_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureDir = "testdata/phase1_acceptance"

// finding mirrors the subset of ScanFinding fields the acceptance test inspects.
// Avoids importing internal/api types here so the fixture stays independent.
type finding struct {
	Title          string         `json:"title"`
	Category       string         `json:"category"`
	Likelihood     string         `json:"likelihood"`
	Impact         string         `json:"impact"`
	Narrative      string         `json:"narrative,omitempty"`
	Component      string         `json:"component,omitempty"`
	LinkedServices []string       `json:"linked_services,omitempty"`
	ControlCodes   []string       `json:"control_codes,omitempty"`
	Evidence       []evidenceItem `json:"evidence,omitempty"`
	Fingerprint    string         `json:"fingerprint,omitempty"`
}

type evidenceItem struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	LineNumber  int    `json:"line_number,omitempty"`
	Description string `json:"description,omitempty"`
}

type scanRequest struct {
	Service  string    `json:"service"`
	Findings []finding `json:"findings"`
}

func buildRvl(t *testing.T) string {
	t.Helper()
	repoRoot, err := repoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "rvl")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/rvl")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func repoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func absFixture(t *testing.T) string {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	src := filepath.Join(root, "internal", "scanner", fixtureDir)

	// Copy the fixture into a temp dir and initialize it as a git repo so
	// LoadProjectConfigFrom finds the fixture's own .revelara.yaml rather
	// than walking up to the parent rvl-cli repo's config.
	dst := filepath.Join(t.TempDir(), "fixture")
	cpCmd := exec.Command("cp", "-r", src, dst)
	if out, err := cpCmd.CombinedOutput(); err != nil {
		t.Fatalf("copy fixture: %v\n%s", err, out)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.email=test@example.com", "-c", "user.name=Test", "add", "."},
		{"-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-q", "-m", "fixture"},
	} {
		c := exec.Command("git", args...)
		c.Dir = dst
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dst
}

func runScan(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	full := append([]string{"scan"}, args...)
	cmd := exec.Command(bin, full...)
	cmd.Stderr = os.Stderr
	out, _ := cmd.Output()
	return out
}

func decodeFindings(t *testing.T, raw []byte) scanRequest {
	t.Helper()
	if len(raw) == 0 {
		t.Fatalf("scanner produced no JSON output")
	}
	var req scanRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("parse JSON: %v\nraw=%s", err, raw)
	}
	return req
}

func findingsBy(req scanRequest, title string) []finding {
	var out []finding
	for _, f := range req.Findings {
		if strings.Contains(strings.ToLower(f.Title), strings.ToLower(title)) {
			out = append(out, f)
		}
	}
	return out
}

// TestPhase1Acceptance is the PRD integration acceptance test.
// It will fail until the scanner is implemented (po-fayz.2 onward).
func TestPhase1Acceptance(t *testing.T) {
	bin := buildRvl(t)
	fixture := absFixture(t)

	out := runScan(t, bin, "--local", "--target", fixture, "--format", "json")
	req := decodeFindings(t, out)

	t.Run("missing-timeout finding present", func(t *testing.T) {
		fs := findingsBy(req, "timeout")
		if len(fs) == 0 {
			t.Fatalf("expected at least one missing-timeout finding, got 0\noutput=%s", out)
		}
		f := fs[0]
		if f.Category != "fault_tolerance" {
			t.Errorf("category=%q, want fault_tolerance", f.Category)
		}
		if !contains(f.ControlCodes, "RC-018") {
			t.Errorf("control_codes=%v, want to include RC-018", f.ControlCodes)
		}
		if len(f.Evidence) == 0 || f.Evidence[0].Path == "" || f.Evidence[0].LineNumber == 0 {
			t.Errorf("evidence missing path/line: %+v", f.Evidence)
		}
		if f.Fingerprint == "" {
			t.Errorf("fingerprint is empty")
		}
		if !strings.HasPrefix(f.Fingerprint, "loc-") {
			t.Errorf("fingerprint=%q, want loc- prefix (Tier 2 location fingerprint)", f.Fingerprint)
		}
		if f.Narrative == "" {
			t.Errorf("narrative empty (provenance must be encoded)")
		}
	})

	t.Run("swallowed-error finding present", func(t *testing.T) {
		if len(findingsBy(req, "swallow")) == 0 && len(findingsBy(req, "error")) == 0 {
			t.Errorf("expected at least one swallowed-error finding\noutput=%s", out)
		}
	})

	t.Run("panic-in-goroutine finding present", func(t *testing.T) {
		if len(findingsBy(req, "panic")) == 0 && len(findingsBy(req, "goroutine")) == 0 {
			t.Errorf("expected at least one panic-in-goroutine finding\noutput=%s", out)
		}
	})

	t.Run("non-Go matchers absent", func(t *testing.T) {
		// Fixture is Go-only; JS/Python-specific matchers should not fire.
		if len(findingsBy(req, "promise")) > 0 {
			t.Errorf("unhandled-promise fired on a Go-only repo")
		}
		if len(findingsBy(req, "console.log")) > 0 {
			t.Errorf("JS console.log matcher fired on a Go-only repo")
		}
	})

	t.Run("findings linked to component", func(t *testing.T) {
		// At least one finding under cmd/server/ should map to the 'server' component.
		// Component mapping uses path prefix from .revelara.yaml.
		var sawServer bool
		for _, f := range req.Findings {
			for _, ev := range f.Evidence {
				if strings.Contains(ev.Path, "cmd/server") && f.Component == "server" {
					sawServer = true
				}
			}
		}
		if !sawServer {
			t.Errorf("no finding mapped to component=server; findings=%+v", req.Findings)
		}
	})
}

// TestPhase1AcceptanceDeterministic asserts that two consecutive scans
// produce identical fingerprints (PRD Integration Acceptance Test step 10).
func TestPhase1AcceptanceDeterministic(t *testing.T) {
	bin := buildRvl(t)
	fixture := absFixture(t)

	out1 := runScan(t, bin, "--local", "--target", fixture, "--format", "json")
	out2 := runScan(t, bin, "--local", "--target", fixture, "--format", "json")

	req1 := decodeFindings(t, out1)
	req2 := decodeFindings(t, out2)

	fps := func(r scanRequest) []string {
		out := make([]string, 0, len(r.Findings))
		for _, f := range r.Findings {
			out = append(out, f.Fingerprint)
		}
		return out
	}

	a, b := fps(req1), fps(req2)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic finding count: run1=%d run2=%d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("non-deterministic fingerprint at index %d: %q vs %q", i, a[i], b[i])
		}
	}
}

// TestPhase1AcceptanceExitCode asserts that the scanner exits with code 1
// when at least one critical/high finding is present (CI gate behavior).
func TestPhase1AcceptanceExitCode(t *testing.T) {
	bin := buildRvl(t)
	fixture := absFixture(t)

	cmd := exec.Command(bin, "scan", "--local", "--target", fixture)
	cmd.Stderr = os.Stderr
	_, err := cmd.Output()
	exit := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exit = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error running scanner: %v", err)
		}
	}
	if exit != 1 {
		t.Errorf("exit code=%d, want 1 (critical/high findings present)", exit)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
