package commands

import (
	"testing"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/project"
	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

func TestActiveWaivers_FiltersExpired(t *testing.T) {
	now := time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC)
	in := []project.WaiverEntry{
		{Matcher: "missing-timeout", Reason: "open"},
		{Matcher: "swallowed-error", Reason: "expired", Expires: "2026-01-01"},
		{Matcher: "raw-sql-no-params", Reason: "future", Expires: "2026-12-31"},
	}
	got := activeWaivers(in, now)
	if len(got) != 2 {
		t.Errorf("expected 2 active waivers (open + future), got %d", len(got))
	}
	for _, w := range got {
		if w.Reason == "expired" {
			t.Errorf("expired waiver leaked through filter")
		}
	}
}

func TestFilterFindingsByWaivers_MatchesBySlug(t *testing.T) {
	findings := []scanner.ScanFinding{
		{
			Slug:     "hardcoded-connection-string",
			Title:    "Hardcoded DB/Redis/AMQP connection string with credentials",
			Evidence: []scanner.ScanEvidence{{Path: "test/fixtures/seed.go", LineNumber: 12}},
		},
		{
			Slug:     "missing-timeout",
			Title:    "HTTP clients without explicit timeout",
			Evidence: []scanner.ScanEvidence{{Path: "internal/client/redis.go", LineNumber: 42}},
		},
	}
	waivers := []AppliedWaiver{
		{Matcher: "hardcoded-connection-string", Paths: []string{"test/fixtures/**"}, Reason: "test fixtures"},
	}
	out, matched := filterFindingsByWaivers(findings, waivers, false, nil)
	if len(out) != 1 {
		t.Fatalf("expected 1 remaining finding (waived match dropped); got %d", len(out))
	}
	if out[0].Slug != "missing-timeout" {
		t.Errorf("wrong finding remained: got slug=%s", out[0].Slug)
	}
	if len(matched) != 1 || matched[0].Matcher != "hardcoded-connection-string" {
		t.Errorf("expected matched waivers to record the audit-trail entry; got %+v", matched)
	}
}

func TestFilterFindingsByWaivers_NoMatchWhenSlugDiffers(t *testing.T) {
	findings := []scanner.ScanFinding{
		{Slug: "missing-timeout", Title: "HTTP clients without explicit timeout"},
	}
	waivers := []AppliedWaiver{
		{Matcher: "hardcoded-connection-string", Reason: "wrong matcher"},
	}
	out, matched := filterFindingsByWaivers(findings, waivers, false, nil)
	if len(out) != 1 {
		t.Errorf("waiver for different slug must NOT suppress; got %d remaining", len(out))
	}
	if len(matched) != 0 {
		t.Errorf("no waivers should have matched; got %d", len(matched))
	}
}

func TestFilterFindingsByWaivers_StrictModeProtectsFloorMatchers(t *testing.T) {
	findings := []scanner.ScanFinding{
		{Slug: "raw-sql-no-params", Title: "SQL via concat", Evidence: []scanner.ScanEvidence{{Path: "test/sql_test.go"}}},
		{Slug: "missing-timeout", Title: "HTTP no timeout", Evidence: []scanner.ScanEvidence{{Path: "test/client_test.go"}}},
	}
	// User attempts to waive both via wide path glob.
	waivers := []AppliedWaiver{
		{Matcher: "raw-sql-no-params", Paths: []string{"test/**"}, Reason: "tests"},
		{Matcher: "missing-timeout", Paths: []string{"test/**"}, Reason: "tests"},
	}
	floorSet := map[string]bool{"raw-sql-no-params": true}

	// Strict mode ON: floor matcher's waiver MUST be ignored.
	out, _ := filterFindingsByWaivers(findings, waivers, true, floorSet)
	var sawSQL, sawTimeout bool
	for _, f := range out {
		if f.Slug == "raw-sql-no-params" {
			sawSQL = true
		}
		if f.Slug == "missing-timeout" {
			sawTimeout = true
		}
	}
	if !sawSQL {
		t.Errorf("strict mode must keep floor-matcher findings even when a yaml waiver tries to suppress them")
	}
	if sawTimeout {
		t.Errorf("strict mode must still let non-floor waivers apply; missing-timeout should have been waived")
	}

	// Strict mode OFF: both findings should be waived as user requested.
	out, _ = filterFindingsByWaivers(findings, waivers, false, floorSet)
	if len(out) != 0 {
		t.Errorf("non-strict mode: both findings should be waived; got %d remaining", len(out))
	}
}

func TestFilterFindingsByWaivers_NoSlugSkipsFilter(t *testing.T) {
	// AI-agent submissions don't set Slug; the filter must pass them through
	// rather than dropping every finding.
	findings := []scanner.ScanFinding{
		{Title: "AI-discovered risk", Evidence: []scanner.ScanEvidence{{Path: "x.go"}}},
	}
	waivers := []AppliedWaiver{
		{Matcher: "anything", Reason: "something"},
	}
	out, _ := filterFindingsByWaivers(findings, waivers, false, nil)
	if len(out) != 1 {
		t.Errorf("findings without slug must NOT be filtered; got %d remaining", len(out))
	}
}
