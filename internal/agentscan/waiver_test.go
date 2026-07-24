package agentscan

import (
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse("2006-01-02", s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return tm
}

func TestApplyWaiversRuleAndGlobMatch(t *testing.T) {
	now := mustTime(t, "2026-07-24")
	findings := []Finding{
		{Rule: "missing-timeout", File: "internal/api/handler.go", Line: 10, Severity: "high"},
		{Rule: "silent-error-swallow", File: "internal/api/handler.go", Line: 20, Severity: "medium"},
		{Rule: "missing-timeout", File: "cmd/main.go", Line: 5, Severity: "high"},
	}
	// Directory scoping uses path.Match semantics (parity with the local
	// scanner): `internal/api/*` matches files directly under that dir but
	// `*` does not cross `/`. Only the rule+path both matching is waived.
	waivers := []Waiver{
		{Rule: "missing-timeout", Paths: []string{"internal/api/*"}, Reason: "known"},
	}
	kept, waived := ApplyWaivers(findings, waivers, now)
	if len(waived) != 1 {
		t.Fatalf("expected 1 waived, got %d", len(waived))
	}
	if waived[0].Finding.File != "internal/api/handler.go" {
		t.Errorf("wrong finding waived: %s", waived[0].Finding.File)
	}
	// silent-error-swallow (wrong rule) and cmd/main.go (wrong path) stay.
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(kept))
	}
}

func TestApplyWaiversWrongRuleKept(t *testing.T) {
	now := mustTime(t, "2026-07-24")
	findings := []Finding{{Rule: "missing-timeout", File: "a.go", Line: 1, Severity: "high"}}
	waivers := []Waiver{{Rule: "resource-leak", Paths: []string{"**/*.go"}}}
	kept, waived := ApplyWaivers(findings, waivers, now)
	if len(waived) != 0 || len(kept) != 1 {
		t.Fatalf("wrong-rule waiver must not match; kept=%d waived=%d", len(kept), len(waived))
	}
}

func TestApplyWaiversEmptyPathsMatchesAnyFile(t *testing.T) {
	now := mustTime(t, "2026-07-24")
	findings := []Finding{
		{Rule: "race-hazard", File: "deep/nested/path/x.go", Line: 1, Severity: "high"},
	}
	waivers := []Waiver{{Rule: "race-hazard"}} // no Paths
	kept, waived := ApplyWaivers(findings, waivers, now)
	if len(waived) != 1 || len(kept) != 0 {
		t.Fatalf("empty-paths waiver must match any file; kept=%d waived=%d", len(kept), len(waived))
	}
}

func TestApplyWaiversExpiry(t *testing.T) {
	findings := []Finding{{Rule: "missing-timeout", File: "a.go", Line: 1, Severity: "high"}}

	// Expired: inert.
	past := []Waiver{{Rule: "missing-timeout", Expires: "2026-01-01"}}
	kept, waived := ApplyWaivers(findings, past, mustTime(t, "2026-07-24"))
	if len(waived) != 0 || len(kept) != 1 {
		t.Fatalf("expired waiver must be inert; kept=%d waived=%d", len(kept), len(waived))
	}

	// Future expiry: active.
	future := []Waiver{{Rule: "missing-timeout", Expires: "2027-01-01"}}
	kept, waived = ApplyWaivers(findings, future, mustTime(t, "2026-07-24"))
	if len(waived) != 1 || len(kept) != 0 {
		t.Fatalf("future-expiry waiver must be active; kept=%d waived=%d", len(kept), len(waived))
	}

	// Same day as expiry: still active (not After).
	sameDay := []Waiver{{Rule: "missing-timeout", Expires: "2026-07-24"}}
	_, waived = ApplyWaivers(findings, sameDay, mustTime(t, "2026-07-24"))
	if len(waived) != 1 {
		t.Fatalf("expiry-day waiver must still be active")
	}

	// Open-ended: always active.
	open := []Waiver{{Rule: "missing-timeout"}}
	_, waived = ApplyWaivers(findings, open, mustTime(t, "2030-01-01"))
	if len(waived) != 1 {
		t.Fatalf("open-ended waiver must always be active")
	}
}

// TestApplyWaiversCrossLensSharedSlug locks the deliberate design that a
// single waiver for a shared slug (missing-timeout) covers findings from
// different lenses, since ApplyWaivers keys on Rule, not Lens.
func TestApplyWaiversCrossLensSharedSlug(t *testing.T) {
	now := mustTime(t, "2026-07-24")
	findings := []Finding{
		{Rule: "missing-timeout", File: "svc.go", Line: 1, Severity: "high", Lens: "go"},
		{Rule: "missing-timeout", File: "svc.go", Line: 2, Severity: "high", Lens: "observability"},
	}
	waivers := []Waiver{{Rule: "missing-timeout", Paths: []string{"*.go"}}}
	kept, waived := ApplyWaivers(findings, waivers, now)
	if len(waived) != 2 || len(kept) != 0 {
		t.Fatalf("one waiver must cover the shared slug across lenses; kept=%d waived=%d", len(kept), len(waived))
	}
}

// TestApplyWaiversGlobParity locks parity with the local scanner glob
// semantics: `**/` prefix matches the basename at any depth, and a plain
// path.Match pattern matches at its own depth.
func TestApplyWaiversGlobParity(t *testing.T) {
	now := mustTime(t, "2026-07-24")
	nested := Finding{Rule: "r", File: "a/b/c/file.go", Line: 1, Severity: "high"}
	shallow := Finding{Rule: "r", File: "file.go", Line: 1, Severity: "high"}

	// **/*.go matches nested basename.
	_, waived := ApplyWaivers([]Finding{nested}, []Waiver{{Rule: "r", Paths: []string{"**/*.go"}}}, now)
	if len(waived) != 1 {
		t.Errorf("**/*.go must waive nested a/b/c/file.go")
	}
	// *.go (no **/) does NOT match a nested path via path.Match.
	kept, _ := ApplyWaivers([]Finding{nested}, []Waiver{{Rule: "r", Paths: []string{"*.go"}}}, now)
	if len(kept) != 1 {
		t.Errorf("*.go must NOT match nested a/b/c/file.go (path.Match parity)")
	}
	// *.go matches a shallow file.
	_, waived = ApplyWaivers([]Finding{shallow}, []Waiver{{Rule: "r", Paths: []string{"*.go"}}}, now)
	if len(waived) != 1 {
		t.Errorf("*.go must match shallow file.go")
	}
}

func TestApplyWaiversEmptyInputs(t *testing.T) {
	now := mustTime(t, "2026-07-24")
	kept, waived := ApplyWaivers(nil, []Waiver{{Rule: "x"}}, now)
	if len(kept) != 0 || len(waived) != 0 {
		t.Errorf("nil findings must yield empty results")
	}
	fs := []Finding{{Rule: "x", File: "a.go", Severity: "high"}}
	kept, waived = ApplyWaivers(fs, nil, now)
	if len(kept) != 1 || len(waived) != 0 {
		t.Errorf("no waivers must keep everything")
	}
}
