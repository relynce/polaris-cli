package commands

import (
	"strings"
	"testing"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

func TestRenderPRComment_StartsWithMarker(t *testing.T) {
	got := RenderPRComment(PRCommentInput{Service: "checkout-api"})
	if !strings.HasPrefix(got, StickyCommentMarker) {
		t.Errorf("output must start with sticky marker so CI scripts can update existing comment, got prefix: %q", got[:64])
	}
}

func TestRenderPRComment_DeltaSign(t *testing.T) {
	cases := []struct {
		name  string
		delta int
		want  string
	}{
		{"positive delta is signed", 12, "Risk Delta: +12"},
		{"zero delta has no sign", 0, "Risk Delta: 0"},
		{"negative delta keeps minus", -5, "Risk Delta: -5"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := RenderPRComment(PRCommentInput{NetDelta: tt.delta})
			if !strings.Contains(got, tt.want) {
				t.Errorf("expected %q in output, got: %s", tt.want, got)
			}
		})
	}
}

func TestRenderPRComment_BannerWhenNoYaml(t *testing.T) {
	withYaml := RenderPRComment(PRCommentInput{HasRevelaraYAML: true})
	withoutYaml := RenderPRComment(PRCommentInput{HasRevelaraYAML: false})

	if strings.Contains(withYaml, "No `.revelara.yaml`") {
		t.Errorf("banner should NOT appear when yaml exists")
	}
	if !strings.Contains(withoutYaml, "No `.revelara.yaml`") {
		t.Errorf("banner SHOULD appear when yaml is missing")
	}
	if !strings.Contains(withoutYaml, "rvl init") {
		t.Errorf("missing-yaml banner must nudge user to rvl init")
	}
}

func TestRenderPRComment_OverBudget(t *testing.T) {
	in := PRCommentInput{
		MeasuredState: 268,
		EffectiveTolerance: &EffectiveTolerance{
			ToleranceTarget:      250,
			ToleranceHeadroomPct: 10,
		},
	}
	got := RenderPRComment(in)
	if !strings.Contains(got, "OVER BUDGET") {
		t.Errorf("over-budget state must surface OVER BUDGET; got %s", got)
	}
	if !strings.Contains(got, "waiver required") {
		t.Errorf("over-budget state must say waiver required")
	}
}

func TestRenderPRComment_WithinBudget(t *testing.T) {
	in := PRCommentInput{
		MeasuredState: 224,
		EffectiveTolerance: &EffectiveTolerance{
			ToleranceTarget:      250,
			ToleranceHeadroomPct: 10,
		},
	}
	got := RenderPRComment(in)
	if !strings.Contains(got, "224/250") {
		t.Errorf("within-budget state must show measured/tolerance; got %s", got)
	}
	if !strings.Contains(got, "within tolerance") {
		t.Errorf("within-budget state must say within tolerance")
	}
	if strings.Contains(got, "OVER BUDGET") {
		t.Errorf("within-budget must NOT show over-budget message")
	}
}

func TestRenderPRComment_StrictModeSurfacesNotice(t *testing.T) {
	in := PRCommentInput{
		EffectiveTolerance: &EffectiveTolerance{
			ToleranceTarget:   250,
			StrictEnforcement: true,
		},
	}
	got := RenderPRComment(in)
	if !strings.Contains(got, "Strict enforcement mode is on") {
		t.Errorf("strict mode must be visible to reviewers")
	}
	if !strings.Contains(got, "emergency override") {
		t.Errorf("strict mode must mention emergency override path")
	}
}

func TestRenderPRComment_PerServiceBreakdownOnlyWhenMultiple(t *testing.T) {
	single := RenderPRComment(PRCommentInput{
		PerServiceBreakdown: []ServiceBudget{
			{Service: "auth-service", NetDelta: 5, Status: "in_budget"},
		},
	})
	if strings.Contains(single, "Per-service breakdown") {
		t.Errorf("single-service PR should NOT show per-service breakdown table")
	}

	multi := RenderPRComment(PRCommentInput{
		PerServiceBreakdown: []ServiceBudget{
			{Service: "auth-service", NetDelta: 5, MeasuredState: 100, Tolerance: 250, Status: "in_budget"},
			{Service: "billing-service", NetDelta: 12, MeasuredState: 270, Tolerance: 250, Status: "over_budget"},
		},
	})
	if !strings.Contains(multi, "Per-service breakdown") {
		t.Errorf("multi-service PR MUST show per-service breakdown table")
	}
	if !strings.Contains(multi, "auth-service") || !strings.Contains(multi, "billing-service") {
		t.Errorf("multi-service breakdown must include both services")
	}
	if !strings.Contains(multi, "Over Budget") {
		t.Errorf("over-budget service must surface its status")
	}
}

func TestRenderPRComment_NewAndResolvedFindingsTables(t *testing.T) {
	in := PRCommentInput{
		NewFindings: []scanner.ScanFinding{
			{
				Title:    "missing-timeout",
				Impact:   "high",
				Evidence: []scanner.ScanEvidence{{Path: "internal/client/redis.go", LineNumber: 42}},
			},
		},
		ResolvedCount: 1,
	}
	got := RenderPRComment(in)
	if !strings.Contains(got, "New findings (1)") {
		t.Errorf("new-findings header must reflect count")
	}
	if !strings.Contains(got, "missing-timeout") {
		t.Errorf("matcher title must appear in new-findings table")
	}
	if !strings.Contains(got, "internal/client/redis.go:42") {
		t.Errorf("evidence file:line must appear")
	}
	if !strings.Contains(got, "Resolved this scan: 1") {
		t.Errorf("resolved-count line must reflect ResolvedCount; got %s", got)
	}
	if false {
		_ = "R-042" // legacy assertion removed: resolved-finding detail awaits server-side scan_id diff
	}
}

func TestRenderPRComment_LeadingProvenanceFromMostSevere(t *testing.T) {
	in := PRCommentInput{
		NewFindings: []scanner.ScanFinding{
			{
				Title:  "no-error-wrapping",
				Impact: "low",
				Provenance: &scanner.ScanProvenance{
					IncidentFrequency: "rare",
				},
			},
			{
				Title:  "missing-timeout",
				Impact: "critical",
				Provenance: &scanner.ScanProvenance{
					IncidentFrequency:  "Present in 47% of cascading failure postmortems",
					TypicalBlastRadius: "service-to-multi-service",
					TypicalMTTR:        "30-90 minutes",
				},
			},
		},
	}
	got := RenderPRComment(in)
	if !strings.Contains(got, "Present in 47% of cascading failure postmortems") {
		t.Errorf("provenance from the most-severe finding must surface; got %s", got)
	}
	if strings.Contains(got, "rare") {
		t.Errorf("low-severity finding's provenance should NOT be the leading one")
	}
}

func TestRenderPRComment_PolarisLinkIncluded(t *testing.T) {
	in := PRCommentInput{PolarisRiskListURL: "https://polaris.example.com/risks?service=auth"}
	got := RenderPRComment(in)
	if !strings.Contains(got, "View full report in Polaris") {
		t.Errorf("Polaris link must appear when URL is provided")
	}
	if !strings.Contains(got, "https://polaris.example.com/risks?service=auth") {
		t.Errorf("Polaris URL must appear verbatim")
	}
}

func TestRenderPRComment_DeterministicForSameInputs(t *testing.T) {
	in := PRCommentInput{
		Service: "auth-service",
		NetDelta: 5,
		EffectiveTolerance: &EffectiveTolerance{
			ToleranceTarget: 250,
		},
		HasRevelaraYAML: true,
	}
	a := RenderPRComment(in)
	b := RenderPRComment(in)
	if a != b {
		t.Errorf("RenderPRComment must be deterministic; got %d vs %d byte outputs", len(a), len(b))
	}
}
