package commands

import (
	"encoding/json"
	"strings"
	"testing"
)

func fullParityView() RiskContextView {
	mttr := 42
	detail := &RiskDetail{
		Risk: Risk{
			RiskCode: "R-9", Title: "Pool exhaustion", Status: "applicable",
			Category: "resilience", Score: 85, Services: []string{"payments-api"},
			UCAType: "not_provided", LossScenario: "Outage under load",
			CausalFactors: []string{"no circuit breaker"}, StaleSince: "2026-06-01T00:00:00Z",
		},
		Narrative:              "Connection pool exhausts under load.",
		Likelihood:             "high",
		Impact:                 "high",
		Trend:                  "increasing",
		PlainSummary:           "Pool exhausts under load causing outage",
		ReadOnly:               true,
		SourceIntelligenceTier: "public",
		RiskClass:              "revenue_critical",
		ConstraintType:         "not_provided",
		EvidenceStatus:         "not_configured",
		GraphMultiplier:        1.5,
		CreatedAt:              "2026-05-01T00:00:00Z",
		UpdatedAt:              "2026-06-10T00:00:00Z",
		GeneratedMatcher:       &GeneratedMatcherRef{Slug: "pool-exhaustion", SourcePatternIDs: []string{"p1", "p2"}},
		ScoreBreakdown: &ScoreBreakdown{
			LikelihoodFactor: 8, LikelihoodSource: "incident", LikelihoodNotes: "seen twice",
			ImpactFactor: 9, ImpactSource: "tier", BaseScore: 72, BusinessMultiplier: 1.2, AdjustedScore: 85,
		},
		CorroboratingIncidents: []CorroboratingIncidentItem{{
			ShortName: "inc-qq3", Title: "Payment timeout cascade", Severity: "high",
			MTTRMinutes: &mttr, Relevance: 0.82, SourceURL: "https://example.com/pm",
		}},
		RelatedFindings: []RelatedFindingItem{{RiskCode: "R-10", Title: "Auth pool exhaustion", Score: 70, SharedControls: 2}},
		STPAProvenance: &STPAProvenanceData{UCAs: []UCARef{{
			Type: "not_provided", Content: "breaker not applied",
			ControlEdges: []ProvenanceEdge{{ControlCode: "RC-1", ControlName: "Circuit breaker", Strength: 0.9}},
		}}},
		LatestDismissal: &LatestDismissal{Reason: "duplicate", Explanation: "same as R-3"},
		Substantiation:  json.RawMessage(`[{"path":"db.go","line":42,"severity":"high","description":"no timeout","snippet":"db.Query(...)"}]`),
	}
	ctx := &RiskContextResponse{
		GroundingProvenance: "Grounded in 3 org incidents and public postmortems.",
		Controls: []ControlContextItem{{
			Control:          MappedControl{ControlCode: "RC-1", Name: "Circuit breaker", Category: "resilience", Type: "preventive"},
			ExistingEvidence: []ContextEvidenceItem{{Type: "code", Name: "cb.go", Status: "configured", URL: "https://example.com/cb"}},
			EvidenceGaps:     []string{"needs test"},
		}},
	}
	coverage := &CoverageStats{ByCategory: []CategoryCoverage{{Category: "resilience", Total: 10, Assessed: 4}}}
	return RiskContextView{Detail: detail, Context: ctx, Coverage: coverage}
}

func TestRenderRiskContext_AllParitySections(t *testing.T) {
	out := renderRiskContext(fullParityView())
	wants := []string{
		"increasing", "pool-exhaustion", "Severity:", "read-only", "revenue_critical", // header extras
		"Score Math", "Base score: 72", "Graph amplification", // score math
		"Grounded in 3 org incidents", "Narrative:", "Connection pool exhausts", // grounding + narrative
		"Causal Analysis (STPA-inspired)", "Leveson", // STPA-inspired heading
		"Corroborating Incidents", "inc-qq3", "https://example.com/pm", // corroborating
		"Related Findings", "R-10", // related
		"https://example.com/cb", "Evidence status", // control evidence URL + status
		"Substantiation Evidence", "db.go:42", // substantiation
		"Defense-Layer Coverage", "single point of failure", // defense layers
		"STPA Provenance", "Circuit breaker", // provenance
		"Previously dismissed", "duplicate", "Stale since", "Created:", // history
		"Assessment Coverage", "6 not yet configured", // coverage gap (10-4)
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n----\n%s", want, out)
		}
	}
}

func TestRenderRiskContext_OmitsEmptySections(t *testing.T) {
	v := RiskContextView{Detail: &RiskDetail{Risk: Risk{RiskCode: "R-1", Title: "X", Status: "applicable", Category: "resilience", Score: 10}}}
	out := renderRiskContext(v)
	for _, absent := range []string{"Score Math", "Corroborating Incidents", "Substantiation", "STPA Provenance", "Defense-Layer Coverage", "Related Findings", "Assessment Coverage"} {
		if strings.Contains(out, absent) {
			t.Errorf("empty risk should not render %q\n%s", absent, out)
		}
	}
}


func TestRenderRiskContext_ExistingSections(t *testing.T) {
	v := RiskContextView{
		Detail: &RiskDetail{Risk: Risk{RiskCode: "R-1", Title: "Pool exhaustion", Status: "applicable", Category: "resilience", Score: 72}},
		Context: &RiskContextResponse{
			Controls: []ControlContextItem{{Control: MappedControl{ControlCode: "RC-1", Name: "Circuit breaker", Category: "resilience", Type: "preventive"}}},
		},
	}
	out := renderRiskContext(v)
	for _, want := range []string{"R-1", "Pool exhaustion", "Control Coverage", "RC-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestComposeRiskContextJSON_PreservesTopLevelForFix(t *testing.T) {
	contextBody := []byte(`{"score_factors":[{"points":5}],"controls":[{"control":{"control_code":"RC-1"}}],"graph_multiplier":1.5,"risk":{"risk_code":"R-1"}}`)
	detailBody := []byte(`{"risk_code":"R-1","corroborating_incidents":[{"short_name":"inc-qq3"}]}`)
	out, err := composeRiskContextJSON(contextBody, detailBody, nil)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	s := string(out)
	for _, want := range []string{`"score_factors"`, `"controls"`, `"graph_multiplier"`, `"detail"`, `"inc-qq3"`} {
		if !strings.Contains(s, want) {
			t.Errorf("json missing %q\n%s", want, s)
		}
	}
}
