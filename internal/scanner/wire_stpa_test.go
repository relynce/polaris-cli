package scanner

import (
	"encoding/json"
	"testing"
)

// po-gli2z: the --scan-dir dedup path round-trips findings through the
// typed ScanFinding struct (commands/scan.go). Before this fix the struct
// had no STPA fields, so any dedup pass silently stripped uca_type,
// causal_factors, loss_scenario, loss_category, estimated_fix_complexity,
// and constraint_type (plus priority and the graph evidence fields) from
// EVERY finding in the request. This test pins that the wire type
// preserves them through a JSON round-trip and through DeduplicateFindings.
func TestScanFindingPreservesSTPAFieldsThroughDedup(t *testing.T) {
	raw := `[
		{
			"title": "Missing timeout",
			"category": "resilience",
			"likelihood": "high",
			"impact": "high",
			"priority": "high",
			"risk_score": 61,
			"slug": "missing-timeout",
			"evidence": [{"type": "code", "path": "a.go", "line_number": 10}],
			"uca_type": "not_provided",
			"causal_factors": ["no deadline propagation", "no client timeout"],
			"loss_scenario": "request hangs, worker pool exhausts",
			"loss_category": "error_budget_managed",
			"estimated_fix_complexity": "medium",
			"constraint_type": "primary",
			"impact_chains": [{"chain": ["a", "b"]}],
			"mitigations": ["add context deadline"],
			"foresight_depth": 2,
			"graph_adjacent_knowledge": ["k1"]
		},
		{
			"title": "Missing timeout",
			"category": "resilience",
			"likelihood": "high",
			"impact": "high",
			"risk_score": 40,
			"slug": "missing-timeout",
			"evidence": [{"type": "code", "path": "a.go", "line_number": 10}]
		}
	]`
	var findings []ScanFinding
	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	deduped := DeduplicateFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected dedup to 1 finding, got %d", len(deduped))
	}
	f := deduped[0]

	if f.UCAType != "not_provided" {
		t.Errorf("UCAType = %q, want not_provided", f.UCAType)
	}
	if len(f.CausalFactors) != 2 {
		t.Errorf("CausalFactors = %v, want 2 entries", f.CausalFactors)
	}
	if f.LossScenario == "" || f.LossCategory != "error_budget_managed" {
		t.Errorf("loss fields lost: scenario=%q category=%q", f.LossScenario, f.LossCategory)
	}
	if f.EstimatedFixComplexity != "medium" || f.ConstraintType != "primary" {
		t.Errorf("complexity=%q constraint=%q, want medium/primary", f.EstimatedFixComplexity, f.ConstraintType)
	}
	if f.Priority != "high" {
		t.Errorf("Priority = %q, want high", f.Priority)
	}

	// Round-trip back to JSON (what scan.go does before submit) must keep
	// the STPA and graph fields on the wire.
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	for _, key := range []string{
		"uca_type", "causal_factors", "loss_scenario", "loss_category",
		"estimated_fix_complexity", "constraint_type", "priority",
		"impact_chains", "mitigations", "foresight_depth", "graph_adjacent_knowledge",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("field %q missing from marshaled finding", key)
		}
	}
}
