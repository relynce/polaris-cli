package commands

import (
	"strings"
	"testing"
)

// po-gli2z: the STPA fields on scan findings used to be guarded only by a
// transform step in the polaris scan skill PROMPT (scan.md Step 4B), which
// agents may skip. When skipped, type-mismatched fields either killed the
// submit at the server boundary or were silently dropped, so the STPA view
// had no data behind a "green" scan. These tests pin the CLI-side
// normalization that replaces that prompt transform.

func finding(overrides map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{
		"component":  "api",
		"title":      "Missing timeout on outbound call",
		"category":   "resilience",
		"likelihood": "high",
		"impact":     "high",
		"narrative":  "n",
		"risk_score": float64(61),
		"priority":   "high",
	}
	for k, v := range overrides {
		m[k] = v
	}
	return m
}

func TestNormalizeFindingsEvidenceStringCoerced(t *testing.T) {
	f := finding(map[string]interface{}{"evidence": "internal/api/handler.go:145 has no timeout"})
	rep := normalizeFindings([]interface{}{f})

	ev, ok := f["evidence"].([]interface{})
	if !ok || len(ev) != 1 {
		t.Fatalf("expected evidence coerced to 1-element array, got %#v", f["evidence"])
	}
	em, ok := ev[0].(map[string]interface{})
	if !ok || em["type"] != "code" || em["description"] != "internal/api/handler.go:145 has no timeout" {
		t.Fatalf("expected {type:code,description:...}, got %#v", ev[0])
	}
	if rep.CoercedFindings != 1 {
		t.Errorf("CoercedFindings = %d, want 1", rep.CoercedFindings)
	}
	if rep.DroppedFields != 0 {
		t.Errorf("DroppedFields = %d, want 0", rep.DroppedFields)
	}
}

func TestNormalizeFindingsEvidenceStringItemsCoerced(t *testing.T) {
	f := finding(map[string]interface{}{"evidence": []interface{}{
		"bare string item",
		map[string]interface{}{"type": "code", "path": "a.go", "description": "ok"},
	}})
	rep := normalizeFindings([]interface{}{f})

	ev := f["evidence"].([]interface{})
	if len(ev) != 2 {
		t.Fatalf("expected 2 evidence items, got %d", len(ev))
	}
	em, ok := ev[0].(map[string]interface{})
	if !ok || em["description"] != "bare string item" || em["type"] != "code" {
		t.Fatalf("expected string item coerced to object, got %#v", ev[0])
	}
	if rep.CoercedFindings != 1 {
		t.Errorf("CoercedFindings = %d, want 1", rep.CoercedFindings)
	}
}

func TestNormalizeFindingsEvidenceLineNumberStringCoerced(t *testing.T) {
	f := finding(map[string]interface{}{"evidence": []interface{}{
		map[string]interface{}{"type": "code", "path": "a.go", "line_number": "145"},
	}})
	rep := normalizeFindings([]interface{}{f})

	em := f["evidence"].([]interface{})[0].(map[string]interface{})
	if em["line_number"] != 145 {
		t.Fatalf("expected line_number coerced to int 145, got %#v", em["line_number"])
	}
	if rep.CoercedFindings != 1 {
		t.Errorf("CoercedFindings = %d, want 1", rep.CoercedFindings)
	}
}

func TestNormalizeFindingsCausalFactorsStringCoerced(t *testing.T) {
	f := finding(map[string]interface{}{
		"uca_type":       "not_provided",
		"causal_factors": "single factor as bare string",
	})
	rep := normalizeFindings([]interface{}{f})

	cf, ok := f["causal_factors"].([]interface{})
	if !ok || len(cf) != 1 || cf[0] != "single factor as bare string" {
		t.Fatalf("expected causal_factors coerced to 1-element array, got %#v", f["causal_factors"])
	}
	if rep.WithSTPA != 1 {
		t.Errorf("WithSTPA = %d, want 1", rep.WithSTPA)
	}
	if rep.CoercedFindings != 1 {
		t.Errorf("CoercedFindings = %d, want 1", rep.CoercedFindings)
	}
	if rep.STPALost() {
		t.Error("STPALost() = true, want false: coercion is not loss")
	}
}

func TestNormalizeFindingsEnumCasingCoerced(t *testing.T) {
	f := finding(map[string]interface{}{
		"uca_type":                 "Not Provided",
		"loss_category":            "ZERO_TOLERANCE",
		"estimated_fix_complexity": " Medium ",
		"constraint_type":          "Primary",
	})
	rep := normalizeFindings([]interface{}{f})

	for field, want := range map[string]string{
		"uca_type":                 "not_provided",
		"loss_category":            "zero_tolerance",
		"estimated_fix_complexity": "medium",
		"constraint_type":          "primary",
	} {
		if got := f[field]; got != want {
			t.Errorf("%s = %#v, want %q", field, got, want)
		}
	}
	if rep.CoercedFindings != 1 {
		t.Errorf("CoercedFindings = %d, want 1", rep.CoercedFindings)
	}
	if rep.STPALost() {
		t.Error("STPALost() = true, want false")
	}
}

func TestNormalizeFindingsInvalidEnumDroppedWithIssue(t *testing.T) {
	f := finding(map[string]interface{}{
		"uca_type":      "banana",
		"loss_category": "zero_tolerance",
	})
	rep := normalizeFindings([]interface{}{f})

	if _, present := f["uca_type"]; present {
		t.Errorf("expected invalid uca_type removed, still present: %#v", f["uca_type"])
	}
	if got := f["loss_category"]; got != "zero_tolerance" {
		t.Errorf("valid loss_category must survive, got %#v", got)
	}
	if rep.DroppedFields != 1 {
		t.Fatalf("DroppedFields = %d, want 1", rep.DroppedFields)
	}
	if !rep.STPALost() {
		t.Error("STPALost() = false, want true: an STPA field was dropped")
	}
	// The issue must name the finding and the field so the user can see
	// exactly what was lost (the whole point of po-gli2z).
	issue := rep.Issues[0]
	if issue.Field != "uca_type" || issue.Action != "dropped" {
		t.Errorf("issue = %+v, want field uca_type action dropped", issue)
	}
	if !strings.Contains(issue.Title, "Missing timeout") {
		t.Errorf("issue.Title = %q, want the finding title", issue.Title)
	}
	if !strings.Contains(issue.Detail, "banana") || !strings.Contains(issue.Detail, "not_provided") {
		t.Errorf("issue.Detail = %q, want offending value and allowed values", issue.Detail)
	}
}

func TestNormalizeFindingsAllEnumFieldsValidated(t *testing.T) {
	f := finding(map[string]interface{}{
		"uca_type":                 "wrong_timing",
		"loss_category":            "sometimes_bad", // invalid
		"estimated_fix_complexity": "extreme",       // invalid
		"constraint_type":          "tertiary",      // invalid
	})
	rep := normalizeFindings([]interface{}{f})

	if rep.DroppedFields != 3 {
		t.Fatalf("DroppedFields = %d, want 3 (issues: %+v)", rep.DroppedFields, rep.Issues)
	}
	if got := f["uca_type"]; got != "wrong_timing" {
		t.Errorf("valid uca_type must survive, got %#v", got)
	}
	for _, field := range []string{"loss_category", "estimated_fix_complexity", "constraint_type"} {
		if _, present := f[field]; present {
			t.Errorf("expected invalid %s removed", field)
		}
	}
}

func TestNormalizeFindingsLossScenarioArrayJoined(t *testing.T) {
	f := finding(map[string]interface{}{
		"loss_scenario": []interface{}{"step one", "step two"},
	})
	rep := normalizeFindings([]interface{}{f})

	ls, ok := f["loss_scenario"].(string)
	if !ok || !strings.Contains(ls, "step one") || !strings.Contains(ls, "step two") {
		t.Fatalf("expected loss_scenario joined to string, got %#v", f["loss_scenario"])
	}
	if rep.CoercedFindings != 1 {
		t.Errorf("CoercedFindings = %d, want 1", rep.CoercedFindings)
	}
}

func TestNormalizeFindingsRiskScoreStringCoerced(t *testing.T) {
	f := finding(map[string]interface{}{"risk_score": "82"})
	rep := normalizeFindings([]interface{}{f})

	if f["risk_score"] != 82 {
		t.Fatalf("expected risk_score coerced to int 82, got %#v", f["risk_score"])
	}
	if rep.CoercedFindings != 1 {
		t.Errorf("CoercedFindings = %d, want 1", rep.CoercedFindings)
	}
}

func TestNormalizeFindingsUncoercibleCausalFactorsDropped(t *testing.T) {
	f := finding(map[string]interface{}{
		"causal_factors": map[string]interface{}{"not": "an array"},
	})
	rep := normalizeFindings([]interface{}{f})

	if _, present := f["causal_factors"]; present {
		t.Errorf("expected uncoercible causal_factors removed, got %#v", f["causal_factors"])
	}
	if rep.DroppedFields != 1 {
		t.Errorf("DroppedFields = %d, want 1", rep.DroppedFields)
	}
	if !rep.STPALost() {
		t.Error("STPALost() = false, want true")
	}
}

func TestNormalizeFindingsCounts(t *testing.T) {
	clean := finding(nil) // no STPA, nothing to coerce
	stpaClean := finding(map[string]interface{}{
		"uca_type":       "not_provided",
		"causal_factors": []interface{}{"a", "b"},
		"loss_scenario":  "scenario",
	})
	stpaCoerced := finding(map[string]interface{}{
		"uca_type":       "Wrong Timing",
		"causal_factors": "bare string",
	})
	stpaDropped := finding(map[string]interface{}{
		"uca_type": "invalid_enum_value",
	})

	rep := normalizeFindings([]interface{}{clean, stpaClean, stpaCoerced, stpaDropped})

	if rep.Total != 4 {
		t.Errorf("Total = %d, want 4", rep.Total)
	}
	if rep.WithSTPA != 3 {
		t.Errorf("WithSTPA = %d, want 3", rep.WithSTPA)
	}
	if rep.CoercedFindings != 1 {
		t.Errorf("CoercedFindings = %d, want 1", rep.CoercedFindings)
	}
	if rep.DroppedFindings != 1 {
		t.Errorf("DroppedFindings = %d, want 1", rep.DroppedFindings)
	}
	if rep.DroppedFields != 1 {
		t.Errorf("DroppedFields = %d, want 1", rep.DroppedFields)
	}
}

func TestNormalizeFindingsValidFindingUntouched(t *testing.T) {
	f := finding(map[string]interface{}{
		"uca_type":                 "providing_incorrectly",
		"causal_factors":           []interface{}{"factor"},
		"loss_scenario":            "a scenario",
		"loss_category":            "error_budget_managed",
		"estimated_fix_complexity": "low",
		"constraint_type":          "secondary",
		"evidence": []interface{}{
			map[string]interface{}{"type": "code", "path": "a.go", "line_number": float64(10)},
		},
	})
	rep := normalizeFindings([]interface{}{f})

	if len(rep.Issues) != 0 {
		t.Errorf("expected no issues for a fully valid finding, got %+v", rep.Issues)
	}
	if rep.CoercedFindings != 0 || rep.DroppedFields != 0 {
		t.Errorf("coerced=%d dropped=%d, want 0/0", rep.CoercedFindings, rep.DroppedFields)
	}
	if rep.WithSTPA != 1 {
		t.Errorf("WithSTPA = %d, want 1", rep.WithSTPA)
	}
}

func TestNormalizeFindingsNonMapEntriesSkipped(t *testing.T) {
	rep := normalizeFindings([]interface{}{"not a map", float64(3), nil, finding(nil)})
	if rep.Total != 4 {
		t.Errorf("Total = %d, want 4", rep.Total)
	}
	if rep.STPALost() {
		t.Error("STPALost() = true, want false")
	}
}

func TestNormalizeFindingsEmptyEnumRemovedSilently(t *testing.T) {
	// An empty string carries no data: removing it is not loss and must
	// not trip the loss banner.
	f := finding(map[string]interface{}{"uca_type": ""})
	rep := normalizeFindings([]interface{}{f})
	if _, present := f["uca_type"]; present {
		t.Errorf("expected empty uca_type removed")
	}
	if rep.STPALost() {
		t.Error("STPALost() = true, want false for empty value")
	}
	if rep.DroppedFields != 0 {
		t.Errorf("DroppedFields = %d, want 0", rep.DroppedFields)
	}
}
