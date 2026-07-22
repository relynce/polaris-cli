package commands

import (
	"strings"
	"testing"
)

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
