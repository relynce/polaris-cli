package commands

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/agentscan"
	"github.com/revelara-ai/rvl-cli/internal/config"
	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

func TestMapAgentFindings(t *testing.T) {
	findings := []agentscan.Finding{{
		Rule:           "missing-timeout",
		Severity:       "high",
		File:           "internal/api/x.go",
		Line:           42,
		Title:          "no timeout on http.Get",
		Description:    "the call can hang",
		Recommendation: "add a context deadline",
		Lens:           "go",
	}}
	out := mapAgentFindings(findings)
	if len(out) != 1 {
		t.Fatalf("want 1 mapped finding, got %d", len(out))
	}
	// Round-trip through JSON to assert the wire shape.
	b, err := json.Marshal(out[0])
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["slug"] != "missing-timeout" {
		t.Errorf("slug = %v, want missing-timeout", got["slug"])
	}
	// po-fc2qs: severity maps to BOTH axes; the server's Path 5 scorer
	// reads likelihood, so it must be set (high severity -> high/high).
	if got["likelihood"] != "high" {
		t.Errorf("likelihood = %v, want high (Path 5 scores off likelihood)", got["likelihood"])
	}
	if got["impact"] != "high" {
		t.Errorf("impact = %v, want high", got["impact"])
	}
	// Confidence must be EMPTY (omitempty -> absent), never the literal
	// "agent" which hits the 0.85 default modulator; empty lets the server
	// fall through to confidence = likelihood.
	if _, present := got["confidence"]; present {
		t.Errorf("confidence must be omitted (empty), got %v", got["confidence"])
	}
	if got["category"] != "go" {
		t.Errorf("category = %v, want the lens id go", got["category"])
	}
	if got["status"] != "new" {
		t.Errorf("status = %v, want new", got["status"])
	}
	ev, ok := got["evidence"].([]interface{})
	if !ok || len(ev) != 1 {
		t.Fatalf("evidence = %v, want one entry", got["evidence"])
	}
	e0 := ev[0].(map[string]interface{})
	if e0["path"] != "internal/api/x.go" || e0["line_number"].(float64) != 42 {
		t.Errorf("evidence path/line wrong: %v", e0)
	}
	corr, _ := got["corroborated_by_agents"].([]interface{})
	if len(corr) != 1 || corr[0] != "go" {
		t.Errorf("corroborated_by_agents = %v, want [go]", got["corroborated_by_agents"])
	}
}

// TestSubmitAgentScanEndToEnd asserts the request the transport actually
// sends: path, auth header, and mapped body. It drives submitScan
// directly (the same transport submitAgentScan uses) against a test
// server.
func TestSubmitAgentScanEndToEnd(t *testing.T) {
	var gotPath, gotAuth string
	var gotReq ScanRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"scan_id":"scan-123","service":"svc","summary":{"total":1}}`))
	}))
	defer srv.Close()

	cfg := &config.Config{APIURL: srv.URL, APIKey: "test-key"}
	req := &ScanRequest{
		Service:  "svc",
		ScanType: ScanTypeIncremental,
		ScanMode: "enforce",
		Findings: mapAgentFindings([]agentscan.Finding{{
			Rule: "missing-timeout", Severity: "high", File: "a.go", Line: 1,
			Title: "t", Description: "d", Lens: "go",
		}}),
	}
	resp, err := submitScan(cfg, req, 5*time.Second)
	if err != nil {
		t.Fatalf("submitScan: %v", err)
	}
	if gotPath != "/api/v1/risks/scan" {
		t.Errorf("path = %s, want /api/v1/risks/scan", gotPath)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("auth = %q, want Bearer test-key", gotAuth)
	}
	if gotReq.ScanType != ScanTypeIncremental || gotReq.ScanMode != "enforce" {
		t.Errorf("scan_type/mode wrong: %s/%s", gotReq.ScanType, gotReq.ScanMode)
	}
	if len(gotReq.Findings) != 1 {
		t.Fatalf("server received %d findings, want 1", len(gotReq.Findings))
	}
	if resp.ScanID != "scan-123" {
		t.Errorf("scan id = %s, want scan-123", resp.ScanID)
	}
}

func TestSubmitScanServerErrorReturnsErr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	cfg := &config.Config{APIURL: srv.URL, APIKey: "k"}
	req := &ScanRequest{Service: "svc", Findings: mapAgentFindings(nil)}
	if _, err := submitScan(cfg, req, 5*time.Second); err == nil {
		t.Fatal("server 500 must return an error (submitAgentScan then warns, exit unchanged)")
	}
}

// TestSubmitAgentScanGuards proves the guard paths never touch the
// network or exit: empty service and empty findings just warn/return.
func TestSubmitAgentScanGuards(t *testing.T) {
	// Empty service (no flag, temp dir has no .revelara.yaml): returns
	// without calling api config / network.
	dir := t.TempDir()
	submitAgentScan(agentscan.PipelineResult{Findings: []agentscan.Finding{{Rule: "r"}}}, "", dir, "enforce", "")
	// No findings: returns even with a service.
	submitAgentScan(agentscan.PipelineResult{}, "svc", dir, "enforce", "")
}

// TestMapAgentFindingsSeverityAxes locks the severity->axes mapping that
// makes Path 5 score the lens severity (po-fc2qs).
func TestMapAgentFindingsSeverityAxes(t *testing.T) {
	cases := []struct{ sev, wantLikelihood, wantImpact string }{
		{"critical", "high", "critical"},
		{"high", "high", "high"},
		{"medium", "medium", "medium"},
		{"low", "low", "low"},
		{"", "medium", "medium"}, // unknown -> medium/medium
	}
	for _, c := range cases {
		out := mapAgentFindings([]agentscan.Finding{{Rule: "r", Severity: c.sev, File: "a.go", Lens: "go"}})
		sf := out[0].(scanner.ScanFinding)
		if sf.Likelihood != c.wantLikelihood || sf.Impact != c.wantImpact {
			t.Errorf("severity %q -> (%s,%s), want (%s,%s)", c.sev, sf.Likelihood, sf.Impact, c.wantLikelihood, c.wantImpact)
		}
		if sf.Confidence != "" {
			t.Errorf("severity %q: confidence must be empty, got %q", c.sev, sf.Confidence)
		}
	}
}
