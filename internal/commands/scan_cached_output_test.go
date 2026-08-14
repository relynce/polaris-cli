package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// po-72d5d: polaris replays a previously-processed ScanResponse when the
// submission's idempotency_key matches a recent scan. The replay used to
// be indistinguishable from a fresh scan, so the CLI happily reprinted
// "[NEW] R-0XX ..." for risks created on some earlier run. These tests
// pin the cache-hit rendering and the old-server fallback.

func TestScanResponseCachedFallsBackToFreshOnOldServers(t *testing.T) {
	// A server that predates the `cached` field sends no such key. The
	// CLI must behave exactly as before: fresh rendering, [NEW] markers.
	var resp ScanResponse
	if err := json.Unmarshal([]byte(`{"scan_id":"s1","service":"svc","findings":[],"timestamp":"now"}`), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Cached {
		t.Fatal("absent cached field must decode as false")
	}
	if got := scanSubmitHeadline(resp.Cached); got != "Scan submitted successfully" {
		t.Fatalf("old-server headline = %q, want the unchanged fresh headline", got)
	}
}

func TestScanResponseCachedDecodesTrue(t *testing.T) {
	var resp ScanResponse
	if err := json.Unmarshal([]byte(`{"scan_id":"s1","service":"svc","findings":[],"timestamp":"now","cached":true}`), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Cached {
		t.Fatal("cached:true must decode as true")
	}
	headline := scanSubmitHeadline(resp.Cached)
	if !strings.Contains(headline, "cached") {
		t.Fatalf("cached headline = %q, want it to say cached", headline)
	}
	if !strings.Contains(headline, "no new processing") {
		t.Fatalf("cached headline = %q, want it to say no new processing", headline)
	}
}

// --ci and --agent --format json pipe the response through verbatim. The
// new field must ride along when set and stay absent when not, so
// existing parsers see no change on a fresh scan.
func TestScanResponseCachedJSONPassthrough(t *testing.T) {
	fresh, err := json.Marshal(ScanResponse{ScanID: "s1", Service: "svc"})
	if err != nil {
		t.Fatalf("marshal fresh: %v", err)
	}
	if bytes.Contains(fresh, []byte(`"cached"`)) {
		t.Fatalf("fresh response must omit cached, got %s", fresh)
	}
	replay, err := json.Marshal(ScanResponse{ScanID: "s1", Service: "svc", Cached: true})
	if err != nil {
		t.Fatalf("marshal replay: %v", err)
	}
	if !bytes.Contains(replay, []byte(`"cached":true`)) {
		t.Fatalf("replayed response must carry cached:true, got %s", replay)
	}
}

func cachedTestResponse(cached bool) *ScanResponse {
	return &ScanResponse{
		ScanID:  "s1",
		Service: "checkout-api",
		Cached:  cached,
		Findings: []ScanResult{
			{RiskCode: "R-001", Title: "Missing timeout", Status: "created", Score: 70, Priority: "high"},
			{RiskCode: "R-002", Title: "No circuit breaker", Status: "updated", Score: 55, Priority: "medium"},
			{RiskCode: "R-003", Title: "Stale runbook", Status: "unchanged", Score: 20, Priority: "low"},
		},
	}
}

func TestPrintScanFindingsFreshKeepsNewMarkers(t *testing.T) {
	var out, errOut bytes.Buffer
	printScanFindings(&out, &errOut, cachedTestResponse(false))

	got := out.String()
	if !strings.Contains(got, "Findings:\n") {
		t.Fatalf("fresh heading changed: %s", got)
	}
	if !strings.Contains(got, "[NEW] R-001") {
		t.Fatalf("fresh scan must still print [NEW]: %s", got)
	}
	if !strings.Contains(got, "[UPD] R-002") {
		t.Fatalf("fresh scan must still print [UPD]: %s", got)
	}
	if strings.Contains(got, "cached") {
		t.Fatalf("fresh scan must not mention cache: %s", got)
	}
}

func TestPrintScanFindingsCachedSuppressesNewMarkers(t *testing.T) {
	var out, errOut bytes.Buffer
	printScanFindings(&out, &errOut, cachedTestResponse(true))

	got := out.String()
	if strings.Contains(got, "[NEW]") {
		t.Fatalf("cache replay must not print a bare [NEW] marker: %s", got)
	}
	if strings.Contains(got, "[UPD]") {
		t.Fatalf("cache replay must not print a bare [UPD] marker: %s", got)
	}
	if !strings.Contains(got, "[was NEW] R-001") {
		t.Fatalf("cache replay must label the earlier status: %s", got)
	}
	if !strings.Contains(got, "[was UPD] R-002") {
		t.Fatalf("cache replay must label the earlier status: %s", got)
	}
	if !strings.Contains(got, "cached") {
		t.Fatalf("cache replay heading must say cached: %s", got)
	}
	// The risk rows themselves are unchanged apart from the marker.
	if !strings.Contains(got, "R-003: Stale runbook (score: 20, low)") {
		t.Fatalf("risk rows must be preserved: %s", got)
	}
}

func TestPrintScanFindingsWarningsGoToStderr(t *testing.T) {
	var out, errOut bytes.Buffer
	resp := cachedTestResponse(true)
	resp.Findings[0].Warnings = []string{"severity coerced"}
	printScanFindings(&out, &errOut, resp)

	if strings.Contains(out.String(), "severity coerced") {
		t.Fatalf("per-finding warnings belong on stderr: %s", out.String())
	}
	if !strings.Contains(errOut.String(), "warning [R-001]: severity coerced") {
		t.Fatalf("per-finding warning missing from stderr: %s", errOut.String())
	}
}
