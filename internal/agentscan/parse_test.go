package agentscan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// findingsJSON builds the findings payload JSON a lens is instructed to
// emit, via json.Marshal so tests never hand-escape strings.
func findingsJSON(t *testing.T, findings []Finding, summary string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"findings": findings,
		"summary":  summary,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// goChangeSet returns a minimal change set with one modified Go file,
// paired with the go lens for validation tests.
func goChangeSet() ChangeSet {
	return ChangeSet{
		Diff:     "diff --git a/a.go b/a.go\n",
		Files:    []ChangedFile{{Path: "a.go", Kind: ChangeModified}},
		BaseDesc: "staged",
	}
}

func goLens(t *testing.T) Lens {
	t.Helper()
	l, ok := LensByID(LensGo)
	if !ok {
		t.Fatal("go lens missing from catalog")
	}
	return l
}

func validFinding() Finding {
	return Finding{
		Rule:        "missing-timeout",
		Severity:    "high",
		File:        "a.go",
		Line:        3,
		Title:       "HTTP call without timeout",
		Description: "The new client has no timeout.",
	}
}

func TestExtractFindingsBareJSON(t *testing.T) {
	raw := findingsJSON(t, []Finding{validFinding()}, "one risk")
	findings, summary, err := ExtractFindings(raw)
	if err != nil {
		t.Fatalf("ExtractFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "missing-timeout" {
		t.Fatalf("findings = %+v, want one missing-timeout", findings)
	}
	if summary != "one risk" {
		t.Fatalf("summary = %q, want %q", summary, "one risk")
	}
}

func TestExtractFindingsFenced(t *testing.T) {
	payload := findingsJSON(t, []Finding{validFinding()}, "fenced")
	raw := "```json\n" + payload + "\n```"
	findings, summary, err := ExtractFindings(raw)
	if err != nil {
		t.Fatalf("ExtractFindings: %v", err)
	}
	if len(findings) != 1 || summary != "fenced" {
		t.Fatalf("got %d findings, summary %q", len(findings), summary)
	}
}

func TestExtractFindingsProseWrapped(t *testing.T) {
	payload := findingsJSON(t, []Finding{validFinding()}, "prose")
	raw := "Here is my analysis of the change:\n\n" + payload + "\n\nLet me know if you need more."
	findings, summary, err := ExtractFindings(raw)
	if err != nil {
		t.Fatalf("ExtractFindings: %v", err)
	}
	if len(findings) != 1 || summary != "prose" {
		t.Fatalf("got %d findings, summary %q", len(findings), summary)
	}
}

func TestExtractFindingsStrayBraceBeforeObject(t *testing.T) {
	payload := findingsJSON(t, nil, "clean")
	raw := "The output shape is { as follows:\n" + payload
	findings, summary, err := ExtractFindings(raw)
	if err != nil {
		t.Fatalf("ExtractFindings: %v", err)
	}
	if len(findings) != 0 || summary != "clean" {
		t.Fatalf("got %d findings, summary %q", len(findings), summary)
	}
}

func TestExtractFindingsBracesInsideStrings(t *testing.T) {
	f := validFinding()
	f.Description = `code like {"nested": "}"} appears in the diff`
	payload := findingsJSON(t, []Finding{f}, "tricky strings")
	findings, _, err := ExtractFindings(payload)
	if err != nil {
		t.Fatalf("ExtractFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].Description != f.Description {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestExtractFindingsNoJSON(t *testing.T) {
	if _, _, err := ExtractFindings("I found no machine-readable output to give you."); err == nil {
		t.Fatal("want error for output without a findings JSON object")
	}
	if _, _, err := ExtractFindings(""); err == nil {
		t.Fatal("want error for empty output")
	}
}

func TestExtractFindingsMalformedJSON(t *testing.T) {
	raw := `{"findings": [{"rule": "missing-timeout",}], "summary": "trailing comma"}`
	if _, _, err := ExtractFindings(raw); err == nil {
		t.Fatal("want error for malformed findings JSON")
	}
}

func TestValidateFindingsStampsLens(t *testing.T) {
	kept, dropped := ValidateFindings(goLens(t), goChangeSet(), []Finding{validFinding()})
	if len(dropped) != 0 {
		t.Fatalf("dropped = %+v, want none", dropped)
	}
	if len(kept) != 1 {
		t.Fatalf("kept = %+v, want one", kept)
	}
	if kept[0].Lens != LensGo {
		t.Fatalf("Lens = %q, want %q (stamped by orchestrator)", kept[0].Lens, LensGo)
	}
}

func TestValidateFindingsDropsUnknownRule(t *testing.T) {
	f := validFinding()
	f.Rule = "made-up-rule"
	kept, dropped := ValidateFindings(goLens(t), goChangeSet(), []Finding{f})
	if len(kept) != 0 {
		t.Fatalf("kept = %+v, want none", kept)
	}
	if len(dropped) != 1 || !strings.Contains(dropped[0].Reason, "made-up-rule") {
		t.Fatalf("dropped = %+v, want one with the rule named in Reason", dropped)
	}
}

func TestValidateFindingsDropsFileOutsideChangeSet(t *testing.T) {
	f := validFinding()
	f.File = "unrelated/secret.go"
	kept, dropped := ValidateFindings(goLens(t), goChangeSet(), []Finding{f})
	if len(kept) != 0 {
		t.Fatalf("kept = %+v, want none", kept)
	}
	if len(dropped) != 1 || !strings.Contains(dropped[0].Reason, "change set") {
		t.Fatalf("dropped = %+v, want one out-of-change-set drop", dropped)
	}
}

func TestValidateFindingsNormalizesSeverityCase(t *testing.T) {
	f := validFinding()
	f.Severity = "HIGH"
	kept, dropped := ValidateFindings(goLens(t), goChangeSet(), []Finding{f})
	if len(dropped) != 0 || len(kept) != 1 {
		t.Fatalf("kept=%d dropped=%d, want 1/0", len(kept), len(dropped))
	}
	if kept[0].Severity != "high" {
		t.Fatalf("Severity = %q, want normalized %q", kept[0].Severity, "high")
	}
}

func TestValidateFindingsDropsBadSeverity(t *testing.T) {
	f := validFinding()
	f.Severity = "urgent"
	kept, dropped := ValidateFindings(goLens(t), goChangeSet(), []Finding{f})
	if len(kept) != 0 {
		t.Fatalf("kept = %+v, want none", kept)
	}
	if len(dropped) != 1 || !strings.Contains(dropped[0].Reason, "urgent") {
		t.Fatalf("dropped = %+v, want one bad-severity drop", dropped)
	}
}

func TestValidateFindingsAllowsDeletedFilePath(t *testing.T) {
	cs := goChangeSet()
	cs.Files = append(cs.Files, ChangedFile{Path: "gone.go", Kind: ChangeDeleted})
	f := validFinding()
	f.File = "gone.go"
	kept, dropped := ValidateFindings(goLens(t), cs, []Finding{f})
	if len(kept) != 1 || len(dropped) != 0 {
		t.Fatalf("kept=%d dropped=%d, want 1/0 (deleted files are part of the change set)", len(kept), len(dropped))
	}
}

// stubAdapter lets RunLens tests inject invoke results without a
// subprocess. It records the prompt and snapshot dir it was given.
type stubAdapter struct {
	res InvokeResult
	err error

	gotPrompt string
	gotDir    string
}

func (s *stubAdapter) Name() string { return "stub" }

func (s *stubAdapter) Invoke(_ context.Context, prompt, snapshotDir string) (InvokeResult, error) {
	s.gotPrompt = prompt
	s.gotDir = snapshotDir
	return s.res, s.err
}

func TestRunLensHappyPath(t *testing.T) {
	cs := goChangeSet()
	l := goLens(t)
	bad := validFinding()
	bad.Rule = "not-a-rule"
	payload := findingsJSON(t, []Finding{validFinding(), bad}, "one real risk")
	stub := &stubAdapter{res: InvokeResult{Raw: payload, CostUSD: 0.42, Model: "sonnet"}}

	res := RunLens(context.Background(), stub, l, cs, "/tmp/snap")
	if res.Err != nil {
		t.Fatalf("RunLens Err = %v", res.Err)
	}
	if res.Lens.ID != LensGo {
		t.Fatalf("Lens = %q, want %q", res.Lens.ID, LensGo)
	}
	if len(res.Findings) != 1 || res.Findings[0].Lens != LensGo {
		t.Fatalf("Findings = %+v, want one stamped with %q", res.Findings, LensGo)
	}
	if len(res.Dropped) != 1 || res.Dropped[0].Finding.Rule != "not-a-rule" {
		t.Fatalf("Dropped = %+v, want the invalid-rule finding", res.Dropped)
	}
	if res.Summary != "one real risk" {
		t.Fatalf("Summary = %q", res.Summary)
	}
	if res.CostUSD != 0.42 {
		t.Fatalf("CostUSD = %v, want 0.42", res.CostUSD)
	}
	if res.Wall <= 0 {
		t.Fatalf("Wall = %v, want > 0", res.Wall)
	}
	if stub.gotDir != "/tmp/snap" {
		t.Fatalf("snapshotDir passed to adapter = %q", stub.gotDir)
	}
	if !strings.Contains(stub.gotPrompt, "missing-timeout") {
		t.Fatal("prompt does not contain the lens rule vocabulary; RenderPrompt not used?")
	}
}

func TestRunLensInvokeError(t *testing.T) {
	stub := &stubAdapter{err: ErrAgentUnavailable}
	res := RunLens(context.Background(), stub, goLens(t), goChangeSet(), "/tmp/snap")
	if res.Err == nil {
		t.Fatal("want Err for invoke failure")
	}
	if !errors.Is(res.Err, ErrAgentUnavailable) {
		t.Fatalf("Err = %v, want errors.Is ErrAgentUnavailable", res.Err)
	}
	if !strings.Contains(res.Err.Error(), LensGo) {
		t.Fatalf("Err = %v, want lens id in message", res.Err)
	}
}

func TestRunLensExtractError(t *testing.T) {
	stub := &stubAdapter{res: InvokeResult{Raw: "no json here", CostUSD: 0.10}}
	res := RunLens(context.Background(), stub, goLens(t), goChangeSet(), "/tmp/snap")
	if res.Err == nil {
		t.Fatal("want Err for unparseable output")
	}
	if res.CostUSD != 0.10 {
		t.Fatalf("CostUSD = %v, want cost preserved even on parse failure", res.CostUSD)
	}
}
