package commands

import (
	"strings"
	"testing"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// TestRenderScanReportMarkdownEmpty asserts the no-findings path emits
// a clean "all clear" message with no empty tables.
func TestRenderScanReportMarkdownEmpty(t *testing.T) {
	out := renderScanReportMarkdown("/tmp/x", "demo", nil, scanner.ScanStats{
		FilesScanned: 12, BytesScanned: 1024, MatchersRun: 5, DurationMS: 17,
	})
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected 'No findings' message; got: %s", out)
	}
	if strings.Contains(out, "## Findings by Category") {
		t.Errorf("empty report should not render category matrix; got: %s", out)
	}
}

func TestRenderScanReportMarkdownGroupsBySeverity(t *testing.T) {
	findings := []scanner.ScanFinding{
		{Title: "x", Category: "fault_tolerance", Impact: "high", Evidence: []scanner.ScanEvidence{{Path: "a.go", LineNumber: 1}}},
		{Title: "y", Category: "fault_tolerance", Impact: "low", Evidence: []scanner.ScanEvidence{{Path: "b.go", LineNumber: 2}}},
		{Title: "z", Category: "fault_tolerance", Impact: "medium", Evidence: []scanner.ScanEvidence{{Path: "c.go", LineNumber: 3}}},
	}
	out := renderScanReportMarkdown("/tmp/x", "demo", findings, scanner.ScanStats{})

	for _, want := range []string{
		"## 🟠 High severity (1)",
		"## 🟡 Medium severity (1)",
		"## ⚪ Low severity (1)",
		"| Category | Finding | Locations |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing severity section %q in:\n%s", want, out)
		}
	}
	// Critical section should NOT render when no critical findings.
	if strings.Contains(out, "Critical severity (") {
		t.Errorf("unexpected empty Critical section in:\n%s", out)
	}
}

func TestRenderFindingsTableEscapesPipe(t *testing.T) {
	findings := []scanner.ScanFinding{
		{
			Title:    "title with | pipe",
			Category: "x",
			Impact:   "high",
			Evidence: []scanner.ScanEvidence{{Path: "a|b.go", LineNumber: 1}},
		},
	}
	out := renderFindingsTable(findings)
	// Title pipe must appear escaped in the table cell.
	if !strings.Contains(out, `title with \| pipe`) {
		t.Errorf("title pipe not escaped:\n%s", out)
	}
}

func TestRenderFindingsTableCollapsesRepeats(t *testing.T) {
	findings := []scanner.ScanFinding{
		{Title: "K8s container without limits", Category: "change_management", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "a.yaml", LineNumber: 1}}},
		{Title: "K8s container without limits", Category: "change_management", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "b.yaml", LineNumber: 1}}},
		{Title: "K8s container without limits", Category: "change_management", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "c.yaml", LineNumber: 1}}},
		{Title: "Different finding", Category: "change_management", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "d.yaml", LineNumber: 1}}},
	}
	out := renderFindingsTable(findings)

	// Table should have ONE row for the collapsed group and ONE for the singleton.
	rowCount := strings.Count(out, "| `change_management`")
	if rowCount != 2 {
		t.Errorf("expected 2 collapsed rows, got %d:\n%s", rowCount, out)
	}
	// Count column shows 3 locations for the collapsed group.
	if !strings.Contains(out, "| 3 |") {
		t.Errorf("expected count of 3 for collapsed group:\n%s", out)
	}
	// Drill-down section appears (because at least one group has multi-location).
	if !strings.Contains(out, "**Locations:**") {
		t.Errorf("expected Locations sub-section:\n%s", out)
	}
	// Each path appears as a nested bullet under the group.
	for _, want := range []string{"`a.yaml:1`", "`b.yaml:1`", "`c.yaml:1`"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected path bullet %q in:\n%s", want, out)
		}
	}
}

func TestRenderFindingsTableSkipsLocationsSubsectionWhenAllSingle(t *testing.T) {
	findings := []scanner.ScanFinding{
		{Title: "A", Category: "x", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "a.go", LineNumber: 1}}},
		{Title: "B", Category: "x", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "b.go", LineNumber: 2}}},
	}
	out := renderFindingsTable(findings)
	if strings.Contains(out, "**Locations:**") {
		t.Errorf("Locations sub-section should be skipped when every group is single-location:\n%s", out)
	}
}

func TestRenderFindingsTableSortsByCategoryThenCount(t *testing.T) {
	findings := []scanner.ScanFinding{
		{Title: "rare", Category: "fault_tolerance", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "rare.go", LineNumber: 1}}},
		{Title: "common", Category: "change_management", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "a.yaml", LineNumber: 1}}},
		{Title: "common", Category: "change_management", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "b.yaml", LineNumber: 1}}},
		{Title: "common", Category: "change_management", Impact: "high",
			Evidence: []scanner.ScanEvidence{{Path: "c.yaml", LineNumber: 1}}},
	}
	out := renderFindingsTable(findings)
	// Both categories should appear; common-3 should come before
	// fault_tolerance/rare.
	commonIdx := strings.Index(out, "common")
	rareIdx := strings.Index(out, "rare")
	if commonIdx < 0 || rareIdx < 0 || commonIdx >= rareIdx {
		t.Errorf("expected common (count 3) before rare (count 1):\n%s", out)
	}
}

func TestRenderScanReportMarkdownIncludesCategoryMatrix(t *testing.T) {
	findings := []scanner.ScanFinding{
		{Title: "a", Category: "fault_tolerance", Impact: "high", Evidence: []scanner.ScanEvidence{{Path: "a.go", LineNumber: 1}}},
		{Title: "b", Category: "monitoring_gaps", Impact: "low", Evidence: []scanner.ScanEvidence{{Path: "b.go", LineNumber: 1}}},
	}
	out := renderScanReportMarkdown("/tmp/x", "demo", findings, scanner.ScanStats{})

	if !strings.Contains(out, "fault_tolerance") || !strings.Contains(out, "monitoring_gaps") {
		t.Errorf("matrix should include both categories; got:\n%s", out)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		512:        "512 B",
		1024:       "1.0 KB",
		1536:       "1.5 KB",
		1048576:    "1.0 MB",
		1500000000: "1.4 GB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d)=%q, want %q", in, got, want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[int64]string{
		17:     "17ms",
		999:    "999ms",
		1500:   "1.5s",
		60000:  "1m0s",
		125000: "2m5s",
	}
	for in, want := range cases {
		if got := humanDuration(in); got != want {
			t.Errorf("humanDuration(%d)=%q, want %q", in, got, want)
		}
	}
}
