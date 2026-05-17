package commands

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/revelara-ai/rvl-cli/internal/scanner"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var titleCaser = cases.Title(language.English)

// renderLocalSummary builds a markdown report of the scan result and
// renders it via glamour when stdout is a terminal. When stdout is
// piped (CI, log capture), it emits raw markdown so the output stays
// greppable and round-trippable.
//
// The split between "build the report" (renderScanReportMarkdown) and
// "render to terminal" (this function) keeps the markdown testable
// without driving a real TTY.
func renderLocalSummary(target, service string, findings []scanner.ScanFinding, stats scanner.ScanStats) {
	md := renderScanReportMarkdown(target, service, findings, stats)

	if !isTTY() {
		// Piped output — emit raw markdown. Still readable in plain
		// terminals and easy to grep / archive in CI logs.
		fmt.Print(md)
		return
	}

	r, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(120),
	)
	if err != nil {
		// Fall back to raw markdown if glamour init fails.
		fmt.Fprintf(os.Stderr, "warning: glamour init failed: %v (falling back to plain output)\n", err)
		fmt.Print(md)
		return
	}
	out, err := r.Render(md)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: glamour render failed: %v (falling back to plain output)\n", err)
		fmt.Print(md)
		return
	}
	fmt.Print(out)
}

// renderScanReportMarkdown returns the report in markdown form. Pure
// function: no IO, no globals. Drives renderLocalSummary and is
// directly testable.
func renderScanReportMarkdown(target, service string, findings []scanner.ScanFinding, stats scanner.ScanStats) string {
	var sb strings.Builder

	// Header.
	sb.WriteString("# Reliability Scan Report\n\n")
	fmt.Fprintf(&sb, "**Target:** `%s`  \n", target)
	fmt.Fprintf(&sb, "**Service:** `%s`  \n", service)
	fmt.Fprintf(&sb, "**Files scanned:** %d &nbsp; **Bytes:** %s &nbsp; **Matchers:** %d &nbsp; **Duration:** %s\n\n",
		stats.FilesScanned, humanBytes(stats.BytesScanned), stats.MatchersRun, humanDuration(stats.DurationMS))

	if len(findings) == 0 {
		sb.WriteString("## Summary\n\n")
		sb.WriteString("✓ **No findings.** All matchers ran cleanly.\n")
		return sb.String()
	}

	counts := severityCountsMap(findings)
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|------:|\n")
	fmt.Fprintf(&sb, "| %s Critical | %d |\n", severityIcon("critical"), counts["critical"])
	fmt.Fprintf(&sb, "| %s High     | %d |\n", severityIcon("high"), counts["high"])
	fmt.Fprintf(&sb, "| %s Medium   | %d |\n", severityIcon("medium"), counts["medium"])
	fmt.Fprintf(&sb, "| %s Low      | %d |\n", severityIcon("low"), counts["low"])
	fmt.Fprintf(&sb, "| **Total**  | **%d** |\n\n", len(findings))

	// po-i7mz2: when classification ran (change-aware scan vs base ref),
	// surface how many findings are new vs pre-existing. Pre-existing
	// findings appear in output but don't gate the CI exit code.
	if nNew, nPre := classificationCounts(findings); nNew+nPre > 0 {
		fmt.Fprintf(&sb, "**Change-aware:** %d new, %d pre-existing (advisory, does not gate).\n\n", nNew, nPre)
	}

	// Category x severity matrix.
	sb.WriteString("## Findings by Category\n\n")
	sb.WriteString(renderCategoryMatrix(findings))
	sb.WriteString("\n")

	// Findings grouped by severity, critical -> low, then file order.
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		fs := findingsBySeverity(findings, sev)
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "## %s %s severity (%d)\n\n",
			severityIcon(sev), titleCaser.String(sev), len(fs))
		sb.WriteString(renderFindingsTable(fs))
		sb.WriteString("\n")
	}

	return sb.String()
}

// renderFindingsTable groups findings by (category, title), renders a
// summary table with one row per group plus a count, then writes a
// definition-list-style sub-section per group with the location bullets.
//
// The layout pattern: scannable summary at the top so the reader sees
// "what kinds of issues exist and how many", then drill-down detail
// underneath when they want specific paths.
//
// Column order is Category, Finding, Locations — category comes
// first because grouping by category is how reliability work is
// usually triaged.
func renderFindingsTable(findings []scanner.ScanFinding) string {
	if len(findings) == 0 {
		return ""
	}
	groups := groupFindings(findings)

	var sb strings.Builder
	sb.WriteString("| Category | Finding | Locations |\n")
	sb.WriteString("|----------|---------|----------:|\n")
	for _, g := range groups {
		fmt.Fprintf(&sb, "| `%s` | %s | %d |\n",
			g.Category, escapeTableCell(g.Title), len(g.Locations))
	}
	sb.WriteString("\n")

	// Drill-down: one bullet per group, locations as nested bullets.
	// Skipped when every group is a single-location entry (the table
	// above already conveys everything).
	if !allGroupsAreSingleLocation(groups) {
		sb.WriteString("**Locations:**\n\n")
		for _, g := range groups {
			fmt.Fprintf(&sb, "- `%s` / %s — %d location%s\n",
				g.Category, g.Title, len(g.Locations), pluralS(len(g.Locations)))
			for _, loc := range g.Locations {
				fmt.Fprintf(&sb, "    - `%s`\n", loc)
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// findingGroup collects all locations for one (category, title) pair.
type findingGroup struct {
	Category  string
	Title     string
	Locations []string // formatted "path:line", deduped, in walk order
}

func groupFindings(findings []scanner.ScanFinding) []findingGroup {
	type key struct{ cat, title string }
	byKey := map[key]*findingGroup{}
	order := []key{} // preserve first-seen order for stable output

	for _, f := range findings {
		category := f.Category
		if category == "" {
			category = "uncategorized"
		}
		k := key{category, f.Title}
		g, ok := byKey[k]
		if !ok {
			g = &findingGroup{Category: category, Title: f.Title}
			byKey[k] = g
			order = append(order, k)
		}
		// W2 rollup model: one Finding can carry N evidence items
		// (every occurrence of one class of risk). Expand all of them
		// so the report's "Locations" column reflects scope of impact,
		// not just the head occurrence.
		for _, ev := range f.Evidence {
			if ev.Path == "" {
				continue
			}
			loc := fmt.Sprintf("%s:%d", ev.Path, ev.LineNumber)
			// po-i7mz2: tag pre-existing findings inline so readers can
			// see which entries are advisory vs which will gate CI.
			if f.Status == scanner.StatusPreExisting {
				loc += " [pre-existing]"
			}
			g.Locations = append(g.Locations, loc)
		}
	}

	out := make([]findingGroup, 0, len(order))
	for _, k := range order {
		g := byKey[k]
		out = append(out, *g)
	}
	// Sort by category, then descending location count, then title —
	// puts the loudest groups in each category first, which is what
	// readers want to triage.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		if len(out[i].Locations) != len(out[j].Locations) {
			return len(out[i].Locations) > len(out[j].Locations)
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func allGroupsAreSingleLocation(groups []findingGroup) bool {
	for _, g := range groups {
		if len(g.Locations) > 1 {
			return false
		}
	}
	return true
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// escapeTableCell escapes the markdown table separator so titles or
// paths containing a literal `|` don't break column alignment.
// Glamour reflows on `|` even inside backtick-quoted text.
func escapeTableCell(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

// renderCategoryMatrix produces the markdown table for the
// category x severity breakdown. Sorted by category for stable output.
func renderCategoryMatrix(findings []scanner.ScanFinding) string {
	type catSev struct{ cat, sev string }
	matrix := map[catSev]int{}
	cats := map[string]bool{}
	for _, f := range findings {
		cat := f.Category
		if cat == "" {
			cat = "uncategorized"
		}
		matrix[catSev{cat, strings.ToLower(f.Impact)}]++
		cats[cat] = true
	}
	catList := make([]string, 0, len(cats))
	for c := range cats {
		catList = append(catList, c)
	}
	sort.Strings(catList)

	var sb strings.Builder
	sb.WriteString("| Category | Critical | High | Medium | Low | Total |\n")
	sb.WriteString("|----------|---------:|-----:|-------:|----:|------:|\n")
	severities := []string{"critical", "high", "medium", "low"}
	for _, c := range catList {
		var total int
		row := make([]int, len(severities))
		for i, s := range severities {
			row[i] = matrix[catSev{c, s}]
			total += row[i]
		}
		fmt.Fprintf(&sb, "| %s | %d | %d | %d | %d | %d |\n",
			c, row[0], row[1], row[2], row[3], total)
	}
	return sb.String()
}

func severityIcon(sev string) string {
	switch sev {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "⚪"
	}
	return "•"
}

func findingsBySeverity(findings []scanner.ScanFinding, sev string) []scanner.ScanFinding {
	var out []scanner.ScanFinding
	for _, f := range findings {
		if strings.EqualFold(f.Impact, sev) {
			out = append(out, f)
		}
	}
	// Stable order: file path, then line.
	sort.SliceStable(out, func(i, j int) bool {
		ai, bj := "", ""
		al, bl := 0, 0
		if len(out[i].Evidence) > 0 {
			ai = out[i].Evidence[0].Path
			al = out[i].Evidence[0].LineNumber
		}
		if len(out[j].Evidence) > 0 {
			bj = out[j].Evidence[0].Path
			bl = out[j].Evidence[0].LineNumber
		}
		if ai != bj {
			return ai < bj
		}
		return al < bl
	})
	return out
}

func severityCountsMap(findings []scanner.ScanFinding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[strings.ToLower(f.Impact)]++
	}
	return out
}

// classificationCounts returns (new, pre-existing) counts for the
// po-i7mz2 change-aware mode. Returns (0, 0) when classification
// didn't run (all Status empty), which is the signal to omit the
// breakdown from the report.
func classificationCounts(findings []scanner.ScanFinding) (int, int) {
	var nNew, nPre int
	for _, f := range findings {
		switch f.Status {
		case scanner.StatusNew:
			nNew++
		case scanner.StatusPreExisting:
			nPre++
		}
	}
	return nNew, nPre
}

// humanBytes renders a byte count as a short human-readable string.
// 1024 -> 1.0KB, 1048576 -> 1.0MB. Used in the report header so the
// stat panel reads naturally instead of "11599632 bytes".
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	if ms < 60000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000.0)
	}
	mins := ms / 60000
	secs := (ms % 60000) / 1000
	return fmt.Sprintf("%dm%ds", mins, secs)
}
