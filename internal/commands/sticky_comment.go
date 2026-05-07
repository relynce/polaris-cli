package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// StickyCommentMarker is an HTML comment posted at the top of every PR
// sticky comment so the CI script can reliably find and update the
// existing comment instead of creating duplicates. The standard pattern
// is `gh pr comment --edit-last` keying off this marker, or `gh api
// repos/.../comments` listing for the marker.
const StickyCommentMarker = "<!-- rvl-sticky-comment:reliability -->"

// PRCommentInput is the bundle of data the markdown generator consumes
// to render the sticky comment for a PR. Keep this a value type — the
// generator must be a pure function so tests can drive it from fixtures
// without HTTP.
type PRCommentInput struct {
	Service             string
	NewFindings         []scanner.ScanFinding
	ResolvedFindings    []ScanResult
	PerServiceBreakdown []ServiceBudget
	NetDelta            int
	EffectiveTolerance  *EffectiveTolerance
	MeasuredState       int
	HasRevelaraYAML     bool
	PolarisRiskListURL  string // e.g., "https://polaris.example.com/risks?service=..."
}

// ServiceBudget represents a single touched service's budget slice for
// the per-service breakdown table. Populated when a PR touches multiple
// services so the comment can show per-service pass/fail.
type ServiceBudget struct {
	Service       string
	NetDelta      int
	MeasuredState int
	Tolerance     int
	Status        string // in_budget | nearing | over_budget | calibrating
}

// RenderPRComment produces the markdown body of the sticky PR comment.
// Pure function: same inputs always produce the same output. Begins with
// StickyCommentMarker so CI scripts can reliably find and update the
// comment instead of creating duplicates.
//
// Reference: docs/designs/local-scanner-developer-workflow.md
//   § "PR Comment UX" and § "Sticky Comment Structure".
func RenderPRComment(in PRCommentInput) string {
	var sb strings.Builder
	sb.WriteString(StickyCommentMarker)
	sb.WriteByte('\n')

	sb.WriteString(fmt.Sprintf("## Revelara Reliability — Risk Delta: %s\n\n", signedInt(in.NetDelta)))

	// Banner: missing .revelara.yaml
	if !in.HasRevelaraYAML {
		sb.WriteString("> **No `.revelara.yaml` in this repo.** Using org-level tolerance defaults. ")
		sb.WriteString("Run `rvl init` to commit a per-service config and unlock per-service overrides.\n\n")
	}

	// Budget summary line
	if in.EffectiveTolerance != nil {
		over := in.MeasuredState > in.EffectiveTolerance.ToleranceTarget
		pct := 0.0
		if in.EffectiveTolerance.ToleranceTarget > 0 {
			pct = float64(in.MeasuredState) / float64(in.EffectiveTolerance.ToleranceTarget) * 100.0
		}
		if over {
			sb.WriteString(fmt.Sprintf("**Budget:** %d/%d **OVER BUDGET** — waiver required to merge.\n\n",
				in.MeasuredState, in.EffectiveTolerance.ToleranceTarget))
		} else {
			sb.WriteString(fmt.Sprintf("**Budget:** %d/%d (%.1f%% used) — within tolerance.\n\n",
				in.MeasuredState, in.EffectiveTolerance.ToleranceTarget, pct))
		}
		if in.EffectiveTolerance.StrictEnforcement {
			sb.WriteString("> **Strict enforcement mode is on.** Floor matchers (SQL injection, ")
			sb.WriteString("hardcoded credentials, unencrypted storage) require an emergency override ")
			sb.WriteString("commit message instead of standard waivers.\n\n")
		}
	}

	// Per-service breakdown when multiple services touched
	if len(in.PerServiceBreakdown) > 1 {
		sb.WriteString("### Per-service breakdown\n\n")
		sb.WriteString("| Service | Δ Risk | Measured / Tolerance | Status |\n")
		sb.WriteString("|---|---|---|---|\n")
		rows := append([]ServiceBudget(nil), in.PerServiceBreakdown...)
		sort.Slice(rows, func(i, j int) bool { return rows[i].Service < rows[j].Service })
		for _, r := range rows {
			sb.WriteString(fmt.Sprintf("| %s | %s | %d / %d | %s |\n",
				r.Service, signedInt(r.NetDelta), r.MeasuredState, r.Tolerance, statusEmoji(r.Status)))
		}
		sb.WriteByte('\n')
	}

	// New findings table
	if len(in.NewFindings) > 0 {
		sb.WriteString(fmt.Sprintf("### New findings (%d)\n\n", len(in.NewFindings)))
		sb.WriteString("| Severity | Matcher | Location |\n")
		sb.WriteString("|---|---|---|\n")
		for _, f := range in.NewFindings {
			loc := ""
			if len(f.Evidence) > 0 {
				loc = fmt.Sprintf("%s:%d", f.Evidence[0].Path, f.Evidence[0].LineNumber)
			}
			sev := strings.ToUpper(f.Impact)
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", sev, f.Title, loc))
		}
		sb.WriteByte('\n')
	}

	// Resolved findings table
	if len(in.ResolvedFindings) > 0 {
		sb.WriteString(fmt.Sprintf("### Resolved findings (%d)\n\n", len(in.ResolvedFindings)))
		sb.WriteString("| Risk | Score returned |\n|---|---|\n")
		for _, f := range in.ResolvedFindings {
			sb.WriteString(fmt.Sprintf("| %s | -%d |\n", f.RiskCode, f.Score))
		}
		sb.WriteByte('\n')
	}

	// Provenance section: surface incident-grounding for the most-impactful
	// new finding so reviewers see the corpus context inline.
	if leading := leadingProvenance(in.NewFindings); leading != "" {
		sb.WriteString("### Provenance\n\n")
		sb.WriteString(leading)
		sb.WriteByte('\n')
	}

	// Footer with Polaris link + waiver hint
	if in.PolarisRiskListURL != "" {
		sb.WriteString(fmt.Sprintf("[View full report in Polaris →](%s)\n\n", in.PolarisRiskListURL))
	}
	sb.WriteString("**Waiver options:** add a yaml waiver to `.revelara.yaml`, comment `/rvl waive <matcher>` ")
	sb.WriteString("(requires `reliability-waiver` permission), or apply the `rvl-waiver-required` label.\n")

	return sb.String()
}

// signedInt formats an int with explicit + or - sign for delta display.
func signedInt(n int) string {
	if n > 0 {
		return fmt.Sprintf("+%d", n)
	}
	return fmt.Sprintf("%d", n)
}

// statusEmoji renders a per-service status pill in compact markdown.
func statusEmoji(status string) string {
	switch status {
	case "over_budget":
		return ":x: Over Budget"
	case "nearing":
		return ":warning: Nearing"
	case "calibrating":
		return ":wrench: Calibrating"
	default:
		return ":white_check_mark: In Budget"
	}
}

// leadingProvenance picks the most-impactful new finding's provenance
// blob (the one with the highest impact severity). Returns the formatted
// human-readable narrative slice. Empty when no findings carry
// scoring-relevant provenance.
func leadingProvenance(findings []scanner.ScanFinding) string {
	if len(findings) == 0 {
		return ""
	}
	leading := findings[0]
	for _, f := range findings[1:] {
		if severityRank(f.Impact) > severityRank(leading.Impact) {
			leading = f
		}
	}
	if leading.Provenance == nil {
		return ""
	}
	p := leading.Provenance
	var lines []string
	if p.IncidentFrequency != "" {
		lines = append(lines, fmt.Sprintf("- **Incident frequency**: %s", p.IncidentFrequency))
	}
	if p.TypicalBlastRadius != "" {
		lines = append(lines, fmt.Sprintf("- **Typical blast radius**: %s", p.TypicalBlastRadius))
	}
	if p.TypicalMTTR != "" {
		lines = append(lines, fmt.Sprintf("- **Typical MTTR**: %s", p.TypicalMTTR))
	}
	if p.OrgIncidentCount > 0 {
		lines = append(lines, fmt.Sprintf("- **Org incident count**: %d", p.OrgIncidentCount))
	}
	if len(lines) == 0 {
		return ""
	}
	return fmt.Sprintf("`%s` is grounded in real-world incident data:\n%s\n",
		leading.Title, strings.Join(lines, "\n"))
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
