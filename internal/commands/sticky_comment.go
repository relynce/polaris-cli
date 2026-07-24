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
// to render the sticky comment for a PR. Keep this a value type - the
// generator must be a pure function so tests can drive it from fixtures
// without HTTP.
//
// Note on resolved findings: the polaris ScanResponse currently only
// reports created/updated/unchanged ScanResult statuses, not a true
// "resolved-this-PR" signal. ResolvedCount carries the count from the
// scan response when polaris populates it (risks that went stale because
// the scan didn't surface them); detailed per-risk resolution awaits a
// follow-up that diffs scan_ids server-side.
type PRCommentInput struct {
	Service             string
	NewFindings         []scanner.ScanFinding
	ResolvedCount       int
	PerServiceBreakdown []ServiceBudget
	NetDelta            int
	EffectiveTolerance  *EffectiveTolerance
	MeasuredState       int
	HasRevelaraYAML     bool
	RevelaraRiskListURL string // e.g., "https://app.revelara.ai/risks?service=..."
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
//
//	§ "PR Comment UX" and § "Sticky Comment Structure".
func RenderPRComment(in PRCommentInput) string {
	var sb strings.Builder
	sb.WriteString(StickyCommentMarker)
	sb.WriteByte('\n')

	fmt.Fprintf(&sb, "## Revelara Reliability - Risk Delta: %s\n\n", signedInt(in.NetDelta))

	// Banner: missing .revelara.yaml
	if !in.HasRevelaraYAML {
		sb.WriteString("> **No `.revelara.yaml` in this repo.** Using org-level tolerance defaults. ")
		sb.WriteString("Run `rvl init` to commit a per-service config and unlock per-service overrides.\n\n")
	}

	// po-qs96.6: calibration banner (takes precedence over budget messaging
	// because gate enforcement is suspended during the 30-day window).
	if in.EffectiveTolerance != nil && in.EffectiveTolerance.Calibrating {
		sb.WriteString("> :wrench: **Calibration mode** - no gate enforcement. Findings are recorded; ")
		sb.WriteString("tolerance will be proposed on day 30 from the measured state at that time. ")
		sb.WriteString("EM accepts or modifies the proposal in Settings → Reliability.\n\n")
	} else if in.EffectiveTolerance != nil {
		// Budget summary line (live gate)
		over := in.MeasuredState > in.EffectiveTolerance.ToleranceTarget
		pct := 0.0
		if in.EffectiveTolerance.ToleranceTarget > 0 {
			pct = float64(in.MeasuredState) / float64(in.EffectiveTolerance.ToleranceTarget) * 100.0
		}
		if over {
			fmt.Fprintf(&sb, "**Budget:** %d/%d **OVER BUDGET** - waiver required to merge.\n\n",
				in.MeasuredState, in.EffectiveTolerance.ToleranceTarget)
		} else {
			fmt.Fprintf(&sb, "**Budget:** %d/%d (%.1f%% used) - within tolerance.\n\n",
				in.MeasuredState, in.EffectiveTolerance.ToleranceTarget, pct)
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
			fmt.Fprintf(&sb, "| %s | %s | %d / %d | %s |\n",
				r.Service, signedInt(r.NetDelta), r.MeasuredState, r.Tolerance, statusEmoji(r.Status))
		}
		sb.WriteByte('\n')
	}

	// New findings table
	if len(in.NewFindings) > 0 {
		fmt.Fprintf(&sb, "### New findings (%d)\n\n", len(in.NewFindings))
		sb.WriteString("| Severity | Matcher | Location |\n")
		sb.WriteString("|---|---|---|\n")
		for _, f := range in.NewFindings {
			loc := ""
			if len(f.Evidence) > 0 {
				loc = fmt.Sprintf("%s:%d", f.Evidence[0].Path, f.Evidence[0].LineNumber)
			}
			sev := strings.ToUpper(f.Impact)
			fmt.Fprintf(&sb, "| %s | %s | %s |\n", sev, f.Title, loc)
		}
		sb.WriteByte('\n')
	}

	// Resolved count (best-effort: server-side diff of scan_ids is a
	// follow-up; today this surfaces the count of risks that went stale
	// because the scan didn't surface them again).
	if in.ResolvedCount > 0 {
		fmt.Fprintf(&sb, "### Resolved this scan: %d\n\n", in.ResolvedCount)
	}

	// Provenance section: surface incident-grounding for the most-impactful
	// new finding so reviewers see the corpus context inline.
	if leading := leadingProvenance(in.NewFindings); leading != "" {
		sb.WriteString("### Provenance\n\n")
		sb.WriteString(leading)
		sb.WriteByte('\n')
	}

	// Footer with Revelara link + waiver hint
	if in.RevelaraRiskListURL != "" {
		fmt.Fprintf(&sb, "[View full report in Revelara →](%s)\n\n", in.RevelaraRiskListURL)
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
