package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/display"
)

// RiskContextView aggregates the three endpoint payloads that back the full
// `rvl risk context` render: the detail response (primary), the context
// response (grounding provenance, service context, score factors, knowledge),
// and the coverage slice from risk stats.
type RiskContextView struct {
	Detail   *RiskDetail
	Context  *RiskContextResponse
	Coverage *CoverageStats
}

// RiskStatsResponse is the subset of GET /api/v1/risks/stats we consume.
type RiskStatsResponse struct {
	Coverage *CoverageStats `json:"coverage,omitempty"`
}

// CoverageStats mirrors the stats coverage object.
type CoverageStats struct {
	TotalControls      int                `json:"total_controls"`
	AssessedControls   int                `json:"assessed_controls"`
	CoveragePercentage float64            `json:"coverage_percentage"`
	ByCategory         []CategoryCoverage `json:"by_category,omitempty"`
}

// CategoryCoverage is one per-category coverage row. The wire has no
// "unconfigured" field; derive it as total - assessed.
type CategoryCoverage struct {
	Category string `json:"category"`
	Total    int    `json:"total"`
	Assessed int    `json:"assessed"`
}

// risk returns the best available risk object, preferring the richer detail
// payload and falling back to the context response's embedded risk.
func (v RiskContextView) risk() *RiskDetail {
	if v.Detail != nil {
		return v.Detail
	}
	if v.Context != nil {
		return &v.Context.Risk
	}
	return nil
}

// firstErr returns the first non-nil error.
func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// coverageFrom decodes the coverage slice from a risk-stats response body.
func coverageFrom(body []byte) *CoverageStats {
	if len(body) == 0 {
		return nil
	}
	var s RiskStatsResponse
	if json.Unmarshal(body, &s) != nil {
		return nil
	}
	return s.Coverage
}

// composeRiskContextJSON returns the context body verbatim (preserving the
// top-level keys /rvl:fix reads via jq: score_factors, controls,
// graph_multiplier) with the full detail payload added under "detail" and
// coverage under "coverage_gap".
func composeRiskContextJSON(contextBody, detailBody []byte, coverage *CoverageStats) ([]byte, error) {
	var merged map[string]any
	if len(contextBody) > 0 {
		if err := json.Unmarshal(contextBody, &merged); err != nil {
			return nil, err
		}
	} else {
		merged = map[string]any{}
	}
	if len(detailBody) > 0 {
		var detail any
		if json.Unmarshal(detailBody, &detail) == nil {
			merged["detail"] = detail
		}
	}
	if coverage != nil {
		merged["coverage_gap"] = coverage
	}
	return json.MarshalIndent(merged, "", "  ")
}

// renderRiskContext renders the full textual risk context view.
func renderRiskContext(v RiskContextView) string {
	var sb strings.Builder
	r := v.risk()
	if r == nil {
		return ""
	}

	fmt.Fprintf(&sb, "\nRisk Context: %s\n", r.RiskCode)
	sb.WriteString(strings.Repeat("=", 80))
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "Title:    %s\n", r.Title)
	fmt.Fprintf(&sb, "Status:   %s\n", display.FormatStatus(r.Status))
	fmt.Fprintf(&sb, "Category: %s\n", r.Category)
	fmt.Fprintf(&sb, "Score:    %d\n", r.Score)

	renderSTPACausal(&sb, r)
	renderScoreFactors(&sb, v.Context)
	renderServiceContext(&sb, v.Context)
	renderControlCoverage(&sb, v.Context)
	renderKnowledge(&sb, v.Context)

	return sb.String()
}

func renderSTPACausal(sb *strings.Builder, r *RiskDetail) {
	hasStructuredSTPA := r.UCAType != "" || len(r.CausalFactors) > 0 || r.LossScenario != ""
	if hasStructuredSTPA {
		sb.WriteString("\nCausal Analysis (STPA-inspired):\n")
		sb.WriteString(strings.Repeat("-", 80))
		sb.WriteString("\n")
		sb.WriteString("Adapted from Systems-Theoretic Process Analysis (Leveson, MIT). Findings are candidates.\n")
		if r.UCAType != "" {
			fmt.Fprintf(sb, "  Unsafe Control Action: %s", display.FormatUCAType(r.UCAType))
			if cat := display.FormatUCACategory(r.UCAType); cat != "" {
				fmt.Fprintf(sb, "  (%s)", cat)
			}
			sb.WriteString("\n")
		}
		if r.LossScenario != "" {
			fmt.Fprintf(sb, "  Loss Scenario: %s\n", r.LossScenario)
		}
		if len(r.CausalFactors) > 0 {
			sb.WriteString("  Causal Factors:\n")
			for _, f := range r.CausalFactors {
				fmt.Fprintf(sb, "    > %s\n", display.WrapText(f, 74, "      "))
			}
		}
		return
	}
	if stpa := display.ParseSTPAContext(r.Narrative); stpa != nil {
		sb.WriteString("\nCausal Analysis (STPA-inspired):\n")
		sb.WriteString(strings.Repeat("-", 80))
		sb.WriteString("\n")
		sb.WriteString("Adapted from Systems-Theoretic Process Analysis (Leveson, MIT). Findings are candidates.\n")
		if stpa.UCAType != "" {
			fmt.Fprintf(sb, "  Unsafe Control Action: %s", display.FormatUCAType(stpa.UCAType))
			if cat := display.FormatUCACategory(stpa.UCAType); cat != "" {
				fmt.Fprintf(sb, "  (%s)", cat)
			}
			sb.WriteString("\n")
		}
		if stpa.LossScenario != "" {
			fmt.Fprintf(sb, "  Loss Scenario: %s\n", stpa.LossScenario)
		}
		if len(stpa.CausalFactors) > 0 {
			sb.WriteString("  Causal Factors:\n")
			for _, f := range stpa.CausalFactors {
				fmt.Fprintf(sb, "    > %s\n", display.WrapText(f, 74, "      "))
			}
		}
	}
}

func renderScoreFactors(sb *strings.Builder, ctx *RiskContextResponse) {
	if ctx == nil {
		return
	}
	factors := ctx.ScoreFactors
	if len(factors) == 0 {
		factors = ctx.ScoreFactorsOld
	}
	if len(factors) == 0 {
		return
	}
	sb.WriteString("\nScore Factors:\n")
	sb.WriteString(strings.Repeat("-", 80))
	sb.WriteString("\n")
	for _, factor := range factors {
		fmt.Fprintf(sb, "  [%+3d] %s (Source: %s)\n", factor.Points, factor.Description, factor.Source)
	}
}

func renderServiceContext(sb *strings.Builder, ctx *RiskContextResponse) {
	if ctx == nil || ctx.ServiceContext == nil {
		return
	}
	sc := ctx.ServiceContext
	sb.WriteString("\nService Context:\n")
	sb.WriteString(strings.Repeat("-", 80))
	sb.WriteString("\n")
	fmt.Fprintf(sb, "Service: %s", sc.ServiceName)
	if sc.Tier != "" {
		fmt.Fprintf(sb, " (Tier: %s)", sc.Tier)
	}
	sb.WriteString("\n")
	if sc.Incidents != nil {
		inc := sc.Incidents
		fmt.Fprintf(sb, "  Incidents: %d total (%d in last 30d, %d in last 90d)\n",
			inc.TotalIncidents, inc.Last30Days, inc.Last90Days)
		fmt.Fprintf(sb, "  Severity: %d critical, %d high\n", inc.CriticalCount, inc.HighCount)
		if inc.AverageMTTR != nil {
			fmt.Fprintf(sb, "  Average MTTR: %d minutes\n", *inc.AverageMTTR)
		}
		if inc.MostRecentTitle != "" {
			fmt.Fprintf(sb, "  Most Recent: %s\n", inc.MostRecentTitle)
		}
	}
}

func renderControlCoverage(sb *strings.Builder, ctx *RiskContextResponse) {
	if ctx == nil || len(ctx.Controls) == 0 {
		return
	}
	sb.WriteString("\nControl Coverage:\n")
	sb.WriteString(strings.Repeat("-", 80))
	sb.WriteString("\n")
	for _, ctrlCtx := range ctx.Controls {
		ctrl := ctrlCtx.Control
		fmt.Fprintf(sb, "\n[%s] %s\n", ctrl.ControlCode, ctrl.Name)
		fmt.Fprintf(sb, "  Category: %s | Type: %s\n", ctrl.Category, display.FormatControlType(ctrl.Type))

		if len(ctrlCtx.ExistingEvidence) > 0 {
			sb.WriteString("  Existing Evidence:\n")
			for _, ev := range ctrlCtx.ExistingEvidence {
				fmt.Fprintf(sb, "    - [%s] %s", ev.Type, ev.Name)
				if ev.Status != "" {
					fmt.Fprintf(sb, " (Status: %s)", ev.Status)
				}
				sb.WriteString("\n")
				if ev.Description != "" {
					for _, line := range strings.Split(display.WrapText(ev.Description, 76, ""), "\n") {
						fmt.Fprintf(sb, "      %s\n", line)
					}
				}
			}
		}

		if len(ctrlCtx.EvidenceGaps) > 0 {
			sb.WriteString("  Evidence Gaps:\n")
			for _, gap := range ctrlCtx.EvidenceGaps {
				fmt.Fprintf(sb, "    - %s\n", gap)
			}
		}
	}
}

func renderKnowledge(sb *strings.Builder, ctx *RiskContextResponse) {
	if ctx == nil {
		return
	}
	if len(ctx.Knowledge.Patterns) > 0 {
		sb.WriteString("\nRelevant Incident Patterns:\n")
		sb.WriteString(strings.Repeat("-", 80))
		sb.WriteString("\n")

		patterns := ctx.Knowledge.Patterns
		sort.Slice(patterns, func(i, j int) bool { return patterns[i].Score > patterns[j].Score })

		for _, pat := range patterns {
			fmt.Fprintf(sb, "\n%s (Type: %s)\n", pat.Title, pat.PatternType)
			fmt.Fprintf(sb, "  Occurrences: %d | Relevance: %.2f\n", pat.OccurrenceCount, pat.Score)
			if pat.TypicalMTTR != "" {
				fmt.Fprintf(sb, "  Typical MTTR: %s\n", pat.TypicalMTTR)
			}
			if pat.TypicalBlastRadius != "" {
				fmt.Fprintf(sb, "  Typical Blast Radius: %s\n", pat.TypicalBlastRadius)
			}
			if len(pat.CausalChain) > 0 {
				sb.WriteString("  Causal Chain:\n")
				sort.Slice(pat.CausalChain, func(i, j int) bool { return pat.CausalChain[i].Order < pat.CausalChain[j].Order })
				for _, link := range pat.CausalChain {
					fmt.Fprintf(sb, "    %d. %s", link.Order, link.Event)
					if link.TypicalDelay != "" {
						fmt.Fprintf(sb, " (delay: %s)", link.TypicalDelay)
					}
					sb.WriteString("\n")
				}
			}
			if pat.TriggerEvent != "" {
				fmt.Fprintf(sb, "  Trigger: %s\n", pat.TriggerEvent)
			}
			if len(pat.PreventionStrategies) > 0 {
				sb.WriteString("  Prevention Strategies:\n")
				for _, strat := range pat.PreventionStrategies {
					for _, line := range strings.Split(display.WrapText(strat, 76, ""), "\n") {
						fmt.Fprintf(sb, "    - %s\n", line)
					}
				}
			}
		}
	}

	if len(ctx.Knowledge.Procedures) > 0 {
		sb.WriteString("\nRelevant Procedures:\n")
		sb.WriteString(strings.Repeat("-", 80))
		sb.WriteString("\n")

		procedures := ctx.Knowledge.Procedures
		sort.Slice(procedures, func(i, j int) bool { return procedures[i].Score > procedures[j].Score })

		for _, proc := range procedures {
			fmt.Fprintf(sb, "\n%s\n", proc.Title)
			fmt.Fprintf(sb, "  Effectiveness: %.2f | Applied: %d times (%d successful)\n",
				proc.EffectivenessScore, proc.AppliedCount, proc.SuccessCount)
			fmt.Fprintf(sb, "  Relevance: %.2f\n", proc.Score)
			if len(proc.RelatedControls) > 0 {
				fmt.Fprintf(sb, "  Related Controls: %s\n", strings.Join(proc.RelatedControls, ", "))
			}
		}
	}

	if len(ctx.Knowledge.Facts) > 0 {
		sb.WriteString("\nRelevant Facts:\n")
		sb.WriteString(strings.Repeat("-", 80))
		sb.WriteString("\n")

		facts := ctx.Knowledge.Facts
		sort.Slice(facts, func(i, j int) bool { return facts[i].Score > facts[j].Score })

		for _, fact := range facts {
			fmt.Fprintf(sb, "\n- %s\n", display.WrapText(fact.Content, 76, ""))
			fmt.Fprintf(sb, "  Confidence: %.2f | Validation: %s | Relevance: %.2f\n",
				fact.Confidence, fact.ValidationStatus, fact.Score)
		}
	}
}
