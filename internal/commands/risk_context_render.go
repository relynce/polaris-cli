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

// CorroboratingIncidentItem is a past incident that corroborates the risk.
type CorroboratingIncidentItem struct {
	ID           string  `json:"id"`
	ShortName    string  `json:"short_name,omitempty"`
	Title        string  `json:"title"`
	Severity     string  `json:"severity,omitempty"`
	IncidentDate string  `json:"incident_date,omitempty"`
	MTTRMinutes  *int    `json:"mttr_minutes,omitempty"`
	Relevance    float64 `json:"relevance"`
	SourceURL    string  `json:"source_url,omitempty"`
}

// ScoreBreakdown mirrors the Path5Breakdown L x I score-math receipt.
type ScoreBreakdown struct {
	LikelihoodFactor   int     `json:"likelihood_factor"`
	LikelihoodSource   string  `json:"likelihood_source,omitempty"`
	LikelihoodNotes    string  `json:"likelihood_notes,omitempty"`
	ImpactFactor       int     `json:"impact_factor"`
	ImpactSource       string  `json:"impact_source,omitempty"`
	ImpactNotes        string  `json:"impact_notes,omitempty"`
	BaseScore          int     `json:"base_score"`
	BusinessMultiplier float64 `json:"business_multiplier"`
	AdjustedScore      int     `json:"adjusted_score"`
}

// GeneratedMatcherRef references the auto-generated matcher for a risk.
type GeneratedMatcherRef struct {
	Slug             string   `json:"slug"`
	SourcePatternIDs []string `json:"source_pattern_ids,omitempty"`
}

// LatestDismissal is the most recent dismissal record on a risk.
type LatestDismissal struct {
	Reason      string `json:"reason"`
	Explanation string `json:"explanation,omitempty"`
}

// RelatedFindingItem is another risk sharing controls with this one.
type RelatedFindingItem struct {
	ID             string `json:"id"`
	RiskCode       string `json:"risk_code"`
	Title          string `json:"title"`
	PlainSummary   string `json:"plain_summary,omitempty"`
	Score          int    `json:"score"`
	SharedControls int    `json:"shared_controls"`
}

// ProvenanceEdge links a UCA or loss scenario to a control.
type ProvenanceEdge struct {
	ControlCode string  `json:"control_code"`
	ControlName string  `json:"control_name,omitempty"`
	Strength    float64 `json:"strength,omitempty"`
}

// UCARef is an unsafe control action with its control edges.
type UCARef struct {
	Type         string           `json:"type"`
	Content      string           `json:"content"`
	ControlEdges []ProvenanceEdge `json:"control_edges,omitempty"`
}

// LossScenarioRef is a loss scenario with its control edges.
type LossScenarioRef struct {
	Title        string           `json:"title,omitempty"`
	Description  string           `json:"description,omitempty"`
	ControlEdges []ProvenanceEdge `json:"control_edges,omitempty"`
}

// STPAProvenanceData is the STPA-inspired provenance for a risk.
type STPAProvenanceData struct {
	UCAs          []UCARef          `json:"ucas,omitempty"`
	LossScenarios []LossScenarioRef `json:"loss_scenarios,omitempty"`
}

// ControlEvidenceRef is one evidence item attached to a mapped control.
type ControlEvidenceRef struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	Description     string `json:"description,omitempty"`
	URLOrIdentifier string `json:"url_or_identifier,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
}

// SubstantiationFinding is one code/config finding that substantiates a risk.
// The wire shape is free-form (oneOf array/object); this models the common
// per-finding array element.
type SubstantiationFinding struct {
	Path        string `json:"path,omitempty"`
	Line        int    `json:"line,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
	Description string `json:"description,omitempty"`
	Kind        string `json:"kind,omitempty"`
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
	renderHeaderExtras(&sb, r)

	renderScoreMath(&sb, r)
	renderGroundingAndNarrative(&sb, v)
	renderSTPACausal(&sb, r)
	renderServicesLine(&sb, r)
	renderRelatedFindings(&sb, r)
	renderCorroborating(&sb, r)
	renderScoreFactors(&sb, v.Context)
	renderServiceContext(&sb, v.Context)
	renderControlCoverage(&sb, v)
	renderSubstantiation(&sb, r)
	renderDefenseLayers(&sb, v)
	renderSTPAProvenance(&sb, r)
	renderKnowledge(&sb, v.Context)
	renderHistory(&sb, r)
	renderCoverageGap(&sb, v)

	return sb.String()
}

// dateOnly trims an RFC3339 timestamp to its date component.
func dateOnly(s string) string {
	if len(s) >= 10 && s[4] == '-' && s[7] == '-' {
		return s[:10]
	}
	return s
}

func renderHeaderExtras(sb *strings.Builder, r *RiskDetail) {
	if r.PlainSummary != "" && r.PlainSummary != r.Title {
		fmt.Fprintf(sb, "Summary:  %s\n", r.PlainSummary)
	}
	if r.Trend != "" {
		fmt.Fprintf(sb, "Trend:    %s\n", r.Trend)
	}
	if r.Likelihood != "" && r.Impact != "" {
		fmt.Fprintf(sb, "Severity: %s (likelihood %s x impact %s)\n", classifyPriority(r.Score), r.Likelihood, r.Impact)
	}
	if r.GeneratedMatcher != nil && r.GeneratedMatcher.Slug != "" {
		fmt.Fprintf(sb, "Matcher:  %s", r.GeneratedMatcher.Slug)
		if n := len(r.GeneratedMatcher.SourcePatternIDs); n > 0 {
			fmt.Fprintf(sb, " (from %d pattern(s))", n)
		}
		sb.WriteString("\n")
	}
	if r.RiskClass != "" {
		fmt.Fprintf(sb, "Class:    %s\n", r.RiskClass)
	}
	if r.ReadOnly {
		if r.SourceIntelligenceTier != "" {
			fmt.Fprintf(sb, "Note:     read-only (%s intelligence)\n", r.SourceIntelligenceTier)
		} else {
			sb.WriteString("Note:     read-only\n")
		}
	}
}

func renderScoreMath(sb *strings.Builder, r *RiskDetail) {
	b := r.ScoreBreakdown
	if b == nil {
		return
	}
	sb.WriteString("\nScore Math:\n")
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	fmt.Fprintf(sb, "  Likelihood: %d", b.LikelihoodFactor)
	if b.LikelihoodSource != "" {
		fmt.Fprintf(sb, " (%s)", b.LikelihoodSource)
	}
	sb.WriteString("\n")
	if b.LikelihoodNotes != "" {
		fmt.Fprintf(sb, "    %s\n", display.WrapText(b.LikelihoodNotes, 74, "    "))
	}
	fmt.Fprintf(sb, "  Impact:     %d", b.ImpactFactor)
	if b.ImpactSource != "" {
		fmt.Fprintf(sb, " (%s)", b.ImpactSource)
	}
	sb.WriteString("\n")
	if b.ImpactNotes != "" {
		fmt.Fprintf(sb, "    %s\n", display.WrapText(b.ImpactNotes, 74, "    "))
	}
	fmt.Fprintf(sb, "  Base score: %d\n", b.BaseScore)
	if b.BusinessMultiplier != 0 && b.BusinessMultiplier != 1 {
		fmt.Fprintf(sb, "  Business x:  %.2f\n", b.BusinessMultiplier)
	}
	fmt.Fprintf(sb, "  Adjusted:   %d\n", b.AdjustedScore)
	if r.GraphMultiplier > 1.0 {
		fmt.Fprintf(sb, "  Graph amplification: x%.2f -> %d\n", r.GraphMultiplier, r.Score)
	}
}

func renderGroundingAndNarrative(sb *strings.Builder, v RiskContextView) {
	if v.Context != nil && v.Context.GroundingProvenance != "" {
		sb.WriteString("\nGrounding:\n")
		sb.WriteString(strings.Repeat("-", 80) + "\n")
		fmt.Fprintf(sb, "%s\n", display.WrapText(v.Context.GroundingProvenance, 80, ""))
	}
	r := v.risk()
	if r == nil || r.Narrative == "" {
		return
	}
	text := r.Narrative
	if stpa := display.ParseSTPAContext(r.Narrative); stpa != nil && stpa.CleanNarrative != "" {
		text = stpa.CleanNarrative
	}
	if text = strings.TrimSpace(text); text == "" {
		return
	}
	sb.WriteString("\nNarrative:\n")
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	fmt.Fprintf(sb, "%s\n", display.WrapText(text, 80, ""))
}

func renderServicesLine(sb *strings.Builder, r *RiskDetail) {
	if len(r.Services) > 0 {
		fmt.Fprintf(sb, "\nServices: %s\n", strings.Join(r.Services, ", "))
	}
}

func renderRelatedFindings(sb *strings.Builder, r *RiskDetail) {
	if len(r.RelatedFindings) == 0 {
		return
	}
	sb.WriteString("\nRelated Findings:\n")
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	for _, rf := range r.RelatedFindings {
		title := rf.Title
		if title == "" {
			title = rf.PlainSummary
		}
		fmt.Fprintf(sb, "  %s  %s (score %d, %d shared control(s))\n", rf.RiskCode, title, rf.Score, rf.SharedControls)
	}
}

func renderCorroborating(sb *strings.Builder, r *RiskDetail) {
	if len(r.CorroboratingIncidents) == 0 {
		return
	}
	sb.WriteString("\nCorroborating Incidents:\n")
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	for _, inc := range r.CorroboratingIncidents {
		if inc.ShortName != "" {
			fmt.Fprintf(sb, "\n%s  %s\n", inc.ShortName, inc.Title)
		} else {
			fmt.Fprintf(sb, "\n%s\n", inc.Title)
		}
		var meta []string
		if inc.Severity != "" {
			meta = append(meta, "severity "+inc.Severity)
		}
		if d := dateOnly(inc.IncidentDate); d != "" {
			meta = append(meta, d)
		}
		if inc.MTTRMinutes != nil {
			meta = append(meta, fmt.Sprintf("MTTR %dm", *inc.MTTRMinutes))
		}
		if inc.Relevance > 0 {
			meta = append(meta, fmt.Sprintf("relevance %.2f", inc.Relevance))
		}
		if len(meta) > 0 {
			fmt.Fprintf(sb, "  %s\n", strings.Join(meta, " | "))
		}
		if inc.SourceURL != "" {
			fmt.Fprintf(sb, "  source: %s\n", inc.SourceURL)
		}
	}
}

func renderSubstantiation(sb *strings.Builder, r *RiskDetail) {
	if len(r.Substantiation) == 0 {
		return
	}
	var findings []SubstantiationFinding
	if json.Unmarshal(r.Substantiation, &findings) != nil || len(findings) == 0 {
		return
	}
	sb.WriteString("\nSubstantiation Evidence:\n")
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	for _, f := range findings {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		if f.Severity != "" {
			fmt.Fprintf(sb, "\n[%s] %s\n", f.Severity, loc)
		} else {
			fmt.Fprintf(sb, "\n%s\n", loc)
		}
		if f.Description != "" {
			fmt.Fprintf(sb, "  %s\n", display.WrapText(f.Description, 76, "  "))
		}
		if f.Snippet != "" {
			lines := strings.Split(f.Snippet, "\n")
			for i, line := range lines {
				if i >= 5 {
					fmt.Fprintf(sb, "    ... (%d more line(s))\n", len(lines)-5)
					break
				}
				fmt.Fprintf(sb, "    %s\n", line)
			}
		}
	}
}

func controlTypes(v RiskContextView) []string {
	var out []string
	if v.Context != nil {
		for _, c := range v.Context.Controls {
			if c.Control.Type != "" {
				out = append(out, c.Control.Type)
			}
		}
	}
	if len(out) == 0 && v.Detail != nil {
		for _, c := range v.Detail.MappedControls {
			if c.Type != "" {
				out = append(out, c.Type)
			}
		}
	}
	return out
}

func renderDefenseLayers(sb *strings.Builder, v RiskContextView) {
	types := controlTypes(v)
	if len(types) == 0 {
		return
	}
	var prevention, detection, correction int
	for _, t := range types {
		switch strings.ToLower(t) {
		case "preventive":
			prevention++
		case "detective":
			detection++
		case "corrective":
			correction++
		}
	}
	covered := 0
	for _, n := range []int{prevention, detection, correction} {
		if n > 0 {
			covered++
		}
	}
	sb.WriteString("\nDefense-Layer Coverage:\n")
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	fmt.Fprintf(sb, "  Prevention: %d control(s)\n", prevention)
	fmt.Fprintf(sb, "  Detection:  %d control(s)\n", detection)
	fmt.Fprintf(sb, "  Correction: %d control(s)\n", correction)
	fmt.Fprintf(sb, "  Layers covered: %d/3\n", covered)
	if covered == 1 {
		sb.WriteString("  WARNING: single point of failure (only one defense layer)\n")
	}
}

func renderSTPAProvenance(sb *strings.Builder, r *RiskDetail) {
	p := r.STPAProvenance
	if p == nil || (len(p.UCAs) == 0 && len(p.LossScenarios) == 0) {
		return
	}
	sb.WriteString("\nSTPA Provenance (STPA-inspired):\n")
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	sb.WriteString("Adapted from Systems-Theoretic Process Analysis (Leveson, MIT). Findings are candidates.\n")
	for _, u := range p.UCAs {
		fmt.Fprintf(sb, "\n  UCA (%s): %s\n", display.FormatUCAType(u.Type), display.WrapText(u.Content, 72, "    "))
		renderProvenanceEdges(sb, u.ControlEdges)
	}
	for _, ls := range p.LossScenarios {
		fmt.Fprintf(sb, "\n  Loss scenario: %s\n", ls.Title)
		if ls.Description != "" {
			fmt.Fprintf(sb, "    %s\n", display.WrapText(ls.Description, 72, "    "))
		}
		renderProvenanceEdges(sb, ls.ControlEdges)
	}
}

func renderProvenanceEdges(sb *strings.Builder, edges []ProvenanceEdge) {
	for _, e := range edges {
		fmt.Fprintf(sb, "    -> %s", e.ControlCode)
		if e.ControlName != "" {
			fmt.Fprintf(sb, " %s", e.ControlName)
		}
		if e.Strength > 0 {
			fmt.Fprintf(sb, " (strength %.2f)", e.Strength)
		}
		sb.WriteString("\n")
	}
}

func renderHistory(sb *strings.Builder, r *RiskDetail) {
	hasResolution := r.ResolutionReason != ""
	hasDismissal := r.LatestDismissal != nil
	hasStale := r.StaleSince != ""
	hasMeta := r.CreatedAt != "" || r.UpdatedAt != ""
	if !hasResolution && !hasDismissal && !hasStale && !hasMeta {
		return
	}
	sb.WriteString("\nContext & History:\n")
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	if hasResolution {
		fmt.Fprintf(sb, "  Resolution: %s", r.ResolutionReason)
		if d := dateOnly(r.ResolvedAt); d != "" {
			fmt.Fprintf(sb, " (%s)", d)
		}
		sb.WriteString("\n")
	}
	if hasDismissal {
		fmt.Fprintf(sb, "  Previously dismissed: %s\n", r.LatestDismissal.Reason)
		if r.LatestDismissal.Explanation != "" {
			fmt.Fprintf(sb, "    %s\n", display.WrapText(r.LatestDismissal.Explanation, 74, "    "))
		}
	}
	if hasStale {
		fmt.Fprintf(sb, "  Stale since: %s\n", dateOnly(r.StaleSince))
	}
	if hasMeta {
		fmt.Fprintf(sb, "  Created: %s | Updated: %s\n", dateOnly(r.CreatedAt), dateOnly(r.UpdatedAt))
	}
}

func renderCoverageGap(sb *strings.Builder, v RiskContextView) {
	if v.Coverage == nil || v.Detail == nil {
		return
	}
	for _, cc := range v.Coverage.ByCategory {
		if !strings.EqualFold(cc.Category, v.Detail.Category) {
			continue
		}
		unconfigured := cc.Total - cc.Assessed
		if unconfigured < 0 {
			unconfigured = 0
		}
		sb.WriteString("\nAssessment Coverage:\n")
		sb.WriteString(strings.Repeat("-", 80) + "\n")
		fmt.Fprintf(sb, "  %s: %d of %d controls assessed (%d not yet configured)\n",
			display.FormatCategory(cc.Category), cc.Assessed, cc.Total, unconfigured)
		return
	}
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
		if r.ConstraintType != "" {
			fmt.Fprintf(sb, "  Constraint Type: %s\n", r.ConstraintType)
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

func renderControlCoverage(sb *strings.Builder, v RiskContextView) {
	ctx := v.Context
	if ctx == nil || len(ctx.Controls) == 0 {
		return
	}
	sb.WriteString("\nControl Coverage:\n")
	sb.WriteString(strings.Repeat("-", 80))
	sb.WriteString("\n")
	if r := v.risk(); r != nil && r.EvidenceStatus != "" {
		fmt.Fprintf(sb, "Evidence status: %s\n", display.FormatEvidenceStatus(r.EvidenceStatus))
	}
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
				if ev.URL != "" {
					fmt.Fprintf(sb, "      url: %s\n", ev.URL)
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
