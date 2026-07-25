package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/config"
	"github.com/revelara-ai/rvl-cli/internal/display"
)

// Risk represents a risk in the system.
//
// po-p3xur: this struct was previously a narrow hand-rolled shape that
// silently stripped spec-defined fields (corroborating_incidents,
// score_breakdown, latest_dismissal, stpa_provenance, generated_matcher,
// score_analysis, graph_multiplier) from the JSON output. Until the CLI
// migrates to a generated client package, we widen by carrying the raw
// payload alongside the typed view via the Raw field; `rvl risk show
// --format=json` re-emits Raw so users get the full server payload
// regardless of which fields are typed here today.
type Risk struct {
	ID            string   `json:"id"`
	RiskCode      string   `json:"risk_code"`
	Title         string   `json:"title"`
	Category      string   `json:"category"`
	Score         int      `json:"score"`
	Status        string   `json:"status"`
	Services      []string `json:"linked_services"`
	ControlCodes  []string `json:"control_codes,omitempty"`
	StaleSince    string   `json:"stale_since,omitempty"`
	LastSeenAt    string   `json:"last_seen_at,omitempty"`
	ResolvedAt    string   `json:"resolved_at,omitempty"`
	UCAType       string   `json:"uca_type,omitempty"`
	CausalFactors []string `json:"causal_factors,omitempty"`
	LossScenario  string   `json:"loss_scenario,omitempty"`
}

// RiskDetail represents detailed risk information
type RiskDetail struct {
	Risk
	MappedControls []MappedControl `json:"mapped_controls,omitempty"`
	Narrative      string          `json:"narrative,omitempty"`

	// po-p3xur / risk-context-parity: typed parity fields for the full
	// `rvl risk context` render. These are additive; `rvl risk show
	// --format=json` still echoes the raw server body, so typing them here
	// does not narrow the JSON output.
	Likelihood             string               `json:"likelihood,omitempty"`
	Impact                 string               `json:"impact,omitempty"`
	Trend                  string               `json:"trend,omitempty"`
	PlainSummary           string               `json:"plain_summary,omitempty"`
	ReadOnly               bool                 `json:"read_only,omitempty"`
	SourceIntelligenceTier string               `json:"source_intelligence_tier,omitempty"`
	RiskClass              string               `json:"risk_class,omitempty"`
	ResolutionReason       string               `json:"resolution_reason,omitempty"`
	ConstraintType         string               `json:"constraint_type,omitempty"`
	EvidenceStatus         string               `json:"evidence_status,omitempty"`
	GraphMultiplier        float64              `json:"graph_multiplier,omitempty"`
	CreatedAt              string               `json:"created_at,omitempty"`
	UpdatedAt              string               `json:"updated_at,omitempty"`
	LinkedIncidents        []string             `json:"linked_incidents,omitempty"`
	RelatedFindings        []RelatedFindingItem `json:"related_findings,omitempty"`
	Substantiation         json.RawMessage      `json:"substantiation,omitempty"`

	CorroboratingIncidents []CorroboratingIncidentItem `json:"corroborating_incidents,omitempty"`
	ScoreBreakdown         *ScoreBreakdown             `json:"score_breakdown,omitempty"`
	LatestDismissal        *LatestDismissal            `json:"latest_dismissal,omitempty"`
	STPAProvenance         *STPAProvenanceData         `json:"stpa_provenance,omitempty"`
	GeneratedMatcher       *GeneratedMatcherRef        `json:"generated_matcher,omitempty"`
}

// MappedControl represents a control mapped to a risk
type MappedControl struct {
	ControlCode string `json:"control_code"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category"`
	Type        string `json:"type"`
	Objective   string `json:"objective,omitempty"`
	// po-p3xur: keep evidence / weight / treatment fields the server
	// includes in MappedControl so they round-trip through --format=json.
	Weight                int                  `json:"weight,omitempty"`
	Treatment             string               `json:"treatment,omitempty"`
	ExpectedEvidenceTypes []string             `json:"expected_evidence_types,omitempty"`
	Evidence              []ControlEvidenceRef `json:"evidence,omitempty"`
}

// ListRisksResponse represents the response from listing risks.
//
// po-6wrlt: the spec declares page and limit as required; previously the
// CLI struct silently dropped them. Now they round-trip so the
// truncation-warning logic in CmdRiskReady (po-eedub) and the table
// renderer can use the server's effective values.
type ListRisksResponse struct {
	Risks []Risk `json:"risks"`
	Total int    `json:"total"`
	Page  int    `json:"page"`
	Limit int    `json:"limit"`
}

// RiskContextResponse represents the full context for a risk.
//
// po-cvy1t: score_analysis and graph_multiplier are populated by the
// server but were silently stripped by the prior hand-rolled struct.
// We keep them as json.RawMessage so the CLI doesn't need to mirror
// every analyzer/multiplier substructure to faithfully echo the full
// payload via --format=json.
//
// po-foyko: the server-side field was renamed from `score_breakdown`
// to `score_factors` (the `score_breakdown` key now refers to the
// Path5Breakdown object on RiskDetailResponse, not this array of
// contributing factors). We accept both keys during the transition so
// older servers continue to work; new servers will only emit the new
// key.
type RiskContextResponse struct {
	Risk            RiskDetail           `json:"risk"`
	Controls        []ControlContextItem `json:"controls"`
	Knowledge       KnowledgeContextResp `json:"knowledge"`
	ServiceContext  *ServiceContextResp  `json:"service_context,omitempty"`
	ScoreFactors    []ScoreFactorResp    `json:"score_factors,omitempty"`
	ScoreFactorsOld []ScoreFactorResp    `json:"score_breakdown,omitempty"` // pre-po-foyko alias
	ScoreAnalysis       json.RawMessage  `json:"score_analysis,omitempty"`
	GraphMultiplier     json.RawMessage  `json:"graph_multiplier,omitempty"`
	GroundingProvenance string           `json:"grounding_provenance,omitempty"`
}

// ControlContextItem represents a control with its context
type ControlContextItem struct {
	Control          MappedControl         `json:"control"`
	ExistingEvidence []ContextEvidenceItem `json:"existing_evidence"`
	EvidenceGaps     []string              `json:"evidence_gaps"`
}

// ContextEvidenceItem represents evidence in a context
type ContextEvidenceItem struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	URL         string `json:"url_or_identifier,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
}

// KnowledgeContextResp represents knowledge context
type KnowledgeContextResp struct {
	Patterns   []PatternItem   `json:"patterns"`
	Procedures []ProcedureItem `json:"procedures"`
	Facts      []FactItem      `json:"facts"`
}

// PatternItem represents a pattern in knowledge context
type PatternItem struct {
	Title                string      `json:"title"`
	PatternType          string      `json:"pattern_type"`
	CausalChain          []ChainLink `json:"causal_chain,omitempty"`
	TriggerEvent         string      `json:"trigger_event,omitempty"`
	OccurrenceCount      int         `json:"occurrence_count"`
	TypicalMTTR          string      `json:"typical_mttr,omitempty"`
	TypicalBlastRadius   string      `json:"typical_blast_radius,omitempty"`
	PreventionStrategies []string    `json:"prevention_strategies,omitempty"`
	Score                float64     `json:"score"`
}

// ChainLink represents a link in a causal chain
type ChainLink struct {
	Order        int    `json:"order"`
	Event        string `json:"event"`
	TypicalDelay string `json:"typical_delay,omitempty"`
}

// ProcedureItem represents a procedure in knowledge context
type ProcedureItem struct {
	Title              string   `json:"title"`
	EffectivenessScore float64  `json:"effectiveness_score"`
	AppliedCount       int      `json:"applied_count"`
	SuccessCount       int      `json:"success_count"`
	RelatedControls    []string `json:"related_controls,omitempty"`
	Score              float64  `json:"score"`
}

// FactItem represents a fact in knowledge context
type FactItem struct {
	Content          string  `json:"content"`
	Confidence       float64 `json:"confidence"`
	ValidationStatus string  `json:"validation_status"`
	Score            float64 `json:"score"`
}

// ServiceContextResp represents service context
type ServiceContextResp struct {
	ServiceName string               `json:"service_name"`
	Tier        string               `json:"tier,omitempty"`
	Incidents   *IncidentHistoryResp `json:"incidents,omitempty"`
}

// IncidentHistoryResp represents incident history for a service
type IncidentHistoryResp struct {
	TotalIncidents  int    `json:"total_incidents"`
	Last30Days      int    `json:"last_30_days"`
	Last90Days      int    `json:"last_90_days"`
	CriticalCount   int    `json:"critical_count"`
	HighCount       int    `json:"high_count"`
	MostRecentTitle string `json:"most_recent_title,omitempty"`
	AverageMTTR     *int   `json:"average_mttr,omitempty"`
}

// ScoreFactorResp represents a factor contributing to a risk score
type ScoreFactorResp struct {
	Description string `json:"description"`
	Points      int    `json:"points"`
	Source      string `json:"source"`
}

// CompoundRiskSummary is the shape returned by GET /api/v1/compound-risks list.
type CompoundRiskSummary struct {
	ID           string   `json:"id"`
	RiskCode     string   `json:"risk_code"`
	Title        string   `json:"title"`
	Category     string   `json:"category"`
	Score        int      `json:"score"`
	Status       string   `json:"status"`
	Likelihood   string   `json:"likelihood"`
	Impact       string   `json:"impact"`
	Narrative    string   `json:"narrative"`
	Services     []string `json:"linked_services"`
	ControlCodes []string `json:"control_codes,omitempty"`
	LastSeenAt   string   `json:"last_seen_at,omitempty"`
}

// CompoundRuleDetail is the triggering rule in a compound risk detail response.
type CompoundRuleDetail struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	Description             *string  `json:"description,omitempty"`
	ControlCodes            []string `json:"control_codes"`
	MinControlCount         int      `json:"min_control_count"`
	BaseInteractionSeverity int      `json:"base_interaction_severity"`
	Rationale               *string  `json:"rationale,omitempty"`
}

// ConstituentRiskSummary is a constituent risk within a compound risk detail.
type ConstituentRiskSummary struct {
	ID           string   `json:"id"`
	RiskCode     string   `json:"risk_code"`
	Title        string   `json:"title"`
	Status       string   `json:"status"`
	ControlCodes []string `json:"control_codes"`
	Service      string   `json:"service"`
	Services     []string `json:"services,omitempty"`
	Score        int      `json:"score"`
	LastSeenAt   string   `json:"last_seen_at,omitempty"`
}

// CompoundRiskDetailResponse is the shape returned by GET /api/v1/compound-risks/{id}.
type CompoundRiskDetailResponse struct {
	Risk         CompoundRiskSummary      `json:"risk"`
	Rule         CompoundRuleDetail       `json:"rule"`
	Constituents []ConstituentRiskSummary `json:"constituents"`
}

// CmdRisk is the main dispatcher for risk commands
func CmdRisk(args []string) {
	if cliutil.WantsHelp(args) {
		printRiskUsage()
		return
	}
	if len(args) == 0 {
		printRiskUsage()
		os.Exit(cliutil.ExitUsage)
	}

	switch args[0] {
	case "list":
		CmdRiskList(args[1:])
	case "show":
		CmdRiskShow(args[1:])
	case "context":
		CmdRiskContext(args[1:])
	case "stale":
		CmdRiskStale(args[1:])
	case "resolve":
		CmdRiskResolve(args[1:])
	case "accept":
		CmdRiskAccept(args[1:])
	case "ready":
		CmdRiskReady(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown risk command: %s\n", args[0])
		printRiskUsage()
		os.Exit(cliutil.ExitUsage)
	}
}

func printRiskUsage() {
	fmt.Println(`Usage: rvl risk <command> [options]

Commands:
  list                    List all risks in the register
  ready                   Top unresolved risks ranked by score (highest value first)
  show <risk-code>        Show detailed information about a specific risk
  context <risk-code>     Show full context (controls, knowledge, service history)
  stale                   List risks marked as stale
  resolve <risk-code>     Mark a risk as resolved
  accept <risk-code>      Accept a risk (intentional decision to retain)

Options:
  --format <json|table>  Output format (default: table)
  --status <status>      Filter by status (for list command)
  --category <category>  Filter by category (for list/ready commands)
  --service <name>       Filter by linked service (for list/ready commands)
  --limit <n>            Number of results (list default: 1000, ready default: 10)

Examples:
  rvl risk list
  rvl risk list --status applicable --service checkout-api
  rvl risk list --limit 50
  rvl risk ready
  rvl risk ready --limit 20 --category change_management
  rvl risk show R-001
  rvl risk context R-001
  rvl risk resolve R-001
  rvl risk resolve R-001 --reason "Fixed in deploy 42" --format=json
  rvl risk show CR-001
  rvl risk context CR-001
  rvl risk resolve CR-001`)
}

// riskListArgs holds the parsed flag set for `rvl risk list`.
type riskListArgs struct {
	status, category, service, format string
	limit                             int
}

// parseRiskListArgs parses the flags for `rvl risk list`. Returns an
// error for unknown flags, missing values, or invalid --limit values so
// the caller can exit with the usage-error code before any config or
// network work happens.
//
// po-cj4s7: --limit is user-settable (default 1000, the server cap).
// Previously the CLI hardcoded limit=1000 while the vendored agent docs
// taught --limit=50; the flag was silently swallowed.
func parseRiskListArgs(args []string) (riskListArgs, error) {
	parsed := riskListArgs{limit: 1000}
	setLimit := func(val string) error {
		n, perr := strconv.Atoi(val)
		if perr != nil || n < 1 {
			return fmt.Errorf("--limit expects a positive integer, got %q", val)
		}
		parsed.limit = n
		return nil
	}
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--status" && i+1 < len(args):
			parsed.status = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--status="):
			parsed.status = strings.TrimPrefix(args[i], "--status=")
		case args[i] == "--category" && i+1 < len(args):
			parsed.category = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--category="):
			parsed.category = strings.TrimPrefix(args[i], "--category=")
		case args[i] == "--service" && i+1 < len(args):
			parsed.service = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--service="):
			parsed.service = strings.TrimPrefix(args[i], "--service=")
		case args[i] == "--format" && i+1 < len(args):
			parsed.format = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--format="):
			parsed.format = strings.TrimPrefix(args[i], "--format=")
		case args[i] == "--limit" && i+1 < len(args):
			if err := setLimit(args[i+1]); err != nil {
				return parsed, err
			}
			i++
		case strings.HasPrefix(args[i], "--limit="):
			if err := setLimit(strings.TrimPrefix(args[i], "--limit=")); err != nil {
				return parsed, err
			}
		case args[i] == "--status" || args[i] == "--category" || args[i] == "--service" || args[i] == "--format" || args[i] == "--limit":
			return parsed, fmt.Errorf("%s requires a value", args[i])
		case strings.HasPrefix(args[i], "-"):
			return parsed, fmt.Errorf("unknown flag: %s", args[i])
		default:
			return parsed, fmt.Errorf("unexpected argument: %q", args[i])
		}
	}
	return parsed, nil
}

// CmdRiskList lists all risks in the register
func CmdRiskList(args []string) {
	parsed, perr := parseRiskListArgs(args)
	if perr != nil {
		fmt.Fprintln(os.Stderr, perr)
		fmt.Fprintln(os.Stderr, "Run 'rvl risk --help' for usage.")
		os.Exit(cliutil.ExitUsage)
	}
	format := parsed.format

	cfg := api.LoadAndResolveConfig()

	// po-2msnd: build the query string via url.Values so service names with
	// '&', '=', or '%' don't smuggle extra params or trigger backend
	// percent-decoding errors.
	q := url.Values{}
	q.Set("limit", strconv.Itoa(parsed.limit))
	if parsed.status != "" {
		q.Set("status", parsed.status)
	}
	if parsed.category != "" {
		q.Set("category", parsed.category)
	}
	if parsed.service != "" {
		q.Set("service", parsed.service)
	}
	endpoint := cfg.APIURL + "/api/v1/risks?" + q.Encode()

	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching risks: %v\n", err)
		os.Exit(1)
	}

	var resp ListRisksResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		fmt.Println(string(body))
		return
	}

	if len(resp.Risks) == 0 {
		fmt.Println("No risks found.")
		return
	}

	fmt.Printf("Total Risks: %d\n\n", resp.Total)
	fmt.Printf("%-10s %-12s %-8s %-20s %-50s\n", "CODE", "STATUS", "SCORE", "CATEGORY", "TITLE")
	fmt.Println(strings.Repeat("-", 110))

	for _, r := range resp.Risks {
		statusStr := display.FormatStatus(r.Status)
		title := r.Title
		if len(title) > 47 {
			title = title[:47] + "..."
		}
		fmt.Printf("%-10s %-12s %-8d %-20s %-50s\n",
			r.RiskCode, statusStr, r.Score, r.Category, title)
	}

	// po-eedub: warn when the server returned a truncated result so the
	// user knows they're seeing the first N by sort, not all matches.
	if resp.Total > len(resp.Risks) {
		fmt.Fprintf(os.Stderr,
			"\nNote: showing first %d of %d total risks. Raise --limit or use --status / --category / --service to narrow.\n",
			len(resp.Risks), resp.Total)
	}
}

// CmdRiskReady shows the top unresolved risks ranked by score (highest value first).
// "Ready" means the risk has status "applicable" - the polaris API emits
// applicable / accepted / mitigated as the canonical lifecycle (post
// po-rf63t / po-072n2); the prior comment claiming "detected" was the
// only open status was stale and the filter below returned nothing in
// production because no row ever has status="detected".
func CmdRiskReady(args []string) {
	var categoryFilter, serviceFilter, format string
	limit := 10
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--category" && i+1 < len(args):
			categoryFilter = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--category="):
			categoryFilter = strings.TrimPrefix(args[i], "--category=")
		case args[i] == "--service" && i+1 < len(args):
			serviceFilter = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--service="):
			serviceFilter = strings.TrimPrefix(args[i], "--service=")
		case args[i] == "--limit" && i+1 < len(args):
			// po-hu71i: reject non-numeric / non-positive --limit
			// with a clear error rather than silently falling back
			// to the default. Typos used to be invisible.
			n, perr := strconv.Atoi(args[i+1])
			if perr != nil || n < 1 {
				fmt.Fprintf(os.Stderr, "Error: --limit expects a positive integer, got %q\n", args[i+1])
				os.Exit(cliutil.ExitUsage)
			}
			limit = n
			i++
		case strings.HasPrefix(args[i], "--limit="):
			n, perr := strconv.Atoi(strings.TrimPrefix(args[i], "--limit="))
			if perr != nil || n < 1 {
				fmt.Fprintf(os.Stderr, "Error: --limit expects a positive integer, got %q\n", strings.TrimPrefix(args[i], "--limit="))
				os.Exit(cliutil.ExitUsage)
			}
			limit = n
		case args[i] == "--format" && i+1 < len(args):
			format = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--format="):
			format = strings.TrimPrefix(args[i], "--format=")
		default:
			// po-cj4s7: unknown flags must error, not silently no-op.
			cliutil.ExitUnknownFlag(args[i], "rvl risk")
		}
	}

	cfg := api.LoadAndResolveConfig()

	// Fetch risks sorted by score descending.
	// po-2msnd: URL-encode query params via url.Values so filter values
	// with '&', '=', or '%' can't smuggle extra params.
	q := url.Values{}
	q.Set("limit", "1000")
	q.Set("sort_by", "score")
	q.Set("sort_order", "desc")
	if categoryFilter != "" {
		q.Set("category", categoryFilter)
	}
	if serviceFilter != "" {
		q.Set("service", serviceFilter)
	}
	endpoint := cfg.APIURL + "/api/v1/risks?" + q.Encode()

	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching risks: %v\n", err)
		os.Exit(1)
	}

	var resp ListRisksResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	// po-eedub: the server caps every request at limit=1000. If the
	// tenant has more than 1000 risks the score-desc ranking is computed
	// on a truncated set and "ready" surfaces the wrong top-N. We can't
	// fix that purely client-side, but we can warn loudly.
	if resp.Total > len(resp.Risks) {
		fmt.Fprintf(os.Stderr,
			"Warning: tenant has %d risks but the server returned only %d (capped at limit=1000). 'ready' ranking may be incomplete; tighten --category/--service to narrow.\n",
			resp.Total, len(resp.Risks))
	}

	// Filter to open statuses only. The polaris API emits applicable /
	// accepted / mitigated; "applicable" is the unaddressed-open state,
	// which is the only one a "ready" remediation queue cares about.
	// "accepted" is intentionally excluded so accepted-risk acknowledgement
	// doesn't keep surfacing items.
	var ready []Risk
	for _, r := range resp.Risks {
		if r.Status == "applicable" {
			ready = append(ready, r)
		}
	}

	if format == "json" {
		// po-9a07e: emit the wrapped {risks, total} shape so jq
		// pipelines have one schema across `risk list` and `risk ready`.
		// Previously this emitted a bare array.
		out := ready
		if len(out) > limit {
			out = out[:limit]
		}
		wrapped := ListRisksResponse{
			Risks: out,
			Total: len(ready),
			Page:  1,
			Limit: limit,
		}
		jsonBytes, jerr := json.MarshalIndent(wrapped, "", "  ")
		if jerr != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", jerr)
			os.Exit(1)
		}
		fmt.Println(string(jsonBytes))
		return
	}

	if len(ready) == 0 {
		fmt.Println("No unresolved risks ready for remediation.")
		return
	}

	showing := len(ready)
	if showing > limit {
		showing = limit
	}

	fmt.Printf("Ready Risks: showing top %d of %d unresolved\n\n", showing, len(ready))
	fmt.Printf("%-6s %-10s %-5s %-14s %-18s %s\n",
		"#", "CODE", "SCORE", "PRIORITY", "CATEGORY", "TITLE")
	fmt.Println(strings.Repeat("-", 100))

	for i, r := range ready {
		if i >= limit {
			break
		}
		priority := classifyPriority(r.Score)
		title := r.Title
		if len(title) > 42 {
			title = title[:42] + "..."
		}
		cat := display.FormatCategory(r.Category)
		if len(cat) > 18 {
			cat = cat[:18]
		}
		fmt.Printf("%-6d %-10s %-5d %-14s %-18s %s\n",
			i+1, r.RiskCode, r.Score, priority, cat, title)
	}

	if len(ready) > limit {
		fmt.Printf("\n  ... %d more unresolved risks (use --limit to see more)\n", len(ready)-limit)
	}
}

func classifyPriority(score int) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// isCompoundCode reports whether code is a compound risk code (CR-XXX prefix).
func isCompoundCode(code string) bool {
	return strings.HasPrefix(code, "CR-")
}

// fetchCompoundRiskDetail looks up a compound risk by its CR-XXX code and
// returns the full detail response (rule + constituents). It makes two
// requests: one to list compound risks (to resolve the CR-XXX code to a UUID),
// then one to fetch the detail.
func fetchCompoundRiskDetail(cfg *config.Config, code string) (*CompoundRiskDetailResponse, []byte, error) {
	listBody, err := api.MakeAPIRequest(cfg, "GET", cfg.APIURL+"/api/v1/compound-risks", nil)
	if err != nil {
		return nil, nil, err
	}
	var list []CompoundRiskSummary
	if err := json.Unmarshal(listBody, &list); err != nil {
		return nil, nil, fmt.Errorf("parsing compound risk list: %w", err)
	}
	var id string
	for _, r := range list {
		if r.RiskCode == code {
			id = r.ID
			break
		}
	}
	if id == "" {
		return nil, nil, fmt.Errorf("compound risk not found: %s (run `rvl risk list` to verify the code)", code)
	}
	detailBody, err := api.MakeAPIRequest(cfg, "GET", cfg.APIURL+"/api/v1/compound-risks/"+id, nil)
	if err != nil {
		return nil, nil, err
	}
	var detail CompoundRiskDetailResponse
	if err := json.Unmarshal(detailBody, &detail); err != nil {
		return nil, nil, fmt.Errorf("parsing compound risk detail: %w", err)
	}
	return &detail, detailBody, nil
}

// CmdRiskShow shows detailed information about a specific risk
func CmdRiskShow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk show <risk-code> [--format=json]")
		os.Exit(cliutil.ExitUsage)
	}

	// po-2sn1o: --format=json must short-circuit table rendering so
	// /rvl:fix's jq pipeline gets a parseable body. Previously this
	// flag was advertised in usage but silently ignored.
	var (
		positional []string
		format     string
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		default:
			if strings.HasPrefix(args[i], "--format=") {
				format = strings.TrimPrefix(args[i], "--format=")
			} else if strings.HasPrefix(args[i], "-") {
				cliutil.ExitUnknownFlag(args[i], "rvl risk")
			} else {
				positional = append(positional, args[i])
			}
		}
	}
	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk show <risk-code> [--format=json]")
		os.Exit(cliutil.ExitUsage)
	}

	cfg := api.LoadAndResolveConfig()

	// Compound risks live at /api/v1/compound-risks, not /api/v1/risks.
	if isCompoundCode(positional[0]) {
		detail, rawBody, err := fetchCompoundRiskDetail(cfg, positional[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching compound risk: %v\n", err)
			os.Exit(1)
		}
		if format == "json" {
			fmt.Println(string(rawBody))
			return
		}
		printCompoundRiskShow(detail)
		return
	}

	// po-eedub: GET /api/v1/risks/{id} now accepts R-XXX codes
	// (po-bcs5c), so pass the user's input through directly instead of
	// calling FindRiskIDByCode. The old indirection issued a list-all
	// request capped at limit=1000 and produced false "risk not found"
	// errors for tenants with >1000 risks.
	endpoint := cfg.APIURL + "/api/v1/risks/" + url.PathEscape(positional[0])
	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching risk: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		fmt.Println(string(body))
		return
	}

	var risk RiskDetail
	if err := json.Unmarshal(body, &risk); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nRisk: %s\n", risk.RiskCode)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Title:    %s\n", risk.Title)
	fmt.Printf("Status:   %s\n", display.FormatStatus(risk.Status))
	fmt.Printf("Category: %s\n", risk.Category)
	fmt.Printf("Score:    %d\n", risk.Score)

	if len(risk.Services) > 0 {
		fmt.Printf("Services: %s\n", strings.Join(risk.Services, ", "))
	}

	if risk.LastSeenAt != "" {
		fmt.Printf("Last Seen: %s\n", risk.LastSeenAt)
	}
	if risk.StaleSince != "" {
		fmt.Printf("Stale Since: %s\n", risk.StaleSince)
	}
	if risk.ResolvedAt != "" {
		fmt.Printf("Resolved At: %s\n", risk.ResolvedAt)
	}

	// Prefer structured STPA fields from API JSON; fall back to narrative parsing
	hasStructuredSTPA := risk.UCAType != "" || len(risk.CausalFactors) > 0 || risk.LossScenario != ""
	if hasStructuredSTPA {
		fmt.Println("\nSTPA Causal Analysis:")
		fmt.Println(strings.Repeat("-", 80))
		if risk.UCAType != "" {
			fmt.Printf("  Unsafe Control Action: %s", display.FormatUCAType(risk.UCAType))
			if cat := display.FormatUCACategory(risk.UCAType); cat != "" {
				fmt.Printf("  (%s)", cat)
			}
			fmt.Println()
		}
		if risk.LossScenario != "" {
			fmt.Printf("  Loss Scenario: %s\n", risk.LossScenario)
		}
		if len(risk.CausalFactors) > 0 {
			fmt.Println("  Causal Factors:")
			for _, f := range risk.CausalFactors {
				wrapped := display.WrapText(f, 74, "      ")
				fmt.Printf("    > %s\n", wrapped)
			}
		}
	}

	if risk.Narrative != "" {
		// Strip STPA markers from narrative if we already showed structured fields
		narrativeText := risk.Narrative
		if hasStructuredSTPA {
			if stpa := display.ParseSTPAContext(risk.Narrative); stpa != nil && stpa.CleanNarrative != "" {
				narrativeText = stpa.CleanNarrative
			}
		}
		fmt.Println("\nNarrative:")
		fmt.Println(strings.Repeat("-", 80))
		wrapped := display.WrapText(narrativeText, 80, "")
		fmt.Println(wrapped)
	}

	if len(risk.MappedControls) > 0 {
		fmt.Println("\nMapped Controls:")
		fmt.Println(strings.Repeat("-", 80))
		for _, ctrl := range risk.MappedControls {
			fmt.Printf("  [%s] %s\n", ctrl.ControlCode, ctrl.Name)
			fmt.Printf("    Category: %s | Type: %s\n", ctrl.Category, display.FormatControlType(ctrl.Type))
			if ctrl.Description != "" {
				wrapped := display.WrapText(ctrl.Description, 76, "")
				lines := strings.Split(wrapped, "\n")
				for _, line := range lines {
					fmt.Printf("    %s\n", line)
				}
			}
			fmt.Println()
		}
	}
}

// CmdRiskContext shows full context for a risk
func CmdRiskContext(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk context <risk-code> [--format=json]")
		os.Exit(cliutil.ExitUsage)
	}

	// po-ljto0: --format=json must short-circuit table rendering. The
	// /rvl:fix slash command pipes this command's output through jq to
	// pull score_factors, controls, and graph_multiplier; until this
	// fix the flag was parsed only by `risk list` and `risk ready`.
	var (
		positional []string
		format     string
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		default:
			if strings.HasPrefix(args[i], "--format=") {
				format = strings.TrimPrefix(args[i], "--format=")
			} else if strings.HasPrefix(args[i], "-") {
				cliutil.ExitUnknownFlag(args[i], "rvl risk")
			} else {
				positional = append(positional, args[i])
			}
		}
	}
	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk context <risk-code> [--format=json]")
		os.Exit(cliutil.ExitUsage)
	}

	cfg := api.LoadAndResolveConfig()

	// Compound risks live at /api/v1/compound-risks, not /api/v1/risks.
	if isCompoundCode(positional[0]) {
		detail, rawBody, err := fetchCompoundRiskDetail(cfg, positional[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching risk context: %v\n", err)
			os.Exit(1)
		}
		if format == "json" {
			fmt.Println(string(rawBody))
			return
		}
		printCompoundRiskContext(detail)
		return
	}

	// po-eedub/po-bcs5c: both the detail and context endpoints accept R-XXX
	// codes directly, so no FindRiskIDByCode round trip is needed. Fetch the
	// detail (primary), context (grounding / service / score-factors /
	// knowledge), and stats (coverage) endpoints concurrently and compose
	// the full view. The detail endpoint is the source of parity with the
	// frontend Risk Detail page; context and stats are best-effort.
	base := cfg.APIURL + "/api/v1/risks/" + url.PathEscape(positional[0])
	var (
		wg                             sync.WaitGroup
		ctxBody, detailBody, statsBody []byte
		ctxErr, detailErr, statsErr    error
	)
	wg.Add(3)
	go func() { defer wg.Done(); ctxBody, ctxErr = api.MakeAPIRequest(cfg, "GET", base+"/context", nil) }()
	go func() { defer wg.Done(); detailBody, detailErr = api.MakeAPIRequest(cfg, "GET", base, nil) }()
	go func() {
		defer wg.Done()
		statsBody, statsErr = api.MakeAPIRequest(cfg, "GET", cfg.APIURL+"/api/v1/risks/stats", nil)
	}()
	wg.Wait()
	_ = statsErr // coverage is optional; coverageFrom tolerates an empty body

	if detailErr != nil && ctxErr != nil {
		fmt.Fprintf(os.Stderr, "Error fetching risk context: %v\n", firstErr(detailErr, ctxErr))
		os.Exit(1)
	}

	if format == "json" {
		out, jerr := composeRiskContextJSON(ctxBody, detailBody, coverageFrom(statsBody))
		if jerr != nil {
			fmt.Println(string(ctxBody))
			return
		}
		fmt.Println(string(out))
		return
	}

	view := RiskContextView{Coverage: coverageFrom(statsBody)}
	if ctxErr == nil {
		var c RiskContextResponse
		if json.Unmarshal(ctxBody, &c) == nil {
			view.Context = &c
		}
	}
	if detailErr == nil {
		var d RiskDetail
		if json.Unmarshal(detailBody, &d) == nil {
			view.Detail = &d
		}
	}
	if view.Context == nil && view.Detail == nil {
		fmt.Fprintln(os.Stderr, "Error parsing risk context response")
		os.Exit(1)
	}

	fmt.Print(renderRiskContext(view))
}

func printCompoundRiskShow(d *CompoundRiskDetailResponse) {
	r := d.Risk
	fmt.Printf("\nCompound Risk: %s\n", r.RiskCode)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Title:    %s\n", r.Title)
	fmt.Printf("Status:   %s\n", display.FormatStatus(r.Status))
	fmt.Printf("Category: compound_failure\n")
	fmt.Printf("Score:    %d (CRITICAL - interaction amplification)\n", r.Score)
	if len(r.Services) > 0 {
		fmt.Printf("Services: %s\n", strings.Join(r.Services, ", "))
	}
	if r.LastSeenAt != "" {
		fmt.Printf("Last Seen: %s\n", r.LastSeenAt)
	}

	fmt.Println("\nTriggering Rule:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("  Name:     %s\n", d.Rule.Name)
	fmt.Printf("  Controls: %s (min %d matched)\n", strings.Join(d.Rule.ControlCodes, ", "), d.Rule.MinControlCount)
	if d.Rule.Description != nil && *d.Rule.Description != "" {
		fmt.Printf("  Why:      %s\n", display.WrapText(*d.Rule.Description, 74, "            "))
	}

	if r.Narrative != "" {
		fmt.Println("\nNarrative:")
		fmt.Println(strings.Repeat("-", 80))
		fmt.Println(display.WrapText(r.Narrative, 80, ""))
	}

	if len(d.Constituents) > 0 {
		fmt.Println("\nConstituent Risks:")
		fmt.Println(strings.Repeat("-", 80))
		fmt.Printf("%-10s %-5s %-12s %s\n", "CODE", "SCORE", "STATUS", "TITLE")
		fmt.Println(strings.Repeat("-", 80))
		for _, c := range d.Constituents {
			title := c.Title
			if len(title) > 52 {
				title = title[:52] + "..."
			}
			fmt.Printf("%-10s %-5d %-12s %s\n", c.RiskCode, c.Score, c.Status, title)
		}
	}
}

func printCompoundRiskContext(d *CompoundRiskDetailResponse) {
	r := d.Risk
	fmt.Printf("\nCompound Risk Context: %s\n", r.RiskCode)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Title:    %s\n", r.Title)
	fmt.Printf("Status:   %s\n", display.FormatStatus(r.Status))
	fmt.Printf("Score:    %d (CRITICAL - interaction amplification)\n", r.Score)
	if len(r.Services) > 0 {
		fmt.Printf("Services: %s\n", strings.Join(r.Services, ", "))
	}

	fmt.Println("\nTriggering Rule:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("  Name:            %s\n", d.Rule.Name)
	fmt.Printf("  Control Pattern: %s\n", strings.Join(d.Rule.ControlCodes, ", "))
	fmt.Printf("  Minimum Matched: %d of %d controls\n", d.Rule.MinControlCount, len(d.Rule.ControlCodes))
	if d.Rule.Rationale != nil && *d.Rule.Rationale != "" {
		fmt.Println("\n  Rationale:")
		fmt.Printf("  %s\n", display.WrapText(*d.Rule.Rationale, 76, "  "))
	}

	if r.Narrative != "" {
		fmt.Println("\nNarrative:")
		fmt.Println(strings.Repeat("-", 80))
		fmt.Println(display.WrapText(r.Narrative, 80, ""))
	}

	if len(d.Constituents) > 0 {
		fmt.Println("\nConstituent Risks (all must be addressed to clear this compound risk):")
		fmt.Println(strings.Repeat("-", 80))
		fmt.Printf("%-10s %-5s %-15s %s\n", "CODE", "SCORE", "CONTROLS", "TITLE")
		fmt.Println(strings.Repeat("-", 80))
		for _, c := range d.Constituents {
			title := c.Title
			if len(title) > 48 {
				title = title[:48] + "..."
			}
			controls := strings.Join(c.ControlCodes, ", ")
			if len(controls) > 15 {
				controls = controls[:14] + "+"
			}
			fmt.Printf("%-10s %-5d %-15s %s\n", c.RiskCode, c.Score, controls, title)
		}
		fmt.Println()
		fmt.Println("  Tip: run `rvl risk context <R-XXX>` on any constituent for full remediation context.")
		fmt.Printf("  Tip: run `rvl risk resolve %s` to resolve all applicable constituents.\n", r.RiskCode)
	}
}

// CmdRiskStale lists risks marked as stale
func CmdRiskStale(args []string) {
	// po-cj4s7: this subcommand takes no flags; error instead of
	// silently ignoring whatever was passed.
	for _, arg := range args {
		cliutil.ExitUnknownFlag(arg, "rvl risk")
	}

	cfg := api.LoadAndResolveConfig()

	endpoint := cfg.APIURL + "/api/v1/risks/stale"
	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching stale risks: %v\n", err)
		os.Exit(1)
	}

	var resp ListRisksResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(resp.Risks) == 0 {
		fmt.Println("No stale risks found.")
		return
	}

	fmt.Printf("Stale Risks: %d\n\n", len(resp.Risks))
	fmt.Printf("%-10s %-20s %-20s %-50s\n", "CODE", "CATEGORY", "STALE SINCE", "TITLE")
	fmt.Println(strings.Repeat("-", 110))

	for _, r := range resp.Risks {
		title := r.Title
		if len(title) > 47 {
			title = title[:47] + "..."
		}
		staleSince := r.StaleSince
		if staleSince == "" {
			staleSince = "N/A"
		}
		fmt.Printf("%-10s %-20s %-20s %-50s\n", r.RiskCode, r.Category, staleSince, title)
	}
}

// CmdRiskResolve marks a risk as resolved
func CmdRiskResolve(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk resolve <risk-code> [--reason \"...\"] [--format=json]")
		os.Exit(cliutil.ExitUsage)
	}

	riskCode := args[0]
	reason := "Resolved"
	format := ""
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--reason" && i+1 < len(args):
			reason = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--reason="):
			reason = strings.TrimPrefix(args[i], "--reason=")
		case args[i] == "--format" && i+1 < len(args):
			format = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--format="):
			format = strings.TrimPrefix(args[i], "--format=")
		default:
			cliutil.ExitUnknownFlag(args[i], "rvl risk")
		}
	}

	cfg := api.LoadAndResolveConfig()

	// Compound risks auto-resolve when all constituent R-XXX risks are mitigated.
	// Resolve each applicable constituent individually.
	if isCompoundCode(riskCode) {
		detail, _, err := fetchCompoundRiskDetail(cfg, riskCode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching compound risk: %v\n", err)
			os.Exit(1)
		}
		resolved := 0
		for _, c := range detail.Constituents {
			if c.Status != "applicable" {
				continue
			}
			cEndpoint := cfg.APIURL + "/api/v1/risks/" + url.PathEscape(c.RiskCode) + "/resolve"
			cBody, _ := json.Marshal(map[string]string{"reason": reason})
			if _, cErr := api.MakeAPIRequest(cfg, "POST", cEndpoint, cBody); cErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to resolve %s: %v\n", c.RiskCode, cErr)
			} else {
				fmt.Printf("  Resolved constituent: %s - %s\n", c.RiskCode, c.Title)
				resolved++
			}
		}
		fmt.Printf("\nResolved %d of %d constituents for %s.\n", resolved, len(detail.Constituents), riskCode)
		fmt.Println("The compound risk will auto-resolve when all applicable constituents are mitigated.")
		return
	}

	riskID, err := FindRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding risk: %v\n", err)
		os.Exit(1)
	}

	endpoint := cfg.APIURL + "/api/v1/risks/" + riskID + "/resolve"
	reqBody, _ := json.Marshal(map[string]string{"reason": reason})
	resp, err := api.MakeAPIRequest(cfg, "POST", endpoint, reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving risk: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		fmt.Println(string(resp))
		return
	}

	fmt.Printf("Risk %s resolved successfully.\n", riskCode)
	var resolved Risk
	if err := json.Unmarshal(resp, &resolved); err == nil {
		if resolved.Status != "" {
			fmt.Printf("  Status:      %s\n", resolved.Status)
		}
		if resolved.ResolvedAt != "" {
			fmt.Printf("  Resolved At: %s\n", resolved.ResolvedAt)
		}
	}
}

// CmdRiskAccept accepts a risk (intentional decision to retain)
func CmdRiskAccept(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk accept <risk-code> [--reason \"...\"]")
		os.Exit(cliutil.ExitUsage)
	}

	riskCode := args[0]
	reason := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--reason" && i+1 < len(args) {
			reason = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--reason=") {
			reason = strings.TrimPrefix(args[i], "--reason=")
		} else {
			cliutil.ExitUnknownFlag(args[i], "rvl risk")
		}
	}

	cfg := api.LoadAndResolveConfig()

	riskID, err := FindRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding risk: %v\n", err)
		os.Exit(1)
	}

	endpoint := cfg.APIURL + "/api/v1/risks/" + riskID + "/status"
	statusBody, _ := json.Marshal(map[string]string{"status": "accepted", "reason": reason})
	_, err = api.MakeAPIRequest(cfg, "PATCH", endpoint, statusBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accepting risk: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Risk %s accepted successfully.\n", riskCode)
}

// FindRiskIDByCode finds a risk ID by its risk code
func FindRiskIDByCode(cfg *config.Config, riskCode string) (string, error) {
	endpoint := cfg.APIURL + "/api/v1/risks?limit=1000"
	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}

	var resp ListRisksResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("error parsing response: %w", err)
	}

	for _, r := range resp.Risks {
		if r.RiskCode == riskCode {
			return r.ID, nil
		}
	}

	return "", fmt.Errorf("risk not found: %s", riskCode)
}
