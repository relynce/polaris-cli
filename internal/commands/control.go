package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/config"
	"github.com/revelara-ai/rvl-cli/internal/display"
)

// Control represents a reliability control from the catalog.
//
// po-iks58 / po-trn0m: the prior struct carried `implementation` and
// `risk_codes` fields the server has never emitted. Renders for both
// were always blank. The replacement is LinkedRisks, which the server
// now populates on the by-code path (po-fgi8u).
type Control struct {
	ID                    string             `json:"id"`
	ControlCode           string             `json:"control_code"`
	Name                  string             `json:"name"`
	Category              string             `json:"category"`
	Type                  string             `json:"type"`
	Objective             string             `json:"objective"`
	Description           string             `json:"description"`
	RiskStatement         string             `json:"risk_statement,omitempty"`
	TestDescription       string             `json:"test_description,omitempty"`
	Remediation           string             `json:"remediation,omitempty"`
	ExpectedEvidenceTypes []string           `json:"expected_evidence_types"`
	Treatment             string             `json:"treatment,omitempty"`
	Weight                int                `json:"weight"`
	LinkedRisks           []ControlLinkedRisk `json:"linked_risks,omitempty"`
}

// ControlLinkedRisk mirrors the server's apispec.ControlLinkedRisk
// (api/components/schemas/controls.yaml#/ControlLinkedRisk).
// The schema is additionalProperties:true server-side; only the
// fields the CLI renders are typed here.
type ControlLinkedRisk struct {
	RiskCode string `json:"risk_code"`
	Title    string `json:"title"`
	Score    int    `json:"score"`
	Status   string `json:"status,omitempty"`
}

// ListControlsResponse wraps the controls list response.
//
// po-6wrlt sibling: the spec declares page + limit as required, so
// the CLI struct carries them too (matches the J30 ListRisksResponse
// fix).
type ListControlsResponse struct {
	Controls []Control `json:"controls"`
	Total    int       `json:"total"`
	Page     int       `json:"page"`
	Limit    int       `json:"limit"`
}

// ControlScopeStatus mirrors the server's apispec.ControlScopeStatusResponse
// (po-9nxdr.2): the per-team breakdown plus the WORST-OF org rollup.
// `unknown_evidence` counts grandfathered rows flagged for re-scoping;
// they are never credited to any scope.
type ControlScopeStatus struct {
	ControlCode     string                   `json:"control_code"`
	OrgStatus       string                   `json:"org_status"`
	Teams           []ControlTeamScopeStatus `json:"teams"`
	UnknownEvidence int                      `json:"unknown_evidence"`
}

// ControlTeamScopeStatus is one team's row in the scope-status breakdown.
type ControlTeamScopeStatus struct {
	TeamSlug          string `json:"team_slug"`
	TeamName          string `json:"team_name"`
	Status            string `json:"status"`
	DirectEvidence    int    `json:"direct_evidence"`
	InheritedEvidence int    `json:"inherited_evidence"`
	GlobalEvidence    int    `json:"global_evidence"`
}

// fetchControlScopeStatus calls GET /api/v1/controls/by-code/{code}/scope-status
// with optional team/service filters. Returns the parsed response plus the
// raw body (for --format=json passthrough). An unknown team/service is a
// 400 whose message lists the org's known slugs/services — MakeAPIRequest
// surfaces that message verbatim, so callers must not swallow the error.
func fetchControlScopeStatus(cfg *config.Config, code, team, service string) (*ControlScopeStatus, []byte, error) {
	q := url.Values{}
	if team != "" {
		q.Set("team", team)
	}
	if service != "" {
		q.Set("service", service)
	}
	endpoint := cfg.APIURL + "/api/v1/controls/by-code/" + url.PathEscape(code) + "/scope-status"
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}
	resp, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		return nil, nil, err
	}
	var st ControlScopeStatus
	if err := json.Unmarshal(resp, &st); err != nil {
		return nil, nil, fmt.Errorf("parse scope-status response: %w", err)
	}
	return &st, resp, nil
}

// renderControlScopeStatus prints the per-team scope breakdown and the
// worst-of org rollup.
func renderControlScopeStatus(w io.Writer, st *ControlScopeStatus) {
	fmt.Fprintln(w, "Scope Status (per team):")
	if len(st.Teams) == 0 {
		fmt.Fprintln(w, "  (no teams in scope — the org has no teams yet, or the filter matched none)")
	} else {
		fmt.Fprintf(w, "  %-20s %-10s %7s %10s %7s\n", "TEAM", "STATUS", "DIRECT", "INHERITED", "GLOBAL")
		for _, t := range st.Teams {
			fmt.Fprintf(w, "  %-20s %-10s %7d %10d %7d\n",
				t.TeamSlug, t.Status, t.DirectEvidence, t.InheritedEvidence, t.GlobalEvidence)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Org status (worst-of): %s\n", st.OrgStatus)
	if st.UnknownEvidence > 0 {
		fmt.Fprintf(w, "Note: %d evidence record(s) have unknown scope (grandfathered; re-scope them — they are never credited to any team).\n",
			st.UnknownEvidence)
	}
}

// orgScopeSummaryLine returns the one-line org scope summary shown on a
// plain `rvl control show` when the control has scoped (non-global)
// evidence, or "" when everything is org-wide and there is nothing scoped
// to surface.
func orgScopeSummaryLine(st *ControlScopeStatus) string {
	if st == nil {
		return ""
	}
	scoped := st.UnknownEvidence > 0
	for _, t := range st.Teams {
		if t.DirectEvidence > 0 || t.InheritedEvidence > 0 {
			scoped = true
			break
		}
	}
	if !scoped {
		return ""
	}
	return fmt.Sprintf("Org scope status: %s (worst-of across %d teams; %d unknown-scope records; see --team/--service)",
		st.OrgStatus, len(st.Teams), st.UnknownEvidence)
}

// CmdControl dispatches control subcommands
func CmdControl(args []string) {
	if cliutil.WantsHelp(args) {
		printControlUsage()
		return
	}
	if len(args) == 0 {
		printControlUsage()
		os.Exit(cliutil.ExitUsage)
	}
	subcmd := args[0]
	switch subcmd {
	case "list":
		cmdControlList(args[1:])
	case "show":
		cmdControlShow(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown control command: %s\n", subcmd)
		printControlUsage()
		os.Exit(cliutil.ExitUsage)
	}
}

func printControlUsage() {
	fmt.Println(`rvl control - Query reliability controls catalog

Usage:
  rvl control <subcommand> [options]

Subcommands:
  list              List controls in the catalog
  show              Show control details by code

List Options:
  --category=<cat>  Filter by category (fault_tolerance, monitoring, change_management, etc.)
  --limit=<n>       Maximum results (default 200; server caps at 1000)
  --format=json     Emit machine-parseable JSON for slash-command pipelines

Show Options:
  --team=<slug>     Show the scope-status breakdown filtered to this team
  --service=<name>  Show the scope-status breakdown filtered to this service
  --format=json     Emit the raw server JSON

Examples:
  rvl control list
  rvl control list --category=fault_tolerance
  rvl control list --format=json | jq '.controls[].control_code'
  rvl control show RC-018
  rvl control show RC-018 --team=payments
  rvl control show RC-018 --team=platform --service=shared-postgres
  rvl control show RC-018 --format=json`)
}

func cmdControlList(args []string) {
	// po-81w0v: --format=json must short-circuit the table render so
	// slash-command jq pipelines can parse the body.
	// po-g5b3w: default raised from 50 -> 200 so the full catalog
	// returns on a no-arg list; the server now caps at 1000 (po-tjgtg).
	var (
		category, format string
		limit            = 200
	)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--category="):
			category = strings.TrimPrefix(arg, "--category=")
		case strings.HasPrefix(arg, "--limit="):
			val := strings.TrimPrefix(arg, "--limit=")
			n, perr := strconv.Atoi(val)
			if perr != nil || n < 1 {
				fmt.Fprintf(os.Stderr, "Error: --limit expects a positive integer, got %q\n", val)
				os.Exit(cliutil.ExitUsage)
			}
			limit = n
		case strings.HasPrefix(arg, "--format="):
			format = strings.TrimPrefix(arg, "--format=")
		case arg == "--limit":
			if i+1 < len(args) {
				n, perr := strconv.Atoi(args[i+1])
				if perr != nil || n < 1 {
					fmt.Fprintf(os.Stderr, "Error: --limit expects a positive integer, got %q\n", args[i+1])
					os.Exit(cliutil.ExitUsage)
				}
				limit = n
				i++
			}
		case arg == "--category":
			if i+1 < len(args) {
				category = args[i+1]
				i++
			}
		case arg == "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		default:
			// po-cj4s7: unknown flags must error, not silently no-op.
			cliutil.ExitUnknownFlag(arg, "rvl control")
		}
	}
	// po-i24do.11: validate --format so an invalid value errors instead of
	// silently rendering a table.
	if format != "" {
		if err := cliutil.ValidateFormat(format, "table", "json"); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(cliutil.ExitUsage)
		}
	}

	cfg := api.LoadAndResolveConfig()

	// po-2msnd sibling: use url.Values so category names with `&`/`%`
	// don't smuggle extra params.
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if category != "" {
		q.Set("category", category)
	}
	endpoint := cfg.APIURL + "/api/v1/controls?" + q.Encode()

	resp, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		// Re-emit the server body verbatim so the wrapped {controls,
		// total, page, limit} shape passes through to jq pipelines.
		fmt.Println(string(resp))
		return
	}

	var listResp ListControlsResponse
	if err := json.Unmarshal(resp, &listResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}
	if len(listResp.Controls) == 0 {
		if category != "" {
			// po-f3dqm: empty result with a category filter is almost
			// always a typo. Hint at the canonical category list so
			// the user doesn't assume the catalog is empty.
			fmt.Fprintln(os.Stderr, "No controls match the requested category.")
			fmt.Fprintln(os.Stderr, "Hint: run `rvl control list` (no filter) to see the catalog,")
			fmt.Fprintln(os.Stderr, "or check spelling - categories use underscore_case slugs.")
		} else {
			fmt.Println("No controls found.")
		}
		return
	}
	fmt.Printf("Found %d controls:\n\n", listResp.Total)
	for _, c := range listResp.Controls {
		typeBadge := display.FormatControlType(c.Type)
		fmt.Printf("%-8s %-14s %d/10 %-12s [%s] %s\n", c.ControlCode, typeBadge, c.Weight, display.FormatWeightTier(c.Weight), display.FormatCategory(c.Category), c.Name)
	}

	// po-g5b3w: warn loudly when the server truncated the result so
	// the user knows they're not seeing everything.
	if listResp.Total > len(listResp.Controls) {
		fmt.Fprintf(os.Stderr,
			"\nNote: showing %d of %d total controls. Use --limit (max 1000) or --category to narrow.\n",
			len(listResp.Controls), listResp.Total)
	}
}

func cmdControlShow(args []string) {
	// po-81w0v: --format=json on show too.
	// po-9nxdr.2: --team/--service render the scope-status breakdown.
	var (
		positional    []string
		format        string
		team, service string
	)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--format="):
			format = strings.TrimPrefix(arg, "--format=")
		case arg == "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--team="):
			team = strings.TrimPrefix(arg, "--team=")
		case arg == "--team":
			if i+1 < len(args) {
				team = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--service="):
			service = strings.TrimPrefix(arg, "--service=")
		case arg == "--service":
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "-"):
			cliutil.ExitUnknownFlag(arg, "rvl control")
		default:
			positional = append(positional, arg)
		}
	}
	// po-i24do.11: validate --format so an invalid value errors instead of
	// silently rendering a table.
	if format != "" {
		if err := cliutil.ValidateFormat(format, "table", "json"); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(cliutil.ExitUsage)
		}
	}
	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "Error: control code required")
		fmt.Fprintln(os.Stderr, "Usage: rvl control show <control-code> [--format=json]")
		os.Exit(cliutil.ExitUsage)
	}
	controlCode := positional[0]
	if strings.HasPrefix(controlCode, "R-") && !strings.HasPrefix(controlCode, "RC-") {
		fmt.Fprintf(os.Stderr, "Note: \"%s\" is a risk code, not a control code (RC-XXX).\n", controlCode)
		fmt.Fprintf(os.Stderr, "Use \"rvl risk show %s\" to see its mapped controls.\n", controlCode)
		os.Exit(cliutil.ExitUsage)
	}
	cfg := api.LoadAndResolveConfig()
	endpoint := cfg.APIURL + "/api/v1/controls/by-code/" + url.PathEscape(controlCode)
	resp, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// po-9nxdr.2: with scope flags the scope-status fetch is part of what
	// the user asked for, so its errors (including the 400 that lists known
	// team slugs / services) are fatal and surfaced verbatim.
	var (
		scopeStatus *ControlScopeStatus
		scopeRaw    []byte
	)
	if team != "" || service != "" {
		scopeStatus, scopeRaw, err = fetchControlScopeStatus(cfg, controlCode, team, service)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	if format == "json" {
		if scopeRaw != nil {
			// Combined envelope so jq pipelines get both bodies in one
			// document: {"control": <control>, "scope_status": <breakdown>}.
			combined, _ := json.Marshal(map[string]json.RawMessage{
				"control":      json.RawMessage(resp),
				"scope_status": json.RawMessage(scopeRaw),
			})
			fmt.Println(string(combined))
			return
		}
		fmt.Println(string(resp))
		return
	}

	var control Control
	if err := json.Unmarshal(resp, &control); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Control: %s - %s\n", control.ControlCode, control.Name)
	fmt.Printf("Category: %s\n", display.FormatCategory(control.Category))
	fmt.Printf("Type: %s\n", control.Type)
	fmt.Printf("Weight: %d/10 (%s)\n", control.Weight, display.FormatWeightTier(control.Weight))
	if control.Treatment != "" {
		fmt.Printf("Treatment: %s\n", control.Treatment)
	}
	if control.Description != "" {
		fmt.Println()
		fmt.Printf("Description:\n  %s\n", display.WrapText(control.Description, 78, "  "))
	}
	if control.Objective != "" {
		fmt.Println()
		fmt.Printf("Objective:\n  %s\n", display.WrapText(control.Objective, 78, "  "))
	}
	if control.RiskStatement != "" {
		fmt.Println()
		fmt.Printf("Risk Statement:\n  %s\n", display.WrapText(control.RiskStatement, 78, "  "))
	}
	if control.TestDescription != "" {
		fmt.Println()
		fmt.Printf("Test Description:\n  %s\n", display.WrapText(control.TestDescription, 78, "  "))
	}
	if control.Remediation != "" {
		fmt.Println()
		fmt.Printf("Remediation:\n  %s\n", display.WrapText(control.Remediation, 78, "  "))
	}
	if len(control.ExpectedEvidenceTypes) > 0 {
		fmt.Println()
		fmt.Printf("Expected Evidence: %s\n", strings.Join(control.ExpectedEvidenceTypes, ", "))
	}
	// po-iks58 / po-trn0m: render the linked_risks the server actually
	// emits (post po-fgi8u) instead of the dead `risk_codes` field.
	if len(control.LinkedRisks) > 0 {
		fmt.Println()
		codes := make([]string, 0, len(control.LinkedRisks))
		for _, r := range control.LinkedRisks {
			codes = append(codes, r.RiskCode)
		}
		fmt.Printf("Related Risks: %s\n", strings.Join(codes, ", "))
	}

	// po-9nxdr.2: scope-aware status. With --team/--service, render the
	// full per-team breakdown (already fetched above, errors fatal).
	// Without flags, a best-effort unfiltered fetch adds a one-line org
	// scope summary when the control has scoped evidence; older servers
	// without the endpoint degrade silently to the classic output.
	if scopeStatus != nil {
		fmt.Println()
		renderControlScopeStatus(os.Stdout, scopeStatus)
		return
	}
	if st, _, serr := fetchControlScopeStatus(cfg, controlCode, "", ""); serr == nil {
		if line := orgScopeSummaryLine(st); line != "" {
			fmt.Println()
			fmt.Println(line)
		}
	}
}

// FindControlIDByCode looks up a control ID by its control code (e.g., "RC-018")
func FindControlIDByCode(cfg *config.Config, controlCode string) (string, error) {
	url := cfg.APIURL + "/api/v1/controls/by-code/" + controlCode
	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("control %s not found: %w", controlCode, err)
	}
	var control struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp, &control); err != nil {
		return "", fmt.Errorf("parse control response: %w", err)
	}
	if control.ID == "" {
		return "", fmt.Errorf("control %s not found", controlCode)
	}
	return control.ID, nil
}
