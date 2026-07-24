package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
)

// ReadinessControl mirrors the server's apispec.ReadinessControl
// (api/components/schemas/compliance.yaml#/ReadinessControl).
type ReadinessControl struct {
	ControlCode string   `json:"control_code"`
	Name        string   `json:"name"`
	Status      string   `json:"status"` // pass | partial | fail | not_assessed
	Criteria    []string `json:"criteria"`
	URL         string   `json:"url"`
}

// ReadinessScorecard mirrors the server's apispec.ReadinessScorecard.
type ReadinessScorecard struct {
	Framework           string             `json:"framework"`
	Set                 string             `json:"set"`
	ReadinessPct        float64            `json:"readiness_pct"`
	ControlsTotal       int                `json:"controls_total"`
	ControlsPassing     int                `json:"controls_passing"`
	ControlsPartial     int                `json:"controls_partial"`
	ControlsFailing     int                `json:"controls_failing"`
	ControlsNotAssessed int                `json:"controls_not_assessed"`
	Controls            []ReadinessControl `json:"controls"`
}

// CmdReport renders a compliance readiness scorecard (the "do these N controls"
// view). It is deliberately readiness/supporting framing - never certification.
func CmdReport(args []string) {
	if cliutil.WantsHelp(args) {
		printReportUsage()
		return
	}

	framework := "soc2"
	set := "starter"
	format := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--framework="):
			framework = strings.TrimPrefix(arg, "--framework=")
		case arg == "--framework":
			if i+1 < len(args) {
				framework = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--set="):
			set = strings.TrimPrefix(arg, "--set=")
		case arg == "--set":
			if i+1 < len(args) {
				set = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--format="):
			format = strings.TrimPrefix(arg, "--format=")
		case arg == "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		default:
			cliutil.ExitUnknownFlag(arg, "rvl report")
		}
	}

	framework = strings.ToLower(strings.TrimSpace(framework))
	set = strings.ToLower(strings.TrimSpace(set))
	if set != "starter" && set != "full" {
		fmt.Fprintf(os.Stderr, "Error: --set expects 'starter' or 'full', got %q\n", set)
		os.Exit(cliutil.ExitUsage)
	}

	cfg := api.LoadAndResolveConfig()
	endpoint := fmt.Sprintf("%s/api/v1/compliance/%s/readiness?set=%s", cfg.APIURL, framework, set)
	resp, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		fmt.Println(string(resp))
		return
	}

	var sc ReadinessScorecard
	if err := json.Unmarshal(resp, &sc); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}
	renderScorecard(sc)
}

func renderScorecard(sc ReadinessScorecard) {
	setLabel := "Starter Set"
	if sc.Set == "full" {
		setLabel = "Full Mapped Set"
	}
	fmt.Printf("%s Readiness - %s\n\n", strings.ToUpper(sc.Framework), setLabel)
	fmt.Printf("Readiness: %.1f%%  (%d/%d passing)\n", sc.ReadinessPct, sc.ControlsPassing, sc.ControlsTotal)
	fmt.Printf("  passing %d   partial %d   failing %d   not assessed %d\n\n",
		sc.ControlsPassing, sc.ControlsPartial, sc.ControlsFailing, sc.ControlsNotAssessed)

	if len(sc.Controls) == 0 {
		fmt.Println("No controls in scope for this set.")
		return
	}
	for _, c := range sc.Controls {
		fmt.Printf("%-8s %-13s %-40s %s\n",
			c.ControlCode, statusBadge(c.Status), truncate(c.Name, 40), strings.Join(c.Criteria, ", "))
	}

	fmt.Println("\nThis is a SOC 2 readiness / supporting-evidence view - not a certification or")
	fmt.Println("attestation. Run `rvl control show <RC-XXX>` for remediation guidance.")
}

func statusBadge(status string) string {
	switch status {
	case "pass":
		return "PASS"
	case "partial":
		return "PARTIAL"
	case "fail":
		return "FAIL"
	default:
		return "NOT ASSESSED"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func printReportUsage() {
	fmt.Println(`rvl report - Compliance readiness scorecard

Usage:
  rvl report [options]

Shows the controls you should implement for a compliance framework and your
current readiness. Readiness/supporting framing only - never certification.

Options:
  --framework=<fw>  Framework key (default soc2)
  --set=<set>       Which controls to score: starter (default) or full
  --format=json     Emit the raw server JSON for scripting

Examples:
  rvl report --framework soc2
  rvl report --framework soc2 --set full
  rvl report --framework soc2 --format json | jq '.readiness_pct'`)
}
