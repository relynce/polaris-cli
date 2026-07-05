package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
)

// IncidentSearchResult mirrors the GET /api/v1/incidents/search response item.
type IncidentSearchResult struct {
	ShortName      string     `json:"short_name"`
	Title          string     `json:"title"`
	Severity       string     `json:"severity,omitempty"`
	IncidentDate   *time.Time `json:"incident_date,omitempty"`
	MTTRMinutes    *int       `json:"mttr_minutes,omitempty"`
	SourceURL      string     `json:"source_url,omitempty"`
	RelevanceScore float64    `json:"relevance_score"`
}

// IncidentSearchResponse mirrors the GET /api/v1/incidents/search response.
type IncidentSearchResponse struct {
	Results []IncidentSearchResult `json:"results"`
	Total   int                    `json:"total"`
}

// CmdIncident is the entry point for `rvl incident <subcommand>`.
func CmdIncident(args []string) {
	if cliutil.WantsHelp(args) {
		printIncidentUsage()
		return
	}
	if len(args) == 0 {
		printIncidentUsage()
		os.Exit(cliutil.ExitUsage)
	}
	switch args[0] {
	case "search":
		cmdIncidentSearch(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", args[0])
		printIncidentUsage()
		os.Exit(cliutil.ExitUsage)
	}
}

func printIncidentUsage() {
	fmt.Println(`rvl incident - Search and retrieve incident postmortems

Usage:
  rvl incident <subcommand> [options]

Subcommands:
  search              Semantic search across indexed postmortems

Search Options:
  --limit=<n>         Maximum results (default 10, max 50)
  --format=table|json Output format (default: table)

Examples:
  rvl incident search "circuit breaker"
  rvl incident search "retry storm cascading failure" --limit=5
  rvl incident search "AI provider outage" --format=json`)
}

func cmdIncidentSearch(args []string) {
	q, limit, format, perr := parseIncidentSearchArgs(args)
	if perr != nil {
		fmt.Fprintln(os.Stderr, perr)
		fmt.Fprintln(os.Stderr, "Run 'rvl incident --help' for usage.")
		os.Exit(cliutil.ExitUsage)
	}
	if q == "" {
		fmt.Fprintln(os.Stderr, "Error: search query required")
		fmt.Fprintln(os.Stderr, "Usage: rvl incident search <query> [--limit=N] [--format=table|json]")
		os.Exit(cliutil.ExitUsage)
	}

	cfg := api.LoadAndResolveConfig()

	params := url.Values{}
	params.Set("q", q)
	params.Set("limit", strconv.Itoa(limit))
	endpoint := cfg.APIURL + "/api/v1/incidents/search?" + params.Encode()

	resp, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		fmt.Println(string(resp))
		return
	}

	var searchResp IncidentSearchResponse
	if err := json.Unmarshal(resp, &searchResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d result(s) for %q:\n\n", searchResp.Total, q)
	fmt.Print(formatIncidentSearchTable(searchResp.Results))
}

// parseIncidentSearchArgs parses args into (query, limit, format).
// Returns an error for unknown flags or invalid --limit values so the
// caller can exit with the usage-error code (po-cj4s7).
func parseIncidentSearchArgs(args []string) (query string, limit int, format string, err error) {
	limit = 10
	format = "table"
	var queryParts []string
	// po-i24do.11: accept both "--flag value" and "--flag=value" and
	// validate --format so an invalid value errors instead of silently
	// falling through to the table render.
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var limitVal string
		var haveLimit bool
		var fmtVal string
		var haveFmt bool
		switch {
		case strings.HasPrefix(arg, "--limit="):
			limitVal, haveLimit = strings.TrimPrefix(arg, "--limit="), true
		case arg == "--limit":
			if i+1 >= len(args) {
				return "", 0, "", fmt.Errorf("--limit requires a value")
			}
			i++
			limitVal, haveLimit = args[i], true
		case strings.HasPrefix(arg, "--format="):
			fmtVal, haveFmt = strings.TrimPrefix(arg, "--format="), true
		case arg == "--format":
			if i+1 >= len(args) {
				return "", 0, "", fmt.Errorf("--format requires a value")
			}
			i++
			fmtVal, haveFmt = args[i], true
		case strings.HasPrefix(arg, "-"):
			return "", 0, "", fmt.Errorf("unknown flag: %s", arg)
		default:
			queryParts = append(queryParts, arg)
		}
		if haveLimit {
			n, perr := strconv.Atoi(limitVal)
			if perr != nil || n < 1 {
				return "", 0, "", fmt.Errorf("--limit expects a positive integer, got %q", limitVal)
			}
			limit = n
		}
		if haveFmt {
			format = fmtVal
		}
	}
	query = strings.Join(queryParts, " ")
	if err := cliutil.ValidateFormat(format, "table", "json"); err != nil {
		return "", 0, "", err
	}
	return query, limit, format, nil
}

const incidentTitleMaxLen = 60

// formatIncidentSearchTable renders results as a text table.
func formatIncidentSearchTable(results []IncidentSearchResult) string {
	if len(results) == 0 {
		return "No incidents found.\n"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %-10s  %-4s  %-7s  %-*s  %s\n",
		"ID", "Rel.", "Sev.", incidentTitleMaxLen, "Title", "Source")
	fmt.Fprintf(&sb, "  %s  %s  %s  %s  %s\n",
		strings.Repeat("-", 10),
		strings.Repeat("-", 4),
		strings.Repeat("-", 7),
		strings.Repeat("-", incidentTitleMaxLen),
		strings.Repeat("-", 6))
	for _, r := range results {
		title := r.Title
		if len(title) > incidentTitleMaxLen {
			title = title[:incidentTitleMaxLen-1] + "…"
		}
		sev := r.Severity
		if sev == "" {
			sev = "-"
		}
		fmt.Fprintf(&sb, "  %-10s  %.2f  %-7s  %-*s  %s\n",
			r.ShortName, r.RelevanceScore, sev, incidentTitleMaxLen, title, r.SourceURL)
	}
	return sb.String()
}
