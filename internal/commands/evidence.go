package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/display"
)

type EvidenceItem struct {
	ID              string  `json:"id"`
	ControlID       string  `json:"control_id"`
	Type            string  `json:"type"`
	Name            string  `json:"name"`
	URLOrIdentifier string  `json:"url_or_identifier,omitempty"`
	Description     string  `json:"description,omitempty"`
	GitHash         *string `json:"git_hash,omitempty"`
	Status          string  `json:"status"`
	VerifiedAt      *string `json:"verified_at,omitempty"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
	OrganizationID  string  `json:"organization_id,omitempty"`
}

type ListEvidenceAPIResponse struct {
	Evidence []EvidenceItem `json:"evidence"`
	Total    int            `json:"total"`
}

func CmdEvidence(args []string) {
	if cliutil.WantsHelp(args) {
		printEvidenceUsage()
		return
	}
	if len(args) == 0 {
		printEvidenceUsage()
		os.Exit(cliutil.ExitUsage)
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "submit":
		cmdEvidenceSubmit(subArgs)
	case "list":
		cmdEvidenceList(subArgs)
	case "verify":
		cmdEvidenceVerify(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown evidence command: %s\n", subcommand)
		printEvidenceUsage()
		os.Exit(cliutil.ExitUsage)
	}
}

func printEvidenceUsage() {
	fmt.Println("Usage: rvl evidence <subcommand> [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  submit    Submit evidence for a control")
	fmt.Println("  list      List evidence records")
	fmt.Println("  verify    Verify evidence")
	fmt.Println()
	fmt.Println("Submit options:")
	fmt.Println("  --control=<code>       Control code (e.g., RC-018)")
	fmt.Println("  --type=<type>          Evidence type (code, test, dashboard, document, configuration, runbook, other)")
	fmt.Println("  --name=<name>          Evidence name")
	fmt.Println("  --url=<url>            URL or identifier (optional)")
	fmt.Println("  --description=<text>   Description (optional)")
	fmt.Println("  --git-hash=<hash>      Git commit hash (auto-detected if not provided)")
	fmt.Println("  --format=json          Output raw JSON response")
	fmt.Println()
	fmt.Println("List options:")
	fmt.Println("  --control=<code>   Filter by control code")
	fmt.Println("  --type=<type>      Filter by evidence type")
	fmt.Println("  --status=<status>  Filter by status (not_configured, configured, sample, verified)")
	fmt.Println("  --limit=<n>        Max records (default: 20)")
	fmt.Println("  --format=json      Output raw JSON response")
	fmt.Println()
	fmt.Println("Verify usage:")
	fmt.Println("  rvl evidence verify <evidence-id>")
	fmt.Println("  --format=json      Output raw JSON response")
}

func cmdEvidenceSubmit(args []string) {
	var controlCode, evidenceType, name, url, description, gitHash, format string
	for _, arg := range args {
		if strings.HasPrefix(arg, "--control=") {
			controlCode = strings.TrimPrefix(arg, "--control=")
		} else if strings.HasPrefix(arg, "--type=") {
			evidenceType = strings.TrimPrefix(arg, "--type=")
		} else if strings.HasPrefix(arg, "--name=") {
			name = strings.TrimPrefix(arg, "--name=")
		} else if strings.HasPrefix(arg, "--url=") {
			url = strings.TrimPrefix(arg, "--url=")
		} else if strings.HasPrefix(arg, "--description=") {
			description = strings.TrimPrefix(arg, "--description=")
		} else if strings.HasPrefix(arg, "--git-hash=") {
			gitHash = strings.TrimPrefix(arg, "--git-hash=")
		} else if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
		} else {
			cliutil.ExitUnknownFlag(arg, "rvl evidence")
		}
	}

	if gitHash == "" {
		if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
			gitHash = strings.TrimSpace(string(out))
		}
	}

	if controlCode == "" {
		fmt.Fprintln(os.Stderr, "Error: --control is required (e.g., --control=RC-018)")
		os.Exit(cliutil.ExitUsage)
	}
	if evidenceType == "" {
		fmt.Fprintln(os.Stderr, "Error: --type is required (code, test, dashboard, document, configuration, runbook, other)")
		os.Exit(cliutil.ExitUsage)
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		os.Exit(cliutil.ExitUsage)
	}

	if strings.HasPrefix(controlCode, "R-") && !strings.HasPrefix(controlCode, "RC-") {
		fmt.Fprintf(os.Stderr, "Note: \"%s\" is a risk code, not a control code (RC-XXX).\n", controlCode)
		fmt.Fprintf(os.Stderr, "Evidence is submitted per control. Use \"rvl risk show %s\" to find mapped controls.\n", controlCode)
		os.Exit(cliutil.ExitUsage)
	}

	cfg := api.LoadAndResolveConfig()
	controlURL := cfg.APIURL + "/api/v1/controls/by-code/" + controlCode
	controlResp, err := api.MakeAPIRequest(cfg, "GET", controlURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: control %s not found: %v\n", controlCode, err)
		os.Exit(1)
	}

	var control Control
	if err := json.Unmarshal(controlResp, &control); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing control response: %v\n", err)
		os.Exit(1)
	}
	if control.ID == "" {
		fmt.Fprintf(os.Stderr, "Error: control %s not found\n", controlCode)
		os.Exit(1)
	}

	if len(control.ExpectedEvidenceTypes) > 0 {
		matched := false
		for _, et := range control.ExpectedEvidenceTypes {
			if et == evidenceType {
				matched = true
				break
			}
		}
		if !matched {
			fmt.Fprintf(os.Stderr, "Note: %s expects evidence types: %s (submitting \"%s\" anyway)\n",
				controlCode, strings.Join(control.ExpectedEvidenceTypes, ", "), evidenceType)
		}
	}

	body := map[string]string{
		"control_id":        control.ID,
		"type":              evidenceType,
		"name":              name,
		"url_or_identifier": url,
		"description":       description,
	}
	if gitHash != "" {
		body["git_hash"] = gitHash
	}

	bodyBytes, _ := json.Marshal(body)
	apiURL := cfg.APIURL + "/api/v1/evidence"
	resp, err := api.MakeAPIRequest(cfg, "POST", apiURL, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var evidence EvidenceItem
	if err := json.Unmarshal(resp, &evidence); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		fmt.Println(string(resp))
		return
	}

	fmt.Printf("Evidence submitted successfully.\n")
	fmt.Printf("  ID:      %s\n", evidence.ID)
	fmt.Printf("  Control: %s (%s)\n", controlCode, control.Name)
	fmt.Printf("  Type:    %s\n", evidence.Type)
	fmt.Printf("  Name:    %s\n", evidence.Name)
	fmt.Printf("  Status:  %s\n", evidence.Status)
	if url != "" {
		fmt.Printf("  URL:     %s\n", url)
	}
	if evidence.GitHash != nil && *evidence.GitHash != "" {
		fmt.Printf("  Commit:  %s\n", *evidence.GitHash)
	}
}

func cmdEvidenceList(args []string) {
	var controlCode, evidenceType, status, format string
	limit := 20
	for _, arg := range args {
		if strings.HasPrefix(arg, "--control=") {
			controlCode = strings.TrimPrefix(arg, "--control=")
		} else if strings.HasPrefix(arg, "--type=") {
			evidenceType = strings.TrimPrefix(arg, "--type=")
		} else if strings.HasPrefix(arg, "--status=") {
			status = strings.TrimPrefix(arg, "--status=")
		} else if strings.HasPrefix(arg, "--limit=") {
			val := strings.TrimPrefix(arg, "--limit=")
			n, perr := strconv.Atoi(val)
			if perr != nil || n < 1 {
				fmt.Fprintf(os.Stderr, "Error: --limit expects a positive integer, got %q\n", val)
				os.Exit(cliutil.ExitUsage)
			}
			limit = n
		} else if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
		} else {
			cliutil.ExitUnknownFlag(arg, "rvl evidence")
		}
	}

	if status != "" {
		validStatuses := map[string]bool{
			"not_configured": true,
			"configured":     true,
			"sample":         true,
			"verified":       true,
		}
		if !validStatuses[status] {
			fmt.Fprintf(os.Stderr, "Error: invalid --status value %q; must be one of: not_configured, configured, sample, verified\n", status)
			os.Exit(cliutil.ExitUsage)
		}
	}

	cfg := api.LoadAndResolveConfig()
	apiURL := cfg.APIURL + "/api/v1/evidence?limit=" + fmt.Sprintf("%d", limit)
	if evidenceType != "" {
		apiURL += "&type=" + evidenceType
	}
	if status != "" {
		apiURL += "&status=" + status
	}
	if controlCode != "" {
		controlID, err := FindControlIDByCode(cfg, controlCode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		apiURL += "&control_id=" + controlID
	}

	resp, err := api.MakeAPIRequest(cfg, "GET", apiURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var listResp ListEvidenceAPIResponse
	if err := json.Unmarshal(resp, &listResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		fmt.Println(string(resp))
		return
	}

	if len(listResp.Evidence) == 0 {
		fmt.Println("No evidence found.")
		return
	}

	fmt.Printf("Found %d evidence records:\n\n", listResp.Total)
	for _, e := range listResp.Evidence {
		statusBadge := display.FormatEvidenceStatus(e.Status)
		commitInfo := ""
		if e.GitHash != nil && *e.GitHash != "" {
			hash := *e.GitHash
			if len(hash) > 8 {
				hash = hash[:8]
			}
			commitInfo = " @ " + hash
		}
		idStr := e.ID
		if len(idStr) > 8 {
			idStr = idStr[:8] + "..."
		}
		fmt.Printf("  %s %s [%s] %s%s\n", idStr, statusBadge, e.Type, e.Name, commitInfo)
		if e.URLOrIdentifier != "" {
			fmt.Printf("    URL: %s\n", e.URLOrIdentifier)
		}
	}
}

func cmdEvidenceVerify(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: evidence ID required")
		fmt.Fprintln(os.Stderr, "Usage: rvl evidence verify <evidence-id>")
		os.Exit(cliutil.ExitUsage)
	}

	var format string
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
		} else {
			cliutil.ExitUnknownFlag(arg, "rvl evidence")
		}
	}

	evidenceID := args[0]
	cfg := api.LoadAndResolveConfig()
	apiURL := cfg.APIURL + "/api/v1/evidence/" + evidenceID + "/verify"
	resp, err := api.MakeAPIRequest(cfg, "POST", apiURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		fmt.Println(string(resp))
		return
	}

	var evidence EvidenceItem
	if err := json.Unmarshal(resp, &evidence); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Evidence %s verified.\n", evidenceID)
	fmt.Printf("  Name:   %s\n", evidence.Name)
	fmt.Printf("  Status: %s\n", evidence.Status)
}
