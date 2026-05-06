package commands

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/config"
	"github.com/revelara-ai/rvl-cli/internal/project"
)

// ScanRequest represents the payload sent to the scan endpoint
type ScanRequest struct {
	Service      string        `json:"service"`
	ScanType     string        `json:"scan_type"`
	ScanMode     string        `json:"scan_mode,omitempty"`
	Findings     []interface{} `json:"findings"`
	Metadata     ScanMetadata  `json:"metadata,omitempty"`

	// Control structure data (optional, populated by scan skill Step 1.2)
	RepoURL          string                    `json:"repo_url,omitempty"`
	ControlStructure *ScanControlStructureData `json:"control_structure,omitempty"`

	// Service catalog data (optional, populated by detect-risks scans)
	Stack        *ScanStackInfo   `json:"stack,omitempty"`
	Components   []ScanComponent  `json:"components,omitempty"`
	Dependencies []ScanDependency `json:"dependencies,omitempty"`
	CatalogMeta         *ScanCatalogMeta `json:"catalog_meta,omitempty"`
	BusinessCriticality *float64         `json:"business_criticality,omitempty"`
}

// ScanControlStructureData is the control structure portion of a scan request.
type ScanControlStructureData struct {
	Nodes        json.RawMessage `json:"nodes"`
	Edges        json.RawMessage `json:"edges"`
	ScannedFiles int             `json:"scanned_files"`
	ScannedLines int64           `json:"scanned_lines"`
}

// ScanMetadata contains metadata about the scan
type ScanMetadata struct {
	GitCommit     string `json:"git_commit,omitempty"`
	GitBranch     string `json:"git_branch,omitempty"`
	ScannerID     string `json:"scanner_id,omitempty"`
	SkillName     string `json:"skill_name,omitempty"`
	SkillVersion  string `json:"skill_version,omitempty"`
	SkillChecksum string `json:"skill_checksum,omitempty"`
}

// ScanStackInfo holds detected technology stack information.
type ScanStackInfo struct {
	Languages      []string `json:"languages,omitempty"`
	Frameworks     []string `json:"frameworks,omitempty"`
	Databases      []string `json:"databases,omitempty"`
	Infrastructure []string `json:"infrastructure,omitempty"`
	CloudProvider  string   `json:"cloud_provider,omitempty"`
}

// ScanComponent represents a service component from .revelara.yaml or auto-detection.
type ScanComponent struct {
	Name         string   `json:"name"`
	Path         string   `json:"path,omitempty"`
	Type         string   `json:"type,omitempty"`
	Description  string   `json:"description,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}

// ScanDependency represents an auto-detected dependency.
type ScanDependency struct {
	Target      string `json:"target"`
	Type        string `json:"type,omitempty"`
	Criticality string `json:"criticality,omitempty"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source,omitempty"`
}

// ScanCatalogMeta holds optional manual overrides from .revelara.yaml.
type ScanCatalogMeta struct {
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	Tier        string `json:"tier,omitempty"`
	TeamName    string `json:"team_name,omitempty"`
	TeamContact string `json:"team_contact,omitempty"`
}

// ScanResponse represents the response from the scan endpoint
type ScanResponse struct {
	ScanID           string                      `json:"scan_id"`
	Service          string                      `json:"service"`
	Summary          ScanSummary                 `json:"summary"`
	Findings         []ScanResult                `json:"findings"`
	ControlStructure *ScanControlStructureResult  `json:"control_structure,omitempty"`
	Warnings         []string                    `json:"warnings,omitempty"`
	Timestamp        string                      `json:"timestamp"`
}

// ScanControlStructureResult is the control structure portion of a scan response.
type ScanControlStructureResult struct {
	SnapshotID   string           `json:"snapshot_id"`
	NodeCount    int              `json:"node_count"`
	EdgeCount    int              `json:"edge_count"`
	ScannedFiles int              `json:"scanned_files"`
	ScannedLines int64            `json:"scanned_lines"`
	UCACoverage  *ScanUCACoverage `json:"uca_coverage,omitempty"`
}

// ScanUCACoverage reports UCA identification results during a scan.
type ScanUCACoverage struct {
	Discovered    int `json:"discovered"`
	Analyzed      int `json:"analyzed"`
	Cap           int `json:"cap"`
	UCAsGenerated int `json:"ucas_generated"`
	UCAsStored    int `json:"ucas_stored"`
}

// ScanSummary provides aggregate statistics about the scan results
type ScanSummary struct {
	Total     int `json:"total"`
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
	Critical  int `json:"critical"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
}

// ScanResult represents a single risk finding from the scan
type ScanResult struct {
	RiskID   string   `json:"risk_id"`
	RiskCode string   `json:"risk_code"`
	Title    string   `json:"title"`
	Status   string   `json:"status"`
	Score    int      `json:"score"`
	Priority string   `json:"priority"`
	Warnings []string `json:"warnings,omitempty"`
}

// CmdScan handles the scan command
func CmdScan(args []string, version string) {
	var service string
	var inputFile string
	var csFile string
	var useStdin bool
	var dryRun bool
	var targetDir string
	var scanDir string
	var reviewMode bool
	var autoInfer bool
	var ciMode bool

	// Local-scanner flags (po-fayz epic).
	var localMode bool
	var format string
	var submit bool
	var listMatchers bool
	var matchersFlag string
	var changedOnly bool
	var baseRef string
	var scanAllOnMissingBase bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--service", "-s":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --service requires a value")
				os.Exit(1)
			}
			i++
			service = args[i]
		case "--target", "-t":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --target requires a value")
				os.Exit(1)
			}
			i++
			targetDir = args[i]
		case "--stdin":
			useStdin = true
		case "--file", "-f":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --file requires a value")
				os.Exit(1)
			}
			i++
			inputFile = args[i]
		case "--cs-file":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --cs-file requires a value")
				os.Exit(1)
			}
			i++
			csFile = args[i]
		case "--scan-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --scan-dir requires a value")
				os.Exit(1)
			}
			i++
			scanDir = args[i]
		case "--dry-run":
			dryRun = true
		case "--review":
			reviewMode = true
		case "--auto-infer":
			autoInfer = true
		case "--ci":
			ciMode = true
		case "--local":
			localMode = true
		case "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --format requires a value")
				os.Exit(1)
			}
			i++
			format = args[i]
		case "--submit":
			submit = true
		case "--list-matchers":
			listMatchers = true
		case "--matchers":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --matchers requires a value")
				os.Exit(1)
			}
			i++
			matchersFlag = args[i]
		case "--changed-only":
			changedOnly = true
		case "--base":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --base requires a value")
				os.Exit(1)
			}
			i++
			baseRef = args[i]
		case "--scan-all-on-missing-base":
			scanAllOnMissingBase = true
		default:
			if strings.HasPrefix(args[i], "--target=") {
				targetDir = strings.TrimPrefix(args[i], "--target=")
			} else if strings.HasPrefix(args[i], "--scan-dir=") {
				scanDir = strings.TrimPrefix(args[i], "--scan-dir=")
			} else if strings.HasPrefix(args[i], "--format=") {
				format = strings.TrimPrefix(args[i], "--format=")
			} else if strings.HasPrefix(args[i], "--matchers=") {
				matchersFlag = strings.TrimPrefix(args[i], "--matchers=")
			} else if strings.HasPrefix(args[i], "--base=") {
				baseRef = strings.TrimPrefix(args[i], "--base=")
			} else if !strings.HasPrefix(args[i], "-") && service == "" {
				service = args[i]
			}
		}
	}

	// --list-matchers is independent of any scan invocation.
	if listMatchers {
		runListMatchers(matchersFlag)
		return
	}

	if localMode {
		runLocalScan(version, localScanArgs{
			service:              service,
			targetDir:            targetDir,
			format:               format,
			submit:               submit,
			matchersFlag:         matchersFlag,
			changedOnly:          changedOnly,
			baseRef:              baseRef,
			scanAllOnMissingBase: scanAllOnMissingBase,
			dryRun:               dryRun,
			ciMode:               ciMode,
		})
		return
	}

	if targetDir != "" {
		absTarget, err := filepath.Abs(targetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid target path: %v\n", err)
			os.Exit(1)
		}
		info, err := os.Stat(absTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: target directory does not exist: %s\n", absTarget)
			os.Exit(1)
		}
		if !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: target is not a directory: %s\n", absTarget)
			os.Exit(1)
		}
		targetDir = absTarget
	}

	if targetDir != "" {
		if projectCfg := project.LoadProjectConfigFrom(targetDir); projectCfg != nil && projectCfg.Project != "" {
			if service != "" && service != projectCfg.Project {
				fmt.Fprintf(os.Stderr, "Warning: --service %q overridden by target's .revelara.yaml project: %q\n", service, projectCfg.Project)
			}
			service = projectCfg.Project
		}
	}

	if service == "" {
		fmt.Fprintln(os.Stderr, "Error: --service is required (or use --target with a project that has .revelara.yaml)")
		fmt.Fprintln(os.Stderr, "Usage: rvl scan --service <name> [--stdin|--file <path>|--scan-dir <path>] [--target <path>]")
		os.Exit(1)
	}

	cfg := api.LoadAndResolveConfig()

	var scanReq ScanRequest

	if scanDir != "" {
		// Merge all JSON part files from scan directory.
		// Each file contributes its fields to the final request.
		if err := mergeScanDir(scanDir, &scanReq); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		var inputData []byte
		var err error
		if useStdin {
			inputData, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
				os.Exit(1)
			}
		} else if inputFile != "" {
			inputData, err = os.ReadFile(inputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "Error: Must specify --stdin, --file, or --scan-dir")
			os.Exit(1)
		}

		if err := json.Unmarshal(inputData, &scanReq); err != nil {
			var findings []interface{}
			if err2 := json.Unmarshal(inputData, &findings); err2 != nil {
				fmt.Fprintf(os.Stderr, "Error parsing input: %v\n", err)
				os.Exit(1)
			}
			scanReq.Findings = findings
		}
	}

	// Merge control structure from separate file if provided.
	// Works with both --file and --scan-dir for backward compatibility.
	if csFile != "" {
		csData, err := os.ReadFile(csFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading --cs-file: %v\n", err)
			os.Exit(1)
		}
		var csPayload struct {
			RepoURL          string                    `json:"repo_url"`
			ControlStructure *ScanControlStructureData `json:"control_structure"`
		}
		if err := json.Unmarshal(csData, &csPayload); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --cs-file: %v\n", err)
			os.Exit(1)
		}
		if csPayload.RepoURL != "" && scanReq.RepoURL == "" {
			scanReq.RepoURL = csPayload.RepoURL
		}
		if csPayload.ControlStructure != nil && scanReq.ControlStructure == nil {
			scanReq.ControlStructure = csPayload.ControlStructure
		}
	}

	// Normalize control structure field names. Handles common agent mistakes:
	// node_key->id, from_key->from_id, to_key->to_id, provenance format.
	normalizeControlStructure(scanReq.ControlStructure)

	scanReq.Service = service
	if scanReq.ScanType == "" {
		scanReq.ScanType = "full"
	}
	scanReq.Metadata.ScannerID = "rely-cli-" + version

	if projectCfg := project.LoadProjectConfigFrom(targetDir); projectCfg != nil {
		if len(projectCfg.Components) > 0 {
			project.MapFindingsToComponents(scanReq.Findings, projectCfg)
		}
		if crit := projectCfg.CriticalityScore(); crit > 0 {
			scanReq.BusinessCriticality = &crit
		}
	}

	// Resolve scan mode: --ci > --auto-infer > --review > default (review if TTY)
	scanMode := "review" // default
	if ciMode {
		scanMode = "ci"
	} else if autoInfer {
		scanMode = "auto"
	} else if reviewMode {
		scanMode = "review"
	} else if !isTTY() {
		// No TTY and no explicit flag: fall back to auto (non-interactive)
		scanMode = "auto"
	}

	// Review mode requires a TTY for interactive confirmation
	if scanMode == "review" && useStdin {
		fmt.Fprintln(os.Stderr, "Warning: --review requires a TTY for confirmation. Falling back to --auto-infer because stdin is used for input.")
		scanMode = "auto"
	}

	scanReq.ScanMode = scanMode

	if dryRun {
		fmt.Printf("Dry run - would submit to %s:\n", cfg.APIURL)
		fmt.Printf("  Service: %s\n", scanReq.Service)
		fmt.Printf("  Mode: %s\n", scanMode)
		if targetDir != "" {
			fmt.Printf("  Target: %s\n", targetDir)
		}
		fmt.Printf("  Findings: %d\n", len(scanReq.Findings))
		fmt.Printf("  Scan Type: %s\n", scanReq.ScanType)
		return
	}

	response, err := submitScan(cfg, &scanReq)
	if err != nil {
		if scanMode == "ci" {
			ciError := map[string]any{"error": err.Error(), "service": service}
			jsonOut, _ := json.Marshal(ciError)
			fmt.Println(string(jsonOut))
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// CI mode: output JSON and exit with code based on severity
	if scanMode == "ci" {
		printCIOutput(response)
		return
	}

	// Review mode: show control structure and ask for confirmation
	if scanMode == "review" && response.ControlStructure != nil {
		printControlStructureReview(response.ControlStructure)
		if !promptConfirmation("Accept this control structure and proceed with results?") {
			fmt.Println("Scan results discarded. Use --auto-infer to skip review.")
			return
		}
		fmt.Println()
	}

	// Standard output (review-confirmed or auto mode)
	fmt.Printf("Scan submitted successfully\n")
	fmt.Printf("  Scan ID: %s\n", response.ScanID)
	fmt.Printf("  Service: %s\n", response.Service)
	fmt.Printf("  Total: %d (Created: %d, Updated: %d, Unchanged: %d)\n",
		response.Summary.Total, response.Summary.Created,
		response.Summary.Updated, response.Summary.Unchanged)
	if response.Summary.Critical > 0 || response.Summary.High > 0 {
		fmt.Printf("  Priority: Critical=%d, High=%d, Medium=%d, Low=%d\n",
			response.Summary.Critical, response.Summary.High,
			response.Summary.Medium, response.Summary.Low)
	}

	if cs := response.ControlStructure; cs != nil {
		fmt.Printf("  Control Structure: %d nodes, %d edges (%d files scanned)\n",
			cs.NodeCount, cs.EdgeCount, cs.ScannedFiles)
		if uca := cs.UCACoverage; uca != nil {
			fmt.Printf("  STPA Coverage: %d/%d control actions analyzed",
				uca.Analyzed, uca.Discovered)
			if uca.Cap > 0 && uca.Discovered > uca.Cap {
				fmt.Printf(" (capped at %d)", uca.Cap)
			}
			fmt.Printf(" | %d UCAs identified\n", uca.UCAsGenerated)
		}
	}
	fmt.Println()

	if len(response.Findings) > 0 {
		fmt.Println("Findings:")
		for _, f := range response.Findings {
			status := f.Status
			if status == "created" {
				status = "NEW"
			} else if status == "updated" {
				status = "UPD"
			} else {
				status = "---"
			}
			fmt.Printf("  [%s] %s: %s (score: %d, %s)\n",
				status, f.RiskCode, f.Title, f.Score, f.Priority)
		}
		fmt.Println()
	}

	if len(response.Warnings) > 0 {
		fmt.Fprintf(os.Stderr, "Warnings:\n")
		for _, w := range response.Warnings {
			fmt.Fprintf(os.Stderr, "  ⚠ %s\n", w)
		}
		fmt.Fprintln(os.Stderr)
	}

	fmt.Printf("View results: %s/risks\n", cfg.APIURL)
}

// isTTY returns true if stdout is a terminal (not piped or redirected).
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// printControlStructureReview displays the control structure for interactive review.
func printControlStructureReview(cs *ScanControlStructureResult) {
	fmt.Println("\nControl Structure (Review Mode)")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Nodes: %d | Edges: %d\n", cs.NodeCount, cs.EdgeCount)
	fmt.Printf("  Files scanned: %d | Lines scanned: %d\n", cs.ScannedFiles, cs.ScannedLines)
	if uca := cs.UCACoverage; uca != nil {
		fmt.Printf("  Control actions: %d discovered, %d analyzed (cap: %d)\n",
			uca.Discovered, uca.Analyzed, uca.Cap)
		fmt.Printf("  UCAs identified: %d (%d stored)\n", uca.UCAsGenerated, uca.UCAsStored)
	}
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
}

// promptConfirmation asks a yes/no question and returns the answer.
func promptConfirmation(question string) bool {
	fmt.Printf("%s [Y/n] ", question)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return true // default to yes on read error
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "" || answer == "y" || answer == "yes"
}

// printCIOutput outputs scan results as JSON for CI/CD pipelines.
// Exit codes: 0 = success (no critical/high), 1 = findings with critical/high severity.
func printCIOutput(response *ScanResponse) {
	out, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling CI output: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(out))

	if response.Summary.Critical > 0 || response.Summary.High > 0 {
		os.Exit(1)
	}
}

// submitScan sends the scan request to the API and returns the response
func submitScan(cfg *config.Config, scanReq *ScanRequest) (*ScanResponse, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	body, err := json.Marshal(scanReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest("POST", cfg.APIURL+"/api/v1/risks/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if cfg.ResolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.ResolvedOrgID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("authentication failed - run 'rvl login' to reconfigure")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}
	var scanResp ScanResponse
	if err := json.Unmarshal(respBody, &scanResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &scanResp, nil
}

// mergeScanDir reads all JSON files from a directory and merges them into
// a single ScanRequest. Files are processed in alphabetical order (use
// numeric prefixes like 01-stack.json, 02-cs.json to control order).
// Array fields (findings, components, dependencies) are concatenated.
// Scalar/object fields use the last non-zero value.
func mergeScanDir(dir string, scanReq *ScanRequest) error {
	pattern := filepath.Join(dir, "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob scan-dir: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no JSON files found in %s", dir)
	}
	sort.Strings(files)

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", filepath.Base(f), err)
			continue
		}

		var partial ScanRequest
		if err := json.Unmarshal(data, &partial); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: invalid JSON: %v\n", filepath.Base(f), err)
			continue
		}

		if partial.RepoURL != "" {
			scanReq.RepoURL = partial.RepoURL
		}
		if partial.ControlStructure != nil {
			scanReq.ControlStructure = partial.ControlStructure
		}
		if partial.Stack != nil {
			scanReq.Stack = partial.Stack
		}
		if len(partial.Components) > 0 {
			scanReq.Components = append(scanReq.Components, partial.Components...)
		}
		if len(partial.Dependencies) > 0 {
			scanReq.Dependencies = append(scanReq.Dependencies, partial.Dependencies...)
		}
		if len(partial.Findings) > 0 {
			scanReq.Findings = append(scanReq.Findings, partial.Findings...)
		}
		if partial.CatalogMeta != nil {
			scanReq.CatalogMeta = partial.CatalogMeta
		}
		if partial.BusinessCriticality != nil {
			scanReq.BusinessCriticality = partial.BusinessCriticality
		}
		if partial.ScanMode != "" {
			scanReq.ScanMode = partial.ScanMode
		}

		fmt.Fprintf(os.Stderr, "Merged: %s (%d bytes)\n", filepath.Base(f), len(data))
	}

	if len(scanReq.Findings) == 0 {
		fmt.Fprintln(os.Stderr, "Warning: no findings found in scan-dir files")
	}

	return nil
}

// normalizeControlStructure fixes common field name errors that agents produce.
// Normalizes: node_key->id, from_key/from_node->from_id, to_key/to_node->to_id.
// Removes edge_type (set server-side). Fixes provenance format mismatches
// (node provenance must be array, edge provenance must be object).
func normalizeControlStructure(cs *ScanControlStructureData) {
	if cs == nil {
		return
	}

	if len(cs.Nodes) > 0 {
		var nodes []map[string]interface{}
		if err := json.Unmarshal(cs.Nodes, &nodes); err == nil {
			changed := false
			for _, node := range nodes {
				if v, ok := node["node_key"]; ok {
					if _, hasID := node["id"]; !hasID {
						node["id"] = v
					}
					delete(node, "node_key")
					changed = true
				}
				// Node provenance must be an array
				if prov, ok := node["provenance"]; ok {
					if _, isMap := prov.(map[string]interface{}); isMap {
						node["provenance"] = []interface{}{prov}
						changed = true
					}
				}
			}
			if changed {
				if normalized, err := json.Marshal(nodes); err == nil {
					cs.Nodes = normalized
				}
			}
		}
	}

	if len(cs.Edges) > 0 {
		var edges []map[string]interface{}
		if err := json.Unmarshal(cs.Edges, &edges); err == nil {
			changed := false
			for _, edge := range edges {
				renames := [][2]string{
					{"from_key", "from_id"},
					{"from_node", "from_id"},
					{"to_key", "to_id"},
					{"to_node", "to_id"},
				}
				for _, pair := range renames {
					if v, ok := edge[pair[0]]; ok {
						if _, has := edge[pair[1]]; !has {
							edge[pair[1]] = v
						}
						delete(edge, pair[0])
						changed = true
					}
				}
				if _, ok := edge["edge_type"]; ok {
					delete(edge, "edge_type")
					changed = true
				}
				// Edge provenance must be an object (not array)
				if prov, ok := edge["provenance"]; ok {
					if arr, isArr := prov.([]interface{}); isArr && len(arr) > 0 {
						edge["provenance"] = arr[0]
						changed = true
					}
				}
			}
			if changed {
				if normalized, err := json.Marshal(edges); err == nil {
					cs.Edges = normalized
				}
			}
		}
	}
}
