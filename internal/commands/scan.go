package commands

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/config"
	"github.com/revelara-ai/rvl-cli/internal/project"
)

// ScanType is the enumerated scan_type value. The Polaris handler validates
// the OpenAPI enum at the boundary (po-f5tmk); we keep typed constants here
// so CLI internals can refer to them without stringly-typing.
type ScanType = string

const (
	ScanTypeFull        ScanType = "full"
	ScanTypeIncremental ScanType = "incremental"
	ScanTypeTargeted    ScanType = "targeted"
)

// ScanRequest represents the payload sent to the scan endpoint
type ScanRequest struct {
	Service      string        `json:"service"`
	ScanType     ScanType      `json:"scan_type"`
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

	// po-qs96.2: per-service tolerance override carried from .revelara.yaml
	// `scanner.tolerance` and `scanner.strict_enforcement` to the Polaris CI
	// gate. Polaris merges this over org-level defaults via ResolveTolerance
	// (most-specific wins) — see docs/designs/local-scanner-developer-workflow.md
	// in the polaris repo.
	ServiceTolerance *ServiceToleranceConfig `json:"service_tolerance,omitempty"`

	// po-zphjg: idempotency key for safe retry after a client-side timeout.
	// submitScan derives a deterministic value from a hash of the request
	// body when this is empty, so a rerun of the same command (same
	// scan-parts, same metadata) reuses the server's cached response
	// instead of re-running every side effect.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// ServiceToleranceConfig mirrors polaris-side ServiceToleranceConfig
// exactly. Pointer fields distinguish "unset" from "zero value" so the
// resolver can fall through to org defaults for any field the service
// did not explicitly override.
type ServiceToleranceConfig struct {
	ToleranceTarget      *int  `json:"tolerance_target,omitempty"`
	ToleranceHeadroomPct *int  `json:"tolerance_headroom_pct,omitempty"`
	StrictEnforcement    *bool `json:"strict_enforcement,omitempty"`
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

	// Local-scanner additions (po-fayz.14 mirrors these on Polaris).
	// MatcherVersion is the matcher set version that produced findings;
	// ExcludedMatchers is the list of slugs the user suppressed via
	// .revelara.yaml so Polaris can drive the Phase 2 feedback loop.
	MatcherVersion   string   `json:"matcher_version,omitempty"`
	ExcludedMatchers []string `json:"excluded_matchers,omitempty"`

	// po-qs96.5: yaml-defined waivers that actually matched at least one
	// finding during this scan. Polaris persists these to the
	// waivers_audit table so EMs/auditors can answer "what did we accept
	// and why" without spelunking.
	AppliedWaivers []AppliedWaiverWire `json:"applied_waivers,omitempty"`
}

// AppliedWaiverWire is the JSON shape submitted to polaris for waiver
// auditing. Mirrors the rvl-cli AppliedWaiver type exactly.
type AppliedWaiverWire struct {
	Matcher string   `json:"matcher"`
	Paths   []string `json:"paths,omitempty"`
	Expires string   `json:"expires,omitempty"`
	Reason  string   `json:"reason"`
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

	// po-qs96.2: effective tolerance after merging per-service override
	// over org defaults. po-qs96.4 reads this for the PR sticky comment
	// budget math. Always populated for scan submissions.
	EffectiveTolerance *EffectiveTolerance `json:"effective_tolerance,omitempty"`
}

// EffectiveTolerance is the resolved tolerance config returned by Polaris
// after merging per-service overrides over org defaults. Mirrors
// polaris-side ReliabilityDefaults exactly.
type EffectiveTolerance struct {
	ToleranceTarget      int  `json:"tolerance_target"`
	ToleranceHeadroomPct int  `json:"tolerance_headroom_pct"`
	StrictEnforcement    bool `json:"strict_enforcement"`

	// po-qs96.6: true when the service is still in the 30-day calibration
	// window. Triggers advisory-mode comment + skip-gate behavior.
	Calibrating bool `json:"calibrating,omitempty"`
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
	Total            int `json:"total"`
	Created          int `json:"created"`
	Updated          int `json:"updated"`
	Unchanged        int `json:"unchanged"`
	ResolvedThisScan int `json:"resolved_this_scan,omitempty"` // po-qs96.4 fix: count of risks marked stale because the scan didn't surface them
	Critical         int `json:"critical"`
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
	var matchersSourceFilter string
	var matchersFlag string
	var changedOnly bool
	var baseRef string
	var scanAllOnMissingBase bool
	var prComment bool // po-qs96.4
	var noDedupe bool  // po-jlsd6
	var scanModeFlag string // po-f96kz
	var profileFlag string  // po-3vsvk
	var cleanupOnSuccess bool // po-gg5dg: remove --scan-dir after a 2xx submit
	var timeoutFlag string    // po-p3k56: optional override for scan submission timeout

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
		case "--source":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --source requires a value")
				os.Exit(1)
			}
			i++
			matchersSourceFilter = args[i]
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
		case "--pr-comment":
			prComment = true
		case "--no-dedupe":
			noDedupe = true
		case "--mode":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --mode requires a value (enforce|eval)")
				os.Exit(1)
			}
			i++
			scanModeFlag = args[i]
		case "--profile":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --profile requires a value")
				os.Exit(1)
			}
			i++
			profileFlag = args[i]
		case "--cleanup-on-success":
			cleanupOnSuccess = true
		case "--timeout":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --timeout requires a value (e.g. 90s, 2m)")
				os.Exit(1)
			}
			i++
			timeoutFlag = args[i]
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
			} else if strings.HasPrefix(args[i], "--mode=") {
				scanModeFlag = strings.TrimPrefix(args[i], "--mode=")
			} else if strings.HasPrefix(args[i], "--profile=") {
				profileFlag = strings.TrimPrefix(args[i], "--profile=")
			} else if strings.HasPrefix(args[i], "--timeout=") {
				timeoutFlag = strings.TrimPrefix(args[i], "--timeout=")
			} else if strings.HasPrefix(args[i], "-") {
				// po-c2iff: unrecognized flag. Silently ignoring used to
				// hide typos and renamed flags (e.g. someone trying the
				// old --diff after it folded into --changed-only).
				fmt.Fprintf(os.Stderr, "Error: unrecognized flag %q\n", args[i])
				fmt.Fprintln(os.Stderr, "Run 'rvl scan --help' for usage.")
				os.Exit(1)
			} else if service == "" {
				service = args[i]
			}
		}
	}

	// --list-matchers is independent of any scan invocation.
	if listMatchers {
		runListMatchers(matchersSourceFilter, format)
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
			prComment:            prComment,
			noDedupe:             noDedupe,
			mode:                 scanModeFlag,
			profile:              profileFlag,
			timeout:              timeoutFlag,
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
		scanReq.ScanType = ScanTypeFull
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
		// po-4g59y: emit JSON on stdout so the /rvl:scan slash command (and
		// any CI integration) can parse it. Human-readable framing goes to
		// stderr so stdout stays machine-readable.
		fmt.Fprintf(os.Stderr, "Dry run - would submit to %s:\n", cfg.APIURL)
		summary := map[string]any{
			"dry_run":   true,
			"api_url":   cfg.APIURL,
			"service":   scanReq.Service,
			"mode":      scanMode,
			"scan_type": scanReq.ScanType,
			"findings":  len(scanReq.Findings),
		}
		if targetDir != "" {
			summary["target"] = targetDir
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
		return
	}

	// po-6u5yx: warn (don't block) when findings have no component and no
	// linked_services. They'll land at the bare project label and split
	// Reliability Budget rows. Surfaced before submit so the user can ^C
	// and rerun with proper component fields.
	if missing := countFindingsWithoutComponent(scanReq.Findings); missing > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d/%d findings have no `component` or `linked_services` and will be attributed to the bare service label %q.\n",
			missing, len(scanReq.Findings), scanReq.Service)
	}

	response, err := submitScan(cfg, &scanReq, resolveScanTimeout(timeoutFlag))
	if err != nil {
		// po-gg5dg: on submit failure, remind the user the scan-parts
		// directory is intact and can be re-submitted as-is. Helps avoid
		// premature `rm -rf` after a 429 or a transient network error.
		if scanDir != "" {
			fmt.Fprintf(os.Stderr, "Scan parts preserved at %s; re-run after resolving the error with:\n  rvl scan --service %s --scan-dir %s\n", scanDir, service, scanDir)
		}
		if scanMode == "ci" {
			ciError := map[string]any{"error": err.Error(), "service": service}
			jsonOut, _ := json.Marshal(ciError)
			fmt.Println(string(jsonOut))
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// po-gg5dg: on success, either cleanup (if --cleanup-on-success) or
	// surface the cleanup instruction so the user doesn't accumulate
	// stale 03-findings.json files across runs.
	if scanDir != "" {
		if cleanupOnSuccess {
			if rmErr := os.RemoveAll(scanDir); rmErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to remove %s: %v\n", scanDir, rmErr)
			} else {
				fmt.Fprintf(os.Stderr, "Removed scan parts at %s (--cleanup-on-success)\n", scanDir)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Scan parts kept at %s; remove with: rm -rf %s\n", scanDir, scanDir)
		}
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
			var status string
			switch f.Status {
			case "created":
				status = "NEW"
			case "updated":
				status = "UPD"
			default:
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

// defaultScanTimeout caps the HTTP submission of a scan. 60s gives the
// polaris server room to finish even when post-processing has not yet
// been fully detached (po-j18em landed; long-tail orgs may still push
// the response toward the ceiling). Override via --timeout or
// RVL_SCAN_TIMEOUT; see resolveScanTimeout.
const defaultScanTimeout = 60 * time.Second

// submitScan sends the scan request to the API and returns the response.
//
// po-alt4a: honors Retry-After on a 429 by retrying once after the
// declared delay (capped at 120s). The CLI exit code is left non-zero so
// CI gates trip on rate-limit, but the message tells the user the
// configured retry window instead of "server error (429)".
//
// po-vwiag: 401/403 messages include the API URL so the user can spot
// dev-key-against-prod-URL mismatches.
//
// po-m0d82: server JSON Error responses (code+message, post po-cw82g)
// are parsed and surfaced verbatim so the user knows what failed.
//
// po-p3k56: timeout is configurable via --timeout / RVL_SCAN_TIMEOUT
// (default 60s). The CLI used to hardcode 30s, which collided with the
// server's pre-async ~30s scan-handler latency and surfaced as
// confusing "context deadline exceeded" failures even when the server
// had already created the risks.
//
// po-zphjg: a deterministic idempotency_key derived from the request
// body is set when the caller did not supply one. The server caches the
// response under this key so the same command rerun after a client
// timeout reuses the cached body without redoing every side effect.
func submitScan(cfg *config.Config, scanReq *ScanRequest, timeout time.Duration) (*ScanResponse, error) {
	const maxRetries = 1
	const maxBackoff = 120 * time.Second

	if timeout <= 0 {
		timeout = defaultScanTimeout
	}

	if scanReq.IdempotencyKey == "" {
		scanReq.IdempotencyKey = deriveIdempotencyKey(scanReq)
	}

	body, err := json.Marshal(scanReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var scanResp ScanResponse
	for attempt := 0; ; attempt++ {
		client := &http.Client{Timeout: timeout}
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
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read response body: %w", readErr)
		}

		switch {
		case resp.StatusCode == 401 || resp.StatusCode == 403:
			return nil, fmt.Errorf("authentication failed against %s — run 'rvl login' to reconfigure (status %d)", cfg.APIURL, resp.StatusCode)
		case resp.StatusCode == 429 && attempt < maxRetries:
			delay := parseRetryAfter(resp.Header.Get("Retry-After"))
			if delay <= 0 || delay > maxBackoff {
				delay = 60 * time.Second
			}
			fmt.Fprintf(os.Stderr, "rate limited by server; retrying in %s\n", delay)
			time.Sleep(delay)
			continue
		case resp.StatusCode >= 400:
			msg, code := decodeServerError(respBody)
			return nil, fmt.Errorf("server error (%d %s) from %s: %s", resp.StatusCode, code, cfg.APIURL, msg)
		}

		if err := json.Unmarshal(respBody, &scanResp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		return &scanResp, nil
	}
}

// deriveIdempotencyKey returns a stable 32-hex-char key derived from the
// request body with IdempotencyKey cleared. Two CmdScan invocations
// against the same service with the same findings/metadata produce the
// same key, so the server-side cache (lookupScanIdempotency) recognizes
// the second submission as a retry. Inputs that legitimately change
// between runs (different findings, different git_commit) produce a
// different key and a fresh scan, which is the right outcome.
func deriveIdempotencyKey(scanReq *ScanRequest) string {
	clone := *scanReq
	clone.IdempotencyKey = ""
	canonical, err := json.Marshal(&clone)
	if err != nil {
		// Marshal failure here is essentially impossible (all fields are
		// JSON-encodable), but if it happens we'd rather skip dedup than
		// crash the submit path. The empty key disables the cache check
		// server-side and the request still completes normally.
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:16])
}

// resolveScanTimeout picks the effective HTTP timeout for the scan
// submission. Precedence: explicit --timeout flag > RVL_SCAN_TIMEOUT env
// > defaultScanTimeout. Invalid env values silently fall through to the
// default rather than failing the scan; a malformed env should not be a
// hard error in the middle of a CI run.
func resolveScanTimeout(flagValue string) time.Duration {
	if flagValue != "" {
		if d, err := time.ParseDuration(flagValue); err == nil && d > 0 {
			return d
		}
		fmt.Fprintf(os.Stderr, "Warning: invalid --timeout %q; using default %s\n", flagValue, defaultScanTimeout)
	}
	if env := os.Getenv("RVL_SCAN_TIMEOUT"); env != "" {
		if d, err := time.ParseDuration(env); err == nil && d > 0 {
			return d
		}
		fmt.Fprintf(os.Stderr, "Warning: invalid RVL_SCAN_TIMEOUT %q; using default %s\n", env, defaultScanTimeout)
	}
	return defaultScanTimeout
}

// countFindingsWithoutComponent returns how many findings lack both a
// `component` field and `linked_services`. po-6u5yx: these findings fall
// back to the bare service label and split Reliability Budget rows.
//
// The findings slice is []interface{} (the CLI deep-merges arbitrary JSON
// shapes from scan-parts), so we inspect each entry as a map.
func countFindingsWithoutComponent(findings []interface{}) int {
	n := 0
	for _, raw := range findings {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		hasComponent := false
		if c, ok := m["component"].(string); ok && strings.TrimSpace(c) != "" {
			hasComponent = true
		}
		hasLinkedServices := false
		if ls, ok := m["linked_services"].([]interface{}); ok && len(ls) > 0 {
			hasLinkedServices = true
		}
		if !hasComponent && !hasLinkedServices {
			n++
		}
	}
	return n
}

// parseRetryAfter parses an HTTP Retry-After value as either delta-seconds
// or an HTTP-date. Returns 0 on parse failure (caller falls back to default).
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}

// decodeServerError extracts message + code from a JSON {code,message}
// error body (po-cw82g shape). Falls back to the raw body when the
// response isn't JSON.
func decodeServerError(body []byte) (message, code string) {
	var parsed struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		// Older handlers used {"error": "..."}
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		if parsed.Message != "" {
			return parsed.Message, parsed.Code
		}
		if parsed.Error != "" {
			return parsed.Error, parsed.Code
		}
	}
	return string(body), ""
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

		// po-bqzg4: warn on overlapping scalars/objects so the user knows
		// later files in alphabetical order win. Silent last-write-wins
		// makes scan-parts ordering accidentally significant.
		if partial.RepoURL != "" {
			if scanReq.RepoURL != "" && scanReq.RepoURL != partial.RepoURL {
				fmt.Fprintf(os.Stderr, "Warning: repo_url in %s overrides earlier value\n", filepath.Base(f))
			}
			scanReq.RepoURL = partial.RepoURL
		}
		if partial.ControlStructure != nil {
			if scanReq.ControlStructure != nil {
				fmt.Fprintf(os.Stderr, "Warning: control_structure in %s overrides earlier value\n", filepath.Base(f))
			}
			scanReq.ControlStructure = partial.ControlStructure
		}
		if partial.Stack != nil {
			if scanReq.Stack != nil {
				fmt.Fprintf(os.Stderr, "Warning: stack in %s overrides earlier value\n", filepath.Base(f))
			}
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
