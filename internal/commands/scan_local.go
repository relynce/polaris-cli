package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/project"
	"github.com/revelara-ai/rvl-cli/internal/scanner"
	"github.com/revelara-ai/rvl-cli/internal/scanner/matchers"
)

// scannerVersion is the matcher-set version string. Bumped when matchers
// change. PRD §Scan Mode in Metadata.
const scannerVersion = "0.1.0"

type localScanArgs struct {
	service              string
	targetDir            string
	format               string
	submit               bool
	matchersFlag         string
	changedOnly          bool
	baseRef              string
	scanAllOnMissingBase bool
	dryRun               bool
	ciMode               bool
}

// runLocalScan is the --local code path. Builds a matcher list, runs
// scanner.Scan against opts.targetDir (or cwd), and either emits JSON to
// stdout, submits to Polaris, or prints a human-readable summary.
//
// Phase 1 user stories: 1, 3, 5, 10, 14.
func runLocalScan(cliVersion string, opts localScanArgs) {
	target := opts.targetDir
	if target == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot get cwd: %v\n", err)
			os.Exit(2)
		}
		target = cwd
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid target: %v\n", err)
		os.Exit(2)
	}
	if info, err := os.Stat(absTarget); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: target is not a directory: %s\n", absTarget)
		os.Exit(2)
	}

	// Resolve service from .revelara.yaml in the target.
	service := opts.service
	projectCfg := project.LoadProjectConfigFrom(absTarget)
	if projectCfg != nil && projectCfg.Project != "" {
		if service != "" && service != projectCfg.Project {
			fmt.Fprintf(os.Stderr, "Warning: --service %q overridden by target's .revelara.yaml project: %q\n", service, projectCfg.Project)
		}
		service = projectCfg.Project
	}
	if service == "" {
		fmt.Fprintln(os.Stderr, "Error: --service is required (or use --target with a project that has .revelara.yaml)")
		os.Exit(2)
	}

	// Build the matcher list. Curated matchers from the registry; org
	// matchers from po-fayz.22 (returns empty in this slice).
	allMatchers := matchers.AllMatchers()
	orgMatchers, _ := scanner.LoadOrgMatchers("")
	allMatchers = append(allMatchers, orgMatchers...)

	scanOpts := scanner.ScanOptions{
		Root:    absTarget,
		Service: service,
		// Auto-detect languages so matchers with non-empty Languages
		// are filtered to the project's actual stack. Output mirrors
		// project.DetectLanguages: proper-case names ("Go", "JavaScript").
		Languages: project.DetectLanguages(absTarget),
	}
	if opts.matchersFlag != "" {
		scanOpts.OnlyMatchers = splitCSV(opts.matchersFlag)
	}
	if opts.changedOnly {
		// Build the resolution config from flag + environment (po-fayz.12
		// will add the .revelara.yaml scanner.base_ref source).
		envCfg := scanner.ChangedOnlyConfig{
			Root:        absTarget,
			FlagBaseRef: opts.baseRef,
			Env: map[string]string{
				"RVL_BASE_REF":                          os.Getenv("RVL_BASE_REF"),
				"GITHUB_BASE_REF":                       os.Getenv("GITHUB_BASE_REF"),
				"CI_MERGE_REQUEST_TARGET_BRANCH_NAME":   os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
			},
		}
		res, err := scanner.ResolveBaseRef(envCfg)
		if err != nil {
			if !opts.scanAllOnMissingBase {
				fmt.Fprint(os.Stderr, scanner.FormatNoBaseRefDiagnostic(res))
				os.Exit(2)
			}
			fmt.Fprintln(os.Stderr, "warning: no reachable base ref; --scan-all-on-missing-base set, falling back to full scan")
		} else {
			files, err := scanner.ResolveChangedFiles(absTarget, res.Ref)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: git diff failed: %v\n", err)
				os.Exit(2)
			}
			scanOpts.OnlyFiles = files
		}
	}

	if opts.dryRun {
		fmt.Printf("Dry run: would scan %s with %d matchers (service=%s)\n", absTarget, len(allMatchers), service)
		return
	}

	cands, stats, err := scanner.Scan(allMatchers, scanOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: scanner failed: %v\n", err)
		os.Exit(2)
	}
	findings := scanner.Convert(cands, allMatchers, service)

	// Component mapping via existing project.MapFindingsToComponents
	// (operates on []interface{}). Convert findings to that shape.
	asInterfaces := make([]interface{}, 0, len(findings))
	for _, f := range findings {
		var b []byte
		b, err = json.Marshal(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: marshal finding: %v\n", err)
			os.Exit(2)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			fmt.Fprintf(os.Stderr, "Error: unmarshal finding: %v\n", err)
			os.Exit(2)
		}
		asInterfaces = append(asInterfaces, m)
	}
	if projectCfg != nil && len(projectCfg.Components) > 0 {
		project.MapFindingsToComponents(asInterfaces, projectCfg)
	}

	if opts.submit {
		submitLocalScan(cliVersion, service, projectCfg, asInterfaces)
		exitOnSeverity(findings)
		return
	}

	if strings.EqualFold(opts.format, "json") {
		writeLocalJSON(service, asInterfaces)
		exitOnSeverity(findings)
		return
	}

	printLocalSummary(absTarget, service, findings, stats)
	exitOnSeverity(findings)
}

func writeLocalJSON(service string, findings []interface{}) {
	out := map[string]interface{}{
		"service":   service,
		"scan_type": "full",
		"findings":  findings,
		"metadata": map[string]interface{}{
			"scanner_id":      "rvl-local-scanner-" + scannerVersion,
			"matcher_version": scannerVersion,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(2)
	}
}

func submitLocalScan(cliVersion, service string, cfg *project.ProjectConfig, findings []interface{}) {
	apiCfg := api.LoadAndResolveConfig()
	scanReq := ScanRequest{
		Service:  service,
		ScanType: "full",
		Findings: findings,
		Metadata: ScanMetadata{
			ScannerID:    "rvl-local-scanner-" + scannerVersion,
			SkillName:    "rvl-local-scanner",
			SkillVersion: scannerVersion,
		},
	}
	if cfg != nil {
		if crit := cfg.CriticalityScore(); crit > 0 {
			scanReq.BusinessCriticality = &crit
		}
	}

	resp, err := submitScan(apiCfg, &scanReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting scan: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("Scan submitted successfully\n")
	fmt.Printf("  Scan ID: %s\n", resp.ScanID)
	fmt.Printf("  Service: %s\n", resp.Service)
	fmt.Printf("  Total: %d (Created: %d, Updated: %d, Unchanged: %d)\n",
		resp.Summary.Total, resp.Summary.Created, resp.Summary.Updated, resp.Summary.Unchanged)
	if resp.Summary.Critical > 0 || resp.Summary.High > 0 {
		fmt.Printf("  Priority: Critical=%d, High=%d, Medium=%d, Low=%d\n",
			resp.Summary.Critical, resp.Summary.High, resp.Summary.Medium, resp.Summary.Low)
	}
}

func printLocalSummary(target, service string, findings []scanner.ScanFinding, stats scanner.ScanStats) {
	fmt.Printf("Scanned %s (service=%s)\n", target, service)
	fmt.Printf("  Files: %d  Bytes: %d  Matchers: %d  Duration: %dms\n",
		stats.FilesScanned, stats.BytesScanned, stats.MatchersRun, stats.DurationMS)
	if len(findings) == 0 {
		fmt.Println("No findings.")
		return
	}
	fmt.Printf("\nFindings (%d):\n", len(findings))
	for _, f := range findings {
		path := ""
		line := 0
		if len(f.Evidence) > 0 {
			path = f.Evidence[0].Path
			line = f.Evidence[0].LineNumber
		}
		fmt.Printf("  [%s] %s\n    %s:%d\n", f.Category, f.Title, path, line)
	}
	// Severity counts.
	counts := severityCounts(findings)
	fmt.Printf("\nBy severity: critical=%d high=%d medium=%d low=%d\n",
		counts["critical"], counts["high"], counts["medium"], counts["low"])
}

// runListMatchers prints the registered matchers with provenance.
// sourceFilter is "curated" or "org-generated" or "" (any). format is
// "" or "table" for the human view, "json" for machine consumption.
//
// PRD §Provenance data flow (Phase 1): list output exposes incident
// frequency, typical blast radius, MTTR, and related controls so users
// can prioritize which matchers to enforce in CI.
func runListMatchers(sourceFilter, format string) {
	all := matchers.AllMatchers()
	sort.SliceStable(all, func(i, j int) bool { return all[i].Slug < all[j].Slug })

	filtered := all[:0]
	for _, m := range all {
		if sourceFilter != "" && !strings.EqualFold(m.Source, sourceFilter) {
			continue
		}
		filtered = append(filtered, m)
	}

	if strings.EqualFold(format, "json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(filtered)
		return
	}

	// Human-readable: one row per matcher, then a Provenance block.
	fmt.Printf("%-32s %-22s %-7s %-7s %-9s %s\n", "SLUG", "CATEGORY", "CONF", "SEV", "SOURCE", "LANGS")
	fmt.Println(strings.Repeat("-", 100))
	for _, m := range filtered {
		fmt.Printf("%-32s %-22s %-7s %-7s %-9s %s\n",
			m.Slug, m.Category, m.Confidence, m.Severity, m.Source, strings.Join(m.Languages, ","))
	}
	fmt.Println()
	for _, m := range filtered {
		fmt.Printf("%s\n", m.Slug)
		if m.Description != "" {
			fmt.Printf("  description:        %s\n", m.Description)
		}
		if len(m.ControlCodes) > 0 {
			fmt.Printf("  control_codes:      %s\n", strings.Join(m.ControlCodes, ", "))
		}
		if m.Provenance.IncidentFrequency != "" {
			fmt.Printf("  incident_frequency: %s\n", m.Provenance.IncidentFrequency)
		}
		if m.Provenance.TypicalBlastRadius != "" {
			fmt.Printf("  blast_radius:       %s\n", m.Provenance.TypicalBlastRadius)
		}
		if m.Provenance.TypicalMTTR != "" {
			fmt.Printf("  typical_mttr:       %s\n", m.Provenance.TypicalMTTR)
		}
		if m.Provenance.OrgIncidentCount > 0 {
			fmt.Printf("  org_incidents:      %d\n", m.Provenance.OrgIncidentCount)
		}
		if len(m.Provenance.OrgAffectedServices) > 0 {
			fmt.Printf("  org_services:       %s\n", strings.Join(m.Provenance.OrgAffectedServices, ", "))
		}
		fmt.Println()
	}
}

// exitOnSeverity sets the process exit code per the existing --ci
// semantics: 1 if any critical or high finding is present, 0 otherwise.
// Errors during the scan exit with 2 (set elsewhere).
func exitOnSeverity(findings []scanner.ScanFinding) {
	c := severityCounts(findings)
	if c["critical"] > 0 || c["high"] > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func severityCounts(findings []scanner.ScanFinding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[strings.ToLower(f.Impact)]++
	}
	return out
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
