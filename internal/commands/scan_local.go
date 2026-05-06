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
	}
	if opts.matchersFlag != "" {
		scanOpts.OnlyMatchers = splitCSV(opts.matchersFlag)
	}
	if opts.changedOnly {
		// po-fayz.9 will replace this stub with the full resolver chain.
		// For now, the stub returns nil meaning "scan everything".
		scanOpts.OnlyFiles, _ = scanner.ResolveChangedFiles(absTarget, opts.baseRef)
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

// runListMatchers prints the registered matchers in a human-readable
// format. po-fayz.10 will expand this to include provenance columns and
// a --source filter.
func runListMatchers(filter string) {
	all := matchers.AllMatchers()
	sort.SliceStable(all, func(i, j int) bool { return all[i].Slug < all[j].Slug })
	for _, m := range all {
		fmt.Printf("%-32s %-20s %-10s %-8s impl=%s langs=%v controls=%v\n",
			m.Slug, m.Category, m.Confidence, m.Severity, m.Impl, m.Languages, m.ControlCodes)
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
