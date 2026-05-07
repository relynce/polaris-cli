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
	prComment            bool // po-qs96.4: emit sticky-comment markdown
}

// runLocalScan is the --local code path. Builds a matcher list, runs
// scanner.Scan against opts.targetDir (or cwd), and either emits JSON to
// stdout, submits to Revelara, or prints a human-readable summary.
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
	// matchers loaded from the lazy-fetch cache (po-fayz.22).
	allMatchers := matchers.AllMatchers()
	cacheDir, _ := scanner.OrgMatcherCacheDir()
	apiCfg := api.LoadAndResolveConfig()
	scanner.LazyFetchOrgMatchers(apiCfg.APIURL, apiCfg.APIKey, apiCfg.ResolvedOrgID)
	if orgMatchers, err := scanner.LoadOrgMatchers(cacheDir); err == nil {
		allMatchers = append(allMatchers, orgMatchers...)
	}

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

	// .revelara.yaml `scanner` overrides. PRD §Configuration in
	// .revelara.yaml: optional, ignored if absent.
	var excludedMatcherSlugs []string
	if projectCfg != nil && projectCfg.Scanner != nil {
		sc := projectCfg.Scanner
		if len(sc.ExcludeMatchers) > 0 {
			scanOpts.ExcludeMatchers = make(map[string]bool, len(sc.ExcludeMatchers))
			for _, s := range sc.ExcludeMatchers {
				scanOpts.ExcludeMatchers[s] = true
				excludedMatcherSlugs = append(excludedMatcherSlugs, s)
			}
		}
		if len(sc.ExcludePaths) > 0 {
			scanOpts.ExcludePaths = sc.ExcludePaths
		}
		if sc.ConfidenceThreshold != "" {
			scanOpts.ConfidenceMin = sc.ConfidenceThreshold
		}
		if sc.IncludeTests {
			scanOpts.IncludeTests = true
		}
	}
	if opts.changedOnly {
		var yamlBaseRef string
		if projectCfg != nil && projectCfg.Scanner != nil {
			yamlBaseRef = projectCfg.Scanner.BaseRef
		}
		envCfg := scanner.ChangedOnlyConfig{
			Root:        absTarget,
			FlagBaseRef: opts.baseRef,
			YAMLBaseRef: yamlBaseRef,
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

	// --format json prints the JSON shape, regardless of --submit.
	// --submit posts to Revelara (after JSON is printed when both are set).
	if strings.EqualFold(opts.format, "json") {
		writeLocalJSON(service, asInterfaces)
	}
	var submitResp *ScanResponse
	if opts.submit {
		submitResp = submitLocalScan(cliVersion, service, projectCfg, asInterfaces, excludedMatcherSlugs)
	}
	if strings.EqualFold(opts.format, "markdown") {
		// Explicit markdown output: emit raw without glamour rendering,
		// regardless of TTY.
		fmt.Print(renderScanReportMarkdown(absTarget, service, findings, stats))
	} else if !strings.EqualFold(opts.format, "json") && !opts.submit {
		renderLocalSummary(absTarget, service, findings, stats)
	}
	// po-qs96.4: --pr-comment emits the sticky-comment markdown to stdout
	// for CI scripts to post via `gh pr comment` (or equivalent). The
	// hidden marker at the top lets the CI script find and update the
	// existing comment instead of creating duplicates.
	if opts.prComment {
		emitPRComment(service, findings, projectCfg, submitResp)
	}
	exitOnSeverity(findings)
}

// emitPRComment writes the sticky-comment markdown to stdout. When
// submitResp is non-nil (i.e., the scan was --submit'd), the budget math
// reflects the polaris-resolved tolerance and post-submission state. When
// submitResp is nil (scan ran but didn't submit) the comment renders
// without budget context — the CI script can still post it as a
// findings-only summary.
func emitPRComment(service string, findings []scanner.ScanFinding, cfg *project.ProjectConfig, resp *ScanResponse) {
	in := PRCommentInput{
		Service:         service,
		NewFindings:     findings,
		HasRevelaraYAML: cfg != nil,
	}
	in.NetDelta = sumFindingScores(findings)
	if resp != nil {
		in.EffectiveTolerance = resp.EffectiveTolerance
		in.MeasuredState = sumScanResultScores(resp.Findings)
		in.ResolvedFindings = filterResolvedFindings(resp.Findings)
		in.PerServiceBreakdown = perServiceBreakdownFrom(resp)
	}
	fmt.Print(RenderPRComment(in))
}

// sumFindingScores estimates the contribution of new local-scanner
// findings to the budget when no submission has happened. Each finding
// is weighted by its impact severity using the same factors Polaris
// applies in Path 5 with severity fallback (high=10*10=100, etc.).
func sumFindingScores(findings []scanner.ScanFinding) int {
	score := 0
	for _, f := range findings {
		score += severityScore(f.Impact)
	}
	return score
}

func sumScanResultScores(results []ScanResult) int {
	score := 0
	for _, r := range results {
		score += r.Score
	}
	return score
}

func filterResolvedFindings(results []ScanResult) []ScanResult {
	out := make([]ScanResult, 0, len(results))
	for _, r := range results {
		if r.Status == "resolved" {
			out = append(out, r)
		}
	}
	return out
}

// severityScore mirrors polaris-side severity-doubled fallback (Path 2):
// low=4*4=16, medium=7*7=49, high=10*10=100.
func severityScore(impact string) int {
	switch strings.ToLower(impact) {
	case "high", "critical":
		return 100
	case "medium":
		return 49
	case "low":
		return 16
	}
	return 49
}

// perServiceBreakdownFrom aggregates the scan response findings by their
// linked services so the sticky comment can show per-service budget
// breakdowns when a PR touches more than one service. Each open finding
// is attributed to every service it lists.
func perServiceBreakdownFrom(resp *ScanResponse) []ServiceBudget {
	if resp == nil {
		return nil
	}
	type acc struct {
		score, count int
	}
	per := map[string]*acc{}
	for _, r := range resp.Findings {
		if r.Status == "resolved" {
			continue
		}
		// rvl-cli ScanResult does not carry linked_services; the polaris
		// API attribution is always against the scan's primary service,
		// so a single-service view is correct here. po-qs96.4 records
		// the structural shape so a later iteration can extend without
		// changing the wire.
		key := resp.Service
		entry, ok := per[key]
		if !ok {
			entry = &acc{}
			per[key] = entry
		}
		entry.score += r.Score
		entry.count++
	}
	if len(per) <= 1 {
		return nil // single-service: caller will not render the per-service table
	}
	out := make([]ServiceBudget, 0, len(per))
	tol := 0
	if resp.EffectiveTolerance != nil {
		tol = resp.EffectiveTolerance.ToleranceTarget
	}
	for svc, a := range per {
		row := ServiceBudget{
			Service:       svc,
			NetDelta:      a.score,
			MeasuredState: a.score,
			Tolerance:     tol,
			Status:        "in_budget",
		}
		if tol > 0 && a.score > tol {
			row.Status = "over_budget"
		}
		out = append(out, row)
	}
	return out
}

// buildServiceToleranceConfig translates the .revelara.yaml `scanner`
// section into the wire shape Polaris consumes. Returns nil when the
// service has not overridden any tolerance fields so the request stays
// compact and the resolver naturally falls through to org defaults.
// po-qs96.2 / docs/designs/local-scanner-developer-workflow.md (polaris).
func buildServiceToleranceConfig(sc *project.ScannerConfig) *ServiceToleranceConfig {
	if sc == nil {
		return nil
	}
	out := &ServiceToleranceConfig{}
	any := false
	if sc.Tolerance != nil {
		if sc.Tolerance.Target != nil {
			out.ToleranceTarget = sc.Tolerance.Target
			any = true
		}
		if sc.Tolerance.HeadroomPct != nil {
			out.ToleranceHeadroomPct = sc.Tolerance.HeadroomPct
			any = true
		}
	}
	if sc.StrictEnforcement != nil {
		out.StrictEnforcement = sc.StrictEnforcement
		any = true
	}
	if !any {
		return nil
	}
	return out
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

func submitLocalScan(cliVersion, service string, cfg *project.ProjectConfig, findings []interface{}, excludedMatchers []string) *ScanResponse {
	apiCfg := api.LoadAndResolveConfig()
	scanReq := ScanRequest{
		Service:  service,
		ScanType: "full",
		Findings: findings,
		Metadata: ScanMetadata{
			ScannerID:        "rvl-local-scanner-" + scannerVersion,
			SkillName:        "rvl-local-scanner",
			SkillVersion:     scannerVersion,
			MatcherVersion:   scannerVersion,
			ExcludedMatchers: excludedMatchers,
		},
	}
	if cfg != nil {
		if crit := cfg.CriticalityScore(); crit > 0 {
			scanReq.BusinessCriticality = &crit
		}
		// po-qs96.2: per-service tolerance flows to the Polaris CI gate
		// when set in .revelara.yaml `scanner.tolerance` and/or
		// `scanner.strict_enforcement`. Polaris merges over org defaults.
		if svcTol := buildServiceToleranceConfig(cfg.Scanner); svcTol != nil {
			scanReq.ServiceTolerance = svcTol
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
	return resp
}

// printLocalSummary is retained as a thin shim around the new
// glamour-rendered renderLocalSummary. Kept so any callers outside
// this file still compile; new code should use renderLocalSummary
// directly.
func printLocalSummary(target, service string, findings []scanner.ScanFinding, stats scanner.ScanStats) {
	renderLocalSummary(target, service, findings, stats)
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
	// po-qs96.2: FLOOR badge marks matchers that bypass the standard
	// waiver path under strict_enforcement.
	fmt.Printf("%-32s %-22s %-7s %-7s %-9s %-7s %s\n", "SLUG", "CATEGORY", "CONF", "SEV", "SOURCE", "FLOOR", "LANGS")
	fmt.Println(strings.Repeat("-", 110))
	for _, m := range filtered {
		floor := ""
		if m.Floor {
			floor = "[FLOOR]"
		}
		fmt.Printf("%-32s %-22s %-7s %-7s %-9s %-7s %s\n",
			m.Slug, m.Category, m.Confidence, m.Severity, m.Source, floor, strings.Join(m.Languages, ","))
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
