package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	noDedupe             bool // po-jlsd6: suppress grouped output, emit flat per-instance only
	mode                 string // po-f96kz: "" | enforce | eval — eval always exits 0
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
	var appliedWaivers []AppliedWaiver
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
		// po-qs96.5: time-bounded waivers from .revelara.yaml. Active
		// waivers are recorded for audit-trail submission to polaris;
		// the actual finding suppression happens in filterFindingsByWaivers
		// after the engine runs (see below) so we have access to the
		// finding slug + path to match the waiver's matcher + path glob.
		appliedWaivers = activeWaivers(sc.Waivers, time.Now())
	}
	// po-i7mz2: resolved base ref is shared between --changed-only file
	// scoping and the change-aware classification step. Classification
	// only runs when we have a reachable base ref AND we're scoped to
	// changed files (otherwise classifying findings in unchanged files
	// as "pre-existing" is misleading).
	var changedHunks map[string][]scanner.LineRange
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
				"RVL_BASE_REF":                        os.Getenv("RVL_BASE_REF"),
				"GITHUB_BASE_REF":                     os.Getenv("GITHUB_BASE_REF"),
				"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
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
			changedHunks, err = scanner.ResolveChangedHunks(absTarget, res.Ref)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: git diff hunks: %v\n", err)
				os.Exit(2)
			}
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

	// po-i7mz2: classify findings as new vs pre-existing against the
	// changed hunks (when --changed-only resolved a base ref). Tags
	// each finding's Status; nothing is dropped here. Pre-existing
	// findings will appear in output but won't fail the CI gate.
	if changedHunks != nil {
		scanner.ClassifyFindings(findings, changedHunks)
	}

	// po-qs96.5: apply yaml-defined waivers post-scan. Floor matchers
	// remain when strict_enforcement is on regardless of any yaml waiver.
	floorSet := floorMatcherSlugs(allMatchers)
	strict := projectCfg != nil && projectCfg.Scanner != nil &&
		projectCfg.Scanner.StrictEnforcement != nil && *projectCfg.Scanner.StrictEnforcement
	var matchedWaivers []AppliedWaiver
	findings, matchedWaivers = filterFindingsByWaivers(findings, appliedWaivers, strict, floorSet)
	_ = matchedWaivers // forwarded to submission metadata below

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
		var groups []scanner.FindingGroup
		if !opts.noDedupe {
			groups = scanner.Group(findings)
		}
		writeLocalJSON(service, asInterfaces, groups)
	}
	var submitResp *ScanResponse
	if opts.submit {
		submitResp = submitLocalScan(cliVersion, service, projectCfg, asInterfaces, excludedMatcherSlugs, matchedWaivers)
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
	// po-f96kz: resolve scan mode from CLI override > config > default.
	// eval short-circuits the severity gate so adoption-stage rollouts
	// can report findings without failing CI.
	var cfgMode string
	if projectCfg != nil && projectCfg.Scanner != nil {
		cfgMode = projectCfg.Scanner.Mode
	}
	resolvedMode, err := resolveScanMode(opts.mode, cfgMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	if resolvedMode == scanModeEval {
		os.Exit(0)
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
		// po-qs96.4 fix: resolved-this-scan signal is the count of risks
		// that exist for this service but were not in the current scan.
		// Polaris populates this in ScanSummary.ResolvedThisScan when it
		// marks risks as stale. Count-only for v1; per-risk detail awaits
		// a server-side scan_id diff.
		in.ResolvedCount = resp.Summary.ResolvedThisScan
		in.PerServiceBreakdown = perServiceBreakdownFromFindings(findings, resp.EffectiveTolerance)
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

// perServiceBreakdownFromFindings aggregates new findings by the
// per-finding Component the scanner attributed (set by
// project.MapFindingsToComponents from .revelara.yaml). Returns rows
// only when more than one distinct component is touched — single-service
// PRs render the simple budget summary instead. po-qs96.4 fix.
func perServiceBreakdownFromFindings(findings []scanner.ScanFinding, tol *EffectiveTolerance) []ServiceBudget {
	if len(findings) == 0 {
		return nil
	}
	type acc struct {
		score, count int
	}
	per := map[string]*acc{}
	for _, f := range findings {
		key := f.Component
		if key == "" && len(f.LinkedServices) > 0 {
			key = f.LinkedServices[0]
		}
		if key == "" {
			continue
		}
		entry, ok := per[key]
		if !ok {
			entry = &acc{}
			per[key] = entry
		}
		entry.score += severityScore(f.Impact)
		entry.count++
	}
	if len(per) <= 1 {
		return nil // single-service: caller will not render the per-service table
	}
	target := 0
	if tol != nil {
		target = tol.ToleranceTarget
	}
	out := make([]ServiceBudget, 0, len(per))
	for svc, a := range per {
		row := ServiceBudget{
			Service:       svc,
			NetDelta:      a.score,
			MeasuredState: a.score,
			Tolerance:     target,
			Status:        "in_budget",
		}
		if target > 0 && a.score > target {
			row.Status = "over_budget"
		}
		out = append(out, row)
	}
	return out
}

// AppliedWaiver is a record of a yaml waiver that was active at scan time.
// Submitted to polaris as scan-metadata so the waivers_audit table has a
// who/when/scope/reason record for every applied suppression.
// po-qs96.5 / docs/designs/local-scanner-developer-workflow.md § "Waivers".
type AppliedWaiver struct {
	Matcher string   `json:"matcher"`
	Paths   []string `json:"paths,omitempty"`
	Expires string   `json:"expires,omitempty"`
	Reason  string   `json:"reason"`
}

// floorMatcherSlugs returns the set of matcher slugs marked Floor:true.
// Used by filterFindingsByWaivers to enforce that strict-enforcement
// mode does not let yaml waivers bypass compliance/security matchers.
// po-qs96.2 + po-qs96.5.
func floorMatcherSlugs(matchers []scanner.Matcher) map[string]bool {
	out := map[string]bool{}
	for _, m := range matchers {
		if m.Floor {
			out[strings.ToLower(m.Slug)] = true
		}
	}
	return out
}

// activeWaivers filters out yaml waivers whose `expires` date has passed.
// Empty `expires` means open-ended (always active until removed in repo).
func activeWaivers(entries []project.WaiverEntry, now time.Time) []AppliedWaiver {
	out := make([]AppliedWaiver, 0, len(entries))
	for _, w := range entries {
		if w.Expires != "" {
			if exp, err := time.Parse("2006-01-02", w.Expires); err == nil {
				if now.After(exp) {
					continue
				}
			}
		}
		out = append(out, AppliedWaiver{
			Matcher: w.Matcher,
			Paths:   append([]string(nil), w.Paths...),
			Expires: w.Expires,
			Reason:  w.Reason,
		})
	}
	return out
}

// filterFindingsByWaivers drops findings whose matcher slug + evidence path
// is covered by an active waiver. Returns the remaining findings + the
// subset of waivers that actually matched at least one finding (the ones
// worth recording in the audit trail). Floor matchers are NEVER waived
// when strictEnforcement is true; instead they require emergency override.
//
// Matching is by ScanFinding.Slug (the matcher slug, set in convert.go),
// not by title-substring against the matcher description.
func filterFindingsByWaivers(findings []scanner.ScanFinding, waivers []AppliedWaiver, strict bool, floorSet map[string]bool) ([]scanner.ScanFinding, []AppliedWaiver) {
	if len(findings) == 0 {
		return findings, nil
	}
	usedWaivers := map[int]bool{}
	out := make([]scanner.ScanFinding, 0, len(findings))
findingLoop:
	for _, f := range findings {
		findingSlug := strings.ToLower(f.Slug)
		// po-qs96.2 + po-qs96.5: in strict mode, floor matchers cannot
		// be waived via yaml/comment/label — only emergency override.
		if strict && findingSlug != "" && floorSet[findingSlug] {
			out = append(out, f)
			continue
		}
		if len(waivers) == 0 || findingSlug == "" {
			out = append(out, f)
			continue
		}
		var path0 string
		if len(f.Evidence) > 0 {
			path0 = f.Evidence[0].Path
		}
		for i, w := range waivers {
			if findingSlug != strings.ToLower(w.Matcher) {
				continue
			}
			if len(w.Paths) == 0 || waiverMatchesPath(w.Paths, path0) {
				usedWaivers[i] = true
				continue findingLoop
			}
		}
		out = append(out, f)
	}
	matched := make([]AppliedWaiver, 0, len(usedWaivers))
	for i := range usedWaivers {
		matched = append(matched, waivers[i])
	}
	return out, matched
}

// waiverMatchesPath returns true if any of the waiver's path globs matches
// the given finding path. Uses path.Match for forward-slash glob semantics
// independent of host OS.
func waiverMatchesPath(globs []string, p string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, p); ok {
			return true
		}
		// Allow `**` prefix glob: `**/*.go` matches `pkg/foo/bar.go`.
		if strings.HasPrefix(g, "**/") {
			suffix := strings.TrimPrefix(g, "**/")
			if ok, _ := path.Match(suffix, path.Base(p)); ok {
				return true
			}
		}
	}
	return false
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

func writeLocalJSON(service string, findings []interface{}, groups []scanner.FindingGroup) {
	out := map[string]interface{}{
		"service":   service,
		"scan_type": "full",
		"findings":  findings,
		"metadata": map[string]interface{}{
			"scanner_id":      "rvl-local-scanner-" + scannerVersion,
			"matcher_version": scannerVersion,
		},
	}
	if len(groups) > 0 {
		// po-jlsd6: groups is the clustered view of findings, one entry per
		// (category, matcher) pair with rolled-up instance counts and
		// locations. CI scripts that want aggregate counts read this;
		// scripts that submit to polaris keep using findings.
		out["groups"] = groups
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(2)
	}
}

func submitLocalScan(cliVersion, service string, cfg *project.ProjectConfig, findings []interface{}, excludedMatchers []string, appliedWaivers []AppliedWaiver) *ScanResponse {
	apiCfg := api.LoadAndResolveConfig()
	wireWaivers := make([]AppliedWaiverWire, 0, len(appliedWaivers))
	for _, w := range appliedWaivers {
		wireWaivers = append(wireWaivers, AppliedWaiverWire(w))
	}
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
			AppliedWaivers:   wireWaivers,
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

// exitOnSeverity sets the process exit code based on whether any
// gating finding is present. A finding gates when its severity is
// critical or high AND its Status is not "pre-existing". When
// classification didn't run (Status empty, no base ref), behavior
// matches the original --ci semantics: any critical/high gates.
// Errors during the scan exit with 2 (set elsewhere).
//
// po-i7mz2: pre-existing findings appear in output but never gate.
// The intent is the staticcheck `--new-from-rev` precedent: surface
// "your edit landed next to a known problem" without blocking the
// build on tech debt.
func exitOnSeverity(findings []scanner.ScanFinding) {
	if scanner.HasGatingFindings(findings) {
		os.Exit(1)
	}
	os.Exit(0)
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
