package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/agentscan"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/project"
	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// This file wires the agentscan pipeline into `rvl scan --agent`
// (po-66evv.5). Exit-code contract for --agent:
//
//	0    pass, eval mode, skip, or infra fail-open
//	1    blocked: finding >= fail_on in enforce mode, strict_errors
//	     infra failure, or secrets refusal in enforce mode
//	2    config/usage error (flag combos, bad fail_on/mode values,
//	     target not a git repo, no base ref)
//	130  interrupted (SIGINT/SIGTERM)
//
// TODO(po-66evv.9): --pre-push hook entrypoint - read githooks(5)
// "<local-ref> <local-sha> <remote-ref> <remote-sha>" lines from stdin,
// skip deletes and tags, and scan <base>...<local-sha> per pushed ref.

// agentScanArgs carries the parsed `rvl scan --agent` flags.
type agentScanArgs struct {
	targetDir      string
	staged         bool
	changedOnly    bool
	baseRef        string
	localMode      bool // set when --local was also passed (invalid combo)
	mode           string
	failOn         string
	model          string
	agentBinary    string
	timeoutSeconds string
	format         string
}

// agentScanSettings is the effective configuration after merging flags
// over .revelara.yaml `scanner.agent` over built-in defaults.
type agentScanSettings struct {
	Mode           string
	FailOn         string
	StrictErrors   bool
	Model          string
	Binary         string // flag-only; never read from repo config (po-66evv.10)
	Timeout        time.Duration
	BudgetWarnUSD  float64
	GeneratedGlobs []string
	MaxInvocations int
}

// forceThroughHint is the last line of a blocked scan's output.
// TODO(po-66evv.6): implement force-through consumption (RVL_FORCE=1
// env and the one-shot `rvl scan force-next` marker under .git/).
const forceThroughHint = "commit blocked; use RVL_FORCE=1 or 'rvl scan force-next' to override (po-66evv.6)"

// validateAgentScanFlags rejects invalid `--agent` flag combinations.
// Callers map a non-nil error to exit code 2 with a usage message.
func validateAgentScanFlags(a agentScanArgs) error {
	if a.localMode {
		return errors.New("--agent and --local are mutually exclusive")
	}
	if a.staged && a.changedOnly {
		return errors.New("--staged and --changed-only are mutually exclusive")
	}
	if !a.staged && !a.changedOnly {
		return errors.New("--agent requires one of --staged or --changed-only")
	}
	if a.format != "" {
		if err := cliutil.ValidateFormat(strings.ToLower(a.format), "human", "json"); err != nil {
			return err
		}
	}
	return nil
}

// resolveAgentScanSettings merges configuration with precedence
// flag > .revelara.yaml scanner.agent > default, validating values.
//
// SECURITY (po-66evv.10 trust boundary): cfg comes from repo-tracked
// .revelara.yaml, which may set VALUES only (thresholds, mode, model,
// budgets). The agent binary override is flag/user-level only and is
// deliberately not read from cfg.
func resolveAgentScanSettings(a agentScanArgs, cfg *project.AgentScanConfig) (agentScanSettings, error) {
	s := agentScanSettings{
		Mode:           agentscan.GateModeEnforce,
		FailOn:         agentscan.DefaultFailOn,
		Model:          agentscan.DefaultModel,
		Timeout:        agentscan.DefaultTimeout,
		MaxInvocations: agentscan.DefaultMaxInvocations,
	}
	if cfg != nil {
		if cfg.Mode != "" {
			mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
			if err := validateScanMode(mode, "scanner.agent.mode"); err != nil {
				return s, err
			}
			s.Mode = mode
		}
		if cfg.FailOn != "" {
			failOn := strings.ToLower(strings.TrimSpace(cfg.FailOn))
			if !agentscan.KnownSeverity(failOn) {
				return s, fmt.Errorf("invalid scanner.agent.fail_on %q (expected critical, high, medium, or low)", cfg.FailOn)
			}
			s.FailOn = failOn
		}
		s.StrictErrors = cfg.StrictErrors
		if cfg.Model != "" {
			s.Model = cfg.Model
		}
		if cfg.TimeoutSeconds != 0 {
			if cfg.TimeoutSeconds < 0 {
				return s, fmt.Errorf("invalid scanner.agent.timeout_seconds %d (must be positive)", cfg.TimeoutSeconds)
			}
			s.Timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
		}
		if cfg.BudgetWarnUSD > 0 {
			s.BudgetWarnUSD = cfg.BudgetWarnUSD
		}
		s.GeneratedGlobs = cfg.GeneratedGlobs
		if cfg.MaxInvocations != 0 {
			if cfg.MaxInvocations < 0 {
				return s, fmt.Errorf("invalid scanner.agent.max_invocations %d (must be positive)", cfg.MaxInvocations)
			}
			s.MaxInvocations = cfg.MaxInvocations
		}
	}
	if a.mode != "" {
		mode := strings.ToLower(strings.TrimSpace(a.mode))
		if err := validateScanMode(mode, "--mode"); err != nil {
			return s, err
		}
		s.Mode = mode
	}
	if a.failOn != "" {
		failOn := strings.ToLower(strings.TrimSpace(a.failOn))
		if !agentscan.KnownSeverity(failOn) {
			return s, fmt.Errorf("invalid --fail-on %q (expected critical, high, medium, or low)", a.failOn)
		}
		s.FailOn = failOn
	}
	if a.model != "" {
		s.Model = a.model
	}
	if a.agentBinary != "" {
		s.Binary = a.agentBinary
	}
	if a.timeoutSeconds != "" {
		n, err := strconv.Atoi(a.timeoutSeconds)
		if err != nil || n <= 0 {
			return s, fmt.Errorf("invalid --timeout-seconds %q (must be a positive integer)", a.timeoutSeconds)
		}
		s.Timeout = time.Duration(n) * time.Second
	}
	return s, nil
}

// runAgentScan is the `rvl scan --agent` code path.
func runAgentScan(a agentScanArgs) {
	if err := validateAgentScanFlags(a); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Usage: rvl scan --agent (--staged | --changed-only [--base <ref>]) [--mode enforce|eval] [--fail-on <sev>] [--format human|json]")
		os.Exit(cliutil.ExitUsage)
	}

	target := a.targetDir
	if target == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot get cwd: %v\n", err)
			os.Exit(cliutil.ExitUsage)
		}
		target = cwd
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid target: %v\n", err)
		os.Exit(cliutil.ExitUsage)
	}
	if info, statErr := os.Stat(absTarget); statErr != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: target is not a directory: %s\n", absTarget)
		os.Exit(cliutil.ExitUsage)
	}
	root, err := gitToplevel(absTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cliutil.ExitUsage)
	}

	projectCfg := project.LoadProjectConfigFrom(absTarget)
	var agentCfg *project.AgentScanConfig
	var yamlBaseRef string
	var waivers []agentscan.Waiver
	if projectCfg != nil && projectCfg.Scanner != nil {
		agentCfg = projectCfg.Scanner.Agent
		yamlBaseRef = projectCfg.Scanner.BaseRef
		waivers = mapWaivers(projectCfg.Scanner.Waivers)
	}
	settings, err := resolveAgentScanSettings(a, agentCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cliutil.ExitUsage)
	}

	// Parent-context cancellation is the user-abort path (exit 130).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var cs agentscan.ChangeSet
	if a.staged {
		cs, err = agentscan.StagedChangeSet(root)
	} else {
		resolved, rerr := scanner.ResolveBaseRef(scanner.ChangedOnlyConfig{
			Root:        root,
			FlagBaseRef: a.baseRef,
			YAMLBaseRef: yamlBaseRef,
			Env: map[string]string{
				"RVL_BASE_REF":                        os.Getenv("RVL_BASE_REF"),
				"GITHUB_BASE_REF":                     os.Getenv("GITHUB_BASE_REF"),
				"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
			},
		})
		if rerr != nil {
			fmt.Fprint(os.Stderr, scanner.FormatNoBaseRefDiagnostic(resolved))
			os.Exit(cliutil.ExitUsage)
		}
		cs, err = agentscan.RangeChangeSet(root, resolved.Ref)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: compute change set: %v\n", err)
		os.Exit(cliutil.ExitUsage)
	}

	adapter := agentscan.NewClaudeAdapter(agentscan.AdapterConfig{
		Model:   settings.Model,
		Timeout: settings.Timeout,
		Binary:  settings.Binary,
	})
	result, err := agentscan.RunPipeline(ctx, agentscan.PipelineConfig{
		Root:                root,
		Adapter:             adapter,
		FailOn:              settings.FailOn,
		Mode:                settings.Mode,
		StrictErrors:        settings.StrictErrors,
		ExtraGeneratedGlobs: settings.GeneratedGlobs,
		BudgetWarnUSD:       settings.BudgetWarnUSD,
		MaxInvocations:      settings.MaxInvocations,
		Waivers:             waivers,
	}, cs)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			fmt.Fprintln(os.Stderr, "agent scan aborted")
			os.Exit(130)
		case errors.Is(err, agentscan.ErrSecretsDetected):
			// HARD refusal: never routed through the infra fail-open
			// path. Enforce blocks; eval exits 0 but warns loudly.
			printSecretsRefusal(err, settings.Mode)
			if settings.Mode == agentscan.GateModeEnforce {
				os.Exit(cliutil.ExitError)
			}
			os.Exit(cliutil.ExitOK)
		default:
			fmt.Fprintf(os.Stderr, "Error: agent scan failed: %v\n", err)
			os.Exit(cliutil.ExitError)
		}
	}

	// TODO(po-66evv.11): --submit - POST the aggregated findings plus
	// fail-open and force-through events to /api/v1/risks/scan here,
	// after the pipeline result exists and before exit-code mapping.

	if strings.EqualFold(a.format, "json") {
		printAgentScanJSON(result, settings)
	} else {
		printAgentScanHuman(result, settings)
	}

	if result.Skipped {
		os.Exit(cliutil.ExitOK)
	}

	// TODO(po-66evv.6): force-through consumption - check RVL_FORCE=1
	// and the one-shot `rvl scan force-next` marker under .git/ HERE,
	// before Blocked maps to the exit code; log the override, emit the
	// force-through event when submit is configured, then exit 0.
	if result.Blocked {
		os.Exit(cliutil.ExitError)
	}
	os.Exit(cliutil.ExitOK)
}

// mapWaivers converts .revelara.yaml WaiverEntry values into agentscan
// waivers (po-66evv.7). The matcher slug becomes the rule key; one
// waivers list serves both the local scanner and the agent scan (their
// slug namespaces are disjoint, so entries only match their own scanner).
func mapWaivers(entries []project.WaiverEntry) []agentscan.Waiver {
	if len(entries) == 0 {
		return nil
	}
	out := make([]agentscan.Waiver, 0, len(entries))
	for _, w := range entries {
		out = append(out, agentscan.Waiver{
			Rule:    w.Matcher,
			Paths:   append([]string(nil), w.Paths...),
			Expires: w.Expires,
			Reason:  w.Reason,
		})
	}
	return out
}

// mapWaivedReport flattens waived findings for the JSON report.
func mapWaivedReport(waived []agentscan.WaivedFinding) []agentWaivedFinding {
	if len(waived) == 0 {
		return nil
	}
	out := make([]agentWaivedFinding, 0, len(waived))
	for _, w := range waived {
		out = append(out, agentWaivedFinding{
			Finding: w.Finding,
			Rule:    w.Waiver.Rule,
			Reason:  w.Waiver.Reason,
			Expires: w.Waiver.Expires,
		})
	}
	return out
}

// gitToplevel resolves the repository root for dir; the change set,
// snapshot, and hygiene stages all need repo-relative paths.
func gitToplevel(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("%s is not inside a git repository", dir)
	}
	return strings.TrimSpace(string(out)), nil
}

// printSecretsRefusal prints the loud multi-line secrets refusal. The
// error message already names each file:line (never values) and points
// at the repo's secret scanner.
func printSecretsRefusal(err error, mode string) {
	line := strings.Repeat("=", 72)
	fmt.Fprintln(os.Stderr, ansiRed(line))
	fmt.Fprintln(os.Stderr, ansiRed("AGENT SCAN REFUSED: potential secrets detected in the outgoing diff"))
	fmt.Fprintf(os.Stderr, "%v\n", err)
	fmt.Fprintln(os.Stderr, "No agent was invoked and no diff content left this machine.")
	if mode == agentscan.GateModeEval {
		fmt.Fprintln(os.Stderr, "mode=eval: exiting 0, but this change set is refused in enforce mode.")
	}
	fmt.Fprintln(os.Stderr, ansiRed(line))
}

// classifyLensErr maps a lens error to its report class. All lens
// errors gate as infra class in v1, but the report distinguishes the
// fail-open taxonomy errors from agent/parse failures.
func classifyLensErr(err error) string {
	switch {
	case errors.Is(err, agentscan.ErrAgentTimeout):
		return "infra: timeout"
	case errors.Is(err, agentscan.ErrAgentUnavailable):
		return "infra: agent unavailable"
	default:
		return "agent error"
	}
}

// ansiRed wraps s in red ANSI codes unless NO_COLOR is set.
func ansiRed(s string) string {
	if os.Getenv("NO_COLOR") != "" {
		return s
	}
	return "\x1b[31m" + s + "\x1b[0m"
}

// gateSummaryLine renders the single final gate line. FileListMode is
// always flagged here so a degraded scan never reads as a full one.
func gateSummaryLine(res agentscan.PipelineResult, s agentScanSettings) string {
	var line string
	switch {
	case res.Blocked:
		line = fmt.Sprintf("Gate: BLOCKED (%s)", res.GateReason)
	case s.Mode == agentscan.GateModeEval && len(res.BlockedOn) > 0:
		line = fmt.Sprintf("Gate: PASS (eval mode; %d finding(s) at or above fail_on=%s would block in enforce mode)",
			len(res.BlockedOn), s.FailOn)
	case len(res.InfraErrors) > 0:
		line = fmt.Sprintf("Gate: PASS (fail-open: %d lens error(s))", len(res.InfraErrors))
	default:
		line = fmt.Sprintf("Gate: PASS (no findings at or above fail_on=%s)", s.FailOn)
	}
	if res.FileListMode {
		line += " [DEGRADED: file-list mode, diff content was not scanned]"
	}
	return line
}

// printAgentScanHuman renders the human report: per-lens lines,
// aggregated findings, notices, total cost, then exactly one gate line.
// A blocked run ends with the force-through hint; a fail-open run ends
// with the red banner as the very last line.
func printAgentScanHuman(res agentscan.PipelineResult, s agentScanSettings) {
	if res.Skipped {
		fmt.Println(res.SkipNotice)
		return
	}
	fmt.Printf("Agent scan: mode=%s fail_on=%s model=%s\n\n", s.Mode, s.FailOn, s.Model)
	fmt.Println("Lenses:")
	for _, lr := range res.LensResults {
		if lr.Err != nil {
			fmt.Printf("  %-14s [%s] %v (%.1fs, $%.2f)\n",
				lr.Lens.ID, classifyLensErr(lr.Err), lr.Err, lr.Wall.Seconds(), lr.CostUSD)
			continue
		}
		fmt.Printf("  %-14s %d finding(s), %d dropped, %.1fs, $%.2f\n",
			lr.Lens.ID, len(lr.Findings), len(lr.Dropped), lr.Wall.Seconds(), lr.CostUSD)
	}
	for _, lr := range res.LensResults {
		for _, d := range lr.Dropped {
			fmt.Printf("  dropped [%s] %s %s:%d: %s\n",
				lr.Lens.ID, d.Finding.Rule, d.Finding.File, d.Finding.Line, d.Reason)
		}
	}
	if len(res.Findings) > 0 {
		fmt.Println("\nFindings:")
		for _, f := range res.Findings {
			fmt.Printf("  %-8s %-28s %s:%d  %s\n",
				strings.ToUpper(f.Severity), f.Rule, f.File, f.Line, f.Title)
		}
	}
	if len(res.Waived) > 0 {
		fmt.Printf("\nWaived (%d):\n", len(res.Waived))
		for _, w := range res.Waived {
			reason := w.Waiver.Reason
			if reason == "" {
				reason = "(no reason given)"
			}
			exp := ""
			if w.Waiver.Expires != "" {
				exp = fmt.Sprintf(" [expires %s]", w.Waiver.Expires)
			}
			fmt.Printf("  %-28s %s:%d  %s%s\n",
				w.Finding.Rule, w.Finding.File, w.Finding.Line, reason, exp)
		}
	}
	if len(res.Notices) > 0 {
		fmt.Println("\nNotices:")
		for _, n := range res.Notices {
			fmt.Printf("  - %s\n", n)
		}
	}
	cost := fmt.Sprintf("Total agent cost: $%.2f", res.TotalCostUSD)
	if s.BudgetWarnUSD > 0 {
		cost += fmt.Sprintf(" (budget warn at $%.2f)", s.BudgetWarnUSD)
	}
	fmt.Println()
	fmt.Println(cost)
	fmt.Println(gateSummaryLine(res, s))
	if res.Blocked {
		fmt.Println(forceThroughHint)
	} else if res.Banner != "" {
		fmt.Println(ansiRed(res.Banner))
	}
}

// Wire shapes for --format json. InfraErrors flatten to strings;
// everything else in PipelineResult is carried through.
type agentLensReport struct {
	Lens       string                `json:"lens"`
	Findings   []agentscan.Finding   `json:"findings"`
	Dropped    []agentDroppedFinding `json:"dropped,omitempty"`
	Summary    string                `json:"summary,omitempty"`
	CostUSD    float64               `json:"cost_usd"`
	WallMS     int64                 `json:"wall_ms"`
	Error      string                `json:"error,omitempty"`
	ErrorClass string                `json:"error_class,omitempty"`
}

type agentDroppedFinding struct {
	Finding agentscan.Finding `json:"finding"`
	Reason  string            `json:"reason"`
}

type agentWaivedFinding struct {
	Finding agentscan.Finding `json:"finding"`
	Rule    string            `json:"rule"`
	Reason  string            `json:"reason,omitempty"`
	Expires string            `json:"expires,omitempty"`
}

type agentScanReport struct {
	Mode         string               `json:"mode"`
	FailOn       string               `json:"fail_on"`
	StrictErrors bool                 `json:"strict_errors"`
	Skipped      bool                 `json:"skipped"`
	SkipNotice   string               `json:"skip_notice,omitempty"`
	Lenses       []agentLensReport    `json:"lenses"`
	Findings     []agentscan.Finding  `json:"findings"`
	Waived       []agentWaivedFinding `json:"waived,omitempty"`
	Notices      []string             `json:"notices,omitempty"`
	TotalCostUSD float64              `json:"total_cost_usd"`
	Degraded     bool                 `json:"degraded"`
	FileListMode bool                 `json:"file_list_mode"`
	InfraErrors  []string             `json:"infra_errors,omitempty"`
	Blocked      bool                 `json:"blocked"`
	BlockedOn    []agentscan.Finding  `json:"blocked_on,omitempty"`
	GateReason   string               `json:"gate_reason,omitempty"`
	Banner       string               `json:"banner,omitempty"`
}

// printAgentScanJSON emits the machine-readable report on stdout. The
// gate/banner visibility lines go to stderr so hooks piping stdout
// still see the outcome, with the banner kept last.
func printAgentScanJSON(res agentscan.PipelineResult, s agentScanSettings) {
	report := agentScanReport{
		Mode:         s.Mode,
		FailOn:       s.FailOn,
		StrictErrors: s.StrictErrors,
		Skipped:      res.Skipped,
		SkipNotice:   res.SkipNotice,
		Lenses:       make([]agentLensReport, 0, len(res.LensResults)),
		Findings:     res.Findings,
		Notices:      res.Notices,
		TotalCostUSD: res.TotalCostUSD,
		Degraded:     res.Degraded,
		Waived:       mapWaivedReport(res.Waived),
		FileListMode: res.FileListMode,
		Blocked:      res.Blocked,
		BlockedOn:    res.BlockedOn,
		GateReason:   res.GateReason,
		Banner:       res.Banner,
	}
	for _, lr := range res.LensResults {
		entry := agentLensReport{
			Lens:     lr.Lens.ID,
			Findings: lr.Findings,
			Summary:  lr.Summary,
			CostUSD:  lr.CostUSD,
			WallMS:   lr.Wall.Milliseconds(),
		}
		for _, d := range lr.Dropped {
			entry.Dropped = append(entry.Dropped, agentDroppedFinding{Finding: d.Finding, Reason: d.Reason})
		}
		if lr.Err != nil {
			entry.Error = lr.Err.Error()
			entry.ErrorClass = classifyLensErr(lr.Err)
		}
		report.Lenses = append(report.Lenses, entry)
	}
	for _, e := range res.InfraErrors {
		report.InfraErrors = append(report.InfraErrors, e.Error())
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(cliutil.ExitError)
	}
	if res.Blocked {
		fmt.Fprintln(os.Stderr, gateSummaryLine(res, s))
		fmt.Fprintln(os.Stderr, forceThroughHint)
	} else if res.Banner != "" {
		fmt.Fprintln(os.Stderr, ansiRed(res.Banner))
	}
}
