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
	prePush        bool // po-66evv.9: read githooks ref lines from stdin
	baseRef        string
	localMode      bool // set when --local was also passed (invalid combo)
	mode           string
	failOn         string
	model          string
	agentBinary    string
	agentPreset    string // po-66evv.10: adapter preset (claude|custom)
	timeoutSeconds string
	format         string
	submit         bool   // po-66evv.11: opt-in POST to the risks scan endpoint
	service        string // service name for submission (or from .revelara.yaml)
	timeout        string // submission HTTP timeout override (e.g. 90s)
}

// agentScanSettings is the effective configuration after merging flags
// over .revelara.yaml `scanner.agent` over built-in defaults.
type agentScanSettings struct {
	Mode           string
	FailOn         string
	StrictErrors   bool
	Preset         string // adapter preset name (repo config may set this: a name, not code)
	Model          string
	Binary         string // flag-only; never read from repo config (po-66evv.10)
	Timeout        time.Duration
	BudgetWarnUSD  float64
	GeneratedGlobs []string
	MaxInvocations int
}

// forceThroughHint is the last line of a blocked scan's output. Both
// override paths (RVL_FORCE=1 and `rvl scan force-next`) are consumed at
// the top of runAgentScan (po-66evv.6).
const forceThroughHint = "commit blocked; use RVL_FORCE=1 or 'rvl scan force-next' to override"

// validateAgentScanFlags rejects invalid `--agent` flag combinations.
// Callers map a non-nil error to exit code 2 with a usage message.
func validateAgentScanFlags(a agentScanArgs) error {
	if a.localMode {
		return errors.New("--agent and --local are mutually exclusive")
	}
	modes := 0
	for _, on := range []bool{a.staged, a.changedOnly, a.prePush} {
		if on {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("--staged, --changed-only, and --pre-push are mutually exclusive")
	}
	if modes == 0 {
		return errors.New("--agent requires one of --staged, --changed-only, or --pre-push")
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
		// Preset is a built-in adapter NAME, safe to accept from repo
		// config (po-66evv.10). A custom command string is not a repo
		// field; it comes only from RVL_AGENT_CMD.
		if cfg.Preset != "" {
			s.Preset = cfg.Preset
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
	if a.agentPreset != "" {
		s.Preset = a.agentPreset
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

	// po-66evv.6: emergency force-through. Checked BEFORE the scan runs,
	// because a force-through skips the gate entirely (spec: Gate policy)
	// so it must not pay the scan's wall-clock or cost. The override is
	// audited locally; TODO(po-66evv.11) submits the event when --submit
	// is configured.
	if mechanism, forced, ferr := agentscan.ForceState(root); ferr == nil && forced {
		handleForceThrough(root, mechanism)
		os.Exit(cliutil.ExitOK)
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

	// Adapter selection with the trust boundary (po-66evv.10): the preset
	// name may come from repo config, but a custom command comes ONLY
	// from RVL_AGENT_CMD (a user-level source), never repo config.
	adapter, err := agentscan.SelectAdapter(agentscan.AdapterChoice{
		Preset:         settings.Preset,
		Config:         agentscan.AdapterConfig{Model: settings.Model, Timeout: settings.Timeout, Binary: settings.Binary},
		TrustedCommand: parseAgentCmdEnv(os.Getenv("RVL_AGENT_CMD")),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cliutil.ExitUsage)
	}

	// Shared pipeline config; the change set and snapshot treeish are set
	// per run (one run for staged/changed-only, one per pushed ref for
	// pre-push).
	baseCfg := agentscan.PipelineConfig{
		Root:                root,
		Adapter:             adapter,
		FailOn:              settings.FailOn,
		Mode:                settings.Mode,
		StrictErrors:        settings.StrictErrors,
		ExtraGeneratedGlobs: settings.GeneratedGlobs,
		BudgetWarnUSD:       settings.BudgetWarnUSD,
		MaxInvocations:      settings.MaxInvocations,
		Waivers:             waivers,
	}

	if a.prePush {
		os.Exit(runAgentPrePush(ctx, a, root, absTarget, settings, baseCfg))
	}

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

	os.Exit(runOnePipeline(ctx, baseCfg, cs, a, settings, absTarget))
}

// runOnePipeline runs the pipeline over one change set and returns the
// process exit code (rather than calling os.Exit), so the pre-push path
// can aggregate results across multiple pushed refs. It handles the
// error taxonomy, optional submit, and report printing.
func runOnePipeline(ctx context.Context, cfg agentscan.PipelineConfig, cs agentscan.ChangeSet, a agentScanArgs, settings agentScanSettings, absTarget string) int {
	result, err := agentscan.RunPipeline(ctx, cfg, cs)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			fmt.Fprintln(os.Stderr, "agent scan aborted")
			return 130
		case errors.Is(err, agentscan.ErrSecretsDetected):
			// HARD refusal: never routed through the infra fail-open
			// path. Enforce blocks; eval exits 0 but warns loudly.
			printSecretsRefusal(err, settings.Mode)
			if settings.Mode == agentscan.GateModeEnforce {
				return cliutil.ExitError
			}
			return cliutil.ExitOK
		default:
			fmt.Fprintf(os.Stderr, "Error: agent scan failed: %v\n", err)
			return cliutil.ExitError
		}
	}

	// po-66evv.11: --submit is opt-in observability. It runs after the
	// gate decision and never changes the exit code; a submission failure
	// is a warning.
	if a.submit && !result.Skipped {
		submitAgentScan(result, a.service, absTarget, settings.Mode, a.timeout)
	}

	if strings.EqualFold(a.format, "json") {
		printAgentScanJSON(result, settings)
	} else {
		printAgentScanHuman(result, settings)
	}

	if result.Skipped {
		return cliutil.ExitOK
	}
	// Force-through is handled at the top of runAgentScan (it skips the
	// scan entirely), so by here the gate decision stands.
	if result.Blocked {
		return cliutil.ExitError
	}
	return cliutil.ExitOK
}

// runAgentPrePush is the `rvl scan --agent --pre-push` entrypoint
// (po-66evv.9). It reads githooks(5) ref lines from stdin, resolves each
// pushed ref to a base...sha range (skipping deletes and tags), scans the
// pushed sha (never HEAD), and aggregates the worst exit code. Returns
// the process exit code.
func runAgentPrePush(ctx context.Context, a agentScanArgs, root, absTarget string, settings agentScanSettings, baseCfg agentscan.PipelineConfig) int {
	// --pre-push reads git's ref lines from stdin. When it is run
	// interactively (stdin is a terminal, not a pipe from git), the read
	// would block forever with no indication and swallow Ctrl+C, since
	// the signal handler is already installed. Detect that and exit with
	// guidance instead of hanging.
	if fi, statErr := os.Stdin.Stat(); statErr == nil && stdinIsInteractive(fi.Mode()) {
		fmt.Fprintln(os.Stderr, "Error: --pre-push reads git's pushed-ref lines from stdin; it is a hook entrypoint, not an interactive command.")
		fmt.Fprintln(os.Stderr, "Install it with: rvl hook install --pre-push")
		fmt.Fprintln(os.Stderr, "Or feed a ref line manually, e.g.:")
		fmt.Fprintln(os.Stderr, "  echo \"refs/heads/$(git branch --show-current) $(git rev-parse HEAD) refs/heads/main $(git rev-parse origin/main)\" | rvl scan --agent --pre-push")
		fmt.Fprintln(os.Stderr, "For a manual scan of committed changes, use: rvl scan --agent --changed-only --base <ref>")
		return cliutil.ExitUsage
	}

	refs, err := agentscan.ParsePrePushRefs(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return cliutil.ExitUsage
	}
	if len(refs) == 0 {
		// No refs on stdin (e.g. invoked outside a real pre-push hook).
		fmt.Fprintln(os.Stderr, "no pushed refs on stdin; nothing to scan")
		return cliutil.ExitOK
	}

	// Default base resolver: the existing config/env chain, else origin
	// default branch. Used only when a pushed ref has no usable
	// remote-sha (e.g. the first push of a new branch).
	defaultBase := func() (string, bool) {
		resolved, rerr := scanner.ResolveBaseRef(scanner.ChangedOnlyConfig{
			Root:        root,
			FlagBaseRef: a.baseRef,
			Env: map[string]string{
				"RVL_BASE_REF":    os.Getenv("RVL_BASE_REF"),
				"GITHUB_BASE_REF": os.Getenv("GITHUB_BASE_REF"),
			},
		})
		if rerr == nil && resolved.Ref != "" {
			return resolved.Ref, true
		}
		for _, cand := range []string{"origin/HEAD", "origin/main", "origin/master"} {
			if agentscan.RefReachable(root, cand) {
				return cand, true
			}
		}
		return "", false
	}

	scans, notices := agentscan.ResolvePrePushScans(root, refs, defaultBase, agentscan.DefaultMaxPrePushRefs)
	for _, n := range notices {
		fmt.Fprintf(os.Stderr, "pre-push: %s\n", n)
	}
	if len(scans) == 0 {
		fmt.Fprintln(os.Stderr, "pre-push: no ref ranges to scan")
		return cliutil.ExitOK
	}

	worst := cliutil.ExitOK
	for _, s := range scans {
		fmt.Printf("\n=== pre-push scan: %s (%s..%s) ===\n", s.Ref, shortSha(s.Base), shortSha(s.Sha))
		cs, cerr := agentscan.RangeChangeSetBetween(root, s.Base, s.Sha)
		if cerr != nil {
			fmt.Fprintf(os.Stderr, "Error: compute change set for %s: %v\n", s.Ref, cerr)
			if worst < cliutil.ExitError {
				worst = cliutil.ExitError
			}
			continue
		}
		cfg := baseCfg
		cfg.SnapshotTreeish = s.Sha
		code := runOnePipeline(ctx, cfg, cs, a, settings, absTarget)
		if code == 130 {
			return 130 // user abort short-circuits
		}
		if code > worst {
			worst = code
		}
	}
	return worst
}

// stdinIsInteractive reports whether stdin's mode is a character device
// (a terminal), meaning --pre-push was run interactively rather than fed
// ref lines by git. A pipe or regular file (the real hook case) is not a
// char device.
func stdinIsInteractive(mode os.FileMode) bool {
	return mode&os.ModeCharDevice != 0
}

// shortSha abbreviates a sha for display; non-sha refs pass through.
func shortSha(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// handleForceThrough prints the loud override notice, records the local
// audit event, and consumes the one-shot marker (idempotent even when
// the mechanism was the env var, so a stale marker cannot apply later).
func handleForceThrough(root, mechanism string) {
	fmt.Fprintln(os.Stderr, ansiRed(fmt.Sprintf(
		"AGENT SCAN FORCED THROUGH (mechanism: %s) - scan skipped, event audited", mechanism)))
	if err := agentscan.AppendAuditEvent(root, agentscan.AuditEvent{
		Kind: agentscan.AuditForceThrough,
		Detail: map[string]string{
			"mechanism": mechanism,
		},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write audit event: %v\n", err)
	}
	if err := agentscan.ConsumeForceMarker(root); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not consume force marker: %v\n", err)
	}
}

// runForceNext arms the one-shot force-through marker (po-66evv.6). The
// next `rvl scan --agent` run in this repo skips the gate and records an
// audit event. Accepts an optional --target/-t (or positional) dir.
func runForceNext(args []string) {
	target := ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--target" || args[i] == "-t":
			if i+1 < len(args) {
				i++
				target = args[i]
			}
		case strings.HasPrefix(args[i], "--target="):
			target = strings.TrimPrefix(args[i], "--target=")
		case !strings.HasPrefix(args[i], "-"):
			target = args[i]
		}
	}
	if target == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot get cwd: %v\n", err)
			os.Exit(cliutil.ExitUsage)
		}
		target = cwd
	}
	root, err := gitToplevel(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cliutil.ExitUsage)
	}
	path, err := agentscan.WriteForceMarker(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cliutil.ExitError)
	}
	fmt.Printf("Force-through armed: %s\n", path)
	fmt.Println("The NEXT `rvl scan --agent` run in this repo will SKIP the gate and record an audit event.")
	fmt.Println("Remove the marker to cancel: rm " + path)
}

// parseAgentCmdEnv splits the RVL_AGENT_CMD user-level command template
// into argv. It is whitespace-split (no shell quoting) - documented as a
// v1 limitation. Empty input yields nil so SelectAdapter treats "no
// trusted command" as the claude default. This is the ONLY source of a
// custom command; repo config can never supply one (po-66evv.10).
func parseAgentCmdEnv(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return strings.Fields(v)
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
// aggregated findings, notices, then exactly one gate line. Cost is not
// shown (see the note below). A blocked run ends with the force-through
// hint; a fail-open run ends with the red banner as the very last line.
func printAgentScanHuman(res agentscan.PipelineResult, s agentScanSettings) {
	if res.Skipped {
		fmt.Println(res.SkipNotice)
		return
	}
	fmt.Printf("Agent scan: mode=%s fail_on=%s model=%s\n\n", s.Mode, s.FailOn, s.Model)
	fmt.Println("Lenses:")
	for _, lr := range res.LensResults {
		if lr.Err != nil {
			fmt.Printf("  %-14s [%s] %v (%.1fs)\n",
				lr.Lens.ID, classifyLensErr(lr.Err), lr.Err, lr.Wall.Seconds())
			continue
		}
		fmt.Printf("  %-14s %d finding(s), %d dropped, %.1fs\n",
			lr.Lens.ID, len(lr.Findings), len(lr.Dropped), lr.Wall.Seconds())
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
	// Cost is deliberately not printed: claude -p reports an API-list-price
	// figure that does not reflect actual spend on a subscription plan, so
	// showing it as "cost" is misleading. The raw number stays in --format
	// json for tooling that wants it, and budget_warn still fires there.
	fmt.Println()
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
