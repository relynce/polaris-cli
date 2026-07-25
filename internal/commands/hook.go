package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/agentscan"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/project"
)

// CmdHook implements `rvl hook install` and `rvl hook doctor` for the
// agent-scan git gate (po-66evv.8). Install is lefthook-aware: when a
// lefthook config is present it prints a ready-to-paste snippet rather
// than writing .git/hooks, so it never fights lefthook for the hook file.

const preCommitScanCmd = "rvl scan --agent --staged --mode enforce"

func CmdHook(args []string) {
	if len(args) == 0 || cliutil.WantsHelp(args) {
		printHookUsage()
		if len(args) == 0 {
			os.Exit(cliutil.ExitUsage)
		}
		return
	}
	switch args[0] {
	case "install":
		runHookInstall(args[1:])
	case "doctor":
		runHookDoctor(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown hook subcommand: %s\n", args[0])
		printHookUsage()
		os.Exit(cliutil.ExitUsage)
	}
}

func printHookUsage() {
	fmt.Println(`rvl hook - install or check the agent-scan git gate

Usage:
  rvl hook install [--pre-commit] [--pre-push] [--force]
  rvl hook doctor

install   Wire the agent scan into this repo's git hooks. With lefthook
          present, prints a snippet to paste into lefthook.yml; otherwise
          writes a hook shim into the git hooks dir. Defaults to
          --pre-commit when no hook is named. --force overwrites (and
          backs up) an existing hook file.
doctor    Read-only preflight: git repo, agent binary, lefthook wiring,
          conflicting hooks, and the resolved agent-scan settings.`)
}

// hookKind is a git hook this command manages.
type hookKind struct {
	name    string // git hook file name
	shim    string // shim body command
	stopgap bool   // true when the shim is a stopgap pending another subtask
}

// selectedHooks parses --pre-commit/--pre-push/--force, defaulting to
// pre-commit. Returns the hooks to install and the force flag.
func selectedHooks(args []string) (hooks []hookKind, force bool, err error) {
	var pre, push bool
	for _, a := range args {
		switch a {
		case "--pre-commit":
			pre = true
		case "--pre-push":
			push = true
		case "--force":
			force = true
		default:
			return nil, false, fmt.Errorf("unknown flag %q", a)
		}
	}
	if !pre && !push {
		pre = true // default
	}
	if pre {
		hooks = append(hooks, hookKind{name: "pre-commit", shim: preCommitScanCmd})
	}
	if push {
		// po-66evv.9 lands the real --pre-push stdin protocol; until then
		// the shim scans the committed range as a stopgap.
		hooks = append(hooks, hookKind{
			name:    "pre-push",
			shim:    "rvl scan --agent --changed-only",
			stopgap: true,
		})
	}
	return hooks, force, nil
}

func runHookInstall(args []string) {
	hooks, force, err := selectedHooks(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		printHookUsage()
		os.Exit(cliutil.ExitUsage)
	}
	root, err := gitToplevel(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cliutil.ExitUsage)
	}

	if lefthookPath, ok := detectLefthook(root); ok {
		printLefthookSnippet(root, lefthookPath, hooks)
		return
	}

	hooksDir, err := hooksDir(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cliutil.ExitError)
	}
	for _, h := range hooks {
		if err := writeHookShim(hooksDir, h, force); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(cliutil.ExitError)
		}
	}
}

// detectLefthook reports whether a lefthook config exists at the repo
// root, returning the config path.
func detectLefthook(root string) (string, bool) {
	for _, name := range []string{"lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml"} {
		p := filepath.Join(root, name)
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

// lefthookHasSecretScan reports whether the lefthook config references a
// secret scanner (gitleaks), so the snippet can advise ordering.
func lefthookHasSecretScan(lefthookPath string) bool {
	data, err := os.ReadFile(lefthookPath)
	if err != nil {
		return false
	}
	body := strings.ToLower(string(data))
	return strings.Contains(body, "gitleaks") || strings.Contains(body, "secret-scan")
}

// printLefthookSnippet prints paste-ready lefthook commands for each hook.
func printLefthookSnippet(root, lefthookPath string, hooks []hookKind) {
	fmt.Printf("Lefthook detected (%s). Add these commands to %s instead of writing .git/hooks:\n\n",
		filepath.Base(lefthookPath), filepath.Base(lefthookPath))
	hasSecret := lefthookHasSecretScan(lefthookPath)
	for _, h := range hooks {
		fmt.Printf("%s:\n  commands:\n", h.name)
		fmt.Printf("    agent-scan:\n")
		if h.name == "pre-push" {
			// Pre-push must read the githooks ref lines from stdin;
			// lefthook replays hook stdin only to commands declaring it.
			fmt.Printf("      run: rvl scan --agent --pre-push   # po-66evv.9\n")
			fmt.Printf("      use_stdin: true\n")
			if h.stopgap {
				fmt.Printf("      # until po-66evv.9 ships, use: rvl scan --agent --changed-only\n")
			}
		} else {
			fmt.Printf("      run: %s\n", h.shim)
			fmt.Printf("      # optional: scope to code files, e.g. glob: \"**/*.{go,ts,py,js}\"\n")
		}
		fmt.Println()
	}
	if hasSecret {
		fmt.Println("Ordering: place agent-scan AFTER your secret-scan command in the file")
		fmt.Println("(lefthook runs sequential commands in file order). The agent scan also")
		fmt.Println("refuses independently when it detects secrets in the diff, so this is")
		fmt.Println("defense in depth, not the sole guard.")
	}
	fmt.Println("Uninstall: remove the agent-scan command(s) from the file.")
}

// hooksDir resolves the git hooks directory via `git rev-parse
// --git-path hooks`, which honors core.hooksPath and linked worktrees.
func hooksDir(root string) (string, error) {
	out, err := exec.Command("git", "-C", root, "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		return "", fmt.Errorf("resolve hooks dir: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	return dir, nil
}

// writeHookShim writes a POSIX shim for h into hooksDir. It refuses to
// overwrite an existing hook unless force is set, in which case the old
// file is backed up to <name>.pre-rvl.
func writeHookShim(hooksDir string, h hookKind, force bool) error {
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks dir: %w", err)
	}
	path := filepath.Join(hooksDir, h.name)
	if _, err := os.Stat(path); err == nil {
		if !force {
			return fmt.Errorf("%s already exists; re-run with --force to overwrite (the old hook is backed up)", path)
		}
		if err := os.Rename(path, path+".pre-rvl"); err != nil {
			return fmt.Errorf("back up existing hook: %w", err)
		}
	}
	var b strings.Builder
	fmt.Fprintln(&b, "#!/bin/sh")
	fmt.Fprintln(&b, "# Installed by `rvl hook install` (po-66evv.8): agent-scan git gate.")
	if h.stopgap {
		fmt.Fprintln(&b, "# WARNING: pre-push stopgap. The real stdin ref protocol lands in")
		fmt.Fprintln(&b, "# po-66evv.9 as `rvl scan --agent --pre-push`; swap it in when available.")
	}
	fmt.Fprintf(&b, "exec %s\n", h.shim)
	if err := os.WriteFile(path, []byte(b.String()), 0o755); err != nil {
		return fmt.Errorf("write hook shim: %w", err)
	}
	fmt.Printf("Installed %s hook: %s\n", h.name, path)
	fmt.Printf("Uninstall: rm %s\n", path)
	return nil
}

// --- doctor ---

// checkStatus is a doctor check outcome.
type checkStatus string

const (
	checkPass checkStatus = "PASS"
	checkWarn checkStatus = "WARN"
	checkFail checkStatus = "FAIL"
)

type doctorCheck struct {
	Status checkStatus
	Label  string
	Detail string
}

func runHookDoctor(args []string) {
	_ = args
	root, err := gitToplevel(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL  not inside a git repository")
		os.Exit(cliutil.ExitError)
	}
	checks := doctorChecks(root, os.Getenv("PATH"))
	worst := checkPass
	for _, c := range checks {
		fmt.Printf("%-5s %s", c.Status, c.Label)
		if c.Detail != "" {
			fmt.Printf(": %s", c.Detail)
		}
		fmt.Println()
		if c.Status == checkFail {
			worst = checkFail
		} else if c.Status == checkWarn && worst != checkFail {
			worst = checkWarn
		}
	}
	if worst == checkFail {
		os.Exit(cliutil.ExitError)
	}
	os.Exit(cliutil.ExitOK)
}

// doctorChecks runs the read-only preflight and returns the results. It
// takes root and a PATH so tests can drive it without touching the real
// environment.
func doctorChecks(root, pathEnv string) []doctorCheck {
	var checks []doctorCheck

	// Resolved settings (flag-free: yaml over defaults).
	projectCfg := project.LoadProjectConfigFrom(root)
	var agentCfg *project.AgentScanConfig
	if projectCfg != nil && projectCfg.Scanner != nil {
		agentCfg = projectCfg.Scanner.Agent
	}
	settings, serr := resolveAgentScanSettings(agentScanArgs{}, agentCfg)
	if serr != nil {
		checks = append(checks, doctorCheck{checkFail, "agent-scan config", serr.Error()})
	} else {
		checks = append(checks, doctorCheck{checkPass, "agent-scan config", fmt.Sprintf(
			"model=%s mode=%s fail_on=%s timeout=%s", settings.Model, settings.Mode, settings.FailOn, settings.Timeout)})
	}

	// Agent binary on PATH.
	bin := settings.Binary
	if bin == "" {
		bin = agentscan.DefaultClaudeBinary
	}
	if p, err := lookPathIn(bin, pathEnv); err == nil {
		checks = append(checks, doctorCheck{checkPass, "agent binary", p})
	} else {
		checks = append(checks, doctorCheck{checkFail, "agent binary",
			fmt.Sprintf("%q not found on PATH; install it or pass --agent-binary", bin)})
	}

	// Auth cannot be verified cheaply/headlessly: guidance, not a check.
	checks = append(checks, doctorCheck{checkWarn, "agent auth",
		"cannot verify headlessly; ensure the agent is logged in for non-interactive use"})

	// Lefthook wiring.
	if lp, ok := detectLefthook(root); ok {
		data, _ := os.ReadFile(lp)
		if strings.Contains(string(data), "scan --agent") {
			checks = append(checks, doctorCheck{checkPass, "lefthook", "agent-scan command present"})
		} else {
			checks = append(checks, doctorCheck{checkWarn, "lefthook",
				"present but no agent-scan command; run `rvl hook install` for a snippet"})
		}
		if lefthookHasSecretScan(lp) {
			checks = append(checks, doctorCheck{checkPass, "secret-scan ordering",
				"order agent-scan after secret-scan in lefthook.yml"})
		}
	} else {
		checks = append(checks, doctorCheck{checkWarn, "lefthook", "not configured; hooks would be written to .git/hooks"})
	}

	// Conflicting .git hooks.
	if hd, err := hooksDir(root); err == nil {
		for _, name := range []string{"pre-commit", "pre-push"} {
			p := filepath.Join(hd, name)
			if data, err := os.ReadFile(p); err == nil {
				if strings.Contains(string(data), "scan --agent") {
					checks = append(checks, doctorCheck{checkPass, name + " hook", "agent-scan shim installed"})
				} else {
					checks = append(checks, doctorCheck{checkWarn, name + " hook",
						"existing hook does not call the agent scan; --force would back it up"})
				}
			}
		}
	}

	return checks
}

// lookPathIn resolves bin against an explicit PATH string (so doctor is
// testable), falling back to exec.LookPath when pathEnv is empty.
func lookPathIn(bin, pathEnv string) (string, error) {
	if pathEnv == "" {
		return exec.LookPath(bin)
	}
	if strings.ContainsRune(bin, os.PathSeparator) {
		if fi, err := os.Stat(bin); err == nil && !fi.IsDir() {
			return bin, nil
		}
		return "", fmt.Errorf("%s not found", bin)
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		cand := filepath.Join(dir, bin)
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("%s not found on PATH", bin)
}
