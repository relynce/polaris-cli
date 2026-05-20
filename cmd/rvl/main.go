// Package main provides the rvl CLI for secure interaction with Revelara API.
// This CLI acts as a trusted intermediary - credentials are stored locally and
// never exposed to LLM contexts.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/commands"
	"github.com/revelara-ai/rvl-cli/internal/plugin"
)

// version and gitHash are set at build time via -ldflags "-X main.version=... -X main.gitHash=..."
// When installed via "go install", these remain at defaults and init() populates them
// from the embedded build info instead.
var version = "source-build"
var gitHash = "dev"

func init() {
	if version != "source-build" {
		return // ldflags were set, nothing to do
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 {
			gitHash = s.Value[:7]
			break
		}
	}
}

// migrateConfigDir performs a 3-way migration of the config directory:
//  1. If ~/.revelara/ exists, ensure api_url inside is current.
//  2. If ~/.relynce/ exists, rename to ~/.revelara/ and rewrite api_url.
//  3. If ~/.polaris/ exists, copy files to ~/.revelara/ and rewrite api_url.
//
// Always runs the api_url rewrite at the end so partial-state directories
// (renamed without api_url update) self-heal on the next invocation.
func migrateConfigDir() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	newDir := filepath.Join(home, ".revelara")

	// If target already exists, still ensure api_url is current and return.
	if _, err := os.Stat(newDir); err == nil {
		rewriteRelynceAPIURL(filepath.Join(newDir, "config.yaml"))
		return
	}

	// Try renaming ~/.relynce/ -> ~/.revelara/
	relynceDir := filepath.Join(home, ".relynce")
	if _, err := os.Stat(relynceDir); err == nil {
		if err := os.Rename(relynceDir, newDir); err == nil {
			fmt.Fprintf(os.Stderr, "Migrated configuration from ~/.relynce/ to ~/.revelara/\n")
			rewriteRelynceAPIURL(filepath.Join(newDir, "config.yaml"))
			return
		}
	}

	// Try copying ~/.polaris/ -> ~/.revelara/
	polarisDir := filepath.Join(home, ".polaris")
	if _, err := os.Stat(polarisDir); os.IsNotExist(err) {
		return
	}

	if err := os.MkdirAll(newDir, 0700); err != nil {
		return
	}
	entries, err := os.ReadDir(polarisDir)
	if err != nil {
		return
	}
	migrated := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue // skip subdirectories for now
		}
		data, err := os.ReadFile(filepath.Join(polarisDir, entry.Name()))
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(newDir, entry.Name()), data, 0600); err != nil {
			continue
		}
		migrated++
	}
	if migrated > 0 {
		fmt.Fprintf(os.Stderr, "Migrated configuration from ~/.polaris/ to ~/.revelara/\n")
		rewriteRelynceAPIURL(filepath.Join(newDir, "config.yaml"))
	}
}

// rewriteRelynceAPIURL replaces api.relynce.ai with api.revelara.ai in the
// given config file. No-op if the file is missing or already current.
func rewriteRelynceAPIURL(configPath string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	if !strings.Contains(string(data), "api.relynce.ai") {
		return
	}
	updated := strings.ReplaceAll(string(data), "api.relynce.ai", "api.revelara.ai")
	if err := os.WriteFile(configPath, []byte(updated), 0600); err == nil {
		fmt.Fprintf(os.Stderr, "Updated api_url in %s (api.relynce.ai -> api.revelara.ai)\n", configPath)
	}
}

// shouldSkipAutoMigrate returns true for invocations that should not trigger
// filesystem changes (help, version, no-arg, unknown flags). Auto-migration
// only runs when the user is actually using the CLI.
func shouldSkipAutoMigrate(args []string) bool {
	if len(args) < 2 {
		return true
	}
	switch args[1] {
	case "help", "--help", "-h", "version", "--version", "-v":
		return true
	}
	// Treat any leading flag (e.g. "rvl --dry-run") as a non-command and skip.
	if strings.HasPrefix(args[1], "-") {
		return true
	}
	return false
}

func main() {
	// Auto-migrate config directory to ~/.revelara/, but only when the user
	// is actually invoking a command. Help/version/unknown-flag invocations
	// must not cause filesystem changes.
	if !shouldSkipAutoMigrate(os.Args) {
		migrateConfigDir()
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "init":
		commands.CmdInit(os.Args[2:])
	case "login":
		commands.CmdLogin()
	case "logout":
		commands.CmdLogout()
	case "status":
		commands.CmdStatus(version, gitHash)
	case "scan":
		commands.CmdScan(os.Args[2:], version)
	case "risk":
		commands.CmdRisk(os.Args[2:])
	case "control":
		commands.CmdControl(os.Args[2:])
	case "knowledge":
		commands.CmdKnowledge(os.Args[2:])
	case "incident":
		commands.CmdIncident(os.Args[2:])
	case "evidence":
		commands.CmdEvidence(os.Args[2:])
	case "config":
		commands.CmdConfig(os.Args[2:])
	case "commands":
		commands.CmdCommands(os.Args[2:])
	case "completion":
		commands.CmdCompletion(os.Args[2:])
	case "plugin":
		plugin.CmdPlugin(os.Args[2:])
	case "review":
		commands.CmdReview(os.Args[2:])
	case "stpa":
		commands.CmdSTPA(os.Args[2:])
	case "migrate":
		commands.CmdMigrate(os.Args[2:])
	case "version":
		fmt.Printf("rvl version %s (%s)\n", version, gitHash)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`rvl - Secure CLI for Revelara reliability analysis

Usage:
  rvl <command> [options]

Commands:
  init               Initialize Revelara for this repository
  login              Configure credentials interactively
  logout             Remove stored credentials
  status             Check connection and authentication status
  scan               Submit risk findings to Revelara
  review             Review a commit or PR for reliability risks (CI/CD gate)
  risk               Manage risk lifecycle (list, close, resolve, etc.)
  control            Query reliability controls catalog
  knowledge          Query organizational knowledge base (facts, procedures, patterns)
  evidence           Manage control evidence (submit, list, verify)
  stpa               STPA safety analysis tools (list-ucas)
  commands           List available skills and agents from the API
  plugin             Manage editor plugins (install, update, list, remove)
  completion         Generate shell completion scripts (bash, zsh, fish)
  config show        Show current configuration (API key masked)
  config set <k> <v> Set a configuration value
  migrate            Migrate project config files to new naming convention
  version            Show version information
  help               Show this help message

Scan Command:
  rvl scan --service <name> --stdin       Read findings JSON from stdin
  rvl scan --service <name> --file <path> Read findings from file
  rvl scan --service <name> --dry-run     Validate without submitting
  rvl scan --target <path> --file <path>  Scan another project (service auto-resolved from .revelara.yaml)

  Local Scanner (--local): runs the built-in pattern matchers against
  a codebase without an LLM. Supports CI gating, JSON output, and
  submission to Revelara in one step.

  rvl scan --local --target <path>                       Run local scan, print human-readable summary
  rvl scan --local --target <path> --format json         Emit ScanRequest JSON on stdout (CI-friendly)
  rvl scan --local --target <path> --service <name> --submit
                                                          Run local scan AND post to Revelara
  rvl scan --local --list-matchers                       List all registered matchers + provenance
  rvl scan --local --list-matchers --source curated      Filter to curated (Phase 1) matchers
  rvl scan --local --list-matchers --format json         Machine-readable matcher catalog
  rvl scan --local --target <path> --changed-only        Scan only files changed vs. base ref (CI mode)
  rvl scan --local --target <path> --matchers a,b,c      Run only the listed matcher slugs

  Local Scanner Flags:
    --local                       Enable the built-in local scanner
    --target <path>               Directory to scan (default: cwd)
    --service <name>              Service name (overrides .revelara.yaml project)
    --submit                      Post findings to Revelara after scanning
    --format <fmt>                Output format: human (default, glamour-rendered when TTY),
                                  json (machine-readable), or markdown (raw)
    --list-matchers               List registered matchers and exit
    --source <s>                  With --list-matchers: curated|org-generated
    --matchers <a,b,c>            Run only these matcher slugs (CSV)
    --changed-only                Scan only files changed since base ref
    --base <ref>                  Base ref for --changed-only (overrides env vars)
    --scan-all-on-missing-base    Fall back to full scan if no base ref reachable

  Base ref resolution chain for --changed-only:
    1. --base flag
    2. RVL_BASE_REF env var
    3. GITHUB_BASE_REF (PR events)
    4. CI_MERGE_REQUEST_TARGET_BRANCH_NAME (GitLab MR)
    5. .revelara.yaml scanner.base_ref
    No reachable ref → exit 2 with diagnostic; pass --scan-all-on-missing-base to override.

  Exit codes for --local:
    0  No findings, or only low/medium findings
    1  At least one critical or high finding (CI gate)
    2  Scanner error (bad config, no base ref, unreadable files)

  .revelara.yaml example:
    project: my-service
    criticality: customer-facing
    components:
      - name: api
        path: cmd/server/
    scanner:
      exclude_matchers: [no-error-wrapping]   # too noisy for our codebase
      exclude_paths:    [legacy/]
      confidence_threshold: medium             # drop low-confidence matchers
      base_ref:         origin/develop
      include_tests:    false                  # per-matcher control still applies

Review Command:
  rvl review [--commit <sha>] [--base <ref>] [--env <env>] [--format <text|json>] [--enforce] [--fail-closed] [--verbose]
    Review a commit or PR for reliability risks
    Flags:
      --commit <sha>     Commit to review (default: HEAD)
      --base <ref>       Base ref for diff (auto-detect from CI, fallback: origin/main)
      --env <env>        Environment name (auto-detect from CI)
      --format <fmt>     Output format: text (default) or json
      --enforce          Exit 1 on hold (default: advisory mode, always exit 0)
      --fail-closed      Exit 1 if API unreachable (default: fail open)
      --verbose          Show full risk details

Risk Command:
  rvl risk list [--status=detected] [--service=name]  List risks
  rvl risk show <risk-code>                           Show risk details with mapped controls
  rvl risk stale [--service=name]                     List stale risks
  rvl risk close <risk-code> [--reason="..."]         Close a risk
  rvl risk resolve <risk-code> --reason="..."         Mark risk as resolved
  rvl risk acknowledge <risk-code> [<risk-code>...]   Acknowledge risks
  rvl risk accept <risk-code> --reason="..."          Accept risk (won't mitigate)

Control Command:
  rvl control list [--category=<cat>]     List controls in catalog
  rvl control show <control-code>         Show control details (e.g., RC-018)

Examples:
  # Initial setup
  rvl login

  # Submit findings from Claude Code skill
  echo '{"findings":[...]}' | rvl scan --service checkout-api --stdin

  # Scan a different project (service name auto-resolved from target's .revelara.yaml)
  rvl scan --target /path/to/other-project --file findings.json

  # Check status
  rvl status

  # Review code for reliability risks (use in CI/CD)
  rvl review --enforce
  rvl review --commit abc123 --env production --format json

  # Manage risks
  rvl risk list --status=detected
  rvl risk close R-001 --reason "Fixed by implementing timeout"
  rvl risk stale --service checkout-api

  # Query controls catalog
  rvl control list --category=fault_tolerance
  rvl control show RC-018

  # Query knowledge base
  rvl knowledge search "circuit breaker timeout"
  rvl knowledge procedures --control=RC-018
  rvl knowledge patterns --type=failure_mode

  # Submit evidence for controls
  rvl evidence submit --control=RC-018 --type=code --name="Circuit breaker impl" --url="https://github.com/..."
  rvl evidence list --status=configured
  rvl evidence verify <evidence-id>

Plugin Command:
  rvl plugin install <editor>      Install plugin for editor
  rvl plugin update [editor]       Update plugin(s) to latest version
  rvl plugin list                  List installed plugins
  rvl plugin editors               List all supported editors
  rvl plugin remove <editor>       Remove installed plugin

Init Command:
  rvl init                         Interactive initialization
  rvl init --project <name>        Set project name non-interactively
  rvl init --skip-plugin           Skip plugin installation
  rvl init --force                 Overwrite existing config without prompting
  rvl init -y                      Accept all defaults

Configuration:
  Credentials are stored in ~/.revelara/config.yaml
  Never share this file or expose credentials to LLM contexts.`)
}
