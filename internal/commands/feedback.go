package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/config"
)

// This file implements `rvl feedback` and its alias `rvl bugreport`
// (po-nmkeg): users AND coding agents can file feedback or bug reports
// from the CLI, with a shape-only diagnostic bundle attached.
//
// Privacy contract: the bundle NEVER contains file contents, code, or
// findings — only CLI version, os/arch, the API host, the configured
// organization, and a summary of the local gate audit trail (event kind
// + timestamp, nothing else).

// feedbackOptions holds the parsed flags for `rvl feedback`/`rvl bugreport`.
type feedbackOptions struct {
	Message           string
	Category          string // "feedback" or "bug"
	AttachDiagnostics bool
	Yes               bool
	Format            string // "text" or "json"
}

// feedbackDiagnostics is the shape-only diagnostic bundle.
type feedbackDiagnostics struct {
	CLIVersion     string             `json:"cli_version"`
	OS             string             `json:"os"`
	Arch           string             `json:"arch"`
	APIHost        string             `json:"api_host,omitempty"`
	OrgID          string             `json:"org_id,omitempty"`
	OrgName        string             `json:"org_name,omitempty"`
	GateEventCount int                `json:"gate_event_count,omitempty"`
	LastGateEvent  *auditEventSummary `json:"last_gate_event,omitempty"`
}

// auditEventSummary is the shape-only summary of the newest entry in the
// per-worktree gate audit log (rvl-audit.jsonl): kind + timestamp only.
type auditEventSummary struct {
	Kind string `json:"kind"`
	Time string `json:"time"`
}

// feedbackSubmission is the POST /api/v1/feedback request body.
type feedbackSubmission struct {
	Message     string               `json:"message"`
	Category    string               `json:"category"`
	CLIVersion  string               `json:"cli_version,omitempty"`
	Diagnostics *feedbackDiagnostics `json:"diagnostics,omitempty"`
}

// CmdFeedback implements `rvl feedback` (defaultCategory "feedback") and
// `rvl bugreport` (defaultCategory "bug").
func CmdFeedback(args []string, version, defaultCategory string) {
	helpCmd := "rvl feedback"
	if defaultCategory == "bug" {
		helpCmd = "rvl bugreport"
	}
	if cliutil.WantsHelp(args) {
		printFeedbackUsage(helpCmd, defaultCategory)
		return
	}

	o, err := parseFeedbackArgs(args, defaultCategory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run '%s --help' for usage.\n", helpCmd)
		os.Exit(cliutil.ExitUsage)
	}

	messageFromStdin := o.Message == "-"
	if messageFromStdin {
		data, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "Error reading message from stdin: %v\n", readErr)
			os.Exit(cliutil.ExitError)
		}
		o.Message = strings.TrimSpace(string(data))
	}

	if err := validateFeedbackOptions(o); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run '%s --help' for usage.\n", helpCmd)
		os.Exit(cliutil.ExitUsage)
	}

	cfg := api.LoadAndResolveConfig()

	cwd, _ := os.Getwd()
	diag := collectDiagnostics(version, cfg, cwd)
	sub := buildFeedbackSubmission(o, version, &diag)

	if !o.Yes {
		fmt.Print(renderFeedbackPreview(sub))
		if !confirmSend(messageFromStdin) {
			fmt.Println("Aborted. Nothing was sent.")
			return
		}
	}

	body, err := json.Marshal(sub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding request: %v\n", err)
		os.Exit(cliutil.ExitError)
	}

	respBody, err := api.MakeAPIRequest(cfg, "POST", cfg.APIURL+"/api/v1/feedback", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting %s: %v\n", categoryNoun(o.Category), err)
		os.Exit(cliutil.ExitError)
	}

	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil || resp.ID == "" {
		fmt.Fprintf(os.Stderr, "Error: unexpected response from server: %s\n", string(respBody))
		os.Exit(cliutil.ExitError)
	}

	if o.Format == "json" {
		out, _ := json.MarshalIndent(map[string]string{
			"id":       resp.ID,
			"category": o.Category,
			"status":   "submitted",
		}, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Printf("Thanks! Your %s was sent to Revelara.\n", categoryNoun(o.Category))
	fmt.Printf("Report id: %s\n", resp.ID)
}

// parseFeedbackArgs parses flags. defaultCategory is "feedback" for
// `rvl feedback` and "bug" for `rvl bugreport`.
func parseFeedbackArgs(args []string, defaultCategory string) (*feedbackOptions, error) {
	o := &feedbackOptions{
		Category:          defaultCategory,
		AttachDiagnostics: true,
		Format:            "text",
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var v string
		var err error
		switch {
		case arg == "--message" || strings.HasPrefix(arg, "--message="):
			v, i, err = cliutil.FlagValue(args, i, "--message")
			o.Message = v
		case arg == "--category" || strings.HasPrefix(arg, "--category="):
			v, i, err = cliutil.FlagValue(args, i, "--category")
			o.Category = v
		case arg == "--attach-diagnostics":
			o.AttachDiagnostics = true
		case strings.HasPrefix(arg, "--attach-diagnostics="):
			switch strings.TrimPrefix(arg, "--attach-diagnostics=") {
			case "true":
				o.AttachDiagnostics = true
			case "false":
				o.AttachDiagnostics = false
			default:
				return nil, fmt.Errorf("invalid --attach-diagnostics %q (valid: true, false)", strings.TrimPrefix(arg, "--attach-diagnostics="))
			}
		case arg == "--yes" || arg == "-y":
			o.Yes = true
		case arg == "--format" || strings.HasPrefix(arg, "--format="):
			v, i, err = cliutil.FlagValue(args, i, "--format")
			o.Format = v
		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

// validateFeedbackOptions checks the resolved options (after any stdin
// message read). All violations are usage errors (exit 2).
func validateFeedbackOptions(o *feedbackOptions) error {
	if strings.TrimSpace(o.Message) == "" {
		return fmt.Errorf("--message is required (pass '--message -' to read it from stdin)")
	}
	if o.Category != "feedback" && o.Category != "bug" {
		return fmt.Errorf("invalid --category %q (valid: feedback, bug)", o.Category)
	}
	return cliutil.ValidateFormat(o.Format, "text", "json")
}

// collectDiagnostics assembles the shape-only bundle. Everything here is
// metadata about the CLI and its configuration; nothing is read from the
// user's project except the rvl gate audit log summary (kind + time).
func collectDiagnostics(version string, cfg *config.Config, workDir string) feedbackDiagnostics {
	d := feedbackDiagnostics{
		CLIVersion: version,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
	}
	if cfg != nil {
		d.APIHost = apiHost(cfg.APIURL)
		d.OrgID = cfg.ResolvedOrgID
		d.OrgName = cfg.OrgName
	}
	if workDir != "" {
		if last, count, err := lastAuditEvent(workDir); err == nil && count > 0 {
			d.GateEventCount = count
			d.LastGateEvent = last
		}
	}
	return d
}

// apiHost returns just the host of the configured API URL (no path,
// no credentials). Falls back to the raw string if it does not parse.
func apiHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

// lastAuditEvent summarizes the per-worktree gate audit log
// (rvl-audit.jsonl in the repo's git dir), if the working directory is
// inside a git repository and the log exists.
func lastAuditEvent(dir string) (*auditEventSummary, int, error) {
	gitDir, err := gitDirFor(dir)
	if err != nil {
		return nil, 0, err
	}
	return lastAuditEventFromFile(filepath.Join(gitDir, "rvl-audit.jsonl"))
}

// gitDirFor resolves the git dir for dir via `git rev-parse --git-dir`
// so linked worktrees resolve to their per-worktree dir.
func gitDirFor(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository")
	}
	gitDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(dir, gitDir)
	}
	return gitDir, nil
}

// lastAuditEventFromFile reads a JSONL audit log and returns the newest
// event's kind + timestamp and the total event count. Only those two
// fields are extracted — detail payloads never leave the machine.
func lastAuditEventFromFile(path string) (*auditEventSummary, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	var last *auditEventSummary
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev struct {
			Time string `json:"time"`
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		count++
		last = &auditEventSummary{Kind: ev.Kind, Time: ev.Time}
	}
	return last, count, nil
}

// buildFeedbackSubmission assembles the request body. Diagnostics are
// only included when --attach-diagnostics is true (the default).
func buildFeedbackSubmission(o *feedbackOptions, version string, diag *feedbackDiagnostics) feedbackSubmission {
	sub := feedbackSubmission{
		Message:    o.Message,
		Category:   o.Category,
		CLIVersion: version,
	}
	if o.AttachDiagnostics {
		sub.Diagnostics = diag
	}
	return sub
}

// renderFeedbackPreview shows exactly what will be sent, so the user can
// verify nothing sensitive is included before confirming.
func renderFeedbackPreview(sub feedbackSubmission) string {
	var b strings.Builder
	b.WriteString("About to send to Revelara:\n\n")
	fmt.Fprintf(&b, "Category: %s\n", sub.Category)
	fmt.Fprintf(&b, "Message:\n  %s\n", strings.ReplaceAll(sub.Message, "\n", "\n  "))
	if sub.Diagnostics != nil {
		d := sub.Diagnostics
		b.WriteString("Diagnostics (shape-only; no code, file contents, or findings):\n")
		fmt.Fprintf(&b, "  cli_version: %s\n", d.CLIVersion)
		fmt.Fprintf(&b, "  os/arch:     %s/%s\n", d.OS, d.Arch)
		if d.APIHost != "" {
			fmt.Fprintf(&b, "  api_host:    %s\n", d.APIHost)
		}
		if d.OrgName != "" {
			fmt.Fprintf(&b, "  org_name:    %s\n", d.OrgName)
		}
		if d.OrgID != "" {
			fmt.Fprintf(&b, "  org_id:      %s\n", d.OrgID)
		}
		if d.GateEventCount > 0 && d.LastGateEvent != nil {
			fmt.Fprintf(&b, "  gate_audit:  %d event(s), last %q at %s\n",
				d.GateEventCount, d.LastGateEvent.Kind, d.LastGateEvent.Time)
		}
	} else {
		b.WriteString("Diagnostics: not attached (--attach-diagnostics=false)\n")
	}
	return b.String()
}

// confirmSend prompts "Send this to Revelara? [y/N]". When the message
// was read from stdin, the prompt reads from /dev/tty instead; if no
// terminal is available the command fails loudly and points at --yes.
func confirmSend(messageFromStdin bool) bool {
	var in io.Reader = os.Stdin
	if messageFromStdin {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: the message was read from stdin, so no terminal is available for confirmation. Pass --yes to send without confirmation.")
			os.Exit(cliutil.ExitError)
		}
		defer tty.Close()
		in = tty
	}
	fmt.Print("Send this to Revelara? [y/N]: ")
	return readYes(in)
}

// readYes reads one line and reports whether it is an affirmative answer.
func readYes(in io.Reader) bool {
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return answer == "y" || answer == "yes"
}

func categoryNoun(category string) string {
	if category == "bug" {
		return "bug report"
	}
	return "feedback"
}

func printFeedbackUsage(helpCmd, defaultCategory string) {
	fmt.Printf(`Usage: %s --message <text> [options]

Send feedback or a bug report to the Revelara team. Works for humans
and for coding agents (use --yes for non-interactive runs).

A shape-only diagnostic bundle is attached by default: CLI version,
os/arch, API host, organization, and a summary of the local gate audit
log (event kind + timestamp). It never includes code, file contents,
or scan findings, and the full bundle is shown before sending.

Options:
  --message <text>            The feedback or bug description (required).
                              Pass '--message -' to read it from stdin.
  --category <feedback|bug>   Report category (default: %s)
  --attach-diagnostics=<bool> Attach the diagnostic bundle (default: true)
  --yes, -y                   Skip the confirmation prompt (headless/agent use)
  --format <text|json>        Output format (default: text)

Examples:
  %s --message "The risk register search misses recent scans"
  git log -1 | %s --message - --yes
  %s --message "scan submit returned 500" --category=bug --format=json --yes
`, helpCmd, defaultCategory, helpCmd, helpCmd, helpCmd)
}
