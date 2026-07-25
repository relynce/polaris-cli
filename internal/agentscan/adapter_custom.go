package agentscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// customAdapter runs a user-provided command template (spec: Agent
// adapters, "custom"). This is the general-solution escape hatch: any
// headless agent (including GitHub Copilot's CLI) can be wired by
// pointing the template at it.
//
// TRUST BOUNDARY (spec: Security model; po-66evv.10): a command template
// selects code to execute, so it is honored ONLY from a user-level
// source (the RVL_AGENT_CMD environment variable, or user-level config),
// never from repo-tracked .revelara.yaml. A cloned repo can select a
// built-in preset by name, but it can never introduce a command string.
// SelectAdapter enforces this; the customAdapter itself just runs what it
// is given.
//
// Prompt transport: the rendered prompt is written to a temp file and
// its path substituted for {promptfile}, so the (attacker-influenced)
// diff never lands on argv. {snapshot_dir} is the snapshot path and is
// also set as the command's working directory. Output is parsed by the
// adapter-agnostic ExtractFindings, so a custom agent only has to print
// the findings JSON (optionally fenced or prose-wrapped).
type customAdapter struct {
	name     string
	template []string // argv template with {promptfile} / {snapshot_dir} tokens
	timeout  time.Duration
}

// CustomAdapterConfig configures a custom command adapter.
type CustomAdapterConfig struct {
	// Name is the reported adapter name (defaults to "custom").
	Name string
	// Command is the argv template. It must reference {promptfile} so the
	// prompt is delivered off-argv. {snapshot_dir} is optional.
	Command []string
	Timeout time.Duration
}

// promptFileToken and snapshotDirToken are the template placeholders.
const (
	promptFileToken  = "{promptfile}"
	snapshotDirToken = "{snapshot_dir}"
)

// NewCustomAdapter builds a custom command adapter. It requires a
// non-empty command that references {promptfile}; otherwise the prompt
// would have to go on argv, which the transport rules forbid.
func NewCustomAdapter(cfg CustomAdapterConfig) (Adapter, error) {
	if len(cfg.Command) == 0 {
		return nil, errors.New("custom adapter: empty command template")
	}
	if !commandReferences(cfg.Command, promptFileToken) {
		return nil, fmt.Errorf("custom adapter: command template must reference %s (the prompt is delivered off-argv)", promptFileToken)
	}
	name := cfg.Name
	if name == "" {
		name = "custom"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &customAdapter{name: name, template: cfg.Command, timeout: timeout}, nil
}

func commandReferences(cmd []string, token string) bool {
	for _, a := range cmd {
		if strings.Contains(a, token) {
			return true
		}
	}
	return false
}

func (a *customAdapter) Name() string { return a.name }

// CheckAvailability verifies the command's executable is on PATH.
func (a *customAdapter) CheckAvailability() error {
	if _, err := exec.LookPath(a.template[0]); err != nil {
		return fmt.Errorf("%w: %q: %v", ErrAgentUnavailable, a.template[0], err)
	}
	return nil
}

func (a *customAdapter) Invoke(ctx context.Context, prompt, snapshotDir string) (InvokeResult, error) {
	bin, err := exec.LookPath(a.template[0])
	if err != nil {
		return InvokeResult{}, fmt.Errorf("%w: %q: %v", ErrAgentUnavailable, a.template[0], err)
	}

	// Write the prompt to a temp file so it never lands on argv.
	pf, err := os.CreateTemp("", "rvl-agent-prompt-*.md")
	if err != nil {
		return InvokeResult{}, fmt.Errorf("custom adapter: temp prompt file: %w", err)
	}
	defer os.Remove(pf.Name())
	if _, err := pf.WriteString(prompt); err != nil {
		pf.Close()
		return InvokeResult{}, fmt.Errorf("custom adapter: write prompt: %w", err)
	}
	pf.Close()

	args := make([]string, 0, len(a.template)-1)
	for _, tok := range a.template[1:] {
		tok = strings.ReplaceAll(tok, promptFileToken, pf.Name())
		tok = strings.ReplaceAll(tok, snapshotDirToken, snapshotDir)
		args = append(args, tok)
	}

	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = snapshotDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second

	runErr := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return InvokeResult{}, fmt.Errorf("%w after %s (%s)", ErrAgentTimeout, a.timeout, a.name)
		}
		return InvokeResult{}, fmt.Errorf("%s invocation canceled: %w", a.name, ctxErr)
	}
	if runErr != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return InvokeResult{}, fmt.Errorf("%s: %w: %s", a.name, runErr, msg)
		}
		return InvokeResult{}, fmt.Errorf("%s: %w", a.name, runErr)
	}

	// Custom agents report no structured cost; ExtractFindings parses the
	// findings JSON out of whatever the command printed.
	return InvokeResult{Raw: stdout.String(), Model: a.name}, nil
}
