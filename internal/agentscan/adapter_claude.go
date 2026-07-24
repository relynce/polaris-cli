package agentscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// claudeAdapter is the built-in `claude -p` preset (spec: Agent
// adapters). Invocation contract:
//
//	claude -p --output-format json --allowedTools Read --model <model>
//
// with the prompt on stdin (never argv) and cwd = the staged snapshot
// directory. --allowedTools Read is the read-confinement half of the
// security model; the snapshot cwd is the other half (spec: Execution
// model).
type claudeAdapter struct {
	cfg AdapterConfig
}

// NewClaudeAdapter builds the claude preset. Zero-value config fields
// take the package defaults (DefaultModel, DefaultTimeout,
// DefaultClaudeBinary).
func NewClaudeAdapter(cfg AdapterConfig) Adapter {
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Binary == "" {
		cfg.Binary = DefaultClaudeBinary
	}
	return &claudeAdapter{cfg: cfg}
}

func (a *claudeAdapter) Name() string { return "claude" }

// claudeEnvelope is the `claude -p --output-format json` output
// envelope. Only the fields the scan consumes are declared; the
// envelope carries more (session id, per-model usage, ...).
type claudeEnvelope struct {
	Result       string  `json:"result"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	IsError      bool    `json:"is_error"`
}

func (a *claudeAdapter) Invoke(ctx context.Context, prompt, snapshotDir string) (InvokeResult, error) {
	bin, err := exec.LookPath(a.cfg.Binary)
	if err != nil {
		// Checked up front so the gate policy can classify this as an
		// infra error before any subprocess work happens.
		return InvokeResult{}, fmt.Errorf("%w: %q: %v", ErrAgentUnavailable, a.cfg.Binary, err)
	}

	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin,
		"-p",
		"--output-format", "json",
		"--allowedTools", "Read",
		"--model", a.cfg.Model,
	)
	cmd.Dir = snapshotDir
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// If the killed process left orphans holding the output pipes,
	// give up on them shortly after cancellation instead of hanging.
	cmd.WaitDelay = 5 * time.Second

	runErr := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return InvokeResult{}, fmt.Errorf("%w after %s (model %s)", ErrAgentTimeout, a.cfg.Timeout, a.cfg.Model)
		}
		return InvokeResult{}, fmt.Errorf("claude invocation canceled: %w", ctxErr)
	}
	if runErr != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return InvokeResult{}, fmt.Errorf("claude: %w: %s", runErr, msg)
		}
		return InvokeResult{}, fmt.Errorf("claude: %w", runErr)
	}

	var env claudeEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &env); err != nil {
		return InvokeResult{}, fmt.Errorf("claude: parse output envelope: %w", err)
	}
	if env.IsError {
		return InvokeResult{}, fmt.Errorf("claude: agent error: %s", strings.TrimSpace(env.Result))
	}
	return InvokeResult{Raw: env.Result, CostUSD: env.TotalCostUSD, Model: a.cfg.Model}, nil
}
