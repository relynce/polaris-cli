package agentscan

import (
	"context"
	"errors"
	"time"
)

// Adapter is one headless coding-agent preset (spec: Agent adapters).
// Invoke runs the agent on a rendered lens prompt with the staged
// snapshot as its working directory and returns the raw model output;
// findings extraction is adapter-agnostic (ExtractFindings), so an
// adapter only has to deliver the prompt and unwrap its own output
// envelope.
//
// Invoke must be safe for concurrent use: the orchestrator fans out one
// invocation per lens in parallel (spec: fixed decision 3).
type Adapter interface {
	// Name is the stable preset identifier ("claude", "copilot", ...)
	// used in config, notices, and cost reporting.
	Name() string

	// Invoke sends the prompt to the agent (via stdin or temp file,
	// never argv - spec: Diff hygiene, prompt transport) and returns
	// its raw text output. Errors are classified for the gate policy:
	// ErrAgentUnavailable and ErrAgentTimeout are infra errors that
	// fail open by default (spec: Gate policy).
	Invoke(ctx context.Context, prompt string, snapshotDir string) (InvokeResult, error)
}

// InvokeResult is one successful agent invocation's output. Raw is the
// unwrapped model text (envelope removed); CostUSD is 0 when the
// adapter cannot report cost.
type InvokeResult struct {
	Raw     string
	CostUSD float64
	Model   string
}

// Adapter defaults. Presets pin a model: reproducibility and cost
// predictions are meaningless otherwise (spec: Agent adapters).
const (
	// DefaultModel is the pinned model alias, sonnet-class per spec.
	DefaultModel = "sonnet"
	// DefaultTimeout is the per-lens invocation timeout (spec: Gate
	// policy, "per-lens timeout default 180 s").
	DefaultTimeout = 180 * time.Second
	// DefaultClaudeBinary is the claude preset's executable name,
	// resolved via PATH.
	DefaultClaudeBinary = "claude"
)

// AdapterConfig configures a preset. Zero values take the defaults
// above (Binary defaults per preset).
type AdapterConfig struct {
	Model   string
	Timeout time.Duration
	Binary  string
	// MaxTurns caps the agent's tool-use loop (claude --max-turns). 0 leaves
	// it uncapped. A cap bounds runaway exploration that would otherwise blow
	// the per-lens Timeout (po-ksrjz). Configurable via scanner.agent.max_turns.
	MaxTurns int
}

// Infra-error taxonomy for the gate policy (spec: Gate policy). Both
// are wrapped with invocation detail; classify with errors.Is.
var (
	// ErrAgentUnavailable: the agent binary is missing or not
	// executable. Fail-open class.
	ErrAgentUnavailable = errors.New("agent unavailable")

	// ErrAgentAPI: the agent reached the upstream model API but it
	// returned an error (e.g. HTTP 500 / rate limit). This is an
	// UPSTREAM failure, not the user's change and not the agent binary;
	// it is fast (num_turns small) and worth a backoff retry. Surfaced
	// distinctly so a fail-open reads as an API problem, not the user's code.
	ErrAgentAPI = errors.New("agent API error")

	// ErrAgentTimeout: the invocation exceeded its timeout and the
	// agent process was killed. Fail-open class.
	ErrAgentTimeout = errors.New("agent timed out")
)
