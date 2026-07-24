package agentscan

import (
	"fmt"
	"strings"
)

// This file selects an adapter by preset name and enforces the trust
// boundary (po-66evv.10). The rule:
//
//   - A PRESET NAME (claude, custom) may come from any config source,
//     including repo-tracked .revelara.yaml: a name only selects
//     built-in code, it cannot introduce code.
//   - A CUSTOM COMMAND TEMPLATE selects code to execute, so it is
//     honored ONLY from a user-level source (the caller passes it in
//     from RVL_AGENT_CMD or user-level config, never from repo config).
//     SelectAdapter fails closed if preset=custom without a trusted
//     command.

// Preset identifiers.
const (
	PresetClaude = "claude"
	PresetCustom = "custom"
)

// AdapterChoice is the resolved, trust-checked adapter selection the CLI
// hands to SelectAdapter. TrustedCommand is non-nil only when a custom
// command came from a user-level source; it is NEVER populated from repo
// config.
type AdapterChoice struct {
	Preset         string
	Config         AdapterConfig
	TrustedCommand []string // user-level custom command template, or nil
}

// SelectAdapter builds the adapter for a choice, enforcing the trust
// boundary. An empty preset defaults to claude.
func SelectAdapter(choice AdapterChoice) (Adapter, error) {
	preset := strings.ToLower(strings.TrimSpace(choice.Preset))
	switch preset {
	case "", PresetClaude:
		return NewClaudeAdapter(choice.Config), nil
	case PresetCustom:
		if len(choice.TrustedCommand) == 0 {
			// Fail closed: a custom preset with no trusted command means
			// someone selected "custom" (possibly from repo config)
			// without a user-level command to run. Never fall back to a
			// shell or to a repo-supplied string.
			return nil, fmt.Errorf(
				"preset %q requires a custom command from a user-level source (set RVL_AGENT_CMD); repo config cannot supply one",
				PresetCustom)
		}
		return NewCustomAdapter(CustomAdapterConfig{
			Name:    PresetCustom,
			Command: choice.TrustedCommand,
			Timeout: choice.Config.Timeout,
		})
	default:
		return nil, fmt.Errorf("unknown agent preset %q (known: %s, %s)", preset, PresetClaude, PresetCustom)
	}
}
