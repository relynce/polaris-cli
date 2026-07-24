package commands

import "fmt"

// Scan mode values. enforce is the historical (and default) behavior:
// critical/high findings exit non-zero. eval mode reports findings but
// always exits 0.
const (
	scanModeEnforce = "enforce"
	scanModeEval    = "eval"
)

// validateScanMode reports whether value is a valid scan mode (or empty).
// Used by the agent scan's --mode / scanner.agent.mode validation.
func validateScanMode(value, source string) error {
	switch value {
	case "", scanModeEnforce, scanModeEval:
		return nil
	default:
		return fmt.Errorf("invalid %s %q (expected %q or %q)",
			source, value, scanModeEnforce, scanModeEval)
	}
}
