package commands

import (
	"fmt"
	"strings"
)

// Scan mode values. enforce is the historical (and default) behavior:
// critical/high findings exit non-zero. eval mode reports findings but
// always exits 0.
const (
	scanModeEnforce = "enforce"
	scanModeEval    = "eval"
)

// resolveScanMode merges the CLI --mode flag, the .revelara.yaml
// `scanner.mode` field, and the built-in default ("enforce") and
// returns the effective scan mode. Precedence: CLI > config > default.
//
// Validation errors name the source so users know which place to fix.
// Comparison is case-insensitive; the returned value is lowercase.
func resolveScanMode(cliFlag, cfgMode string) (string, error) {
	cliFlag = strings.ToLower(strings.TrimSpace(cliFlag))
	cfgMode = strings.ToLower(strings.TrimSpace(cfgMode))
	if err := validateScanMode(cliFlag, "--mode"); err != nil {
		return "", err
	}
	if err := validateScanMode(cfgMode, "scanner.mode"); err != nil {
		return "", err
	}
	if cliFlag != "" {
		return cliFlag, nil
	}
	if cfgMode != "" {
		return cfgMode, nil
	}
	return scanModeEnforce, nil
}

func validateScanMode(value, source string) error {
	switch value {
	case "", scanModeEnforce, scanModeEval:
		return nil
	default:
		return fmt.Errorf("invalid %s %q (expected %q or %q)",
			source, value, scanModeEnforce, scanModeEval)
	}
}
