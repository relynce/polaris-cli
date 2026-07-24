package project

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProjectConfig represents the .revelara.yaml project configuration file
type ProjectConfig struct {
	Project     string             `yaml:"project"`
	Criticality string             `yaml:"criticality,omitempty"`
	Components  []ProjectComponent `yaml:"components"`
	Scanner     *ScannerConfig     `yaml:"scanner,omitempty"`
}

// ScannerConfig is the optional .revelara.yaml `scanner` section consumed
// by the local reliability scanner. Absent = all defaults.
//
// Example:
//
//	scanner:
//	  exclude_matchers: [hardcoded-connection-string]
//	  exclude_paths:    ["legacy/"]
//	  confidence_threshold: medium
//	  base_ref: origin/develop
//	  include_tests: false
//	  tolerance:
//	    target: 200
//	    headroom_pct: 10
//	  strict_enforcement: false
type ScannerConfig struct {
	ExcludeMatchers     []string         `yaml:"exclude_matchers,omitempty"`
	ExcludePaths        []string         `yaml:"exclude_paths,omitempty"`
	ConfidenceThreshold string           `yaml:"confidence_threshold,omitempty"`
	BaseRef             string           `yaml:"base_ref,omitempty"`
	IncludeTests        bool             `yaml:"include_tests,omitempty"`
	Tolerance           *ToleranceConfig `yaml:"tolerance,omitempty"`
	StrictEnforcement   *bool            `yaml:"strict_enforcement,omitempty"`

	// po-f96kz: enforce (default) gates CI on critical/high findings;
	// eval reports findings but always exits 0. Useful for rolling the
	// scanner out to a team that wants visibility before flipping the
	// gate on. CLI --mode overrides this value.
	Mode string `yaml:"mode,omitempty"`

	// po-3vsvk: named matcher profile to activate by default.
	// Built-ins: "fast" (regex-impl matchers only) and "full" (all).
	// Custom names must appear in Profiles below. CLI --profile overrides.
	Profile string `yaml:"profile,omitempty"`

	// po-3vsvk: user-defined or built-in-override profile slug lists.
	// Keys are profile names; values are explicit lists of matcher
	// slugs. A user key matching a built-in name (fast, full) replaces
	// the built-in's computed list.
	Profiles map[string][]string `yaml:"profiles,omitempty"`

	// po-qs96.5: time-bounded, reason-bearing waivers for known-acceptable
	// patterns. Different from ExcludeMatchers (no-questions-asked
	// suppression). Each waiver gets logged to the polaris waivers_audit
	// table when the scan submits, so EMs and auditors have a
	// who/when/scope/reason record.
	Waivers []WaiverEntry `yaml:"waivers,omitempty"`

	// po-66evv.5: `scanner.agent` configures `rvl scan --agent`, the
	// change-scoped agent scan. See AgentScanConfig for the trust
	// boundary on what repo-tracked config may set.
	Agent *AgentScanConfig `yaml:"agent,omitempty"`
}

// AgentScanConfig is the .revelara.yaml `scanner.agent` section for the
// change-scoped agent scan (`rvl scan --agent`).
//
// SECURITY / TRUST BOUNDARY (po-66evv.10, agent-scan spec "Security
// model"): repo-tracked config may set gate and threshold VALUES only.
// There is deliberately NO agent_cmd, binary, or template-path field
// here, and none may be added: anything that selects code to execute is
// honored only from user-level config or an explicit trust grant
// (direnv model). The agent-binary override is the user-level
// --agent-binary flag only.
//
// Example:
//
//	scanner:
//	  agent:
//	    fail_on: high          # critical|high|medium|low (default high)
//	    mode: enforce          # enforce|eval (eval never blocks)
//	    strict_errors: false   # true = infra errors fail the gate closed
//	    model: sonnet          # pinned agent model
//	    timeout_seconds: 180   # per-lens invocation timeout
//	    budget_warn_usd: 5.0   # warn when cumulative scan cost exceeds this
//	    generated_globs: ["gen/**"]  # extra generated-content globs
//	    max_invocations: 12    # chunk x lens fan-out cap
type AgentScanConfig struct {
	// Preset names a built-in adapter (claude, custom). A NAME is safe
	// to accept from repo config: it selects built-in code, it cannot
	// introduce code. A custom COMMAND string is never a repo field
	// (po-66evv.10 trust boundary); it comes from RVL_AGENT_CMD only.
	Preset         string   `yaml:"preset,omitempty"`
	FailOn         string   `yaml:"fail_on,omitempty"`
	Mode           string   `yaml:"mode,omitempty"`
	StrictErrors   bool     `yaml:"strict_errors,omitempty"`
	Model          string   `yaml:"model,omitempty"`
	TimeoutSeconds int      `yaml:"timeout_seconds,omitempty"`
	BudgetWarnUSD  float64  `yaml:"budget_warn_usd,omitempty"`
	GeneratedGlobs []string `yaml:"generated_globs,omitempty"`
	MaxInvocations int      `yaml:"max_invocations,omitempty"`
}

// WaiverEntry is a single in-repo waiver. The matcher slug is required;
// paths is a list of glob patterns scoping the waiver; expires is an ISO
// date after which the waiver no longer applies; reason is required for
// audit accountability.
type WaiverEntry struct {
	Matcher string   `yaml:"matcher"`
	Paths   []string `yaml:"paths,omitempty"`
	Expires string   `yaml:"expires,omitempty"` // YYYY-MM-DD
	Reason  string   `yaml:"reason"`
}

// ToleranceConfig is the per-service tolerance override that flows from
// .revelara.yaml to the Polaris CI gate via the scan submission. Each
// field is a pointer so unset fields fall through to org-level defaults
// (most-specific wins). Reference: docs/designs/local-scanner-developer-workflow.md
// in the polaris repo.
type ToleranceConfig struct {
	Target      *int `yaml:"target,omitempty"`
	HeadroomPct *int `yaml:"headroom_pct,omitempty"`
}

// CriticalityScore maps the human-friendly criticality label to a float64 (0.0-1.0)
// for use in risk scoring. Unknown or empty values default to 0.0 (no boost).
func (c *ProjectConfig) CriticalityScore() float64 {
	switch c.Criticality {
	case "hobby":
		return 0.0
	case "internal":
		return 0.25
	case "customer-facing":
		return 0.6
	case "critical":
		return 1.0
	default:
		return 0.0
	}
}

// ProjectComponent represents a component within a project
type ProjectComponent struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// LoadProjectConfigFrom reads .revelara.yaml from the specified directory's git root.
// If targetDir is empty, uses the current working directory (existing behavior).
// Falls back to .relynce.yaml then .polaris.yaml, auto-renaming to .revelara.yaml.
func LoadProjectConfigFrom(targetDir string) *ProjectConfig {
	var gitRoot string
	if targetDir != "" {
		absTarget, err := filepath.Abs(targetDir)
		if err != nil {
			return nil
		}
		cmd := exec.Command("git", "-C", absTarget, "rev-parse", "--show-toplevel")
		out, err := cmd.Output()
		if err != nil {
			// Not a git repo - try using the directory itself
			gitRoot = absTarget
		} else {
			gitRoot = strings.TrimSpace(string(out))
		}
	} else {
		cmd := exec.Command("git", "rev-parse", "--show-toplevel")
		out, err := cmd.Output()
		if err != nil {
			return nil
		}
		gitRoot = strings.TrimSpace(string(out))
	}

	revelaraPath := filepath.Join(gitRoot, ".revelara.yaml")
	legacyRelyncePath := filepath.Join(gitRoot, ".relynce.yaml")
	polarisPath := filepath.Join(gitRoot, ".polaris.yaml")

	// 1. Try .revelara.yaml first
	data, err := os.ReadFile(revelaraPath)
	if err != nil {
		// 2. Fallback: try .relynce.yaml and auto-rename
		data, err = os.ReadFile(legacyRelyncePath)
		if err != nil {
			// 3. Fallback: try .polaris.yaml and auto-rename
			data, err = os.ReadFile(polarisPath)
			if err != nil {
				return nil
			}
			if renameErr := os.Rename(polarisPath, revelaraPath); renameErr == nil {
				fmt.Fprintf(os.Stderr, "Renamed .polaris.yaml to .revelara.yaml\n")
			}
		} else {
			if renameErr := os.Rename(legacyRelyncePath, revelaraPath); renameErr == nil {
				fmt.Fprintf(os.Stderr, "Renamed .relynce.yaml to .revelara.yaml\n")
			}
		}
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return &cfg
}

// LoadProjectConfig reads .revelara.yaml from the current directory's git root.
func LoadProjectConfig() *ProjectConfig {
	return LoadProjectConfigFrom("")
}

// WriteProjectConfig writes a ProjectConfig to disk as .revelara.yaml
func WriteProjectConfig(path string, cfg *ProjectConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	header := "# Revelara project configuration\n# Used by /rvl:scan and reliability-review skills for consistent service naming\n"
	return os.WriteFile(path, []byte(header+string(data)), 0644)
}
