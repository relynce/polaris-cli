package commands

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/agentscan"
	"github.com/revelara-ai/rvl-cli/internal/project"
)

func TestValidateAgentScanFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    agentScanArgs
		wantErr string // substring; "" means valid
	}{
		{"staged is valid", agentScanArgs{staged: true}, ""},
		{"changed-only is valid", agentScanArgs{changedOnly: true}, ""},
		{"json format is valid", agentScanArgs{staged: true, format: "json"}, ""},
		{"human format is valid", agentScanArgs{staged: true, format: "human"}, ""},
		{"staged and changed-only conflict", agentScanArgs{staged: true, changedOnly: true}, "mutually exclusive"},
		{"one change-set mode required", agentScanArgs{}, "--staged or --changed-only"},
		{"agent and local conflict", agentScanArgs{staged: true, localMode: true}, "--local"},
		{"invalid format", agentScanArgs{staged: true, format: "yaml"}, "invalid --format"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateAgentScanFlags(c.args)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestResolveAgentScanSettingsDefaults(t *testing.T) {
	s, err := resolveAgentScanSettings(agentScanArgs{staged: true}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Mode != agentscan.GateModeEnforce {
		t.Errorf("Mode = %q, want enforce", s.Mode)
	}
	if s.FailOn != agentscan.DefaultFailOn {
		t.Errorf("FailOn = %q, want %q", s.FailOn, agentscan.DefaultFailOn)
	}
	if s.Model != agentscan.DefaultModel {
		t.Errorf("Model = %q, want %q", s.Model, agentscan.DefaultModel)
	}
	if s.Timeout != agentscan.DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", s.Timeout, agentscan.DefaultTimeout)
	}
	if s.MaxInvocations != agentscan.DefaultMaxInvocations {
		t.Errorf("MaxInvocations = %d, want %d", s.MaxInvocations, agentscan.DefaultMaxInvocations)
	}
	if s.StrictErrors || s.BudgetWarnUSD != 0 || s.Binary != "" || len(s.GeneratedGlobs) != 0 {
		t.Errorf("non-default zero fields: %+v", s)
	}
}

func TestResolveAgentScanSettingsYAML(t *testing.T) {
	cfg := &project.AgentScanConfig{
		FailOn:         "medium",
		Mode:           "eval",
		StrictErrors:   true,
		Model:          "opus",
		TimeoutSeconds: 60,
		BudgetWarnUSD:  5.5,
		GeneratedGlobs: []string{"dist/**"},
		MaxInvocations: 6,
	}
	s, err := resolveAgentScanSettings(agentScanArgs{staged: true}, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Mode != "eval" || s.FailOn != "medium" || !s.StrictErrors || s.Model != "opus" {
		t.Errorf("yaml values not applied: %+v", s)
	}
	if s.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want 60s", s.Timeout)
	}
	if s.BudgetWarnUSD != 5.5 || s.MaxInvocations != 6 {
		t.Errorf("budget/invocations not applied: %+v", s)
	}
	if len(s.GeneratedGlobs) != 1 || s.GeneratedGlobs[0] != "dist/**" {
		t.Errorf("GeneratedGlobs = %v", s.GeneratedGlobs)
	}
	// SECURITY (po-66evv.10 trust boundary): repo config carries no
	// binary override; Binary stays flag-only.
	if s.Binary != "" {
		t.Errorf("Binary = %q, must never come from repo config", s.Binary)
	}
}

func TestResolveAgentScanSettingsFlagOverridesYAML(t *testing.T) {
	cfg := &project.AgentScanConfig{FailOn: "medium", Mode: "eval", Model: "opus", TimeoutSeconds: 60}
	a := agentScanArgs{
		staged:         true,
		mode:           "enforce",
		failOn:         "CRITICAL",
		model:          "haiku",
		agentBinary:    "/opt/bin/claude",
		timeoutSeconds: "30",
	}
	s, err := resolveAgentScanSettings(a, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Mode != "enforce" {
		t.Errorf("Mode = %q, want flag override enforce", s.Mode)
	}
	if s.FailOn != "critical" {
		t.Errorf("FailOn = %q, want critical (case-normalized flag)", s.FailOn)
	}
	if s.Model != "haiku" || s.Binary != "/opt/bin/claude" {
		t.Errorf("model/binary overrides not applied: %+v", s)
	}
	if s.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", s.Timeout)
	}
}

func TestResolveAgentScanSettingsInvalid(t *testing.T) {
	cases := []struct {
		name    string
		args    agentScanArgs
		cfg     *project.AgentScanConfig
		wantErr string
	}{
		{"bad flag fail-on", agentScanArgs{failOn: "urgent"}, nil, "--fail-on"},
		{"bad yaml fail_on", agentScanArgs{}, &project.AgentScanConfig{FailOn: "urgent"}, "scanner.agent.fail_on"},
		{"bad flag mode", agentScanArgs{mode: "audit"}, nil, "--mode"},
		{"bad yaml mode", agentScanArgs{}, &project.AgentScanConfig{Mode: "audit"}, "scanner.agent.mode"},
		{"non-numeric timeout flag", agentScanArgs{timeoutSeconds: "abc"}, nil, "--timeout-seconds"},
		{"zero timeout flag", agentScanArgs{timeoutSeconds: "0"}, nil, "--timeout-seconds"},
		{"negative yaml timeout", agentScanArgs{}, &project.AgentScanConfig{TimeoutSeconds: -5}, "scanner.agent.timeout_seconds"},
		{"negative yaml max_invocations", agentScanArgs{}, &project.AgentScanConfig{MaxInvocations: -1}, "scanner.agent.max_invocations"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolveAgentScanSettings(c.args, c.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestAnsiRedRespectsNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if got := ansiRed("boom"); !strings.Contains(got, "\x1b[31m") {
		t.Errorf("with NO_COLOR unset, want ANSI red, got %q", got)
	}
	t.Setenv("NO_COLOR", "1")
	if got := ansiRed("boom"); got != "boom" {
		t.Errorf("with NO_COLOR set, want plain text, got %q", got)
	}
}

func TestClassifyLensErr(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("lens go: %w", agentscan.ErrAgentTimeout), "infra: timeout"},
		{fmt.Errorf("lens go: %w", agentscan.ErrAgentUnavailable), "infra: agent unavailable"},
		{errors.New("no findings JSON object in agent output"), "agent error"},
	}
	for _, c := range cases {
		if got := classifyLensErr(c.err); got != c.want {
			t.Errorf("classifyLensErr(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}
