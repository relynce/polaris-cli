package cliutil

import "testing"

func TestWantsHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"nil args", nil, false},
		{"empty args", []string{}, false},
		{"help word first", []string{"help"}, true},
		{"long flag first", []string{"--help"}, true},
		{"short flag first", []string{"-h"}, true},
		{"long flag after subcommand", []string{"list", "--help"}, true},
		{"short flag after subcommand", []string{"list", "-h"}, true},
		{"help word after subcommand is positional", []string{"search", "help"}, false},
		{"regular subcommand", []string{"list"}, false},
		{"regular flags", []string{"list", "--limit=5"}, false},
		{"help embedded in flag value", []string{"--reason=--help me"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WantsHelp(tt.args); got != tt.want {
				t.Errorf("WantsHelp(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestValidateFormat(t *testing.T) {
	if err := ValidateFormat("json", "table", "json"); err != nil {
		t.Errorf("json should be valid: %v", err)
	}
	if err := ValidateFormat("table", "table", "json"); err != nil {
		t.Errorf("table should be valid: %v", err)
	}
	err := ValidateFormat("yaml", "table", "json")
	if err == nil {
		t.Fatal("yaml should be invalid")
	}
	if got := err.Error(); got != `invalid --format "yaml" (valid: table, json)` {
		t.Errorf("unexpected message: %q", got)
	}
}

func TestFlagValue(t *testing.T) {
	// equals form: value in same token, index unchanged.
	v, next, err := FlagValue([]string{"--format=json"}, 0, "--format")
	if err != nil || v != "json" || next != 0 {
		t.Fatalf("equals form: v=%q next=%d err=%v", v, next, err)
	}
	// space form: value in next token, index advanced.
	v, next, err = FlagValue([]string{"--format", "json"}, 0, "--format")
	if err != nil || v != "json" || next != 1 {
		t.Fatalf("space form: v=%q next=%d err=%v", v, next, err)
	}
	// space form with no following token errors.
	if _, _, err := FlagValue([]string{"--format"}, 0, "--format"); err == nil {
		t.Fatal("expected error for missing value")
	}
}
