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
