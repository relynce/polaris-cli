package commands

import (
	"strings"
	"testing"
)

func TestResolveScanMode(t *testing.T) {
	cases := []struct {
		name      string
		cliFlag   string
		cfgMode   string
		want      string
		wantErr   string // substring match
	}{
		{"defaults to enforce", "", "", "enforce", ""},
		{"config sets eval", "", "eval", "eval", ""},
		{"config sets enforce explicitly", "", "enforce", "enforce", ""},
		{"cli overrides config eval -> enforce", "enforce", "eval", "enforce", ""},
		{"cli overrides config enforce -> eval", "eval", "enforce", "eval", ""},
		{"cli alone", "eval", "", "eval", ""},
		{"invalid cli value", "audit", "", "", "invalid --mode"},
		{"invalid config value", "", "audit", "", "invalid scanner.mode"},
		{"case-insensitive cli", "EVAL", "", "eval", ""},
		{"case-insensitive config", "", "Enforce", "enforce", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveScanMode(c.cliFlag, c.cfgMode)
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", c.wantErr)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
