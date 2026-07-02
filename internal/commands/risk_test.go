package commands

import "testing"

func TestParseRiskListArgs_Defaults(t *testing.T) {
	parsed, err := parseRiskListArgs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.limit != 1000 {
		t.Errorf("expected default limit 1000, got %d", parsed.limit)
	}
	if parsed.status != "" || parsed.category != "" || parsed.service != "" || parsed.format != "" {
		t.Errorf("expected empty filters, got %+v", parsed)
	}
}

func TestParseRiskListArgs_Valid(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want riskListArgs
	}{
		{
			"equals form",
			[]string{"--status=applicable", "--service=checkout-api", "--limit=50", "--format=json"},
			riskListArgs{status: "applicable", service: "checkout-api", limit: 50, format: "json"},
		},
		{
			"space form",
			[]string{"--status", "applicable", "--category", "change_management", "--limit", "25"},
			riskListArgs{status: "applicable", category: "change_management", limit: 25},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseRiskListArgs(tt.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed != tt.want {
				t.Errorf("parseRiskListArgs(%v) = %+v, want %+v", tt.args, parsed, tt.want)
			}
		})
	}
}

func TestParseRiskListArgs_Errors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"unknown flag", []string{"--org-id=abc"}, "unknown flag: --org-id=abc"},
		{"unknown short flag", []string{"-x"}, "unknown flag: -x"},
		{"unexpected positional", []string{"applicable"}, `unexpected argument: "applicable"`},
		{"non-numeric limit", []string{"--limit=abc"}, `--limit expects a positive integer, got "abc"`},
		{"zero limit", []string{"--limit=0"}, `--limit expects a positive integer, got "0"`},
		{"negative limit", []string{"--limit", "-5"}, `--limit expects a positive integer, got "-5"`},
		{"missing value", []string{"--status"}, "--status requires a value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRiskListArgs(tt.args)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}
