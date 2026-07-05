package plugin

import "testing"

func TestParseAgentsListFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantEditor string
		wantJSON   bool
		wantHelp   bool
		wantErr    bool
	}{
		{"default", nil, "claude", false, false, false},
		{"format json", []string{"--format=json"}, "claude", true, false, false},
		{"format table", []string{"--format=table"}, "claude", false, false, false},
		{"json alias", []string{"--json"}, "claude", true, false, false},
		{"editor override", []string{"--editor=cursor", "--format=json"}, "cursor", true, false, false},
		{"help", []string{"--help"}, "claude", false, true, false},
		{"invalid format errors", []string{"--format=yaml"}, "claude", false, false, true},
		{"unknown flag errors", []string{"--bogus"}, "claude", false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			editor, asJSON, wantHelp, err := parseAgentsListFlags(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if editor != tt.wantEditor {
				t.Errorf("editor = %q, want %q", editor, tt.wantEditor)
			}
			if asJSON != tt.wantJSON {
				t.Errorf("asJSON = %v, want %v", asJSON, tt.wantJSON)
			}
			if wantHelp != tt.wantHelp {
				t.Errorf("wantHelp = %v, want %v", wantHelp, tt.wantHelp)
			}
		})
	}
}
