package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCriticalityScore(t *testing.T) {
	tests := []struct {
		label    string
		expected float64
	}{
		{"hobby", 0.0},
		{"internal", 0.25},
		{"customer-facing", 0.6},
		{"critical", 1.0},
		{"", 0.0},       // empty defaults to no boost
		{"unknown", 0.0}, // unrecognized defaults to no boost
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			cfg := &ProjectConfig{Criticality: tt.label}
			score := cfg.CriticalityScore()
			if score != tt.expected {
				t.Errorf("CriticalityScore(%q) = %f, want %f", tt.label, score, tt.expected)
			}
		})
	}
}

// TestLoadProjectConfigTeamFields pins the .revelara.yaml team contract
// (po-77b6w.1): a top-level team: (repo default) and per-component team:
// entries. Uses a non-git temp dir, which exercises the directory-itself
// fallback in LoadProjectConfigFrom.
func TestLoadProjectConfigTeamFields(t *testing.T) {
	dir := t.TempDir()
	yaml := `project: checkout-api
criticality: customer-facing
team: checkout
components:
    - name: api
      path: cmd/api
    - name: worker
      path: cmd/worker
      team: payments
`
	if err := writeTestConfig(dir, yaml); err != nil {
		t.Fatal(err)
	}

	cfg := LoadProjectConfigFrom(dir)
	if cfg == nil {
		t.Fatal("LoadProjectConfigFrom returned nil")
	}
	if cfg.Team != "checkout" {
		t.Errorf("Team = %q, want checkout", cfg.Team)
	}
	if len(cfg.Components) != 2 {
		t.Fatalf("got %d components, want 2", len(cfg.Components))
	}
	if cfg.Components[0].Team != "" {
		t.Errorf("components[0].Team = %q, want empty (inherits repo default)", cfg.Components[0].Team)
	}
	if cfg.Components[1].Team != "payments" {
		t.Errorf("components[1].Team = %q, want payments", cfg.Components[1].Team)
	}
}

// TestWriteProjectConfigTeamRoundTripAndExample: written configs carry the
// commented team: example (rvl init cold-start), and a set Team survives a
// write/load round trip.
func TestWriteProjectConfigTeamRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.revelara.yaml"
	if err := WriteProjectConfig(path, &ProjectConfig{
		Project: "svc",
		Team:    "platform",
		Components: []ProjectComponent{
			{Name: "svc", Path: ".", Team: "platform"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	data, err := readTestConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "#   team: platform"; !containsLine(data, want) {
		t.Errorf("written config missing commented team example %q:\n%s", want, data)
	}

	cfg := LoadProjectConfigFrom(dir)
	if cfg == nil {
		t.Fatal("round-trip load returned nil")
	}
	if cfg.Team != "platform" || cfg.Components[0].Team != "platform" {
		t.Errorf("round trip lost team fields: %+v", cfg)
	}
}

func writeTestConfig(dir, content string) error {
	return os.WriteFile(filepath.Join(dir, ".revelara.yaml"), []byte(content), 0644)
}

func readTestConfig(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}

func containsLine(haystack, line string) bool {
	return strings.Contains(haystack, line)
}
