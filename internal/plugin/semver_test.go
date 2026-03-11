package plugin

import "testing"

func TestSemVerBase(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"0.2.0+abc123f", "0.2.0"},
		{"0.2.0", "0.2.0"},
		{"dev-abc123f+abc123f", "dev-abc123f"},
		{"dev", "dev"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := SemVerBase(tt.input); got != tt.want {
			t.Errorf("SemVerBase(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSemVerNewer(t *testing.T) {
	tests := []struct {
		installed, available string
		want                 bool
	}{
		// Same version, different build metadata
		{"0.2.0", "0.2.0", false},
		{"0.2.0+abc", "0.2.0+def", false},

		// Newer available
		{"0.1.0", "0.2.0", true},
		{"0.2.0", "0.2.1", true},
		{"0.2.0", "1.0.0", true},
		{"0.2.0+abc", "0.3.0+def", true},

		// Older available (downgrade)
		{"0.3.0", "0.2.0", false},
		{"1.0.0", "0.9.9", false},

		// Non-semver fallback (string inequality)
		{"dev", "dev", false},
		{"dev-abc", "dev-def", true},

		// Mixed semver and non-semver
		{"dev", "0.2.0", true},
		{"0.2.0", "dev", true},
	}
	for _, tt := range tests {
		if got := SemVerNewer(tt.installed, tt.available); got != tt.want {
			t.Errorf("SemVerNewer(%q, %q) = %v, want %v", tt.installed, tt.available, got, tt.want)
		}
	}
}
