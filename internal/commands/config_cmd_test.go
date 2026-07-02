package commands

import "testing"

func TestMaskConfigValue(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{"api_key long value masked to prefix", "api_key", "pk_live_1234567890abcdef", "pk_live_..."},
		{"api_key short value fully hidden", "api_key", "shortkey", "[set]"},
		{"api_key boundary 12 chars fully hidden", "api_key", "123456789012", "[set]"},
		{"api_key 13 chars masked to prefix", "api_key", "1234567890123", "12345678..."},
		{"api_url echoed unchanged", "api_url", "https://api.revelara.ai", "https://api.revelara.ai"},
		{"org_name echoed unchanged", "org_name", "acme-corp", "acme-corp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskConfigValue(tt.key, tt.value); got != tt.want {
				t.Errorf("maskConfigValue(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.want)
			}
		})
	}
}
