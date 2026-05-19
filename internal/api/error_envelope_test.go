package api

import "testing"

// TestExtractAPIErrorMessage verifies the spec-shaped envelope is
// parsed when present, and that non-envelope bodies fall through.
func TestExtractAPIErrorMessage(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "full_envelope",
			body: `{"error":"validation_error","message":"the field is required"}`,
			want: "validation_error: the field is required",
		},
		{
			name: "message_only",
			body: `{"message":"something broke"}`,
			want: "something broke",
		},
		{
			name: "error_only",
			body: `{"error":"internal_error"}`,
			want: "internal_error",
		},
		{
			name: "non_json",
			body: "plain text 500",
			want: "",
		},
		{
			name: "empty",
			body: "",
			want: "",
		},
		{
			name: "json_without_envelope",
			body: `{"foo":"bar"}`,
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractAPIErrorMessage([]byte(tc.body))
			if got != tc.want {
				t.Errorf("extractAPIErrorMessage(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}
