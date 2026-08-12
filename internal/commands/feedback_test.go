package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFeedbackArgsDefaults(t *testing.T) {
	o, err := parseFeedbackArgs([]string{"--message", "hello"}, "feedback")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Message != "hello" {
		t.Errorf("message: got %q want %q", o.Message, "hello")
	}
	if o.Category != "feedback" {
		t.Errorf("category default: got %q want feedback", o.Category)
	}
	if !o.AttachDiagnostics {
		t.Error("attach-diagnostics should default to true")
	}
	if o.Yes {
		t.Error("--yes should default to false")
	}
	if o.Format != "text" {
		t.Errorf("format default: got %q want text", o.Format)
	}
}

func TestParseFeedbackArgsBugreportDefault(t *testing.T) {
	// `rvl bugreport` passes "bug" as the default category.
	o, err := parseFeedbackArgs([]string{"--message=broken"}, "bug")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Category != "bug" {
		t.Errorf("category default for bugreport: got %q want bug", o.Category)
	}
}

func TestParseFeedbackArgsAllFlags(t *testing.T) {
	o, err := parseFeedbackArgs([]string{
		"--message=scan did not submit",
		"--category=bug",
		"--attach-diagnostics=false",
		"--yes",
		"--format=json",
	}, "feedback")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Category != "bug" {
		t.Errorf("category: got %q want bug", o.Category)
	}
	if o.AttachDiagnostics {
		t.Error("attach-diagnostics=false not honored")
	}
	if !o.Yes {
		t.Error("--yes not honored")
	}
	if o.Format != "json" {
		t.Errorf("format: got %q want json", o.Format)
	}
}

func TestParseFeedbackArgsUnknownFlag(t *testing.T) {
	if _, err := parseFeedbackArgs([]string{"--bogus"}, "feedback"); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestParseFeedbackArgsBadAttachValue(t *testing.T) {
	if _, err := parseFeedbackArgs([]string{"--message=m", "--attach-diagnostics=maybe"}, "feedback"); err == nil {
		t.Fatal("expected error for invalid --attach-diagnostics value")
	}
}

func TestValidateFeedbackOptions(t *testing.T) {
	tests := []struct {
		name string
		o    feedbackOptions
		ok   bool
	}{
		{"valid feedback", feedbackOptions{Message: "m", Category: "feedback", Format: "text"}, true},
		{"valid bug json", feedbackOptions{Message: "m", Category: "bug", Format: "json"}, true},
		{"empty message", feedbackOptions{Message: "  ", Category: "feedback", Format: "text"}, false},
		{"bad category", feedbackOptions{Message: "m", Category: "rant", Format: "text"}, false},
		{"bad format", feedbackOptions{Message: "m", Category: "bug", Format: "yaml"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFeedbackOptions(&tt.o)
			if tt.ok && err != nil {
				t.Errorf("want ok, got error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}

func TestBuildFeedbackSubmissionOmitsDiagnostics(t *testing.T) {
	o := &feedbackOptions{Message: "m", Category: "bug", AttachDiagnostics: false, Format: "text"}
	diag := feedbackDiagnostics{CLIVersion: "1.2.3", OS: "linux", Arch: "amd64"}
	sub := buildFeedbackSubmission(o, "1.2.3", &diag)
	if sub.Diagnostics != nil {
		t.Fatal("diagnostics must be nil when --attach-diagnostics=false")
	}
	raw, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "diagnostics") {
		t.Errorf("payload must omit diagnostics key entirely: %s", raw)
	}
	if !strings.Contains(string(raw), `"cli_version":"1.2.3"`) {
		t.Errorf("payload missing cli_version: %s", raw)
	}
}

func TestBuildFeedbackSubmissionAttachesDiagnostics(t *testing.T) {
	o := &feedbackOptions{Message: "m", Category: "feedback", AttachDiagnostics: true, Format: "text"}
	diag := feedbackDiagnostics{CLIVersion: "1.2.3", OS: "linux", Arch: "amd64", APIHost: "api.revelara.ai"}
	sub := buildFeedbackSubmission(o, "1.2.3", &diag)
	if sub.Diagnostics == nil {
		t.Fatal("diagnostics must be attached by default")
	}
	if sub.Diagnostics.APIHost != "api.revelara.ai" {
		t.Errorf("api host: got %q", sub.Diagnostics.APIHost)
	}
}

func TestAPIHost(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://api.revelara.ai", "api.revelara.ai"},
		{"http://localhost:8080", "localhost:8080"},
		{"not a url", "not a url"},
	}
	for _, tt := range tests {
		if got := apiHost(tt.in); got != tt.want {
			t.Errorf("apiHost(%q): got %q want %q", tt.in, got, tt.want)
		}
	}
}

func TestLastAuditEventFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rvl-audit.jsonl")
	lines := `{"time":"2026-08-01T00:00:00Z","kind":"force-through","detail":{"mechanism":"env"}}
{"time":"2026-08-02T00:00:00Z","kind":"fail-open","detail":{"lens_errors":"2"}}
`
	if err := os.WriteFile(path, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	last, count, err := lastAuditEventFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("count: got %d want 2", count)
	}
	if last == nil || last.Kind != "fail-open" {
		t.Errorf("last event: got %+v want kind=fail-open", last)
	}
	if last != nil && last.Time != "2026-08-02T00:00:00Z" {
		t.Errorf("last event time: got %q", last.Time)
	}
}

func TestLastAuditEventFromFileMissing(t *testing.T) {
	_, count, err := lastAuditEventFromFile(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if count != 0 {
		t.Errorf("count: got %d want 0", count)
	}
}

func TestRenderFeedbackPreview(t *testing.T) {
	sub := feedbackSubmission{
		Message:    "the scan did not submit data",
		Category:   "bug",
		CLIVersion: "1.2.3",
		Diagnostics: &feedbackDiagnostics{
			CLIVersion: "1.2.3",
			OS:         "linux",
			Arch:       "amd64",
			APIHost:    "api.revelara.ai",
			OrgID:      "11111111-2222-3333-4444-555555555555",
		},
	}
	out := renderFeedbackPreview(sub)
	for _, want := range []string{"the scan did not submit data", "bug", "1.2.3", "linux", "amd64", "api.revelara.ai"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview missing %q:\n%s", want, out)
		}
	}
	// Product name policy: internal codename must never appear in
	// user-facing CLI output.
	if strings.Contains(out, "Polaris") {
		t.Errorf("preview must not contain the internal codename:\n%s", out)
	}
}

func TestRenderFeedbackPreviewNoDiagnostics(t *testing.T) {
	sub := feedbackSubmission{Message: "m", Category: "feedback"}
	out := renderFeedbackPreview(sub)
	if !strings.Contains(out, "not attached") {
		t.Errorf("preview should state diagnostics are not attached:\n%s", out)
	}
}

func TestReadYes(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"y\n", true},
		{"Y\n", true},
		{"yes\n", true},
		{"n\n", false},
		{"\n", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := readYes(strings.NewReader(tt.in)); got != tt.want {
			t.Errorf("readYes(%q): got %v want %v", tt.in, got, tt.want)
		}
	}
}
