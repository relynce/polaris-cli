package commands

import (
	"strings"
	"testing"
	"time"
)

func TestFormatIncidentSearchTable_Empty(t *testing.T) {
	out := formatIncidentSearchTable([]IncidentSearchResult{})
	if !strings.Contains(out, "No incidents found") {
		t.Errorf("expected 'No incidents found', got: %s", out)
	}
}

func TestFormatIncidentSearchTable_ShowsColumns(t *testing.T) {
	date := time.Date(2025, 10, 20, 0, 0, 0, 0, time.UTC)
	mttr := 890
	results := []IncidentSearchResult{
		{
			ShortName:      "inc-qq3",
			Title:          "AWS: US-EAST-1 load-balancer glitch sparks internet-scale outage",
			Severity:       "critical",
			IncidentDate:   &date,
			MTTRMinutes:    &mttr,
			SourceURL:      "https://www.ilert.com/postmortems/aws-internet-scale-outage",
			RelevanceScore: 0.87,
		},
	}
	out := formatIncidentSearchTable(results)
	if !strings.Contains(out, "inc-qq3") {
		t.Errorf("expected short_name in output, got: %s", out)
	}
	if !strings.Contains(out, "0.87") {
		t.Errorf("expected relevance score in output, got: %s", out)
	}
	if !strings.Contains(out, "critical") {
		t.Errorf("expected severity in output, got: %s", out)
	}
}

func TestFormatIncidentSearchTable_TruncatesLongTitle(t *testing.T) {
	longTitle := strings.Repeat("x", 100)
	results := []IncidentSearchResult{
		{ShortName: "inc-abc", Title: longTitle, RelevanceScore: 0.5},
	}
	out := formatIncidentSearchTable(results)
	if strings.Contains(out, longTitle) {
		t.Errorf("expected long title to be truncated, got full title in: %s", out)
	}
}

func TestParseIncidentSearchArgs_DefaultLimit(t *testing.T) {
	q, limit, format, err := parseIncidentSearchArgs([]string{"circuit breaker"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q != "circuit breaker" {
		t.Errorf("expected query 'circuit breaker', got %q", q)
	}
	if limit != 10 {
		t.Errorf("expected default limit 10, got %d", limit)
	}
	if format != "table" {
		t.Errorf("expected default format 'table', got %q", format)
	}
}

func TestParseIncidentSearchArgs_WithFlags(t *testing.T) {
	q, limit, format, err := parseIncidentSearchArgs([]string{"retry", "storm", "--limit=5", "--format=json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q != "retry storm" {
		t.Errorf("expected query 'retry storm', got %q", q)
	}
	if limit != 5 {
		t.Errorf("expected limit 5, got %d", limit)
	}
	if format != "json" {
		t.Errorf("expected format 'json', got %q", format)
	}
}

func TestParseIncidentSearchArgs_EmptyQuery(t *testing.T) {
	q, _, _, err := parseIncidentSearchArgs([]string{"--limit=5"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q != "" {
		t.Errorf("expected empty query, got %q", q)
	}
}

func TestParseIncidentSearchArgs_Errors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"unknown flag", []string{"query", "--severity=high"}, "unknown flag: --severity=high"},
		{"non-numeric limit", []string{"query", "--limit=abc"}, `--limit expects a positive integer, got "abc"`},
		{"zero limit", []string{"query", "--limit=0"}, `--limit expects a positive integer, got "0"`},
		{"negative limit", []string{"query", "--limit=-3"}, `--limit expects a positive integer, got "-3"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parseIncidentSearchArgs(tt.args)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// po-i24do.11: "--flag value" (space form) is accepted alongside
// "--flag=value", and an invalid --format errors instead of silently
// rendering a table.
func TestParseIncidentSearchArgs_SpaceForm(t *testing.T) {
	q, limit, format, err := parseIncidentSearchArgs([]string{"retry", "storm", "--limit", "5", "--format", "json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q != "retry storm" {
		t.Errorf("expected query 'retry storm', got %q", q)
	}
	if limit != 5 {
		t.Errorf("expected limit 5, got %d", limit)
	}
	if format != "json" {
		t.Errorf("expected format 'json', got %q", format)
	}
}

func TestParseIncidentSearchArgs_InvalidFormatErrors(t *testing.T) {
	_, _, _, err := parseIncidentSearchArgs([]string{"query", "--format=yaml"})
	if err == nil {
		t.Fatal("expected error for invalid --format, got nil")
	}
	if got := err.Error(); got != `invalid --format "yaml" (valid: table, json)` {
		t.Errorf("unexpected error: %q", got)
	}
}

func TestParseIncidentSearchArgs_MissingFormatValueErrors(t *testing.T) {
	_, _, _, err := parseIncidentSearchArgs([]string{"query", "--format"})
	if err == nil {
		t.Fatal("expected error for --format with no value, got nil")
	}
}
