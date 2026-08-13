package commands

import (
	"strings"
	"testing"
)

// po-9nxdr.2: evidence scope flags (--team / --service / --scope-state).

func TestBuildEvidenceSubmitBody_ScopeFlags(t *testing.T) {
	tests := []struct {
		name          string
		team, service string
		wantTeam      bool
		wantService   bool
	}{
		{"no scope", "", "", false, false},
		{"team only", "payments", "", true, false},
		{"service only", "", "checkout-api", false, true},
		{"team and service (AND)", "platform", "shared-postgres", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := buildEvidenceSubmitBody("cid", "code", "n", "u", "d", "abc123", tt.team, tt.service)
			gotTeam, hasTeam := body["team"]
			gotService, hasService := body["service"]
			if hasTeam != tt.wantTeam {
				t.Errorf("team key present = %v, want %v", hasTeam, tt.wantTeam)
			}
			if hasService != tt.wantService {
				t.Errorf("service key present = %v, want %v", hasService, tt.wantService)
			}
			if hasTeam && gotTeam != tt.team {
				t.Errorf("team = %q, want %q", gotTeam, tt.team)
			}
			if hasService && gotService != tt.service {
				t.Errorf("service = %q, want %q", gotService, tt.service)
			}
			// Base fields must always survive.
			if body["control_id"] != "cid" || body["type"] != "code" || body["name"] != "n" {
				t.Errorf("base fields lost: %+v", body)
			}
			if body["git_hash"] != "abc123" {
				t.Errorf("git_hash lost: %+v", body)
			}
		})
	}
}

func TestBuildEvidenceListURL_ScopeFilters(t *testing.T) {
	url := buildEvidenceListURL("https://api.example.com", 20, "code", "verified", "cid-1", "payments", "checkout api", "team")
	for _, want := range []string{
		"limit=20", "type=code", "status=verified", "control_id=cid-1",
		"team=payments", "service=checkout+api", "scope_state=team",
	} {
		if !strings.Contains(url, want) {
			t.Errorf("url %q missing %q", url, want)
		}
	}
}

func TestBuildEvidenceListURL_OmitsEmptyScopeFilters(t *testing.T) {
	url := buildEvidenceListURL("https://api.example.com", 20, "", "", "", "", "", "")
	for _, absent := range []string{"team=", "service=", "scope_state="} {
		if strings.Contains(url, absent) {
			t.Errorf("url %q must not contain %q when filter unset", url, absent)
		}
	}
}

func TestValidScopeState(t *testing.T) {
	for _, ok := range []string{"team", "service", "global", "unknown"} {
		if !validScopeState(ok) {
			t.Errorf("validScopeState(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "org", "TEAM", "all"} {
		if validScopeState(bad) {
			t.Errorf("validScopeState(%q) = true, want false", bad)
		}
	}
}

func TestEvidenceScopeLabel(t *testing.T) {
	team := "payments"
	svc := "checkout-api"
	tests := []struct {
		name string
		e    EvidenceItem
		want string
	}{
		{"no scope state (old server)", EvidenceItem{}, ""},
		{"global is silent", EvidenceItem{ScopeState: "global"}, ""},
		{"team scope", EvidenceItem{ScopeState: "team", TeamSlug: &team}, "team=payments"},
		{"service scope", EvidenceItem{ScopeState: "service", ServiceName: &svc}, "service=checkout-api"},
		{
			"team and service",
			EvidenceItem{ScopeState: "team", TeamSlug: &team, ServiceName: &svc},
			"team=payments service=checkout-api",
		},
		{"unknown flagged for re-scoping", EvidenceItem{ScopeState: "unknown"}, "unknown scope (needs re-scoping)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evidenceScopeLabel(tt.e); got != tt.want {
				t.Errorf("evidenceScopeLabel = %q, want %q", got, tt.want)
			}
		})
	}
}
