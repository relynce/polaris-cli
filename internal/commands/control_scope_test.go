package commands

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/revelara-ai/rvl-cli/internal/config"
)

// po-9nxdr.2: scope-status breakdown on `rvl control show`.

func scopeStatusFixture() *ControlScopeStatus {
	return &ControlScopeStatus{
		ControlCode: "RC-018",
		OrgStatus:   "absent",
		Teams: []ControlTeamScopeStatus{
			{TeamSlug: "payments", TeamName: "Payments", Status: "evidenced", DirectEvidence: 2, InheritedEvidence: 1, GlobalEvidence: 0},
			{TeamSlug: "platform", TeamName: "Platform", Status: "absent", DirectEvidence: 0, InheritedEvidence: 0, GlobalEvidence: 0},
		},
		UnknownEvidence: 3,
	}
}

func TestFetchControlScopeStatus_PathAndFilters(t *testing.T) {
	var gotPath, gotTeam, gotService string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotTeam = r.URL.Query().Get("team")
		gotService = r.URL.Query().Get("service")
		_ = json.NewEncoder(w).Encode(scopeStatusFixture())
	}))
	defer srv.Close()

	cfg := &config.Config{APIURL: srv.URL, APIKey: "pk_test"}
	st, _, err := fetchControlScopeStatus(cfg, "RC-018", "payments", "checkout api")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/controls/by-code/RC-018/scope-status" {
		t.Errorf("path = %q", gotPath)
	}
	if gotTeam != "payments" || gotService != "checkout api" {
		t.Errorf("filters = team %q service %q", gotTeam, gotService)
	}
	if st.OrgStatus != "absent" || len(st.Teams) != 2 || st.UnknownEvidence != 3 {
		t.Errorf("parsed response wrong: %+v", st)
	}
}

func TestFetchControlScopeStatus_SurfacesServerHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "bad_request",
			"message": `unknown team "paymnets"; known team slugs: payments, platform`,
		})
	}))
	defer srv.Close()

	cfg := &config.Config{APIURL: srv.URL, APIKey: "pk_test"}
	_, _, err := fetchControlScopeStatus(cfg, "RC-018", "paymnets", "")
	if err == nil {
		t.Fatal("expected error on 400")
	}
	// The server's hint (which lists the known slugs) must pass through verbatim.
	if !strings.Contains(err.Error(), "known team slugs: payments, platform") {
		t.Errorf("server hint swallowed: %v", err)
	}
}

func TestRenderControlScopeStatus(t *testing.T) {
	var buf bytes.Buffer
	renderControlScopeStatus(&buf, scopeStatusFixture())
	out := buf.String()
	for _, want := range []string{
		"payments", "platform", "evidenced", "absent",
		"Org status (worst-of): absent",
		"3 evidence record(s) have unknown scope",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q in:\n%s", want, out)
		}
	}
	// Direct/inherited/global counts for the evidenced team must appear.
	if !strings.Contains(out, "2") || !strings.Contains(out, "1") {
		t.Errorf("evidence counts missing in:\n%s", out)
	}
}

func TestRenderControlScopeStatus_NoTeams(t *testing.T) {
	var buf bytes.Buffer
	renderControlScopeStatus(&buf, &ControlScopeStatus{ControlCode: "RC-018", OrgStatus: "evidenced", UnknownEvidence: 0})
	out := buf.String()
	if !strings.Contains(out, "no teams") {
		t.Errorf("no-teams render should say the org has no teams, got:\n%s", out)
	}
	if !strings.Contains(out, "Org status (worst-of): evidenced") {
		t.Errorf("org status line missing in:\n%s", out)
	}
}

func TestOrgScopeSummaryLine(t *testing.T) {
	tests := []struct {
		name string
		st   *ControlScopeStatus
		want string // "" = no summary line
	}{
		{"scoped evidence present", scopeStatusFixture(), "Org scope status: absent (worst-of across 2 teams; 3 unknown-scope records; see --team/--service)"},
		{
			"only global evidence",
			&ControlScopeStatus{
				OrgStatus: "evidenced",
				Teams: []ControlTeamScopeStatus{
					{TeamSlug: "payments", Status: "evidenced", GlobalEvidence: 2},
				},
			},
			"",
		},
		{"no teams no unknown", &ControlScopeStatus{OrgStatus: "evidenced"}, ""},
		{
			"unknown only",
			&ControlScopeStatus{OrgStatus: "evidenced", UnknownEvidence: 1},
			"Org scope status: evidenced (worst-of across 0 teams; 1 unknown-scope records; see --team/--service)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orgScopeSummaryLine(tt.st); got != tt.want {
				t.Errorf("orgScopeSummaryLine = %q, want %q", got, tt.want)
			}
		})
	}
}
