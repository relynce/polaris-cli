package commands

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/revelara-ai/rvl-cli/internal/project"
)

// TestApplyTeamAssignments pins the resolution order: --team overrides the
// whole submission (repo default AND components); otherwise .revelara.yaml
// team: (repo default) plus per-component team: entries apply.
func TestApplyTeamAssignments(t *testing.T) {
	cfg := &project.ProjectConfig{
		Project: "checkout-api",
		Team:    "checkout",
		Components: []project.ProjectComponent{
			{Name: "api", Path: "cmd/api"},
			{Name: "worker", Path: "cmd/worker", Team: "payments"},
		},
	}

	t.Run("file values", func(t *testing.T) {
		var req ScanRequest
		applyTeamAssignments(&req, cfg, "")
		if req.Team != "checkout" {
			t.Errorf("Team = %q, want checkout", req.Team)
		}
		if req.TeamSource != "" {
			t.Errorf("TeamSource = %q, want empty (server defaults to scan)", req.TeamSource)
		}
		want := map[string]string{"worker": "payments"}
		if !reflect.DeepEqual(req.ComponentTeams, want) {
			t.Errorf("ComponentTeams = %v, want %v", req.ComponentTeams, want)
		}
	})

	t.Run("override wins over file and drops component teams", func(t *testing.T) {
		var req ScanRequest
		applyTeamAssignments(&req, cfg, "platform")
		if req.Team != "platform" || req.TeamSource != "override" {
			t.Errorf("got (%q, %q), want (platform, override)", req.Team, req.TeamSource)
		}
		if req.ComponentTeams != nil {
			t.Errorf("ComponentTeams = %v, want nil under override", req.ComponentTeams)
		}
	})

	t.Run("override works without a config file", func(t *testing.T) {
		var req ScanRequest
		applyTeamAssignments(&req, nil, "platform")
		if req.Team != "platform" || req.TeamSource != "override" {
			t.Errorf("got (%q, %q), want (platform, override)", req.Team, req.TeamSource)
		}
	})

	t.Run("no team info leaves request untouched", func(t *testing.T) {
		var req ScanRequest
		applyTeamAssignments(&req, &project.ProjectConfig{Project: "p"}, "")
		if req.Team != "" || req.TeamSource != "" || req.ComponentTeams != nil {
			t.Errorf("expected zero team fields, got %+v", req)
		}
	})
}

// TestSlugifyTeamPreview mirrors the polaris server-side slugify contract
// (hygiene layer 1): lowercase, trim, whitespace/underscores -> hyphens,
// no affix stripping, invalid chars dropped, 2..63 chars.
func TestSlugifyTeamPreview(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Checkout", "checkout"},
		{" checkout ", "checkout"},
		{"Checkout Team", "checkout-team"},
		{"checkout_team", "checkout-team"},
		{"platform-team", "platform-team"},
		{"pay/ments", "payments"},
		{"x", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := slugifyTeamPreview(tc.in); got != tc.want {
			t.Errorf("slugifyTeamPreview(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNearestSlugs(t *testing.T) {
	known := []string{"checkout", "payments", "platform", "data-eng"}
	got := nearestSlugs("chekout", known, 3)
	if len(got) == 0 || got[0] != "checkout" {
		t.Errorf("nearestSlugs(chekout) = %v, want checkout first", got)
	}
	// Prefix relationships rank first.
	got = nearestSlugs("pay", known, 3)
	if len(got) == 0 || got[0] != "payments" {
		t.Errorf("nearestSlugs(pay) = %v, want payments first", got)
	}
	// Nothing near: distance > 3 from everything.
	if got := nearestSlugs("zzzzzzzzzz", known, 3); len(got) != 0 {
		t.Errorf("nearestSlugs(zzzzzzzzzz) = %v, want none", got)
	}
}

// TestWarnUnknownTeams pins the did-you-mean contract: loud on unknown
// teams (with suggestions), silent on known ones, skipped entirely when
// the slug lookup failed (nil), and never anything but warnings.
func TestWarnUnknownTeams(t *testing.T) {
	t.Run("unknown team warns with suggestion", func(t *testing.T) {
		var buf bytes.Buffer
		warnUnknownTeams(&buf, []string{"checkout", "payments"}, &ScanRequest{Team: "Chekout"})
		out := buf.String()
		if !strings.Contains(out, "is not a known team") {
			t.Errorf("expected unknown-team warning, got %q", out)
		}
		if !strings.Contains(out, "checkout") {
			t.Errorf("expected checkout suggestion, got %q", out)
		}
		if !strings.Contains(out, "creates a new team") {
			t.Errorf("expected create-a-new-team notice, got %q", out)
		}
	})

	t.Run("known team is silent", func(t *testing.T) {
		var buf bytes.Buffer
		// "Checkout Team" slugifies to checkout-team, which is known.
		warnUnknownTeams(&buf, []string{"checkout-team"}, &ScanRequest{Team: "Checkout Team"})
		if buf.Len() != 0 {
			t.Errorf("expected silence for known team, got %q", buf.String())
		}
	})

	t.Run("nil slug list skips the check", func(t *testing.T) {
		var buf bytes.Buffer
		warnUnknownTeams(&buf, nil, &ScanRequest{Team: "anything"})
		if buf.Len() != 0 {
			t.Errorf("expected silence when lookup failed, got %q", buf.String())
		}
	})

	t.Run("component teams are checked too", func(t *testing.T) {
		var buf bytes.Buffer
		warnUnknownTeams(&buf, []string{"checkout"}, &ScanRequest{
			Team:           "checkout",
			ComponentTeams: map[string]string{"worker": "paymments"},
		})
		out := buf.String()
		if !strings.Contains(out, "paymments") {
			t.Errorf("expected warning for component team, got %q", out)
		}
	})

	t.Run("empty org team list warns but does not block", func(t *testing.T) {
		var buf bytes.Buffer
		warnUnknownTeams(&buf, []string{}, &ScanRequest{Team: "checkout"})
		if !strings.Contains(buf.String(), "creates a new team") {
			t.Errorf("expected first-team warning, got %q", buf.String())
		}
	})
}

// TestScanRequestTeamWireShape locks the wire contract shared with
// polaris (internal/api/risk_handlers.go ScanRequest): field names team,
// team_source, component_teams; all omitted when empty.
func TestScanRequestTeamWireShape(t *testing.T) {
	data, err := json.Marshal(&ScanRequest{
		Service:        "svc",
		Team:           "checkout",
		TeamSource:     "override",
		ComponentTeams: map[string]string{"worker": "payments"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["team"] != "checkout" || m["team_source"] != "override" {
		t.Errorf("wire fields = team:%v team_source:%v, want checkout/override", m["team"], m["team_source"])
	}
	ct, ok := m["component_teams"].(map[string]interface{})
	if !ok || ct["worker"] != "payments" {
		t.Errorf("component_teams = %v, want {worker: payments}", m["component_teams"])
	}

	// Empty fields stay off the wire (older servers must see no change).
	data, err = json.Marshal(&ScanRequest{Service: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	var m2 map[string]interface{}
	if err := json.Unmarshal(data, &m2); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"team", "team_source", "component_teams"} {
		if _, present := m2[key]; present {
			t.Errorf("%s must be omitted when empty", key)
		}
	}
}
