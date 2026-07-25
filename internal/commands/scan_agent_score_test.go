package commands

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/revelara-ai/rvl-cli/internal/agentscan"
	"github.com/revelara-ai/rvl-cli/internal/config"
)

func TestServerScorer_MapsBandsByPosition(t *testing.T) {
	var gotReq findingScoreRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pk_test" {
			t.Errorf("wrong auth header: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		_ = json.NewEncoder(w).Encode(findingScoreResponse{Scored: []findingScoreRespItem{
			{Rule: "data-loss-hazard", Score: 80, Band: "critical"},
			{Rule: "n-plus-one-query", Score: 42, Band: "medium"},
		}})
	}))
	defer srv.Close()

	sc := &serverScorer{cfg: &config.Config{APIURL: srv.URL, APIKey: "pk_test"}, service: "svc", businessCriticality: 0.6}
	in := []agentscan.Finding{
		{Rule: "data-loss-hazard", Severity: "medium", File: "a.go", Line: 1},
		{Rule: "n-plus-one-query", Severity: "high", File: "b.go", Line: 2},
	}
	out, err := sc.Score(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Severity != "critical" || out[1].Severity != "medium" {
		t.Errorf("server bands not applied: %q, %q", out[0].Severity, out[1].Severity)
	}
	if gotReq.Service != "svc" || gotReq.BusinessCriticality != 0.6 || len(gotReq.Findings) != 2 {
		t.Errorf("request shape wrong: %+v", gotReq)
	}
	if gotReq.Findings[0].Rule != "data-loss-hazard" || gotReq.Findings[0].File != "a.go" || gotReq.Findings[0].Line != 1 {
		t.Errorf("request finding fields lost: %+v", gotReq.Findings[0])
	}
}

func TestServerScorer_ErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	sc := &serverScorer{cfg: &config.Config{APIURL: srv.URL, APIKey: "pk_test"}, service: "svc"}
	if _, err := sc.Score(context.Background(), []agentscan.Finding{{Rule: "x"}}); err == nil {
		t.Error("expected an error on 500 so the caller fails open")
	}
}

// A short response must not blank a finding's severity.
func TestServerScorer_ShortResponseKeepsAgentSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(findingScoreResponse{Scored: []findingScoreRespItem{
			{Rule: "a", Band: "high"},
		}})
	}))
	defer srv.Close()
	sc := &serverScorer{cfg: &config.Config{APIURL: srv.URL, APIKey: "pk_test"}, service: "svc"}
	out, err := sc.Score(context.Background(), []agentscan.Finding{
		{Rule: "a", Severity: "low"}, {Rule: "b", Severity: "medium"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Severity != "high" || out[1].Severity != "medium" {
		t.Errorf("short response mishandled: %q, %q", out[0].Severity, out[1].Severity)
	}
}
