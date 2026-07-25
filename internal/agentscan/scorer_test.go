package agentscan

import (
	"context"
	"errors"
	"testing"
)

type stubScorer struct {
	out    []Finding
	err    error
	called bool
}

func (s *stubScorer) Score(_ context.Context, f []Finding) ([]Finding, error) {
	s.called = true
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

func TestApplyServerSeverity_ReplacesOnSuccess(t *testing.T) {
	res := &PipelineResult{Findings: []Finding{{Rule: "data-loss-hazard", Severity: "medium"}}}
	sc := &stubScorer{out: []Finding{{Rule: "data-loss-hazard", Severity: "critical"}}}
	applyServerSeverity(context.Background(), PipelineConfig{Scorer: sc}, res)
	if !sc.called {
		t.Fatal("scorer was not called")
	}
	if res.Findings[0].Severity != "critical" {
		t.Errorf("severity = %q, want the server band 'critical'", res.Findings[0].Severity)
	}
}

func TestApplyServerSeverity_FailOpenOnError(t *testing.T) {
	res := &PipelineResult{Findings: []Finding{{Rule: "x", Severity: "high"}}}
	sc := &stubScorer{err: errors.New("endpoint down")}
	applyServerSeverity(context.Background(), PipelineConfig{Scorer: sc}, res)
	if res.Findings[0].Severity != "high" {
		t.Errorf("fail-open must keep the agent severity, got %q", res.Findings[0].Severity)
	}
	if len(res.Notices) == 0 {
		t.Error("expected a fail-open notice when scoring errors")
	}
}

func TestApplyServerSeverity_NilScorerAndEmpty(t *testing.T) {
	res := &PipelineResult{Findings: []Finding{{Severity: "low"}}}
	applyServerSeverity(context.Background(), PipelineConfig{}, res) // nil Scorer
	if res.Findings[0].Severity != "low" {
		t.Error("nil scorer must be a no-op")
	}

	sc := &stubScorer{}
	applyServerSeverity(context.Background(), PipelineConfig{Scorer: sc}, &PipelineResult{})
	if sc.called {
		t.Error("scorer must not be called when there are no findings")
	}
}
