package scanner

import (
	"os/exec"
	"testing"
)

func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.email=t@e.co", "-c", "user.name=T", "commit", "--allow-empty", "-q", "-m", "init"},
	} {
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestResolveBaseRefFlagWins(t *testing.T) {
	dir := initGitRepo(t)
	res, err := ResolveBaseRef(ChangedOnlyConfig{
		Root:        dir,
		FlagBaseRef: "main",
		Env:         map[string]string{"RVL_BASE_REF": "feature/x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ref != "main" || res.Source != BaseRefFromFlag {
		t.Errorf("got ref=%q source=%q, want main/flag", res.Ref, res.Source)
	}
}

func TestResolveBaseRefSkipsUnreachable(t *testing.T) {
	dir := initGitRepo(t)
	res, err := ResolveBaseRef(ChangedOnlyConfig{
		Root:        dir,
		FlagBaseRef: "does-not-exist",
		Env:         map[string]string{"RVL_BASE_REF": "main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ref != "main" || res.Source != BaseRefFromRVLEnv {
		t.Errorf("got ref=%q source=%q, want main/RVL_BASE_REF after flag was unreachable", res.Ref, res.Source)
	}
}

func TestResolveBaseRefNoneReachable(t *testing.T) {
	dir := initGitRepo(t)
	_, err := ResolveBaseRef(ChangedOnlyConfig{Root: dir})
	if err != ErrNoBaseRef {
		t.Fatalf("want ErrNoBaseRef, got %v", err)
	}
}

func TestFormatNoBaseRefDiagnostic(t *testing.T) {
	out := FormatNoBaseRefDiagnostic(BaseRefResolution{Tried: []BaseRefSource{BaseRefFromFlag, BaseRefFromRVLEnv}})
	if out == "" {
		t.Fatal("expected a non-empty diagnostic")
	}
}

func TestDeduplicateFindingsKeepsHighestScore(t *testing.T) {
	findings := []ScanFinding{
		{Slug: "missing-timeout", RiskScore: 40, Evidence: []ScanEvidence{{Path: "a.go", LineNumber: 10}}},
		{Slug: "missing-timeout", RiskScore: 80, Evidence: []ScanEvidence{{Path: "a.go", LineNumber: 10}}},
		{Slug: "other", RiskScore: 20, Evidence: []ScanEvidence{{Path: "b.go", LineNumber: 5}}},
	}
	out := DeduplicateFindings(findings)
	if len(out) != 2 {
		t.Fatalf("want 2 deduped findings, got %d", len(out))
	}
	// The (missing-timeout, a.go, 10) pair collapses to the score-80 winner.
	var mt *ScanFinding
	for i := range out {
		if out[i].Slug == "missing-timeout" {
			mt = &out[i]
		}
	}
	if mt == nil || mt.RiskScore != 80 {
		t.Errorf("expected the score-80 winner, got %+v", mt)
	}
}

func TestDeduplicateFindingsSluglessKeyedByTitle(t *testing.T) {
	// LLM findings with no Slug must key by Title, not collapse together.
	findings := []ScanFinding{
		{Title: "issue A", Evidence: []ScanEvidence{{Path: "a.go", LineNumber: 1}}},
		{Title: "issue B", Evidence: []ScanEvidence{{Path: "b.go", LineNumber: 1}}},
	}
	out := DeduplicateFindings(findings)
	if len(out) != 2 {
		t.Errorf("slugless findings with distinct titles must not collapse; got %d", len(out))
	}
}
