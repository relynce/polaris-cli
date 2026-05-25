package scanner

import (
	"testing"
)

func mkFinding(slug, title, cat, sev, path string, line int) ScanFinding {
	return ScanFinding{
		Slug:       slug,
		Title:      title,
		Category:   cat,
		Impact:     sev,
		Likelihood: sev,
		Evidence:   []ScanEvidence{{Type: "code", Path: path, LineNumber: line}},
	}
}

func TestGroupEmpty(t *testing.T) {
	if got := Group(nil); len(got) != 0 {
		t.Errorf("Group(nil) = %v, want empty", got)
	}
	if got := Group([]ScanFinding{}); len(got) != 0 {
		t.Errorf("Group([]) = %v, want empty", got)
	}
}

func TestGroupMergesSameSlug(t *testing.T) {
	in := []ScanFinding{
		mkFinding("a", "Title A", "cat1", "high", "x.go", 1),
		mkFinding("a", "Title A", "cat1", "high", "y.go", 2),
		mkFinding("a", "Title A", "cat1", "high", "z.go", 3),
	}
	got := Group(in)
	if len(got) != 1 {
		t.Fatalf("got %d groups, want 1: %+v", len(got), got)
	}
	g := got[0]
	if g.Slug != "a" {
		t.Errorf("got slug %q, want a", g.Slug)
	}
	if g.InstanceCount != 3 {
		t.Errorf("got count %d, want 3", g.InstanceCount)
	}
	if len(g.Locations) != 3 {
		t.Errorf("got %d locations, want 3", len(g.Locations))
	}
}

func TestGroupSeparatesSlugs(t *testing.T) {
	in := []ScanFinding{
		mkFinding("a", "Title A", "cat1", "high", "x.go", 1),
		mkFinding("b", "Title B", "cat1", "high", "x.go", 2),
		mkFinding("a", "Title A", "cat1", "high", "y.go", 3),
	}
	got := Group(in)
	if len(got) != 2 {
		t.Fatalf("got %d groups, want 2: %+v", len(got), got)
	}
	bySlug := map[string]FindingGroup{}
	for _, g := range got {
		bySlug[g.Slug] = g
	}
	if bySlug["a"].InstanceCount != 2 {
		t.Errorf("slug a count = %d, want 2", bySlug["a"].InstanceCount)
	}
	if bySlug["b"].InstanceCount != 1 {
		t.Errorf("slug b count = %d, want 1", bySlug["b"].InstanceCount)
	}
}

func TestGroupOrdersByCategoryThenCountDesc(t *testing.T) {
	in := []ScanFinding{
		// catA has one rare and one common finding
		mkFinding("rare", "Rare", "catA", "high", "x.go", 1),
		mkFinding("common", "Common", "catA", "high", "y.go", 1),
		mkFinding("common", "Common", "catA", "high", "y.go", 2),
		mkFinding("common", "Common", "catA", "high", "y.go", 3),
		// catB has one finding
		mkFinding("solo", "Solo", "catB", "high", "z.go", 1),
	}
	got := Group(in)
	if len(got) != 3 {
		t.Fatalf("got %d groups, want 3", len(got))
	}
	// Expected order: catA/common (3), catA/rare (1), catB/solo (1)
	if got[0].Category != "catA" || got[0].Slug != "common" {
		t.Errorf("first = %+v, want catA/common", got[0])
	}
	if got[1].Category != "catA" || got[1].Slug != "rare" {
		t.Errorf("second = %+v, want catA/rare", got[1])
	}
	if got[2].Category != "catB" || got[2].Slug != "solo" {
		t.Errorf("third = %+v, want catB/solo", got[2])
	}
}

func TestGroupPreservesScoringFields(t *testing.T) {
	in := []ScanFinding{
		{
			Slug:         "x",
			Title:        "X",
			Category:     "cat",
			Impact:       "high",
			Likelihood:   "high",
			ControlCodes: []string{"RC-001"},
			Confidence:   "high",
			Evidence:     []ScanEvidence{{Path: "a.go", LineNumber: 1}},
		},
	}
	got := Group(in)
	if len(got) != 1 {
		t.Fatalf("want 1 group")
	}
	g := got[0]
	if g.Impact != "high" || g.Confidence != "high" {
		t.Errorf("group lost impact/confidence: %+v", g)
	}
	if len(g.ControlCodes) != 1 || g.ControlCodes[0] != "RC-001" {
		t.Errorf("group lost controls: %+v", g.ControlCodes)
	}
}

func TestGroupUsesUncategorizedWhenEmpty(t *testing.T) {
	in := []ScanFinding{mkFinding("a", "A", "", "high", "x.go", 1)}
	got := Group(in)
	if len(got) != 1 {
		t.Fatalf("want 1 group")
	}
	if got[0].Category != "uncategorized" {
		t.Errorf("got category %q, want uncategorized", got[0].Category)
	}
}

// --- DeduplicateFindings tests (po-ta8wj.3) ---

func mkFindingWithScore(slug, path string, line, score int, component string) ScanFinding {
	return ScanFinding{
		Slug:      slug,
		Title:     slug,
		Category:  "cat",
		Impact:    "high",
		Evidence:  []ScanEvidence{{Type: "code", Path: path, LineNumber: line}},
		RiskScore: score,
		Component: component,
	}
}

func TestDeduplicateFindingsEmpty(t *testing.T) {
	if got := DeduplicateFindings(nil); len(got) != 0 {
		t.Errorf("DeduplicateFindings(nil) = %v, want empty", got)
	}
	if got := DeduplicateFindings([]ScanFinding{}); len(got) != 0 {
		t.Errorf("DeduplicateFindings([]) = %v, want empty", got)
	}
}

func TestDeduplicateFindingsNoDuplicates(t *testing.T) {
	in := []ScanFinding{
		mkFindingWithScore("a", "x.go", 1, 10, "svc-a"),
		mkFindingWithScore("b", "y.go", 2, 20, "svc-b"),
		mkFindingWithScore("c", "z.go", 3, 30, "svc-c"),
	}
	got := DeduplicateFindings(in)
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3", len(got))
	}
}

// TestDeduplicateFindings10With3PairsReturns7 is the primary acceptance criterion.
func TestDeduplicateFindings10With3PairsReturns7(t *testing.T) {
	in := []ScanFinding{
		// Pair 1: slug "alpha", x.go:10 — second has higher score, wins
		mkFindingWithScore("alpha", "x.go", 10, 5, "agent-1"),
		mkFindingWithScore("alpha", "x.go", 10, 15, "agent-2"),
		// Pair 2: slug "beta", y.go:20 — both same score, first wins alphabetically
		mkFindingWithScore("beta", "y.go", 20, 8, "agent-1"),
		mkFindingWithScore("beta", "y.go", 20, 8, "agent-3"),
		// Pair 3: slug "gamma", z.go:30 — first has higher score, wins
		mkFindingWithScore("gamma", "z.go", 30, 50, "agent-2"),
		mkFindingWithScore("gamma", "z.go", 30, 20, "agent-3"),
		// Unique findings (no duplicates)
		mkFindingWithScore("delta", "a.go", 1, 10, "agent-1"),
		mkFindingWithScore("epsilon", "b.go", 2, 10, "agent-2"),
		mkFindingWithScore("zeta", "c.go", 3, 10, "agent-3"),
		mkFindingWithScore("eta", "d.go", 4, 10, "agent-1"),
	}
	got := DeduplicateFindings(in)
	if len(got) != 7 {
		t.Fatalf("got %d findings, want 7: %+v", len(got), got)
	}
}

func TestDeduplicateFindingsHigherScoreWins(t *testing.T) {
	in := []ScanFinding{
		mkFindingWithScore("slug", "x.go", 1, 5, "low-scorer"),
		mkFindingWithScore("slug", "x.go", 1, 15, "high-scorer"),
	}
	got := DeduplicateFindings(in)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Component != "high-scorer" {
		t.Errorf("winner component = %q, want high-scorer", got[0].Component)
	}
}

func TestDeduplicateFindingsCorroboratedByAgents(t *testing.T) {
	in := []ScanFinding{
		mkFindingWithScore("slug", "x.go", 1, 10, "agent-a"),
		mkFindingWithScore("slug", "x.go", 1, 5, "agent-b"),
	}
	got := DeduplicateFindings(in)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	// Winner is agent-a (higher score); agent-b is corroboration.
	if got[0].Component != "agent-a" {
		t.Errorf("winner = %q, want agent-a", got[0].Component)
	}
	if len(got[0].CorroboratedByAgents) == 0 {
		t.Error("CorroboratedByAgents should be non-empty when agents differ")
	}
	found := false
	for _, a := range got[0].CorroboratedByAgents {
		if a == "agent-b" {
			found = true
		}
	}
	if !found {
		t.Errorf("CorroboratedByAgents = %v, want to contain agent-b", got[0].CorroboratedByAgents)
	}
}

func TestDeduplicateFindingsProjectLevel(t *testing.T) {
	// Project-level findings (no Evidence path) should dedup by slug alone.
	f1 := ScanFinding{Slug: "proj-slug", Title: "T", Category: "cat", Impact: "high", RiskScore: 10, Component: "agent-1"}
	f2 := ScanFinding{Slug: "proj-slug", Title: "T", Category: "cat", Impact: "high", RiskScore: 5, Component: "agent-2"}
	got := DeduplicateFindings([]ScanFinding{f1, f2})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Component != "agent-1" {
		t.Errorf("winner = %q, want agent-1", got[0].Component)
	}
}

func TestDeduplicateFindingsDeterministic(t *testing.T) {
	// Same input should always produce same output.
	in := []ScanFinding{
		mkFindingWithScore("a", "x.go", 1, 10, "c1"),
		mkFindingWithScore("b", "y.go", 2, 20, "c2"),
		mkFindingWithScore("a", "x.go", 1, 10, "c3"),
	}
	got1 := DeduplicateFindings(in)
	got2 := DeduplicateFindings(in)
	if len(got1) != len(got2) {
		t.Fatalf("non-deterministic: len %d vs %d", len(got1), len(got2))
	}
	for i := range got1 {
		if got1[i].Slug != got2[i].Slug || got1[i].Component != got2[i].Component {
			t.Errorf("non-deterministic at index %d: %+v vs %+v", i, got1[i], got2[i])
		}
	}
}
