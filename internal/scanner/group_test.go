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
