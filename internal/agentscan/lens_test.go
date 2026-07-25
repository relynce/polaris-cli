package agentscan

import (
	"regexp"
	"testing"
)

func lensIDs(lenses []Lens) []string {
	ids := make([]string, 0, len(lenses))
	for _, l := range lenses {
		ids = append(ids, l.ID)
	}
	return ids
}

func assertIDs(t *testing.T, got []Lens, want []string) {
	t.Helper()
	gotIDs := lensIDs(got)
	if len(gotIDs) != len(want) {
		t.Fatalf("lens ids = %v, want %v", gotIDs, want)
	}
	for i := range want {
		if gotIDs[i] != want[i] {
			t.Fatalf("lens ids = %v, want %v", gotIDs, want)
		}
	}
}

func TestSelectLensesGoMajority(t *testing.T) {
	files := []ChangedFile{
		{Path: "internal/api/server.go", Kind: ChangeModified},
		{Path: "internal/api/server_test.go", Kind: ChangeModified},
		{Path: "cmd/main.go", Kind: ChangeAdded},
		{Path: "frontend/src/app.ts", Kind: ChangeModified},
		{Path: "README.md", Kind: ChangeModified},
	}
	assertIDs(t, SelectLenses(files), []string{LensGo, LensObservability, LensGeneral})
}

func TestSelectLensesDocsOnlyNoLanguageLens(t *testing.T) {
	files := []ChangedFile{
		{Path: "docs/design.md", Kind: ChangeModified},
		{Path: "README.md", Kind: ChangeModified},
		{Path: "config.yaml", Kind: ChangeAdded},
	}
	assertIDs(t, SelectLenses(files), []string{LensObservability, LensGeneral})
}

func TestSelectLensesEmptyChangeSet(t *testing.T) {
	assertIDs(t, SelectLenses(nil), []string{LensObservability, LensGeneral})
}

func TestSelectLensesSingleLanguageByMajority(t *testing.T) {
	// Python majority over javascript: only one language lens, chosen by count.
	files := []ChangedFile{
		{Path: "svc/worker.py", Kind: ChangeModified},
		{Path: "svc/tasks.py", Kind: ChangeAdded},
		{Path: "web/index.ts", Kind: ChangeModified},
	}
	assertIDs(t, SelectLenses(files), []string{LensPython, LensObservability, LensGeneral})

	// Flip the majority: javascript wins. .jsx/.mjs count toward javascript.
	files = []ChangedFile{
		{Path: "web/index.tsx", Kind: ChangeModified},
		{Path: "web/util.mjs", Kind: ChangeAdded},
		{Path: "web/legacy.jsx", Kind: ChangeModified},
		{Path: "svc/worker.py", Kind: ChangeModified},
	}
	assertIDs(t, SelectLenses(files), []string{LensJavaScript, LensObservability, LensGeneral})
}

func TestSelectLensesTieIsDeterministic(t *testing.T) {
	files := []ChangedFile{
		{Path: "svc/worker.py", Kind: ChangeModified},
		{Path: "cmd/main.go", Kind: ChangeModified},
	}
	first := lensIDs(SelectLenses(files))
	for i := 0; i < 10; i++ {
		again := lensIDs(SelectLenses(files))
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d: ids %v differ from first run %v", i, again, first)
			}
		}
	}
	// Exactly one language lens even on a tie.
	if len(first) != 3 {
		t.Fatalf("tie produced %d lenses (%v), want 3", len(first), first)
	}
}

func TestSelectLensesCap(t *testing.T) {
	files := []ChangedFile{
		{Path: "a.go", Kind: ChangeModified},
		{Path: "b.ts", Kind: ChangeModified},
		{Path: "c.py", Kind: ChangeModified},
		{Path: "d.go", Kind: ChangeModified},
	}
	got := SelectLenses(files)
	if len(got) > 4 {
		t.Fatalf("SelectLenses returned %d lenses, cap is 4", len(got))
	}
	// Still at most one language lens.
	langs := 0
	for _, l := range got {
		switch l.ID {
		case LensGo, LensJavaScript, LensPython:
			langs++
		}
	}
	if langs != 1 {
		t.Fatalf("got %d language lenses, want exactly 1: %v", langs, lensIDs(got))
	}
}

var slugRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func TestRuleVocabHygiene(t *testing.T) {
	lenses := BuiltinLenses()
	if len(lenses) == 0 {
		t.Fatal("no built-in lenses")
	}
	seenIDs := map[string]bool{}
	for _, l := range lenses {
		if seenIDs[l.ID] {
			t.Fatalf("duplicate lens ID %q", l.ID)
		}
		seenIDs[l.ID] = true
		if l.Name == "" || l.Focus == "" {
			t.Errorf("lens %q: empty Name or Focus", l.ID)
		}
		if len(l.RuleVocab) < 8 || len(l.RuleVocab) > 15 {
			t.Errorf("lens %q: vocab size %d, want 8-15 (closed, stable set)", l.ID, len(l.RuleVocab))
		}
		seen := map[string]bool{}
		for _, slug := range l.RuleVocab {
			if !slugRe.MatchString(slug) {
				t.Errorf("lens %q: slug %q is not stable kebab-case", l.ID, slug)
			}
			if seen[slug] {
				t.Errorf("lens %q: duplicate slug %q", l.ID, slug)
			}
			seen[slug] = true
		}
	}
}

func TestBuiltinLensCatalog(t *testing.T) {
	want := []string{LensGo, LensJavaScript, LensPython, LensObservability, LensGeneral}
	got := lensIDs(BuiltinLenses())
	for _, id := range want {
		found := false
		for _, g := range got {
			if g == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("built-in catalog missing lens %q (got %v)", id, got)
		}
	}
	for _, id := range want {
		l, ok := LensByID(id)
		if !ok {
			t.Errorf("LensByID(%q) not found", id)
			continue
		}
		if l.ID != id {
			t.Errorf("LensByID(%q).ID = %q", id, l.ID)
		}
	}
	if _, ok := LensByID("no-such-lens"); ok {
		t.Error("LensByID returned ok for unknown lens")
	}
}
