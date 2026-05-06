package scanner

import "testing"

func TestMatcherLanguagesIntersect(t *testing.T) {
	cases := []struct {
		name     string
		matcher  []string
		detected []string
		want     bool
	}{
		{"empty matcher languages = always run", nil, []string{"Go"}, true},
		{"empty detected = always run", []string{"Go"}, nil, true},
		{"intersect match", []string{"Go", "Java"}, []string{"Go"}, true},
		{"case-insensitive match", []string{"Go"}, []string{"go"}, true},
		{"no intersection", []string{"Go"}, []string{"Python"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set := map[string]bool{}
			for _, l := range c.detected {
				set[toLowerASCII(l)] = true
			}
			m := Matcher{Languages: c.matcher}
			if got := matcherLanguagesIntersect(m, set); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// toLowerASCII is a tiny helper to avoid an extra strings import.
func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func TestScanRespectsLanguageFiltering(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "BAD")
	writeFile(t, root, "main.py", "BAD")

	goOnly := stubMatcher("go-bad", "")
	goOnly.Languages = []string{"Go"}
	goOnly.FilePatterns = []string{"**/*.go"}

	pyOnly := stubMatcher("py-bad", "")
	pyOnly.Languages = []string{"Python"}
	pyOnly.FilePatterns = []string{"**/*.py"}

	cands, _, err := Scan([]Matcher{goOnly, pyOnly}, ScanOptions{
		Root:      root,
		Service:   "test",
		Languages: []string{"Go"}, // only Go detected
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate (Go matcher only), got %d: %+v", len(cands), cands)
	}
	if cands[0].Slug != "go-bad" {
		t.Errorf("got slug %q, want go-bad", cands[0].Slug)
	}
}
