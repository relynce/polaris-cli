package scanner

import (
	"reflect"
	"testing"
)

func TestParseChangedHunks(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string][]LineRange
	}{
		{
			name: "single file single hunk",
			in: `diff --git a/foo.go b/foo.go
index aaa..bbb 100644
--- a/foo.go
+++ b/foo.go
@@ -10,2 +10,3 @@
 unchanged
+added line
 unchanged
`,
			want: map[string][]LineRange{"foo.go": {{Start: 10, End: 12}}},
		},
		{
			name: "single line hunk without count",
			in: `diff --git a/foo.go b/foo.go
--- a/foo.go
+++ b/foo.go
@@ -42 +42 @@
-old
+new
`,
			want: map[string][]LineRange{"foo.go": {{Start: 42, End: 42}}},
		},
		{
			name: "multiple hunks one file",
			in: `diff --git a/foo.go b/foo.go
--- a/foo.go
+++ b/foo.go
@@ -10,1 +10,1 @@
-x
+y
@@ -50,2 +50,3 @@
 a
+b
 c
`,
			want: map[string][]LineRange{"foo.go": {{Start: 10, End: 10}, {Start: 50, End: 52}}},
		},
		{
			name: "two files",
			in: `diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -1,1 +1,2 @@
 x
+y
diff --git a/b.go b/b.go
--- a/b.go
+++ b/b.go
@@ -5,0 +5,1 @@
+new
`,
			want: map[string][]LineRange{
				"a.go": {{Start: 1, End: 2}},
				"b.go": {{Start: 5, End: 5}},
			},
		},
		{
			name: "pure deletion produces zero-length new range; dropped",
			in: `diff --git a/foo.go b/foo.go
--- a/foo.go
+++ b/foo.go
@@ -10,2 +9,0 @@
-deleted
-also deleted
`,
			want: map[string][]LineRange{},
		},
		{
			name: "empty diff",
			in:   "",
			want: map[string][]LineRange{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseChangedHunks(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestClassifyFindingsTagsNewAndPreExisting(t *testing.T) {
	hunks := map[string][]LineRange{
		"foo.go": {{Start: 10, End: 20}, {Start: 50, End: 50}},
		"bar.go": {{Start: 1, End: 1}},
	}
	in := []ScanFinding{
		mkFinding("a", "A", "cat", "high", "foo.go", 5),  // outside hunks -> pre-existing
		mkFinding("a", "A", "cat", "high", "foo.go", 15), // inside hunk -> new
		mkFinding("a", "A", "cat", "high", "foo.go", 50), // inside single-line hunk -> new
		mkFinding("a", "A", "cat", "high", "foo.go", 99), // outside hunks -> pre-existing
		mkFinding("a", "A", "cat", "high", "bar.go", 1),  // inside hunk -> new
		mkFinding("a", "A", "cat", "high", "baz.go", 1),  // file not in diff -> pre-existing
	}
	ClassifyFindings(in, hunks)
	wantStatus := []string{"pre-existing", "new", "new", "pre-existing", "new", "pre-existing"}
	for i, f := range in {
		if f.Status != wantStatus[i] {
			t.Errorf("findings[%d] (%s:%d) status=%q, want %q",
				i, f.Evidence[0].Path, f.Evidence[0].LineNumber, f.Status, wantStatus[i])
		}
	}
}

func TestClassifyFindingsNilHunksMeansNoBaseRef(t *testing.T) {
	// When classification didn't run (e.g., no base ref), findings
	// retain their original (empty) Status. Callers treat empty as
	// "gate normally" for back-compat.
	in := []ScanFinding{mkFinding("a", "A", "cat", "high", "x.go", 1)}
	ClassifyFindings(in, nil)
	if in[0].Status != "" {
		t.Errorf("nil hunks should not change status; got %q", in[0].Status)
	}
}

func TestClassifyFindingsEmptyFindings(t *testing.T) {
	// No findings to classify is a no-op, not a panic.
	ClassifyFindings(nil, map[string][]LineRange{"x.go": {{Start: 1, End: 1}}})
	ClassifyFindings([]ScanFinding{}, map[string][]LineRange{"x.go": {{Start: 1, End: 1}}})
}

func TestHasGatingFindings(t *testing.T) {
	cases := []struct {
		name string
		in   []ScanFinding
		want bool
	}{
		{"empty", nil, false},
		{
			"only low severity → no gate",
			[]ScanFinding{{Impact: "low"}},
			false,
		},
		{
			"high severity, status empty → gate (back-compat, no classification ran)",
			[]ScanFinding{{Impact: "high"}},
			true,
		},
		{
			"high severity, status new → gate",
			[]ScanFinding{{Impact: "high", Status: "new"}},
			true,
		},
		{
			"high severity, status pre-existing → no gate",
			[]ScanFinding{{Impact: "high", Status: "pre-existing"}},
			false,
		},
		{
			"mix: pre-existing high and new low → no gate",
			[]ScanFinding{
				{Impact: "high", Status: "pre-existing"},
				{Impact: "low", Status: "new"},
			},
			false,
		},
		{
			"mix: pre-existing high and new high → gate",
			[]ScanFinding{
				{Impact: "high", Status: "pre-existing"},
				{Impact: "high", Status: "new"},
			},
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HasGatingFindings(c.in); got != c.want {
				t.Errorf("HasGatingFindings = %v, want %v", got, c.want)
			}
		})
	}
}
