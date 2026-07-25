package agentscan

import "testing"

// sampleDiff: foo.go gains two funcs at post-change lines 3-4 (context at
// 1,2,5); new.go is added entirely (lines 1-2).
const sampleDiff = `diff --git a/foo.go b/foo.go
index abc1234..def5678 100644
--- a/foo.go
+++ b/foo.go
@@ -1,3 +1,5 @@
 package p

+func Added() {}
+func Also() {}
 func Existing() {}
diff --git a/new.go b/new.go
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/new.go
@@ -0,0 +1,2 @@
+package q
+func New() {}
`

func TestChangedLineSet(t *testing.T) {
	got := changedLineSet(sampleDiff)
	if !got["foo.go"][3] || !got["foo.go"][4] {
		t.Errorf("foo.go changed lines = %v, want to include {3,4}", got["foo.go"])
	}
	if got["foo.go"][1] || got["foo.go"][2] || got["foo.go"][5] {
		t.Errorf("foo.go must not record context lines 1/2/5: %v", got["foo.go"])
	}
	if !got["new.go"][1] || !got["new.go"][2] {
		t.Errorf("new.go changed lines = %v, want {1,2}", got["new.go"])
	}
}

func TestInChangedScope(t *testing.T) {
	changed := changedLineSet(sampleDiff)
	cases := []struct {
		file string
		line int
		want bool
	}{
		{"foo.go", 3, true},   // exact added line
		{"foo.go", 4, true},   // exact added line
		{"foo.go", 6, true},   // within tolerance (3) of line 4
		{"foo.go", 50, false}, // far pre-existing
		{"foo.go", 0, true},   // file-level finding on a changed file
		{"bar.go", 3, false},  // untouched file
		{"new.go", 2, true},   // added file
	}
	for _, c := range cases {
		got := inChangedScope(Finding{File: c.file, Line: c.line}, changed, newCodeTolerance)
		if got != c.want {
			t.Errorf("inChangedScope(%s:%d) = %v, want %v", c.file, c.line, got, c.want)
		}
	}
}

func TestClassifyNewCode(t *testing.T) {
	cs := ChangeSet{Diff: sampleDiff}
	findings := []Finding{
		{File: "foo.go", Line: 3, Severity: "high"},  // on changed line -> gates
		{File: "foo.go", Line: 50, Severity: "high"}, // pre-existing -> advisory
		{File: "bar.go", Line: 1, Severity: "high"},  // untouched file -> advisory
	}
	out := classifyNewCode(PipelineConfig{GateScope: GateScopeChanged}, cs, findings)
	if out[0].Advisory {
		t.Error("finding on a changed line must NOT be advisory")
	}
	if !out[1].Advisory || !out[2].Advisory {
		t.Errorf("pre-existing / untouched-file findings must be advisory: %+v", out)
	}

	// gate_scope=all disables new-code gating: nothing is marked advisory.
	out2 := classifyNewCode(PipelineConfig{GateScope: GateScopeAll}, cs, []Finding{{File: "bar.go", Line: 1}})
	if out2[0].Advisory {
		t.Error("gate_scope=all must not mark anything advisory")
	}
}

func TestComputeGate_SkipsAdvisory(t *testing.T) {
	res := PipelineResult{Findings: []Finding{
		{Rule: "on-change", Severity: "high", Advisory: false},
		{Rule: "pre-existing", Severity: "critical", Advisory: true}, // must not block
	}}
	d := ComputeGate(PipelineConfig{FailOn: "high", Mode: GateModeEnforce}, res)
	if len(d.BlockedOn) != 1 || d.BlockedOn[0].Rule != "on-change" {
		t.Errorf("gate must block only on the non-advisory finding, got %+v", d.BlockedOn)
	}
	if !d.Blocked {
		t.Error("expected a block from the one non-advisory high")
	}

	// An advisory-only critical must NOT block.
	only := PipelineResult{Findings: []Finding{{Rule: "x", Severity: "critical", Advisory: true}}}
	if ComputeGate(PipelineConfig{FailOn: "high", Mode: GateModeEnforce}, only).Blocked {
		t.Error("an advisory-only critical must not block the gate")
	}
}
