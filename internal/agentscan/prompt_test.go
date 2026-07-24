package agentscan

import (
	"strings"
	"testing"
)

const fixtureDiff = `diff --git a/internal/pay/charge.go b/internal/pay/charge.go
index 1a2b3c4..5d6e7f8 100644
--- a/internal/pay/charge.go
+++ b/internal/pay/charge.go
@@ -10,7 +10,7 @@ func Charge(amount int) error {
 	if err := gateway.Submit(amount); err != nil {
-		return err
+		return nil // retry later
 	}
 	return nil
 }`

func fixtureChangeSet() ChangeSet {
	return ChangeSet{
		Diff: fixtureDiff,
		Files: []ChangedFile{
			{Path: "internal/pay/charge.go", Kind: ChangeModified},
			{Path: "internal/pay/refund.go", OldPath: "internal/pay/refund_legacy.go", Kind: ChangeRenamed},
			{Path: "internal/pay/receipt.go", Kind: ChangeAdded},
			{Path: "internal/pay/deprecated.go", Kind: ChangeDeleted},
		},
		BaseDesc: "staged",
	}
}

const fixtureSnapshotDir = "/tmp/rvl-agentscan-snapshot-12345"

// mustContain asserts each needle appears in the rendered prompt.
func mustContain(t *testing.T, prompt string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(prompt, n) {
			t.Errorf("prompt missing %q\n---\n%s", n, prompt)
		}
	}
}

func TestRenderPromptAllBuiltinLenses(t *testing.T) {
	cs := fixtureChangeSet()
	for _, l := range BuiltinLenses() {
		t.Run(l.ID, func(t *testing.T) {
			prompt, err := RenderPrompt(l, cs, fixtureSnapshotDir)
			if err != nil {
				t.Fatalf("RenderPrompt(%s): %v", l.ID, err)
			}

			// Lens identity and charter.
			mustContain(t, prompt, l.Name, l.Focus)

			// The unified diff is inlined verbatim.
			mustContain(t, prompt, fixtureDiff)

			// Every vocabulary slug is rendered; the rule value must come
			// from this closed list.
			for _, slug := range l.RuleVocab {
				mustContain(t, prompt, slug)
			}

			// Changed-file list with change kinds, including the rename origin.
			mustContain(t, prompt,
				"internal/pay/charge.go",
				"internal/pay/receipt.go",
				string(ChangeModified),
				string(ChangeAdded),
				"internal/pay/refund_legacy.go",
			)

			// Deleted files listed, with the never-read instruction.
			mustContain(t, prompt,
				"internal/pay/deprecated.go",
				"never be read",
			)

			// Snapshot directory note.
			mustContain(t, prompt, fixtureSnapshotDir)

			// Strict-scope contract sentences (spec: Lenses and templates;
			// these produced the measured 60s result).
			mustContain(t, prompt,
				"ONLY risks introduced or worsened",
				"at most once",
			)

			// JSON output contract.
			mustContain(t, prompt,
				`{"findings":[{"rule":`,
				`"severity":"critical|high|medium|low"`,
				`"summary":"one sentence"`,
				"Output ONLY a single JSON object",
				"will be dropped",
			)
		})
	}
}

func TestRenderPromptForbidsExploration(t *testing.T) {
	l, ok := LensByID(LensGeneral)
	if !ok {
		t.Fatal("general lens missing")
	}
	prompt, err := RenderPrompt(l, fixtureChangeSet(), fixtureSnapshotDir)
	if err != nil {
		t.Fatal(err)
	}
	// The prompt must confine the agent to the change set: it may read the
	// listed changed files in the snapshot, and MUST NOT explore anything else.
	mustContain(t, prompt, "MUST NOT explore")
	if strings.Contains(prompt, "read callers if needed") {
		t.Error("prompt contains loose-scope language from the rejected experiment variant")
	}
}

func TestRenderPromptNoDeletions(t *testing.T) {
	cs := ChangeSet{
		Diff: "diff --git a/a.go b/a.go\n+// hi",
		Files: []ChangedFile{
			{Path: "a.go", Kind: ChangeModified},
		},
		BaseDesc: "main...HEAD",
	}
	l, _ := LensByID(LensObservability)
	prompt, err := RenderPrompt(l, cs, "/tmp/snap")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "Deleted files") {
		t.Error("prompt renders a deleted-files section for a change set with no deletions")
	}
	mustContain(t, prompt, "main...HEAD")
}

func TestRenderPromptEmptyBaseDesc(t *testing.T) {
	cs := ChangeSet{
		Diff:  "diff --git a/a.go b/a.go\n+// hi",
		Files: []ChangedFile{{Path: "a.go", Kind: ChangeModified}},
	}
	l, _ := LensByID(LensGeneral)
	prompt, err := RenderPrompt(l, cs, "/tmp/snap")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "()") {
		t.Error("empty BaseDesc rendered as empty parens")
	}
}
