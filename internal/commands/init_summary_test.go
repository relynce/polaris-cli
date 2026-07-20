package commands

import (
	"strings"
	"testing"

	"github.com/revelara-ai/rvl-cli/internal/project"
)

func summaryOutput(t *testing.T, agentsMdAction, claudeMdAction string) string {
	t.Helper()
	cfg := &project.ProjectConfig{Project: "demo"}
	var sb strings.Builder
	printInitSummary(&sb, cfg, true, "1.0.0", true, agentsMdAction, claudeMdAction)
	return sb.String()
}

// po-dhtnw: the completion summary reported AGENTS.md but was silent about
// CLAUDE.md, even when init created it from scratch.
func TestInitSummary_ReportsClaudeMdAction(t *testing.T) {
	out := summaryOutput(t, "created", "created")
	if !strings.Contains(out, "AGENTS.md: created") {
		t.Errorf("summary missing AGENTS.md line:\n%s", out)
	}
	if !strings.Contains(out, "CLAUDE.md: created") {
		t.Errorf("summary missing CLAUDE.md line:\n%s", out)
	}
}

func TestInitSummary_OmitsClaudeMdWhenSkippedOrAbsent(t *testing.T) {
	for _, action := range []string{"", "skipped"} {
		out := summaryOutput(t, "created", action)
		if strings.Contains(out, "CLAUDE.md:") {
			t.Errorf("summary should not report CLAUDE.md for action %q:\n%s", action, out)
		}
	}
}

// The commit hint should list every context file init actually wrote.
func TestInitSummary_CommitHintIncludesWrittenFiles(t *testing.T) {
	out := summaryOutput(t, "created", "created")
	if !strings.Contains(out, "Commit .revelara.yaml, AGENTS.md, and CLAUDE.md") {
		t.Errorf("commit hint should list CLAUDE.md when it was written:\n%s", out)
	}

	out = summaryOutput(t, "created", "")
	if !strings.Contains(out, "Commit .revelara.yaml and AGENTS.md") {
		t.Errorf("commit hint should fall back to AGENTS.md only:\n%s", out)
	}
	if strings.Contains(out, "CLAUDE.md") {
		t.Errorf("commit hint should not mention CLAUDE.md when nothing was written:\n%s", out)
	}
}
