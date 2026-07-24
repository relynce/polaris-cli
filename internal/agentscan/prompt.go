package agentscan

import (
	"embed"
	"fmt"
	"strings"
	"text/template"
)

//go:embed templates/scan.md
var templateFS embed.FS

// scanTemplate is the shared base template for every lens; per-lens
// content (Focus, RuleVocab) is injected at render time (spec: Lenses
// and templates). The strict-scope contract encoded in the template -
// diff inlined, Read only the listed changed files in the snapshot, no
// exploration, minimal turns - is what produced the measured ~60s scan;
// loosening it is a behavior change, not a wording tweak.
var scanTemplate = template.Must(template.ParseFS(templateFS, "templates/scan.md"))

// promptData is the render context for the scan template.
type promptData struct {
	Lens        Lens
	SnapshotDir string
	BaseDesc    string
	Present     []ChangedFile
	Deleted     []string
	Diff        string
}

// RenderPrompt renders the lens prompt for a change set. snapshotDir is
// the staged-snapshot directory the agent will run in (its cwd); the
// prompt confines all reads to the changed files inside it.
func RenderPrompt(l Lens, cs ChangeSet, snapshotDir string) (string, error) {
	baseDesc := cs.BaseDesc
	if baseDesc == "" {
		baseDesc = "change set"
	}
	data := promptData{
		Lens:        l,
		SnapshotDir: snapshotDir,
		BaseDesc:    baseDesc,
		Present:     cs.Present(),
		Deleted:     cs.Deleted(),
		Diff:        cs.Diff,
	}
	var sb strings.Builder
	if err := scanTemplate.Execute(&sb, data); err != nil {
		return "", fmt.Errorf("render %s lens prompt: %w", l.ID, err)
	}
	return sb.String(), nil
}
