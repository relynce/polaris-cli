package plugin

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/project"
)

// AGENTS.md shares the managed-block markers with CLAUDE.md (claudemd.go) so
// both files can be maintained with the same marker-based replace strategy.
const (
	agentsMdBlockStart = claudeMdBlockStart
	agentsMdBlockEnd   = claudeMdBlockEnd

	// legacyAgentsMdHeading is the section heading written by older versions
	// of `rvl init` before managed-block markers existed. EnsureAgentsMd
	// migrates such sections in place instead of appending a duplicate.
	legacyAgentsMdHeading = "## Revelara"
)

// AgentsMdState values returned by AgentsMdState.
const (
	AgentsMdStateMissing   = "missing"   // AGENTS.md does not exist
	AgentsMdStateUnmanaged = "unmanaged" // exists, but has no Revelara block or section
	AgentsMdStateManaged   = "managed"   // has a managed block (or legacy Revelara section)
)

// agentsMdTemplate is the editor-agnostic Revelara block written into
// AGENTS.md. AGENTS.md is read natively by most agent runtimes, so this
// content must not assume any specific editor or agent capability beyond
// running shell commands.
const agentsMdTemplate = `## Revelara

This project uses Revelara for reliability risk analysis. When making design
or implementation decisions that affect reliability (error handling, retries,
timeouts, deployments, data integrity, observability), consult the Revelara
context below and ground the decision in real risk and incident data.

### Context Tools (rvl CLI)

Add ` + "`--format=json`" + ` to any of these for machine-readable output.

**Risks:**
- ` + "`rvl risk list --service=<service>`" + ` — current risks for a service
- ` + "`rvl risk show R-XXX`" + ` — full risk details with mapped controls
- ` + "`rvl risk context R-XXX --format=json`" + ` — risk + controls + knowledge + incidents
- ` + "`rvl risk ready --service=<service>`" + ` — risks ready to remediate (no blockers)

**Controls:**
- ` + "`rvl control list --limit=100`" + ` — reliability controls catalog
- ` + "`rvl control show RC-XXX`" + ` — control details and evidence status

**Knowledge:**
- ` + "`rvl knowledge search \"<query>\" --limit=5`" + ` — search incidents and patterns
- ` + "`rvl knowledge enrich --query=\"<query>\"`" + ` — enriched context with patterns and procedures

**Evidence & Resolution:**
- ` + "`rvl evidence submit --control=RC-XXX --type=code --name=\"...\" --url=\"...\" --description=\"...\"`" + ` — record implementation evidence
- ` + "`rvl risk resolve R-XXX --reason=\"...\"`" + ` — mark a risk as resolved

### Skills

Where your coding agent supports skills or slash commands, the following are
available after ` + "`rvl plugin install`" + `:

- ` + "`/rvl:scan`" + ` — scan the codebase for reliability risks
- ` + "`/rvl:fix R-XXX`" + ` — guided remediation for a specific risk
- ` + "`/rvl:ask \"question\"`" + ` — ask a reliability question to a domain expert
- ` + "`/rvl:risks`" + ` — view risk posture, open risks, and ready-to-fix items
- ` + "`/rvl:review`" + ` — review code changes for reliability issues
- ` + "`/rvl:evidence RC-XXX`" + ` — submit evidence after implementing a control
- ` + "`/rvl:status`" + ` — check connection and configuration

Agents without slash commands auto-discover the same skills; ask naturally,
e.g. "scan this codebase for reliability risks".
`

// agentsMdManagedBlock returns the full managed block (markers included).
func agentsMdManagedBlock() string {
	return agentsMdBlockStart + "\n" + strings.TrimSpace(agentsMdTemplate) + "\n" + agentsMdBlockEnd + "\n"
}

// AgentsMdState reports the state of AGENTS.md in gitRoot: missing, unmanaged
// (exists without a Revelara block), or managed (has a managed block or a
// legacy "## Revelara" section).
func AgentsMdState(gitRoot string) string {
	content, err := os.ReadFile(filepath.Join(gitRoot, "AGENTS.md"))
	if err != nil {
		return AgentsMdStateMissing
	}
	contentStr := string(content)
	if strings.Contains(contentStr, agentsMdBlockStart) || hasLegacyAgentsMdSection(contentStr) {
		return AgentsMdStateManaged
	}
	return AgentsMdStateUnmanaged
}

// hasLegacyAgentsMdSection reports whether the content contains a pre-marker
// "## Revelara" heading on its own line.
func hasLegacyAgentsMdSection(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == legacyAgentsMdHeading {
			return true
		}
	}
	return false
}

// EnsureAgentsMd creates or updates the project AGENTS.md with a managed
// Revelara block, mirroring EnsureClaudeMd's marker-based replace strategy.
// Legacy "## Revelara" sections written by older `rvl init` versions are
// migrated in place. If yesAll is false and AGENTS.md exists without any
// Revelara content, the file is left untouched (callers prompt first).
//
// Returns the action taken: "created", "appended", "updated", or "skipped".
func EnsureAgentsMd(gitRoot string, yesAll bool) (string, error) {
	managedBlock := agentsMdManagedBlock()
	agentsMdPath := filepath.Join(gitRoot, "AGENTS.md")

	content, err := os.ReadFile(agentsMdPath)
	if os.IsNotExist(err) {
		if err := os.WriteFile(agentsMdPath, []byte(managedBlock), 0644); err != nil {
			return "", err
		}
		return "created", nil
	}
	if err != nil {
		return "", err
	}

	contentStr := string(content)

	if strings.Contains(contentStr, agentsMdBlockStart) {
		if !strings.Contains(contentStr, agentsMdBlockEnd) {
			return "skipped", fmt.Errorf("AGENTS.md has start marker but no end marker — manual fix needed")
		}

		startIdx := strings.Index(contentStr, agentsMdBlockStart)
		endIdx := strings.Index(contentStr, agentsMdBlockEnd) + len(agentsMdBlockEnd)
		// Include trailing newline if present
		if endIdx < len(contentStr) && contentStr[endIdx] == '\n' {
			endIdx++
		}

		updatedContent := contentStr[:startIdx] + managedBlock + contentStr[endIdx:]
		if updatedContent == contentStr {
			// Block already current — still report "updated" for parity with
			// EnsureClaudeMd, but avoid rewriting the file.
			return "updated", nil
		}
		if err := os.WriteFile(agentsMdPath, []byte(updatedContent), 0644); err != nil {
			return "", err
		}
		return "updated", nil
	}

	if hasLegacyAgentsMdSection(contentStr) {
		updatedContent := replaceLegacyAgentsMdSection(contentStr, managedBlock)
		if err := os.WriteFile(agentsMdPath, []byte(updatedContent), 0644); err != nil {
			return "", err
		}
		return "updated", nil
	}

	// AGENTS.md exists with no Revelara content — append only when allowed.
	if !yesAll {
		return "skipped", nil
	}

	updatedContent := contentStr
	if !strings.HasSuffix(contentStr, "\n") {
		updatedContent += "\n"
	}
	updatedContent += "\n" + managedBlock
	if err := os.WriteFile(agentsMdPath, []byte(updatedContent), 0644); err != nil {
		return "", err
	}
	return "appended", nil
}

// replaceLegacyAgentsMdSection replaces the legacy "## Revelara" section
// (from its heading up to the next level-2 heading or EOF) with the managed
// block. Level-3+ subheadings ("### ...") belong to the section.
func replaceLegacyAgentsMdSection(content, managedBlock string) string {
	lines := strings.Split(content, "\n")
	var out []string
	inSection := false
	replaced := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !replaced && trimmed == legacyAgentsMdHeading {
			inSection = true
			replaced = true
			out = append(out, strings.TrimSuffix(managedBlock, "\n"))
			continue
		}
		if inSection {
			if strings.HasPrefix(trimmed, "## ") && !strings.HasPrefix(trimmed, "###") {
				inSection = false
				out = append(out, line)
			}
			continue
		}
		out = append(out, line)
	}

	updated := strings.Join(out, "\n")
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	return updated
}

// EnsureAgentsMdForInstall installs or updates the managed AGENTS.md block in
// the git repository containing startDir (empty means the current directory).
// When startDir is not inside a git repo, it prints a notice to out and skips.
//
// Returns the action taken: "created", "appended", "updated", or "skipped".
func EnsureAgentsMdForInstall(startDir string, out io.Writer) (string, error) {
	gitRoot := project.DetectGitRootFrom(startDir)
	if gitRoot == "" {
		fmt.Fprintln(out, "Note: not inside a git repository — skipping AGENTS.md setup (run this from your project, or run 'rvl init' there)")
		return "skipped", nil
	}
	return EnsureAgentsMd(gitRoot, true)
}
