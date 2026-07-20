package plugin

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	claudeMdBlockStart    = "<!-- BEGIN REVELARA MANAGED BLOCK - DO NOT EDIT -->"
	claudeMdBlockEnd      = "<!-- END REVELARA MANAGED BLOCK -->"
	claudeMdBlockStartOld = "<!-- BEGIN RELYNCE MANAGED BLOCK - DO NOT EDIT -->"
	claudeMdBlockEndOld   = "<!-- END RELYNCE MANAGED BLOCK -->"
)

// claudeMdExtrasTemplate holds the Claude-specific additions to the shared
// context block: expert-agent routing via the Task tool, which agent-neutral
// AGENTS.md must not mention (see TestAgentsMdTemplate_NoInternalCodename).
//
//go:embed claudemd_extras.md
var claudeMdExtrasTemplate string

// installedTemplate returns the named context-file template from the
// installed Claude plugin content (~/.revelara/marketplace/plugins/revelara),
// or "" when no served copy is available. The served copy is authoritative:
// the backend single-sources both templates as versioned plugin content, so
// context wording ships with plugin updates and stays loosely coupled to CLI
// releases (po-pw4p6). The baked-in templates are the offline fallback for
// installs without plugin content on disk.
func installedTemplate(name string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".revelara", "marketplace", "plugins", "revelara", name))
	if err != nil || len(strings.TrimSpace(string(b))) == 0 {
		return ""
	}
	return string(b)
}

// claudeMdTemplate is the CLAUDE.md block body: the backend-served template
// when installed, else the fallback composition of the agent-neutral
// AGENTS.md template plus the Claude-specific extras. The fallback mirrors
// the backend's own composition (single shared source, po-pw4p6).
func claudeMdTemplate() string {
	if served := installedTemplate("CLAUDE.md"); served != "" {
		return strings.TrimSpace(served)
	}
	return strings.TrimSpace(agentsMdTemplate) + "\n\n" + strings.TrimSpace(claudeMdExtrasTemplate)
}

// EnsureClaudeMd creates or updates the project CLAUDE.md with a managed Revelara block.
// If yesAll is true, all prompts are auto-accepted.
//
// Returns the action taken: "created", "appended", "updated", or "skipped".
func EnsureClaudeMd(gitRoot string, yesAll bool) (string, error) {
	managedBlock := claudeMdBlockStart + "\n" + claudeMdTemplate() + "\n" + claudeMdBlockEnd + "\n"

	claudeMdPath := filepath.Join(gitRoot, "CLAUDE.md")
	content, err := os.ReadFile(claudeMdPath)

	if os.IsNotExist(err) {
		// No CLAUDE.md — create with just the managed block
		if err := os.WriteFile(claudeMdPath, []byte(managedBlock), 0644); err != nil {
			return "", err
		}
		return "created", nil
	}

	if err != nil {
		return "", err
	}

	contentStr := string(content)

	// Detect start marker: try new name first, then old name
	hasStartMarker := strings.Contains(contentStr, claudeMdBlockStart)
	hasEndMarker := strings.Contains(contentStr, claudeMdBlockEnd)
	hasOldStartMarker := strings.Contains(contentStr, claudeMdBlockStartOld)
	hasOldEndMarker := strings.Contains(contentStr, claudeMdBlockEndOld)

	// If old markers are present but new ones aren't, migrate them
	if !hasStartMarker && hasOldStartMarker {
		hasStartMarker = true
		hasEndMarker = hasOldEndMarker
		// Replace old markers with new ones in content before processing
		contentStr = strings.Replace(contentStr, claudeMdBlockStartOld, claudeMdBlockStart, 1)
		contentStr = strings.Replace(contentStr, claudeMdBlockEndOld, claudeMdBlockEnd, 1)
	}

	if !hasStartMarker {
		// CLAUDE.md exists but no managed block — append
		if !yesAll {
			// In non-interactive mode from plugin install, skip prompting
			return "skipped", nil
		}

		updatedContent := contentStr
		if !strings.HasSuffix(contentStr, "\n") {
			updatedContent += "\n"
		}
		updatedContent += "\n" + managedBlock
		if err := os.WriteFile(claudeMdPath, []byte(updatedContent), 0644); err != nil {
			return "", err
		}
		return "appended", nil
	}

	// Has start marker — replace the managed block
	if !hasEndMarker {
		// Malformed: has start but no end. Append end marker after the block.
		return "skipped", fmt.Errorf("CLAUDE.md has start marker but no end marker — manual fix needed")
	}

	// Replace content between markers
	startIdx := strings.Index(contentStr, claudeMdBlockStart)
	endIdx := strings.Index(contentStr, claudeMdBlockEnd) + len(claudeMdBlockEnd)

	// Include trailing newline if present
	if endIdx < len(contentStr) && contentStr[endIdx] == '\n' {
		endIdx++
	}

	updatedContent := contentStr[:startIdx] + managedBlock + contentStr[endIdx:]
	if err := os.WriteFile(claudeMdPath, []byte(updatedContent), 0644); err != nil {
		return "", err
	}
	return "updated", nil
}
