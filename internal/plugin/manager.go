package plugin

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/relynce/rely-cli/internal/api"
	"github.com/relynce/rely-cli/internal/config"
)

// GetPluginDir returns the installation directory for a given editor's plugin.
func GetPluginDir(editor, version string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	switch editor {
	case "claude":
		return filepath.Join(home, ".claude", "plugins", "cache", "relynce-api", "relynce", version), nil
	case "codex":
		return filepath.Join(home, ".agents", "skills"), nil
	case "gemini":
		return filepath.Join(home, ".gemini"), nil
	case "cursor":
		return filepath.Join(home, ".cursor"), nil
	case "windsurf":
		return filepath.Join(home, ".codeium", "windsurf", "skills"), nil
	case "copilot":
		return filepath.Join(home, ".copilot"), nil
	case "augment":
		return filepath.Join(home, ".augment"), nil
	default:
		return "", fmt.Errorf("unsupported editor: %s (available: claude, codex, gemini, cursor, windsurf, copilot, augment)", editor)
	}
}

// ExtractTarball extracts a tar.gz tarball to the target directory
func ExtractTarball(tarballData []byte, targetDir string) error {
	gzReader, err := gzip.NewReader(bytes.NewReader(tarballData))
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	fileCount := 0

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		targetPath := filepath.Join(targetDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("create parent directory: %w", err)
			}

			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("write file %s: %w", targetPath, err)
			}
			outFile.Close()
			fileCount++
		}
	}

	fmt.Printf("✓ Extracted %d files\n", fileCount)
	return nil
}

// InstallPlugin downloads and installs the Relynce plugin for the specified editor
func InstallPlugin(editor string) error {
	fmt.Printf("Installing Relynce plugin for %s...\n", editor)

	if editor == "claude" {
		if err := CleanupOldClaudeInstallations(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not clean up old installations: %v\n", err)
		}
	}

	cfg, err := config.LoadConfig()
	if err != nil || cfg == nil || cfg.APIKey == "" || cfg.APIURL == "" {
		return fmt.Errorf("no API credentials configured — run 'rely login' first")
	}

	client := &http.Client{Timeout: 60 * time.Second}
	downloadURL := cfg.APIURL + "/api/v1/plugin/download?editor=" + editor

	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	fmt.Printf("Downloading plugin from %s...\n", downloadURL)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download plugin: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Prefer X-Plugin-SemVer header (new servers), fall back to Content-Disposition parsing
	version := resp.Header.Get("X-Plugin-SemVer")
	if version == "" {
		version = resp.Header.Get("X-Plugin-Version")
	}
	if version == "" {
		// Legacy fallback: parse from Content-Disposition filename
		cd := resp.Header.Get("Content-Disposition")
		version = strings.TrimPrefix(cd, "attachment; filename=relynce-plugin-")
		version = strings.TrimPrefix(version, "attachment; filename=polaris-plugin-")
		version = strings.TrimSuffix(version, ".tar.gz")
		version = strings.TrimPrefix(version, editor+"-")
	}
	version = SemVerBase(version)
	checksum := resp.Header.Get("X-Checksum")

	tarballData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read tarball: %w", err)
	}

	if checksum != "" {
		hash := sha256.Sum256(tarballData)
		actualChecksum := "sha256:" + hex.EncodeToString(hash[:])
		if actualChecksum != checksum {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", checksum, actualChecksum)
		}
		fmt.Println("✓ Checksum verified")
	}

	if editor == "claude" {
		return InstallClaudePlugin(version, tarballData)
	}

	targetDir, err := GetPluginDir(editor, version)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("create plugin directory: %w", err)
	}

	fmt.Printf("Extracting to %s...\n", targetDir)
	if err := ExtractTarball(tarballData, targetDir); err != nil {
		return err
	}

	if editor == "gemini" {
		if err := EnableGeminiSubagents(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not enable Gemini subagents: %v\n", err)
		}
	}

	if err := SavePluginInfo(editor, version, targetDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save plugin metadata: %v\n", err)
	}

	PrintPostInstallInstructions(editor, targetDir)

	return nil
}

// UpdatePlugin updates installed plugin(s) to the latest version
func UpdatePlugin(editor string) error {
	if editor == "" {
		plugins, err := GetInstalledPlugins()
		if err != nil {
			return err
		}

		if len(plugins) == 0 {
			fmt.Println("No plugins installed.")
			return nil
		}

		fmt.Printf("Updating %d plugin(s)...\n", len(plugins))
		for _, p := range plugins {
			fmt.Printf("\nUpdating %s plugin...\n", p.Editor)
			if err := InstallPlugin(p.Editor); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", p.Editor, err)
			}
		}
		return nil
	}

	return InstallPlugin(editor)
}

// ListInstalledPlugins lists all installed Relynce plugins
func ListInstalledPlugins() {
	plugins, err := GetInstalledPlugins()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if len(plugins) == 0 {
		fmt.Println("No Relynce plugins installed.")
		fmt.Println("\nTo install:")
		fmt.Println("  rely plugin install <editor>")
		fmt.Println("  Available: claude, codex, gemini, cursor, windsurf, copilot, augment")
		return
	}

	cfg, _ := config.LoadConfig()
	serverVersion := api.FetchServerPluginVersion(cfg)

	fmt.Println("Installed Relynce plugins:")
	for _, p := range plugins {
		fmt.Printf("\n  %s\n", p.Editor)
		fmt.Printf("    Version:   %s\n", p.Version)
		if serverVersion != "" && SemVerNewer(p.Version, serverVersion) {
			fmt.Printf("    Latest:    %s (update available)\n", serverVersion)
		} else if serverVersion != "" {
			fmt.Printf("    Latest:    %s (up to date)\n", serverVersion)
		}
		fmt.Printf("    Installed: %s\n", p.Installed)
		fmt.Printf("    Location:  %s\n", p.Location)
	}

	if serverVersion != "" {
		for _, p := range plugins {
			if SemVerNewer(p.Version, serverVersion) {
				fmt.Printf("\nRun 'rely plugin update' to upgrade.\n")
				break
			}
		}
	}
}

// RemovePlugin removes an installed plugin (all versions)
func RemovePlugin(editor string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	fmt.Printf("Remove Relynce plugin for %s? [y/N] ", editor)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		fmt.Println("Cancelled.")
		return nil
	}

	switch editor {
	case "claude":
		fmt.Println("Uninstalling plugin via Claude Code CLI...")
		cmd := exec.Command("claude", "plugin", "uninstall", "rely@relynce-local")
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: claude plugin uninstall failed: %v\n", err)
			fmt.Println("Attempting manual cleanup...")
		} else {
			fmt.Println(string(output))
		}

		marketplaceDir := filepath.Join(home, ".relynce", "marketplace")
		if err := os.RemoveAll(marketplaceDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove marketplace: %v\n", err)
		} else {
			fmt.Println("✓ Removed local marketplace")
		}

		fmt.Println("Removing marketplace registration...")
		cmd = exec.Command("claude", "plugin", "marketplace", "remove", "relynce-local")
		cmd.Run()

	case "codex":
		skillsDir := filepath.Join(home, ".agents", "skills")
		RemoveSkillDirs(skillsDir)

	case "gemini":
		RemoveSkillDirs(filepath.Join(home, ".gemini", "skills"))
		RemoveAgentFiles(filepath.Join(home, ".gemini", "agents"))

	case "cursor":
		RemoveSkillDirs(filepath.Join(home, ".cursor", "skills"))
		RemoveAgentFiles(filepath.Join(home, ".cursor", "agents"))

	case "windsurf":
		skillsDir := filepath.Join(home, ".codeium", "windsurf", "skills")
		RemoveSkillDirs(skillsDir)

	case "copilot":
		RemoveSkillDirs(filepath.Join(home, ".copilot", "skills"))
		RemoveCopilotAgentFiles(filepath.Join(home, ".copilot", "agents"))

	case "augment":
		RemoveSkillDirs(filepath.Join(home, ".augment", "skills"))
		RemoveAgentFiles(filepath.Join(home, ".augment", "agents"))

	default:
		return fmt.Errorf("unsupported editor: %s", editor)
	}

	metadataFile := filepath.Join(home, ".relynce", "plugins.json")
	_ = RemovePluginFromMetadata(editor, metadataFile)

	fmt.Printf("✓ Removed %s plugin\n", editor)
	return nil
}

// RemoveSkillDirs removes known Relynce skill subdirectories from a base directory
func RemoveSkillDirs(baseDir string) {
	for _, name := range PolarisSkillNames {
		dir := filepath.Join(baseDir, name)
		if _, err := os.Stat(dir); err == nil {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", dir, err)
			}
		}
	}
}

// EnableGeminiSubagents ensures experimental.enableAgents is true in ~/.gemini/settings.json.
func EnableGeminiSubagents() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	settingsPath := filepath.Join(home, ".gemini", "settings.json")

	var settings map[string]any
	if data, err := os.ReadFile(settingsPath); err == nil {
		_ = json.Unmarshal(data, &settings)
	}
	if settings == nil {
		settings = make(map[string]any)
	}

	experimental, ok := settings["experimental"].(map[string]any)
	if !ok {
		experimental = make(map[string]any)
		settings["experimental"] = experimental
	}

	if enabled, ok := experimental["enableAgents"].(bool); ok && enabled {
		return nil
	}

	experimental["enableAgents"] = true

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return err
	}

	fmt.Println("✓ Enabled experimental subagents in ~/.gemini/settings.json")
	return nil
}

// RemoveAgentFiles removes rely-*.md agent files from a directory
func RemoveAgentFiles(agentsDir string) {
	matches, err := filepath.Glob(filepath.Join(agentsDir, "rely-*.md"))
	if err != nil {
		return
	}
	for _, f := range matches {
		if err := os.Remove(f); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", f, err)
		}
	}
}

// RemoveCopilotAgentFiles removes rely-*.agent.md agent files from a directory.
func RemoveCopilotAgentFiles(agentsDir string) {
	matches, err := filepath.Glob(filepath.Join(agentsDir, "rely-*.agent.md"))
	if err != nil {
		return
	}
	for _, f := range matches {
		if err := os.Remove(f); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", f, err)
		}
	}
}

// PrintPostInstallInstructions prints editor-specific next steps
func PrintPostInstallInstructions(editor, location string) {
	fmt.Printf("\n✓ Relynce skills installed for %s\n\n", editor)

	switch editor {
	case "claude":
		fmt.Println("To use the plugin:")
		fmt.Println("  1. Add to your settings.json:")
		fmt.Printf("     \"enabledPlugins\": [\"rely@%s\"]\n\n", location)
		fmt.Println("  2. Or start Claude Code with:")
		fmt.Printf("     claude --plugin-dir %s\n\n", location)
		fmt.Println("Available commands:")
		fmt.Println("  /rely:detect-risks     - Scan for reliability risks")
		fmt.Println("  /rely:analyze-risks    - Analyze detected risks")
		fmt.Println("  /rely:remediate-risks  - Generate remediation plans")
	case "codex":
		fmt.Printf("Skills installed to: %s\n\n", location)
		fmt.Println("Skills are auto-discovered by Codex CLI.")
		fmt.Println("Try: \"scan this codebase for reliability risks\"")
	case "gemini":
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
		fmt.Println("Skills are auto-discovered by Gemini CLI.")
		fmt.Println("Subagents enabled via experimental.enableAgents in ~/.gemini/settings.json")
		fmt.Println("\nNote: Subagents are experimental and run in YOLO mode (no per-tool confirmation).")
		fmt.Println("Try: \"scan this codebase for reliability risks\"")
	case "cursor":
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
		fmt.Println("Skills and agents are auto-discovered by Cursor.")
		fmt.Println("Use /detect-risks or ask naturally.")
	case "windsurf":
		fmt.Printf("Skills installed to: %s\n\n", location)
		fmt.Println("Skills are auto-discovered by Windsurf.")
		fmt.Println("Use @detect-risks or ask Cascade naturally.")
	case "copilot":
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
		fmt.Println("Skills and agents are auto-discovered by Copilot CLI.")
		fmt.Println("Try: \"scan this codebase for reliability risks\"")
	case "augment":
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
		fmt.Println("Skills and agents are auto-discovered by Augment CLI.")
		fmt.Println("Try: \"scan this codebase for reliability risks\"")
	}
}

// CmdPlugin handles plugin management (install, update, list, remove).
func CmdPlugin(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `Usage: rely plugin <command>

Commands:
  install <editor>   Install skills for editor (claude, codex, gemini, cursor, windsurf, copilot, augment)
  update [editor]    Update skills to latest version
  list               List installed skills
  remove <editor>    Remove installed skills

Examples:
  rely plugin install claude    Install Claude Code plugin
  rely plugin install codex     Install Codex CLI skills
  rely plugin install gemini    Install Gemini CLI skills + agents
  rely plugin update            Update all installed plugins
  rely plugin list              Show installed plugins`)
		os.Exit(1)
	}

	switch args[0] {
	case "install":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: editor name required")
			fmt.Fprintln(os.Stderr, "Usage: rely plugin install <editor>")
			fmt.Fprintln(os.Stderr, "Available: claude, codex, gemini, cursor, windsurf, copilot, augment")
			os.Exit(1)
		}
		editor := args[1]
		if err := InstallPlugin(editor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "update":
		editor := ""
		if len(args) >= 2 {
			editor = args[1]
		}
		if err := UpdatePlugin(editor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		ListInstalledPlugins()
	case "remove", "uninstall":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: editor name required")
			fmt.Fprintln(os.Stderr, "Usage: rely plugin remove <editor>")
			os.Exit(1)
		}
		editor := args[1]
		if err := RemovePlugin(editor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown plugin command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: rely plugin <install|update|list|remove>")
		os.Exit(1)
	}
}

// IsEditorAvailable checks if the given CLI binary is on the PATH.
func IsEditorAvailable(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}
