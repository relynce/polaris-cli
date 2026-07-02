package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/project"
)

// CleanupOldClaudeInstallations removes old Revelara installations from Claude Code directories
func CleanupOldClaudeInstallations() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	// Remove old commands from ~/.claude/commands/polaris/
	oldCommandsDir := filepath.Join(home, ".claude", "commands", "polaris")
	if _, err := os.Stat(oldCommandsDir); err == nil {
		fmt.Printf("Removing old Revelara commands from %s...\n", oldCommandsDir)
		if err := os.RemoveAll(oldCommandsDir); err != nil {
			return fmt.Errorf("remove old commands: %w", err)
		}
		fmt.Println("✓ Removed old commands")
	}

	return nil
}

// InstallClaudePlugin installs the plugin using Claude Code's local marketplace mechanism
func InstallClaudePlugin(version string, tarballData []byte, opts InstallOptions) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	// Create local marketplace structure at ~/.revelara/marketplace
	marketplaceDir := filepath.Join(home, ".revelara", "marketplace")
	pluginDir := filepath.Join(marketplaceDir, "plugins", "revelara")

	// Clean up existing installation
	if err := os.RemoveAll(marketplaceDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clean up old marketplace: %w", err)
	}

	// Create plugin directory
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("create plugin directory: %w", err)
	}

	// Extract plugin to local marketplace
	fmt.Printf("Setting up local marketplace at %s...\n", marketplaceDir)
	if err := ExtractTarball(tarballData, pluginDir); err != nil {
		return fmt.Errorf("extract plugin: %w", err)
	}

	// Create marketplace.json
	marketplaceJSON := fmt.Sprintf(`{
  "$schema": "https://anthropic.com/claude-code/marketplace.schema.json",
  "name": "revelara-local",
  "description": "Revelara plugin for reliability risk analysis",
  "owner": {
    "name": "Revelara",
    "email": "team@revelara.ai"
  },
  "plugins": [
    {
      "name": "revelara",
      "version": "%s",
      "description": "Reliability risk analysis and incident prevention for engineering teams",
      "author": {
        "name": "Revelara",
        "email": "team@revelara.ai"
      },
      "source": "./plugins/revelara",
      "category": "development",
      "homepage": "https://docs.revelara.ai"
    }
  ]
}`, version)

	marketplaceManifestDir := filepath.Join(marketplaceDir, ".claude-plugin")
	if err := os.MkdirAll(marketplaceManifestDir, 0755); err != nil {
		return fmt.Errorf("create marketplace manifest directory: %w", err)
	}

	marketplaceManifestPath := filepath.Join(marketplaceManifestDir, "marketplace.json")
	if err := os.WriteFile(marketplaceManifestPath, []byte(marketplaceJSON), 0644); err != nil {
		return fmt.Errorf("write marketplace manifest: %w", err)
	}

	fmt.Println("✓ Created local marketplace")

	// Remove old marketplace if it exists
	fmt.Println("Removing old Revelara marketplace (if exists)...")
	cmd := exec.Command("claude", "plugin", "marketplace", "remove", "revelara-local")
	cmd.Run() // Ignore error - marketplace might not exist

	// Add marketplace using claude CLI
	fmt.Println("Registering marketplace with Claude Code...")
	cmd = exec.Command("claude", "plugin", "marketplace", "add", marketplaceDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("add marketplace: %w\nOutput: %s", err, string(output))
	}
	fmt.Println("✓ Marketplace registered")

	// Install plugin using claude CLI
	fmt.Println("Installing plugin...")
	cmd = exec.Command("claude", "plugin", "install", "revelara@revelara-local")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install plugin: %w\nOutput: %s", err, string(output))
	}
	fmt.Println("✓ Plugin installed")

	// Prune stale version directories left by previous installs. Claude Code's
	// `plugin install` creates a new versioned directory each time but never
	// removes old ones, which can cause outdated skill files to be loaded
	// alongside the current version.
	if err := pruneOldCacheVersions(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not prune old plugin cache versions: %v\n", err)
	}

	// Save metadata for polaris CLI tracking
	if err := SavePluginInfo("claude", version, pluginDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save plugin metadata: %v\n", err)
	}

	// Install CLAUDE.md managed block if we're in a git repo
	// (AGENTS.md is handled centrally by InstallPluginWithOptions for all editors)
	if gitRoot := project.DetectGitRoot(); gitRoot != "" && !opts.SkipContextFiles {
		claudeMdSrc := filepath.Join(pluginDir, "CLAUDE.md")
		if _, err := os.Stat(claudeMdSrc); err == nil {
			action, err := EnsureClaudeMd(gitRoot, claudeMdSrc, true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not set up CLAUDE.md: %v\n", err)
			} else if action != "skipped" {
				fmt.Printf("✓ CLAUDE.md: %s\n", action)
			}
		}
	}

	fmt.Printf("\n✅ Revelara plugin successfully installed!\n")
	fmt.Printf("Commands are now available: /rvl:scan, /rvl:fix, /rvl:ask, etc.\n")
	fmt.Printf("\nRestart Claude Code to ensure all commands are loaded.\n")

	return nil
}

// pruneOldCacheVersions removes stale versioned directories from the plugin
// cache, keeping only the version that Claude Code's registry currently points
// to. It reads ~/.claude/plugins/installed_plugins.json to find the active
// installPath, then deletes all sibling directories under the same parent.
func pruneOldCacheVersions() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	registryFile := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	data, err := os.ReadFile(registryFile)
	if err != nil {
		return fmt.Errorf("read installed_plugins.json: %w", err)
	}

	var reg struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(data, &reg); err != nil {
		return fmt.Errorf("parse installed_plugins.json: %w", err)
	}

	// Find the active installPath for the revelara plugin (key may be
	// revelara@revelara-local or rvl@revelara-api depending on install path).
	var activePath string
	for _, entries := range reg.Plugins {
		for _, e := range entries {
			if filepath.Base(filepath.Dir(e.InstallPath)) == "revelara" {
				activePath = e.InstallPath
				break
			}
		}
		if activePath != "" {
			break
		}
	}
	if activePath == "" {
		return fmt.Errorf("revelara plugin not found in installed_plugins.json")
	}

	// Parent is e.g. ~/.claude/plugins/cache/revelara-local/revelara/
	cacheParent := filepath.Dir(activePath)
	activeVersion := filepath.Base(activePath)

	entries, err := os.ReadDir(cacheParent)
	if err != nil {
		return fmt.Errorf("read cache directory: %w", err)
	}

	var pruned []string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == activeVersion {
			continue
		}
		stale := filepath.Join(cacheParent, entry.Name())
		if removeErr := os.RemoveAll(stale); removeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove stale cache version %s: %v\n", entry.Name(), removeErr)
		} else {
			pruned = append(pruned, entry.Name())
		}
	}

	if len(pruned) > 0 {
		fmt.Printf("✓ Pruned %d stale cache version(s): %v\n", len(pruned), pruned)
	}
	return nil
}

// RegisterWithClaudeCode updates ~/.claude/plugins/installed_plugins.json
func RegisterWithClaudeCode(version, installPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	registryFile := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")

	// Load existing registry
	type pluginEntry struct {
		Scope        string `json:"scope"`
		InstallPath  string `json:"installPath"`
		Version      string `json:"version"`
		InstalledAt  string `json:"installedAt"`
		LastUpdated  string `json:"lastUpdated"`
		Enabled      bool   `json:"enabled"`
		GitCommitSha string `json:"gitCommitSha,omitempty"`
	}

	type registry struct {
		Version int                      `json:"version"`
		Plugins map[string][]pluginEntry `json:"plugins"`
	}

	var reg registry
	if data, err := os.ReadFile(registryFile); err == nil {
		_ = json.Unmarshal(data, &reg)
	}

	// Initialize if empty
	if reg.Version == 0 {
		reg.Version = 2
	}
	if reg.Plugins == nil {
		reg.Plugins = make(map[string][]pluginEntry)
	}

	// Add or update polaris plugin entry
	now := time.Now().Format(time.RFC3339)
	entry := pluginEntry{
		Scope:       "user",
		InstallPath: installPath,
		Version:     version,
		InstalledAt: now,
		LastUpdated: now,
		Enabled:     true,
	}

	// Use key format: plugin@source
	key := "rvl@revelara-api"
	reg.Plugins[key] = []pluginEntry{entry}

	// Save registry
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(registryFile, data, 0644); err != nil {
		return err
	}

	// Also enable plugin in settings.json
	return EnablePluginInSettings(key)
}

// EnablePluginInSettings enables the plugin in ~/.claude/settings.json
func EnablePluginInSettings(pluginKey string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	settingsFile := filepath.Join(home, ".claude", "settings.json")

	var settings map[string]interface{}
	if data, err := os.ReadFile(settingsFile); err == nil {
		_ = json.Unmarshal(data, &settings)
	}

	if settings == nil {
		settings = make(map[string]interface{})
	}

	enabledPlugins, ok := settings["enabledPlugins"].(map[string]interface{})
	if !ok {
		enabledPlugins = make(map[string]interface{})
		settings["enabledPlugins"] = enabledPlugins
	}

	enabledPlugins[pluginKey] = true

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsFile, data, 0644)
}

// DisablePluginInSettings disables the plugin in ~/.claude/settings.json
func DisablePluginInSettings(pluginKey string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	settingsFile := filepath.Join(home, ".claude", "settings.json")

	var settings map[string]interface{}
	if data, err := os.ReadFile(settingsFile); err == nil {
		_ = json.Unmarshal(data, &settings)
	}

	if settings == nil {
		return nil
	}

	enabledPlugins, ok := settings["enabledPlugins"].(map[string]interface{})
	if !ok {
		return nil
	}

	delete(enabledPlugins, pluginKey)

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsFile, data, 0644)
}

// removeClaudePlugin handles the entire removal flow for Claude Code.
// It runs the claude CLI uninstall, removes the marketplace, and deregisters.
func removeClaudePlugin(home string) error {
	fmt.Println("Uninstalling plugin via Claude Code CLI...")
	cmd := exec.Command("claude", "plugin", "uninstall", "rvl@revelara-local")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: claude plugin uninstall failed: %v\n", err)
		fmt.Println("Attempting manual cleanup...")
	} else {
		fmt.Println(string(output))
	}

	marketplaceDir := filepath.Join(home, ".revelara", "marketplace")
	if err := os.RemoveAll(marketplaceDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not remove marketplace: %v\n", err)
	} else {
		fmt.Println("✓ Removed local marketplace")
	}

	fmt.Println("Removing marketplace registration...")
	cmd = exec.Command("claude", "plugin", "marketplace", "remove", "revelara-local")
	cmd.Run()

	return nil
}

// UnregisterFromClaudeCode removes polaris from ~/.claude/plugins/installed_plugins.json
func UnregisterFromClaudeCode() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	registryFile := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")

	type pluginEntry struct {
		Scope        string `json:"scope"`
		InstallPath  string `json:"installPath"`
		Version      string `json:"version"`
		InstalledAt  string `json:"installedAt"`
		LastUpdated  string `json:"lastUpdated"`
		GitCommitSha string `json:"gitCommitSha,omitempty"`
	}

	type registry struct {
		Version int                      `json:"version"`
		Plugins map[string][]pluginEntry `json:"plugins"`
	}

	var reg registry
	if data, err := os.ReadFile(registryFile); err == nil {
		_ = json.Unmarshal(data, &reg)
	}

	if reg.Plugins == nil {
		return nil
	}

	key := "rvl@revelara-api"
	delete(reg.Plugins, key)

	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(registryFile, data, 0644); err != nil {
		return err
	}

	return DisablePluginInSettings(key)
}
