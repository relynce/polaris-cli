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
	"sort"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/config"
	"github.com/revelara-ai/rvl-cli/internal/project"
)

// GetPluginDir returns the installation directory for a given editor's plugin.
func GetPluginDir(editor, version string) (string, error) {
	def, ok := Registry[editor]
	if !ok {
		return "", fmt.Errorf("unsupported editor: %s (available: %s)", editor, EditorNames())
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	if def.InstallDir == "" {
		// Claude uses a version-dependent path (legacy compat)
		return filepath.Join(home, ".claude", "plugins", "cache", "revelara-api", "revelara", version), nil
	}

	return filepath.Join(home, def.InstallDir), nil
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

		// Prevent path traversal: ensure extracted path stays within targetDir
		cleanTarget := filepath.Clean(targetPath)
		if !strings.HasPrefix(cleanTarget, filepath.Clean(targetDir)+string(os.PathSeparator)) && cleanTarget != filepath.Clean(targetDir) {
			return fmt.Errorf("invalid file path in tarball (path traversal): %s", header.Name)
		}

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
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("close file %s: %w", targetPath, err)
			}
			fileCount++
		}
	}

	fmt.Printf("✓ Extracted %d files\n", fileCount)
	return nil
}

// detectProjectRoot returns the project root directory.
// Uses git root if available, otherwise the current working directory.
func detectProjectRoot() (string, error) {
	root := project.DetectGitRoot()
	if root != "" {
		return root, nil
	}
	return os.Getwd()
}

// extractFlag removes a flag from an argument list and returns whether it was present.
func extractFlag(args []string, flag string) ([]string, bool) {
	var filtered []string
	found := false
	for _, a := range args {
		if a == flag {
			found = true
		} else {
			filtered = append(filtered, a)
		}
	}
	return filtered, found
}

// InstallOptions controls optional plugin install/update behavior.
type InstallOptions struct {
	// SkipContextFiles skips writing the managed CLAUDE.md and AGENTS.md
	// blocks into the current git repository (--no-context-files).
	SkipContextFiles bool
}

// installContextFiles runs the post-install context-file step: it installs or
// updates the managed AGENTS.md block in the git repository containing
// startDir. Skipped silently when opts.SkipContextFiles is set — callers that
// own the skip (the --no-context-files flag, or rvl init's interactive
// Steps 4/5) report it themselves. Failures are warnings — the plugin itself
// installed fine.
func installContextFiles(startDir string, opts InstallOptions, out io.Writer) {
	if opts.SkipContextFiles {
		return
	}
	action, err := EnsureAgentsMdForInstall(startDir, out)
	if err != nil {
		fmt.Fprintf(out, "Warning: could not set up AGENTS.md: %v\n", err)
		return
	}
	if action != "skipped" {
		fmt.Fprintf(out, "✓ AGENTS.md: %s\n", action)
	}
}

// InstallPlugin downloads and installs the Revelara plugin for the specified editor.
// If projectRoot is non-empty, installs to projectRoot/LocalDir (project-local).
func InstallPlugin(editor, projectRoot string) error {
	return InstallPluginWithOptions(editor, projectRoot, InstallOptions{})
}

// InstallPluginWithOptions is InstallPlugin with explicit install options.
func InstallPluginWithOptions(editor, projectRoot string, opts InstallOptions) error {
	def, ok := Registry[editor]
	if !ok {
		return fmt.Errorf("unsupported editor: %s (available: %s)", editor, EditorNames())
	}

	isProject := projectRoot != ""

	if isProject {
		if def.LocalDir == "" {
			return fmt.Errorf("--project not supported for %s", editor)
		}
		if def.CustomInstall != nil {
			return fmt.Errorf("--project not supported for %s (uses custom install flow)", editor)
		}
		fmt.Printf("Installing Revelara plugin for %s (project-local)...\n", editor)
	} else {
		fmt.Printf("Installing Revelara plugin for %s...\n", editor)
	}

	if !isProject && editor == "claude" {
		if err := CleanupOldClaudeInstallations(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not clean up old installations: %v\n", err)
		}
	}

	cfg, err := config.LoadConfig()
	if err != nil || cfg == nil || cfg.APIKey == "" || cfg.APIURL == "" {
		return fmt.Errorf("no API credentials configured — run 'rvl login' first")
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
		version = strings.TrimPrefix(cd, "attachment; filename=revelara-plugin-")
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

	if checksum == "" {
		if os.Getenv("RVL_ALLOW_MISSING_CHECKSUM") != "1" {
			return fmt.Errorf("server did not send X-Checksum header; set RVL_ALLOW_MISSING_CHECKSUM=1 to install unsigned plugins")
		}
	} else {
		hash := sha256.Sum256(tarballData)
		actualChecksum := "sha256:" + hex.EncodeToString(hash[:])
		if actualChecksum != checksum {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", checksum, actualChecksum)
		}
		fmt.Println("✓ Checksum verified")
	}

	// Verify integrity manifest signature and per-file hashes.
	// Fail-closed: non-nil err means signing check failed; plugin install is blocked.
	// Self-hosted deployments can set RVL_ALLOW_UNSIGNED_PLUGIN=1 to opt out.
	signingKey, skErr := api.FetchSigningKey(cfg)
	if skErr != nil {
		if os.Getenv("RVL_ALLOW_UNSIGNED_PLUGIN") == "1" {
			signingKey = nil // proceed without verification
		} else {
			return fmt.Errorf("could not fetch signing key for integrity verification: %w", skErr)
		}
	}
	if signingKey != nil {
		manifest, verifyErr := VerifyTarball(tarballData, signingKey)
		if verifyErr != nil {
			return fmt.Errorf("integrity verification failed: %w", verifyErr)
		}
		fmt.Printf("✓ Integrity verified (signed by %s at %s)\n", manifest.KeyID, manifest.SignedAt)
	}

	// Editors with CustomInstall handle the entire flow themselves (global only)
	if !isProject && def.CustomInstall != nil {
		if err := def.CustomInstall(version, tarballData, opts); err != nil {
			return err
		}
		// AGENTS.md is editor-agnostic and handled centrally for every editor
		// (custom installs like Claude only manage their own CLAUDE.md block).
		installContextFiles(".", opts, os.Stdout)
		return nil
	}

	var targetDir string
	if isProject {
		targetDir = filepath.Join(projectRoot, def.LocalDir)
	} else {
		targetDir, err = GetPluginDir(editor, version)
		if err != nil {
			return err
		}
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("create plugin directory: %w", err)
	}

	fmt.Printf("Extracting to %s...\n", targetDir)
	if err := ExtractTarball(tarballData, targetDir); err != nil {
		return err
	}

	// Run post-install hook if defined (e.g., EnableGeminiSubagents) — global only
	if !isProject && def.PostInstall != nil {
		if err := def.PostInstall(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: post-install hook failed: %v\n", err)
		}
	}

	// Track global installs in metadata; project-local installs live in the repo
	if !isProject {
		if err := SavePluginInfo(editor, version, targetDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save plugin metadata: %v\n", err)
		}
	}

	// Ambient reach: give every agent runtime that reads AGENTS.md a pointer
	// to the rvl context tools, regardless of editor.
	contextStart := "."
	if isProject {
		contextStart = projectRoot
	}
	installContextFiles(contextStart, opts, os.Stdout)

	PrintPostInstallInstructions(editor, targetDir)

	return nil
}

// UpdatePlugin updates installed plugin(s) to the latest version
func UpdatePlugin(editor string) error {
	return UpdatePluginWithOptions(editor, InstallOptions{})
}

// UpdatePluginWithOptions is UpdatePlugin with explicit install options.
func UpdatePluginWithOptions(editor string, opts InstallOptions) error {
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
			if err := InstallPluginWithOptions(p.Editor, "", opts); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", p.Editor, err)
			}
		}
		return nil
	}

	return InstallPluginWithOptions(editor, "", opts)
}

// listEditors prints all supported editors grouped by integration type.
func listEditors() {
	custom, universal := EditorsByTier()

	fmt.Println("Custom integrations (agent-specific install):")
	for _, e := range custom {
		fmt.Fprintf(os.Stdout, "  %-14s %s\n", e.Name, e.DisplayName)
	}

	fmt.Println("\nUniversal integrations (generic skills directory):")
	for _, e := range universal {
		fmt.Fprintf(os.Stdout, "  %-14s %s\n", e.Name, e.DisplayName)
	}

	fmt.Println("\nInstall:  rvl plugin install <name>")
	fmt.Println("Auto:     rvl plugin install --all")
}

// ListInstalledPlugins lists all installed Revelara plugins
func ListInstalledPlugins() {
	plugins, err := GetInstalledPlugins()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if len(plugins) == 0 {
		fmt.Println("No Revelara plugins installed.")
		fmt.Println("\nTo install:")
		fmt.Println("  rvl plugin install <agent>")
		fmt.Printf("  Available: %s\n", EditorNames())
		return
	}

	cfg, _ := config.LoadConfig()
	serverVersion := api.FetchServerPluginVersion(cfg)

	fmt.Println("Installed Revelara plugins:")
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
				fmt.Printf("\nRun 'rvl plugin update' to upgrade.\n")
				break
			}
		}
	}

	// Show project-local installations if we're in a project
	root := project.DetectGitRoot()
	if root != "" {
		var localEditors []string
		for name, def := range Registry {
			if def.LocalDir == "" {
				continue
			}
			localDir := filepath.Join(root, def.LocalDir)
			// Check if any current skill dirs exist
			for _, skill := range PolarisSkillNames[:7] {
				if _, err := os.Stat(filepath.Join(localDir, skill)); err == nil {
					localEditors = append(localEditors, name)
					break
				}
			}
		}
		if len(localEditors) > 0 {
			sort.Strings(localEditors)
			fmt.Printf("\nProject-local installations (%s):\n", root)
			for _, e := range localEditors {
				def := Registry[e]
				fmt.Printf("  %s → %s\n", e, filepath.Join(root, def.LocalDir))
			}
		}
	}
}

// AgentEntry describes one installed agent (lens) available to the scanner.
type AgentEntry struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// ListInstalledAgents prints the list of agent files (lenses) installed for the
// given editor. Default editor is "claude". Output is human-readable by default;
// pass --json for machine-readable output (used by the scan skill).
// parseAgentsListFlags parses the flags for `rvl plugin agents`. It accepts
// --format=json|table (aligning with the rest of the CLI) and keeps --json as
// a back-compat alias for --format=json (po-i24do.7). It returns the editor,
// whether JSON output was requested, whether --help was passed, and any flag
// error (invalid --format value or unknown flag).
func parseAgentsListFlags(args []string) (editor string, asJSON, wantHelp bool, err error) {
	editor = "claude"
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--format="):
			format := strings.TrimPrefix(a, "--format=")
			switch format {
			case "json":
				asJSON = true
			case "table", "text", "":
				asJSON = false
			default:
				return editor, asJSON, false, fmt.Errorf("invalid --format %q (valid: table, json)", format)
			}
		case a == "--json":
			asJSON = true
		case strings.HasPrefix(a, "--editor="):
			editor = strings.TrimPrefix(a, "--editor=")
		case a == "--help", a == "-h":
			return editor, asJSON, true, nil
		default:
			return editor, asJSON, false, fmt.Errorf("unknown flag: %s", a)
		}
	}
	return editor, asJSON, false, nil
}

func ListInstalledAgents(args []string) {
	editor, asJSON, wantHelp, err := parseAgentsListFlags(args)
	if err != nil {
		if strings.HasPrefix(err.Error(), "unknown flag: ") {
			cliutil.ExitUnknownFlag(strings.TrimPrefix(err.Error(), "unknown flag: "), "rvl plugin")
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cliutil.ExitUsage)
	}
	if wantHelp {
		fmt.Println("Usage: rvl plugin agents [--editor=<name>] [--format=json|table]")
		fmt.Println("\nList installed agent lenses available to the scanner.")
		fmt.Println("Default editor: claude. --json is an alias for --format=json.")
		return
	}

	agentsDir, err := installedAgentsDir(editor)
	if err != nil {
		if asJSON {
			fmt.Println(`{"agents":[]}`)
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			return
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		if asJSON {
			fmt.Println(`{"agents":[]}`)
			fmt.Fprintf(os.Stderr, "Warning: read agents directory %s: %v\n", agentsDir, err)
			return
		}
		fmt.Fprintf(os.Stderr, "Error: read agents directory %s: %v\n", agentsDir, err)
		os.Exit(1)
	}

	var agents []AgentEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".md")
		desc := readFrontmatterDescription(filepath.Join(agentsDir, e.Name()))
		agents = append(agents, AgentEntry{ID: id, Description: desc})
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].ID < agents[j].ID })

	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"agents": agents})
		return
	}
	for _, a := range agents {
		if a.Description != "" {
			fmt.Printf("%s\t%s\n", a.ID, a.Description)
		} else {
			fmt.Println(a.ID)
		}
	}
}

// installedAgentsDir resolves the directory that holds installed agent files
// for the given editor. It uses PluginInfo.Location (set at install time) as
// the canonical anchor and applies editor-specific layout rules.
func installedAgentsDir(editor string) (string, error) {
	plugins, err := GetInstalledPlugins()
	if err != nil {
		return "", fmt.Errorf("read installed plugins: %w", err)
	}
	for _, p := range plugins {
		if p.Editor != editor {
			continue
		}
		// Claude installs as a marketplace plugin: <Location>/agents/*.md.
		// Tier-2 editors (gemini, cursor, copilot, augment) use Registry.AgentsDir
		// rooted at $HOME.
		if editor == "claude" {
			return filepath.Join(p.Location, "agents"), nil
		}
		def, ok := Registry[editor]
		if !ok {
			return "", fmt.Errorf("unsupported editor: %s", editor)
		}
		if def.AgentsDir == "" {
			return "", fmt.Errorf("editor %q does not expose a separate agents directory", editor)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home dir: %w", err)
		}
		return filepath.Join(home, def.AgentsDir), nil
	}
	return "", fmt.Errorf("no Revelara plugin installed for editor %q (run: rvl plugin install %s)", editor, editor)
}

// readFrontmatterDescription scans a markdown file for the YAML frontmatter
// `description:` line and returns its trimmed value. Returns "" if the file
// has no frontmatter, no description, or cannot be read.
func readFrontmatterDescription(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	inFrontmatter := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "---" {
			if inFrontmatter {
				return ""
			}
			inFrontmatter = true
			continue
		}
		if !inFrontmatter {
			continue
		}
		if strings.HasPrefix(line, "description:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "description:"))
			// Strip a single layer of surrounding quotes (some agents use
			// quoted scalars in their frontmatter).
			if len(val) >= 2 {
				if (val[0] == '"' && val[len(val)-1] == '"') ||
					(val[0] == '\'' && val[len(val)-1] == '\'') {
					val = val[1 : len(val)-1]
				}
			}
			return val
		}
	}
	return ""
}

// RemovePlugin removes an installed plugin (all versions).
// If projectRoot is non-empty, removes from projectRoot/LocalDir (project-local).
func RemovePlugin(editor, projectRoot string) error {
	def, ok := Registry[editor]
	if !ok {
		return fmt.Errorf("unsupported editor: %s (available: %s)", editor, EditorNames())
	}

	isProject := projectRoot != ""

	if isProject && def.LocalDir == "" {
		return fmt.Errorf("--project not supported for %s", editor)
	}

	scope := "global"
	if isProject {
		scope = "project-local"
	}

	fmt.Printf("Remove %s Revelara plugin for %s? [y/N] ", scope, editor)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		fmt.Println("Cancelled.")
		return nil
	}

	if isProject {
		// Project-local removal: clean up from project root
		baseDir := filepath.Join(projectRoot, def.LocalDir)
		RemoveSkillDirs(baseDir)

		if def.AgentsDir != "" {
			// Derive project-local agents dir from LocalDir
			agentsDir := filepath.Join(projectRoot, def.LocalDir, "agents")
			removeAgentFilesByGlob(agentsDir, def.effectiveAgentGlob())
		}
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}

		if def.CustomRemove != nil {
			if err := def.CustomRemove(home); err != nil {
				return err
			}
		} else {
			// Standard removal: clean up skill dirs and agent files
			skillsDir := filepath.Join(home, def.effectiveSkillsDir())
			RemoveSkillDirs(skillsDir)

			if def.AgentsDir != "" {
				agentsDir := filepath.Join(home, def.AgentsDir)
				removeAgentFilesByGlob(agentsDir, def.effectiveAgentGlob())
			}
		}

		metadataFile := filepath.Join(home, ".revelara", "plugins.json")
		_ = RemovePluginFromMetadata(editor, metadataFile)
	}

	fmt.Printf("✓ Removed %s plugin (%s)\n", editor, scope)
	return nil
}

// removeAgentFilesByGlob removes agent files matching the given glob pattern.
func removeAgentFilesByGlob(agentsDir, pattern string) {
	matches, err := filepath.Glob(filepath.Join(agentsDir, pattern))
	if err != nil {
		return
	}
	for _, f := range matches {
		if err := os.Remove(f); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", f, err)
		}
	}
}

// RemoveSkillDirs removes known Revelara skill subdirectories from a base directory
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


// PrintPostInstallInstructions prints editor-specific next steps
func PrintPostInstallInstructions(editor, location string) {
	def, ok := Registry[editor]
	if !ok {
		return
	}

	fmt.Printf("\n✓ Revelara skills installed for %s\n\n", editor)

	if def.AgentsDir != "" {
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
	} else {
		fmt.Printf("Skills installed to: %s\n\n", location)
	}

	for _, line := range def.Instructions {
		fmt.Println(line)
	}
}

// installAll detects installed editors and installs the plugin to each one.
// If projectRoot is non-empty, installs project-locally. Editors without
// LocalDir are skipped for project-local installs.
func installAll(projectRoot string, opts InstallOptions) {
	editors := DetectInstalled()
	if len(editors) == 0 {
		fmt.Println("No supported AI coding agents detected.")
		fmt.Printf("Supported: %s\n", EditorNames())
		fmt.Println("\nInstall an AI coding agent, then run: rvl plugin install --all")
		return
	}

	fmt.Printf("Detected %d AI coding agent(s): %s\n\n", len(editors), strings.Join(editors, ", "))

	var succeeded, failed, skipped int
	for _, editor := range editors {
		// Skip editors that don't support project-local installs
		if projectRoot != "" {
			def := Registry[editor]
			if def.LocalDir == "" || def.CustomInstall != nil {
				fmt.Printf("Skipping %s (--project not supported)\n\n", editor)
				skipped++
				continue
			}
		}
		if err := InstallPluginWithOptions(editor, projectRoot, opts); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to install for %s: %v\n\n", editor, err)
			failed++
		} else {
			succeeded++
			fmt.Println()
		}
	}

	fmt.Printf("Done: %d succeeded", succeeded)
	if failed > 0 {
		fmt.Printf(", %d failed", failed)
	}
	if skipped > 0 {
		fmt.Printf(", %d skipped", skipped)
	}
	fmt.Println()
}

// pluginUsage returns the usage text for `rvl plugin`.
func pluginUsage() string {
	return fmt.Sprintf("Usage: rvl plugin <command>\n\nCommands:\n  install <agent>             Install skills for agent (%s)\n  install <agent> --project   Install to current project directory\n  install --all               Auto-detect and install to all agents\n  install --all --project     Auto-detect and install project-locally\n  update [agent]              Update skills to latest version\n  update --all                Update all installed plugins\n  list                        List installed skills\n  agents [--editor=NAME]      List installed agent lenses (default: claude)\n  editors                     List all supported agents\n  remove <agent>              Remove installed skills\n  remove <agent> --project    Remove project-local skills\n\nOptions:\n  --no-context-files          Skip writing the managed AGENTS.md/CLAUDE.md\n                              blocks into the current git repo (install/update)\n\nExamples:\n  rvl plugin install claude         Install Claude Code plugin\n  rvl plugin install gemini --project  Install to project directory\n  rvl plugin install --all          Install to all detected agents\n  rvl plugin install codex --no-context-files  Install skills only\n  rvl plugin update                 Update all installed plugins\n  rvl plugin agents --json          List installed lenses as JSON (used by /rvl:scan)\n  rvl plugin editors                Show all supported agents\n  rvl plugin list                   Show installed plugins\n", EditorNames())
}

// CmdPlugin handles plugin management (install, update, list, remove).
func CmdPlugin(args []string) {
	// po-cj4s7: help prints usage to stdout and exits 0, no network.
	if cliutil.WantsHelp(args) {
		fmt.Print(pluginUsage())
		return
	}

	if len(args) == 0 {
		fmt.Fprint(os.Stderr, pluginUsage())
		os.Exit(cliutil.ExitUsage)
	}

	// Extract --project and --no-context-files flags from subcommand args
	subArgs := args[1:]
	subArgs, isProject := extractFlag(subArgs, "--project")
	subArgs, noContextFiles := extractFlag(subArgs, "--no-context-files")
	opts := InstallOptions{SkipContextFiles: noContextFiles}
	if noContextFiles && (args[0] == "install" || args[0] == "update") {
		fmt.Println("Skipping AGENTS.md/CLAUDE.md context files (--no-context-files)")
	}

	var projectRoot string
	if isProject {
		var err error
		projectRoot, err = detectProjectRoot()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not detect project root: %v\n", err)
			os.Exit(1)
		}
	}

	switch args[0] {
	case "install":
		if len(subArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Error: agent name required")
			fmt.Fprintln(os.Stderr, "Usage: rvl plugin install <agent> [--project]")
			fmt.Fprintln(os.Stderr, "       rvl plugin install --all [--project]")
			fmt.Fprintf(os.Stderr, "Available: %s\n", EditorNames())
			os.Exit(cliutil.ExitUsage)
		}
		if subArgs[0] == "--all" {
			installAll(projectRoot, opts)
		} else {
			editor := subArgs[0]
			if err := InstallPluginWithOptions(editor, projectRoot, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}
	case "update":
		editor := ""
		if len(subArgs) >= 1 && subArgs[0] != "--all" {
			editor = subArgs[0]
		}
		if err := UpdatePluginWithOptions(editor, opts); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		ListInstalledPlugins()
	case "agents":
		ListInstalledAgents(subArgs)
	case "editors":
		listEditors()
	case "remove", "uninstall":
		if len(subArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Error: agent name required")
			fmt.Fprintln(os.Stderr, "Usage: rvl plugin remove <agent> [--project]")
			os.Exit(cliutil.ExitUsage)
		}
		editor := subArgs[0]
		if err := RemovePlugin(editor, projectRoot); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown plugin command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: rvl plugin <install|update|list|editors|remove>")
		os.Exit(cliutil.ExitUsage)
	}
}

// IsEditorAvailable checks if the given CLI binary is on the PATH.
func IsEditorAvailable(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}
