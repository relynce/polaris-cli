package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/config"
	"github.com/revelara-ai/rvl-cli/internal/plugin"
	"github.com/revelara-ai/rvl-cli/internal/project"
	"gopkg.in/yaml.v3"
)

const agentsMdTemplate = `## Revelara

This project uses Revelara for reliability risk analysis. The following skills are available:

### Core Skills
- ` + "`/rvl:scan`" + ` — Scan codebase for reliability risks
- ` + "`/rvl:fix R-XXX`" + ` — Get remediation guidance and auto-fix a risk
- ` + "`/rvl:ask \"question\"`" + ` — Ask any reliability question to a domain expert
- ` + "`/rvl:risks`" + ` — View risk posture, open risks, and ready-to-fix items
- ` + "`/rvl:review`" + ` — Review code changes for reliability issues
- ` + "`/rvl:evidence RC-XXX`" + ` — Submit evidence after implementing a control
- ` + "`/rvl:status`" + ` — Check connection and configuration

### Quick Reference
- Run ` + "`rvl risk list`" + ` to see current risks
- Run ` + "`rvl risk show <code>`" + ` for risk details with mapped controls
- Run ` + "`rvl control show <code>`" + ` for control implementation guidance
`

// huhTheme is the shared high-contrast theme for every interactive prompt
// (po-bs7jx). huh's default (ThemeCharm) renders the focused button as
// near-white text on a fuchsia/pink background (cream on #F780E2) — the
// low-contrast "white on pink" the init wizard was flagged for. We base on
// ThemeBase16 (terminal-adaptive ANSI colors) and force the focused button to
// black-on-light-gray so the active choice is always legible.
var huhTheme = func() *huh.Theme {
	t := huh.ThemeBase16()
	t.Focused.FocusedButton = t.Focused.FocusedButton.
		Foreground(lipgloss.Color("0")).
		Background(lipgloss.Color("7")).
		Bold(true)
	return t
}()

func printInitUsage() {
	fmt.Println(`rvl init - Initialize Revelara for this repository

Usage:
  rvl init [options]

Options:
  --project <name>    Set project name (default: from git remote or directory name)
  --skip-plugin       Skip installing the Revelara plugin for Claude Code
  --force             Overwrite existing config and plugin without prompting
  -y, --yes           Accept all defaults non-interactively

What it does:
  1. Creates .revelara.yaml with project name and detected components
  2. Installs the Revelara plugin for Claude Code (if available)
  3. Adds Revelara sections to AGENTS.md (creates or appends)
  4. Checks if API credentials are configured

Examples:
  rvl init                         Interactive setup
  rvl init --project my-service    Set project name directly
  rvl init -y                      Accept all auto-detected defaults
  rvl init --force                 Overwrite existing config`)
}

// CmdInit initializes Revelara for a repository
func CmdInit(args []string) {
	var projectName string
	var skipPlugin bool
	var force bool
	var yesAll bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "help", "--help", "-h":
			printInitUsage()
			return
		case "--skip-plugin", "--skip-skills":
			skipPlugin = true
		case "--force":
			force = true
		case "-y", "--yes":
			yesAll = true
		case "--project":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --project requires a value")
				os.Exit(cliutil.ExitUsage)
			}
			i++
			projectName = args[i]
		default:
			if strings.HasPrefix(args[i], "--project=") {
				projectName = strings.TrimPrefix(args[i], "--project=")
			} else {
				cliutil.ExitUnknownFlag(args[i], "rvl init")
			}
		}
	}

	fmt.Println("Initializing Revelara...")
	fmt.Println()

	// Step 1: Require git repo
	gitRoot := project.DetectGitRoot()
	if gitRoot == "" {
		fmt.Fprintln(os.Stderr, "Error: not a git repository.")
		fmt.Fprintln(os.Stderr, "Revelara reads your git repository to detect project structure and service names.")
		fmt.Fprintln(os.Stderr, "Navigate to a git repository or run 'git init' here first.")
		os.Exit(1)
	}

	// Step 2: Generate .revelara.yaml
	configPath := filepath.Join(gitRoot, ".revelara.yaml")
	writeConfig := true

	if _, err := os.Stat(configPath); err == nil {
		if yesAll {
			writeConfig = false
			fmt.Println("Keeping existing .revelara.yaml (use interactive mode to overwrite)")
		} else {
			existing, _ := os.ReadFile(configPath)
			fmt.Println("Existing .revelara.yaml found:")
			fmt.Println(string(existing))

			var overwrite bool
			err := huh.NewConfirm().
				Title("Overwrite existing .revelara.yaml?").
				Affirmative("Yes").
				Negative("No").
				Value(&overwrite).
				WithTheme(huhTheme).
				Run()
			if err != nil || !overwrite {
				writeConfig = false
				fmt.Println("Keeping existing .revelara.yaml")
			}
		}
	}

	var cfg *project.ProjectConfig
	if writeConfig {
		var buildErr error
		cfg, buildErr = buildProjectConfig(gitRoot, projectName, yesAll)
		if buildErr != nil {
			if errors.Is(buildErr, huh.ErrUserAborted) {
				fmt.Println("Cancelled. No files written.")
				return
			}
			fmt.Fprintf(os.Stderr, "Error: %v\n", buildErr)
			os.Exit(1)
		}
		if err := project.WriteProjectConfig(configPath, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing .revelara.yaml: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Created .revelara.yaml (project: %s, %d components)\n", cfg.Project, len(cfg.Components))
	} else {
		// Load existing config for summary
		data, _ := os.ReadFile(configPath)
		cfg = &project.ProjectConfig{}
		_ = yaml.Unmarshal(data, cfg)
	}

	// po-ta8wj.1: ensure .revelara/memory/ exists and seed digest.compact
	// if it doesn't already exist. The skeleton comment header signals the
	// file format version to tools that read it without a full parse.
	memoryDir := filepath.Join(gitRoot, ".revelara", "memory")
	if err := os.MkdirAll(memoryDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create .revelara/memory/: %v\n", err)
	} else {
		digestPath := filepath.Join(memoryDir, "digest.compact")
		if _, statErr := os.Stat(digestPath); os.IsNotExist(statErr) {
			skeleton := "# digest.compact v1 — auto-generated by rvl init\n# Do not hand-edit. Human-readable history is in RISKS.md and ENTRYPOINT.md.\n"
			if writeErr := os.WriteFile(digestPath, []byte(skeleton), 0644); writeErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not write digest.compact: %v\n", writeErr)
			}
		}
	}

	fmt.Println()

	// Step 3: Install skills for detected editors
	pluginInstalled := false
	pluginVersion := ""
	if !skipPlugin {
		plugins, _ := plugin.GetInstalledPlugins()
		installedMap := make(map[string]*plugin.PluginInfo)
		for i := range plugins {
			installedMap[plugins[i].Editor] = &plugins[i]
		}

		// Fetch server version once for update checks
		loginCfgForPlugin, _ := config.LoadConfig()
		serverVersion := api.FetchServerPluginVersion(loginCfgForPlugin)

		// Detect available editors
		detectedEditors := plugin.DetectInstalled()

		if len(detectedEditors) == 0 {
			fmt.Println("Skills: No supported AI coding agents detected on PATH")
			fmt.Printf("  Supported: %s\n", plugin.EditorNames())
			fmt.Println("  Install an AI coding agent, then run: rvl plugin install <agent>")
		}

		for _, editorName := range detectedEditors {
			existing := installedMap[editorName]

			if existing != nil {
				// Already installed — check for updates
				if serverVersion != "" && plugin.SemVerNewer(existing.Version, serverVersion) {
					doUpdate := force || yesAll
					if !doUpdate {
						err := huh.NewConfirm().
							Title(fmt.Sprintf("Update Revelara skills for %s? (v%s → v%s)", editorName, existing.Version, serverVersion)).
							Affirmative("Yes").
							Negative("No").
							Value(&doUpdate).
							WithTheme(huhTheme).
							Run()
						if err != nil {
							doUpdate = false
						}
					}
					if doUpdate {
						if err := plugin.InstallPlugin(editorName, ""); err != nil {
							fmt.Fprintf(os.Stderr, "Warning: could not update %s skills: %v\n", editorName, err)
						} else {
							pluginInstalled = true
							pluginVersion = serverVersion
						}
					} else {
						pluginInstalled = true
						pluginVersion = existing.Version
						fmt.Printf("Skills (%s): Keeping v%s\n", editorName, existing.Version)
					}
				} else {
					pluginInstalled = true
					pluginVersion = existing.Version
					fmt.Printf("Skills (%s): Up to date (v%s)\n", editorName, existing.Version)
				}
			} else {
				// Editor available but skills not installed
				doInstall := yesAll
				if !yesAll {
					err := huh.NewConfirm().
						Title(fmt.Sprintf("Install Revelara skills for %s?", editorName)).
						Affirmative("Yes").
						Negative("No").
						Value(&doInstall).
						WithTheme(huhTheme).
						Run()
					if err != nil {
						doInstall = false
					}
				}
				if doInstall {
					if err := plugin.InstallPlugin(editorName, ""); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: could not install %s skills: %v\n", editorName, err)
					} else {
						pluginInstalled = true
						// Read back the version from metadata
						updatedPlugins, _ := plugin.GetInstalledPlugins()
						for _, p := range updatedPlugins {
							if p.Editor == editorName {
								pluginVersion = p.Version
								break
							}
						}
					}
				}
			}
		}
		fmt.Println()
	}

	// Step 4: Set up AGENTS.md
	agentsMdAction := ""
	action, err := EnsureAgentsMd(gitRoot, force, yesAll)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not set up AGENTS.md: %v\n", err)
	} else {
		agentsMdAction = action
		switch action {
		case "created":
			fmt.Println("Created AGENTS.md with Revelara sections")
		case "appended":
			fmt.Println("Appended Revelara sections to AGENTS.md")
		case "updated":
			fmt.Println("Updated Revelara sections in AGENTS.md")
		case "skipped":
			fmt.Println("AGENTS.md: Skipped")
		}
	}
	fmt.Println()

	// Step 5: Set up CLAUDE.md managed block (Claude editor only)
	if pluginInstalled {
		home, _ := os.UserHomeDir()
		claudeMdSrc := filepath.Join(home, ".revelara", "marketplace", "plugins", "revelara", "CLAUDE.md")
		if _, statErr := os.Stat(claudeMdSrc); statErr == nil {
			claudeAction, claudeErr := plugin.EnsureClaudeMd(gitRoot, claudeMdSrc, yesAll || force)
			if claudeErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not set up CLAUDE.md: %v\n", claudeErr)
			} else {
				switch claudeAction {
				case "created":
					fmt.Println("Created CLAUDE.md with Revelara managed block")
				case "appended":
					fmt.Println("Appended Revelara managed block to CLAUDE.md")
				case "updated":
					fmt.Println("Updated Revelara managed block in CLAUDE.md")
				case "skipped":
					fmt.Println("CLAUDE.md: Skipped")
				}
			}
			fmt.Println()
		}
	}

	// Step 6: Check credentials
	credentialsConfigured := false
	credentialsURL := ""
	loginCfg, _ := config.LoadConfig()
	if loginCfg != nil && loginCfg.APIKey != "" {
		credentialsConfigured = true
		credentialsURL = loginCfg.APIURL
		fmt.Printf("Credentials: Configured (API URL: %s)\n", credentialsURL)
	} else {
		fmt.Println("Credentials: Not configured")
		fmt.Println("  Run 'rvl login' to set up API credentials.")
	}
	fmt.Println()

	// Step 7: Record onboarding milestone (best-effort, fire-and-forget).
	// po-vfzc0: the backend tracks this as "cli_setup" (it counts toward the
	// "Set up the Revelara CLI" onboarding step). Posting the old "cli_init"
	// name was silently rejected as an invalid milestone, so step 2 never
	// completed from CLI usage. The server still aliases cli_init -> cli_setup
	// for older builds.
	if credentialsConfigured {
		api.PostOnboardingMilestone(loginCfg, "cli_setup")
	}

	// Step 8: Print summary
	printInitSummary(cfg, pluginInstalled, pluginVersion, credentialsConfigured, agentsMdAction)
}

// buildProjectConfig creates a ProjectConfig interactively or from defaults.
// Returns (nil, huh.ErrUserAborted) if the user pressed Ctrl-C.
func buildProjectConfig(gitRoot, projectName string, yesAll bool) (*project.ProjectConfig, error) {
	// Auto-detect project name
	if projectName == "" {
		projectName = project.DetectProjectName(gitRoot)
	}

	// Auto-detect components
	components := project.DetectComponents(gitRoot)

	if yesAll {
		if len(components) == 0 {
			components = []project.ProjectComponent{{Name: projectName, Path: "."}}
		}
		return &project.ProjectConfig{Project: projectName, Components: components}, nil
	}

	// Interactive: prompt for project name
	err := huh.NewInput().
		Title("Project name").
		Value(&projectName).
		WithTheme(huhTheme).
		Run()
	if err != nil {
		return nil, err
	}

	// Show detected components
	if len(components) > 0 {
		fmt.Println("Detected components:")
		for i, c := range components {
			fmt.Printf("  %d. %-20s %s\n", i+1, c.Name, c.Path)
		}
		fmt.Println()

		var accept bool
		err := huh.NewConfirm().
			Title("Accept detected components?").
			Affirmative("Yes").
			Negative("No, let me edit").
			Value(&accept).
			WithTheme(huhTheme).
			Run()
		if err != nil {
			return nil, err
		}

		if !accept {
			var promptErr error
			components, promptErr = promptComponents()
			if promptErr != nil {
				return nil, promptErr
			}
		}
	} else {
		fmt.Println("No components auto-detected.")
		fmt.Println()

		fmt.Println("A component is a subdirectory Revelara analyzes as a separate service (e.g., api/, worker/).")
		fmt.Println("For a single-service repository, choose 'No' to treat the whole repo as one project.")
		fmt.Println()

		var addManual bool
		err := huh.NewConfirm().
			Title("Add components manually?").
			Affirmative("Yes, add components").
			Negative("No — treat whole repo as one project").
			Value(&addManual).
			WithTheme(huhTheme).
			Run()
		if err != nil {
			return nil, err
		}

		if addManual {
			var promptErr error
			components, promptErr = promptComponents()
			if promptErr != nil {
				return nil, promptErr
			}
		} else {
			components = []project.ProjectComponent{{Name: projectName, Path: "."}}
		}
	}

	return &project.ProjectConfig{Project: projectName, Components: components}, nil
}

// promptComponents interactively collects component definitions.
// Returns (nil, huh.ErrUserAborted) if the user pressed Ctrl-C.
func promptComponents() ([]project.ProjectComponent, error) {
	fmt.Println("Enter a name and relative path for each component.")
	fmt.Println("Example: name=api, path=api/")
	fmt.Println()

	var components []project.ProjectComponent
	for {
		var name, path string

		err := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Component name").
					Value(&name),
				huh.NewInput().
					Title("Component path (relative to repo root)").
					Value(&path),
			),
		).WithTheme(huhTheme).Run()
		if err != nil {
			if errors.Is(err, huh.ErrUserAborted) {
				return nil, err
			}
			break
		}

		if name == "" || path == "" {
			break
		}

		// Ensure path ends with /
		if path != "." && !strings.HasSuffix(path, "/") {
			path += "/"
		}

		components = append(components, project.ProjectComponent{Name: name, Path: path})
		fmt.Printf("  Added: %s -> %s\n", name, path)

		var addMore bool
		err = huh.NewConfirm().
			Title("Add another component?").
			Affirmative("Yes").
			Negative("Done").
			Value(&addMore).
			WithTheme(huhTheme).
			Run()
		if err != nil {
			if errors.Is(err, huh.ErrUserAborted) {
				return nil, err
			}
			break
		}
		if !addMore {
			break
		}
	}
	return components, nil
}

// EnsureAgentsMd creates or updates AGENTS.md with Revelara sections
func EnsureAgentsMd(gitRoot string, force, yesAll bool) (string, error) {
	agentsMdPath := filepath.Join(gitRoot, "AGENTS.md")
	content, err := os.ReadFile(agentsMdPath)

	if os.IsNotExist(err) {
		if err := os.WriteFile(agentsMdPath, []byte(agentsMdTemplate), 0644); err != nil {
			return "", err
		}
		return "created", nil
	}

	if err != nil {
		return "", err
	}

	contentStr := string(content)
	hasPolarisSection := strings.Contains(contentStr, "## Revelara")

	if !hasPolarisSection {
		var shouldAppend bool
		if yesAll || force {
			shouldAppend = true
		} else {
			err := huh.NewConfirm().
				Title("AGENTS.md exists but has no Revelara section. Append?").
				Affirmative("Yes").
				Negative("No").
				Value(&shouldAppend).
				WithTheme(huhTheme).
				Run()
			if err != nil {
				return "skipped", nil
			}
		}

		if shouldAppend {
			updatedContent := contentStr
			if !strings.HasSuffix(contentStr, "\n") {
				updatedContent += "\n"
			}
			updatedContent += "\n" + agentsMdTemplate
			if err := os.WriteFile(agentsMdPath, []byte(updatedContent), 0644); err != nil {
				return "", err
			}
			return "appended", nil
		}
		return "skipped", nil
	}

	// Already has Polaris section — prompt to update
	var shouldUpdate bool
	if yesAll || force {
		shouldUpdate = true
	} else {
		err := huh.NewConfirm().
			Title("AGENTS.md already has Revelara section. Update?").
			Affirmative("Yes").
			Negative("No").
			Value(&shouldUpdate).
			WithTheme(huhTheme).
			Run()
		if err != nil {
			return "skipped", nil
		}
	}

	if shouldUpdate {
		lines := strings.Split(contentStr, "\n")
		var newLines []string
		var inPolarisSection bool

		for i, line := range lines {
			if strings.TrimSpace(line) == "## Revelara" {
				inPolarisSection = true
				newLines = append(newLines, agentsMdTemplate)
				continue
			}

			if inPolarisSection {
				if strings.HasPrefix(strings.TrimSpace(line), "##") && line != "## Revelara" {
					inPolarisSection = false
					newLines = append(newLines, line)
				}
				if i == len(lines)-1 {
					break
				}
				continue
			}

			newLines = append(newLines, line)
		}

		updatedContent := strings.Join(newLines, "\n")
		if err := os.WriteFile(agentsMdPath, []byte(updatedContent), 0644); err != nil {
			return "", err
		}
		return "updated", nil
	}

	return "skipped", nil
}

func printInitSummary(cfg *project.ProjectConfig, pluginInstalled bool, pluginVersion string, credentialsConfigured bool, agentsMdAction string) {
	fmt.Println("=== Revelara Initialization Complete ===")
	fmt.Println()
	fmt.Printf("Project: %s\n", cfg.Project)
	fmt.Printf("Components: %d\n", len(cfg.Components))
	for _, c := range cfg.Components {
		fmt.Printf("  - %s (%s)\n", c.Name, c.Path)
	}
	fmt.Println()
	if pluginInstalled {
		fmt.Printf("Skills: Installed (v%s)\n", pluginVersion)
	} else {
		fmt.Println("Skills: Not installed")
	}
	if agentsMdAction != "" && agentsMdAction != "skipped" {
		fmt.Printf("AGENTS.md: %s\n", agentsMdAction)
	}
	if credentialsConfigured {
		fmt.Println("Credentials: Configured")
	} else {
		fmt.Println("Credentials: Not configured — run 'rvl login'")
	}
	fmt.Println()
	fmt.Println("Next steps:")
	if !credentialsConfigured {
		fmt.Println("  1. rvl login")
		fmt.Println("  2. rvl plugin install claude")
	} else if !pluginInstalled {
		fmt.Println("  1. rvl plugin install claude")
	}
	fmt.Println("  - Commit .revelara.yaml and AGENTS.md to your repository")
	fmt.Println("  - Open Claude Code in this directory and run /rvl:scan to scan for reliability risks")
}
