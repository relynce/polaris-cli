package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/relynce/rely-cli/internal/api"
	"github.com/relynce/rely-cli/internal/config"
	"github.com/relynce/rely-cli/internal/plugin"
	"golang.org/x/term"
)

// CmdLogin handles the login command
func CmdLogin() {
	reader := bufio.NewReader(os.Stdin)
	cfg, _ := config.LoadConfig()
	if cfg == nil {
		cfg = &config.Config{}
	}
	defaultURL := cfg.APIURL
	if defaultURL == "" {
		defaultURL = "https://api-dev.relynce.ai"
	}
	fmt.Printf("Relynce API URL [%s]: ", defaultURL)
	apiURL, _ := reader.ReadString('\n')
	apiURL = strings.TrimSpace(apiURL)
	if apiURL == "" {
		apiURL = defaultURL
	}
	cfg.APIURL = apiURL

	if cfg.APIKey != "" {
		masked := cfg.APIKey[:8] + "..." + cfg.APIKey[len(cfg.APIKey)-4:]
		fmt.Printf("API Key [%s] (Enter to keep): ", masked)
	} else {
		fmt.Print("API Key: ")
	}
	apiKeyBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading API key: %v\n", err)
		os.Exit(1)
	}
	apiKey := strings.TrimSpace(string(apiKeyBytes))
	if apiKey != "" {
		cfg.APIKey = apiKey
		fmt.Println("  API key received.")
	} else if cfg.APIKey != "" {
		fmt.Println("  Keeping existing API key.")
	}
	if cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: API key is required")
		os.Exit(1)
	}

	defaultOrg := cfg.OrgName
	fmt.Printf("Organization name [%s]: ", defaultOrg)
	orgName, _ := reader.ReadString('\n')
	orgName = strings.TrimSpace(orgName)
	if orgName == "" {
		orgName = defaultOrg
	}
	cfg.OrgName = orgName

	fmt.Println("\nValidating credentials...")
	if cfg.OrgName != "" {
		if err := api.ResolveOrganizationID(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Organization resolved: %s -> %s\n", cfg.OrgName, cfg.ResolvedOrgID)
	}
	if err := api.ValidateCredentials(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := config.SaveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Configuration saved to ~/.relynce/config.yaml")
}

// CmdLogout removes stored credentials
func CmdLogout() {
	path := config.GetConfigPath()
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No credentials stored.")
			return
		}
		fmt.Fprintf(os.Stderr, "Error removing config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Credentials removed.")
}

// CmdStatus checks connection and auth status
// Takes version and gitHash as params since they're defined in main
func CmdStatus(version, gitHash string) {
	cfg := api.LoadAndResolveConfig()
	fmt.Printf("Relynce CLI v%s (%s)\n", version, gitHash)
	fmt.Printf("API URL: %s\n", cfg.APIURL)
	if len(cfg.APIKey) > 8 {
		fmt.Printf("API Key: %s...%s\n", cfg.APIKey[:4], cfg.APIKey[len(cfg.APIKey)-4:])
	} else {
		fmt.Println("API Key: (set)")
	}
	if cfg.OrgName != "" {
		fmt.Printf("Organization: %s\n", cfg.OrgName)
	}

	fmt.Println("\nChecking connection...")
	if err := api.ValidateCredentials(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Status: Connected")

	fmt.Println("\nPlugins:")
	serverVersion := api.FetchServerPluginVersion(cfg)
	plugins, err := plugin.GetInstalledPlugins()
	if err != nil || len(plugins) == 0 {
		fmt.Println("  No plugins installed")
		fmt.Println("  Run 'rely plugin install <editor>' to install")
		fmt.Println("  Available: claude, codex, gemini, cursor, windsurf, copilot, augment")
	} else {
		for _, p := range plugins {
			if serverVersion != "" && plugin.SemVerNewer(p.Version, serverVersion) {
				fmt.Printf("  %s: v%s (update available: v%s)\n", p.Editor, p.Version, serverVersion)
				fmt.Printf("    Run 'rely plugin update %s' to upgrade\n", p.Editor)
			} else if serverVersion != "" {
				fmt.Printf("  %s: v%s (up to date)\n", p.Editor, p.Version)
			} else {
				fmt.Printf("  %s: v%s\n", p.Editor, p.Version)
			}
		}
	}
}
