package commands

import (
	"fmt"
	"os"

	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/config"
)

// maskConfigValue masks sensitive config values before echoing them
// back to the terminal. po-cj4s7: `rvl config set api_key <key>` used
// to echo the full plaintext key, which lands in shell history readers,
// terminal scrollback, and agent transcripts. Non-sensitive keys echo
// unchanged.
func maskConfigValue(key, value string) string {
	if key != "api_key" {
		return value
	}
	if len(value) > 12 {
		return value[:8] + "..."
	}
	return "[set]"
}

// CmdConfig handles config subcommands (show, set)
func CmdConfig(args []string) {
	if cliutil.WantsHelp(args) {
		printConfigUsage()
		return
	}
	if len(args) == 0 {
		printConfigUsage()
		os.Exit(cliutil.ExitUsage)
	}
	switch args[0] {
	case "show":
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if cfg == nil {
			fmt.Println("No configuration found. Run 'rvl login' first, or set RVL_API_KEY for headless/CI use.")
			return
		}
		fmt.Printf("api_url: %s\n", cfg.APIURL)
		if len(cfg.APIKey) > 8 {
			fmt.Printf("api_key: %s...%s\n", cfg.APIKey[:4], cfg.APIKey[len(cfg.APIKey)-4:])
		} else {
			fmt.Println("api_key: (set)")
		}
		fmt.Printf("org_name: %s\n", cfg.OrgName)
	case "set":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: rvl config set <key> <value>")
			os.Exit(cliutil.ExitUsage)
		}
		key, value := args[1], args[2]
		cfg, _ := config.LoadConfig()
		if cfg == nil {
			cfg = &config.Config{APIURL: config.DefaultAPIURL}
		}
		switch key {
		case "api_url":
			cfg.APIURL = value
		case "api_key":
			cfg.APIKey = value
		case "org_name":
			cfg.OrgName = value
		default:
			fmt.Fprintf(os.Stderr, "Unknown config key: %s\n", key)
			fmt.Fprintln(os.Stderr, "Valid keys: api_url, api_key, org_name")
			os.Exit(cliutil.ExitUsage)
		}
		if err := config.SaveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Set %s = %s\n", key, maskConfigValue(key, value))
	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", args[0])
		printConfigUsage()
		os.Exit(cliutil.ExitUsage)
	}
}

func printConfigUsage() {
	fmt.Println(`rvl config - View and edit CLI configuration

Usage:
  rvl config show             Show current configuration (API key masked)
  rvl config set <key> <value>  Set a configuration value

Keys:
  api_url     API endpoint (default: ` + config.DefaultAPIURL + `)
  api_key     API key (echoed masked when set)
  org_name    Organization name

Environment variables RVL_API_KEY, RVL_API_URL, and RVL_ORG_NAME take
precedence over the config file; use them for headless/CI environments.

Examples:
  rvl config show
  rvl config set org_name my-org`)
}
