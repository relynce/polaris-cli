package commands

import (
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/revelara-ai/rvl-cli/internal/cliutil"
	"github.com/revelara-ai/rvl-cli/internal/config"
)

// validateAPIURL rejects api_url values that would send the bearer API
// key in cleartext. po-i24do.20: any scheme was previously accepted, so
// `rvl config set api_url http://…` transmitted the key over plaintext
// HTTP. Only https:// is allowed, except for loopback hosts (localhost,
// 127.0.0.1, ::1) where http is the normal local-dev convention and no
// key ever crosses the network.
func validateAPIURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid api_url %q: %v", raw, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("api_url must use https:// (http:// is only allowed for localhost); got %q", raw)
}

// isLoopbackHost reports whether host is a loopback name or address.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

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
			if err := validateAPIURL(value); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(cliutil.ExitUsage)
			}
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
