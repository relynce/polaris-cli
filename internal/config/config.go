package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	configDir  = ".revelara"
	configFile = "config.yaml"

	// DefaultAPIURL is the production Revelara API endpoint.
	DefaultAPIURL = "https://api.revelara.ai"
)

// Config holds the CLI configuration
type Config struct {
	APIURL  string `yaml:"api_url"`
	APIKey  string `yaml:"api_key"`
	OrgName string `yaml:"org_name"`

	// ResolvedOrgID is runtime-only: resolved org UUID (not persisted to YAML)
	ResolvedOrgID string `yaml:"-"`
}

// GetConfigPath returns the path to the config file
func GetConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(home, configDir, configFile)
}

// LoadConfig loads configuration from disk and overlays environment
// variables on top. Env vars take precedence over yaml — the
// CI/CD use case has no `~/.revelara/config.yaml` and must work via
// secrets injected as env vars.
//
// Env vars (highest precedence):
//   - RVL_API_KEY  → Config.APIKey
//   - RVL_API_URL  → Config.APIURL
//   - RVL_ORG_NAME → Config.OrgName
//
// When the config file is absent AND no RVL_API_KEY env var is set,
// returns (nil, nil) so the caller can surface "Not configured".
func LoadConfig() (*Config, error) {
	var cfg Config

	path := GetConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		// No config file — fall through; env vars may still satisfy auth.
	} else {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
	}

	if v := os.Getenv("RVL_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("RVL_API_URL"); v != "" {
		cfg.APIURL = v
	}
	if v := os.Getenv("RVL_ORG_NAME"); v != "" {
		cfg.OrgName = v
	}

	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}

	// If neither file nor env var supplied an API key, return nil so the
	// caller (LoadAndResolveConfig) prints the "Not configured" message.
	if cfg.APIKey == "" {
		return nil, nil
	}
	return &cfg, nil
}

// SaveConfig saves configuration to disk
func SaveConfig(cfg *Config) error {
	path := GetConfigPath()
	dir := filepath.Dir(path)

	// Create directory with restricted permissions
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	// Write with restricted permissions (owner read/write only)
	return os.WriteFile(path, data, 0600)
}
