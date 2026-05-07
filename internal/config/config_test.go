package config

import (
	"os"
	"path/filepath"
	"testing"
)

// withTempHome runs fn with HOME pointing at a temp dir so config
// reads/writes don't touch the developer's real ~/.revelara.
func withTempHome(t *testing.T, fn func(home string)) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	fn(tmp)
}

// clearEnv ensures the three RVL_ env vars are unset for the duration of
// the test. t.Setenv("KEY", "") still leaves the var defined; we instead
// set them to "" via t.Setenv (Go's testing harness restores original on
// cleanup) which is sufficient because our LoadConfig treats "" as unset.
func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv("RVL_API_KEY", "")
	t.Setenv("RVL_API_URL", "")
	t.Setenv("RVL_ORG_NAME", "")
}

func TestLoadConfig_NoFileNoEnv_ReturnsNil(t *testing.T) {
	withTempHome(t, func(home string) {
		clearEnv(t)
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg != nil {
			t.Errorf("expected nil cfg when neither file nor env supplies an API key")
		}
	})
}

func TestLoadConfig_EnvVarsAlone_Sufficient(t *testing.T) {
	withTempHome(t, func(home string) {
		clearEnv(t)
		t.Setenv("RVL_API_KEY", "pk_envkey")
		t.Setenv("RVL_API_URL", "https://env.example.com")
		t.Setenv("RVL_ORG_NAME", "env-org")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil cfg from env vars alone")
		}
		if cfg.APIKey != "pk_envkey" {
			t.Errorf("APIKey: want pk_envkey, got %s", cfg.APIKey)
		}
		if cfg.APIURL != "https://env.example.com" {
			t.Errorf("APIURL: want env URL, got %s", cfg.APIURL)
		}
		if cfg.OrgName != "env-org" {
			t.Errorf("OrgName: want env-org, got %s", cfg.OrgName)
		}
	})
}

func TestLoadConfig_EnvOverridesFile(t *testing.T) {
	withTempHome(t, func(home string) {
		clearEnv(t)
		// Seed the config file with file-only values.
		dir := filepath.Join(home, ".revelara")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		yaml := []byte("api_url: https://file.example.com\napi_key: pk_filekey\norg_name: file-org\n")
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), yaml, 0600); err != nil {
			t.Fatal(err)
		}

		// Env vars should win.
		t.Setenv("RVL_API_KEY", "pk_envkey")
		t.Setenv("RVL_API_URL", "https://env.example.com")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("cfg should not be nil")
		}
		if cfg.APIKey != "pk_envkey" {
			t.Errorf("env APIKey must override file; got %s", cfg.APIKey)
		}
		if cfg.APIURL != "https://env.example.com" {
			t.Errorf("env APIURL must override file; got %s", cfg.APIURL)
		}
		// OrgName not env-overridden so file value carries through.
		if cfg.OrgName != "file-org" {
			t.Errorf("OrgName should fall back to file when env is unset; got %s", cfg.OrgName)
		}
	})
}

func TestLoadConfig_DefaultAPIURLWhenUnset(t *testing.T) {
	withTempHome(t, func(home string) {
		clearEnv(t)
		t.Setenv("RVL_API_KEY", "pk_envkey")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.APIURL != DefaultAPIURL {
			t.Errorf("APIURL should default to %s when neither file nor env sets it; got %s",
				DefaultAPIURL, cfg.APIURL)
		}
	})
}
