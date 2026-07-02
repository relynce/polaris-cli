package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/config"
)

// LoadAndResolveConfig loads config and resolves org name to UUID.
func LoadAndResolveConfig() *config.Config {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	if cfg == nil || cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: Not configured. Run 'rvl login' first, or set RVL_API_KEY for headless/CI use.")
		os.Exit(1)
	}
	if err := ResolveOrganizationID(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// ResolveOrganizationID resolves an org name to its UUID by listing the user's orgs.
func ResolveOrganizationID(cfg *config.Config) error {
	if cfg.OrgName == "" {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/organizations", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("fetch organizations failed (status %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	var orgsResp struct {
		Organizations []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"organizations"`
	}
	if err := json.Unmarshal(body, &orgsResp); err != nil {
		return fmt.Errorf("parse organizations: %w", err)
	}

	for _, org := range orgsResp.Organizations {
		if strings.EqualFold(org.Name, cfg.OrgName) {
			cfg.ResolvedOrgID = org.ID
			return nil
		}
	}

	// Distinguish "no orgs accessible" from "wrong name" — they have different fixes.
	if len(orgsResp.Organizations) == 0 {
		return fmt.Errorf("no organizations are accessible with this API key. " +
			"Your account may not be associated with an organization, or the API key " +
			"was issued for a different environment. Visit https://app.revelara.ai/settings/api-keys " +
			"to reconfigure, or contact support@revelara.ai")
	}

	names := make([]string, len(orgsResp.Organizations))
	for i, org := range orgsResp.Organizations {
		names[i] = org.Name
	}
	return fmt.Errorf("organization %q not found; available: %s", cfg.OrgName, strings.Join(names, ", "))
}

// ValidateCredentials checks if credentials are valid
func ValidateCredentials(cfg *config.Config) error {
	// Try to call a simple endpoint to validate
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/risks/stats", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if cfg.ResolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.ResolvedOrgID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("authentication failed (status %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server error (status %d)", resp.StatusCode)
	}

	return nil
}

// MakeAPIRequest makes an authenticated API request with the default
// 30s timeout. Most CLI calls finish well inside that budget.
//
// po-8eld4: when a longer budget is required (e.g. the knowledge
// foresight subcommand walks the graph at depth>=3 and can take
// minutes on a populated KB), call MakeAPIRequestWithTimeout instead
// and pass an explicit per-call timeout.
func MakeAPIRequest(cfg *config.Config, method, url string, body []byte) ([]byte, error) {
	return MakeAPIRequestWithTimeout(cfg, method, url, body, 30*time.Second)
}

// MakeAPIRequestWithTimeout is the per-call timeout variant of
// MakeAPIRequest. Use a generous timeout for endpoints that walk the
// knowledge graph or run hybrid search over large corpora; use the
// default 30s for most things.
func MakeAPIRequestWithTimeout(cfg *config.Config, method, url string, body []byte, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if cfg.ResolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.ResolvedOrgID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// po-l5nfr: 401 and 403 mean different things to a user. 401 = the
	// API key didn't authenticate (expired / wrong env), and "rvl login"
	// is the right fix. 403 = the key authenticated but lacks access to
	// the requested resource — usually an org mismatch — and "rvl login"
	// here sends the user into a loop. Surface them separately.
	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("authentication failed (401) - run 'rvl login' to reconfigure (API key may be expired or for a different environment)")
	}
	if resp.StatusCode == 403 {
		// po-cj4s7: there is no --org flag; point at the real remediation
		// surfaces (config file key or env var).
		return nil, fmt.Errorf("forbidden (403) - your API key authenticated but lacks access to this resource; check 'rvl config show' for the active organization, then fix it with 'rvl config set org_name <name>' or the RVL_ORG_NAME environment variable")
	}
	if resp.StatusCode >= 400 {
		// po-ug34g: prefer the spec-shaped {error, message} envelope
		// over dumping the raw body. Falls back to the body string if
		// the response isn't JSON or doesn't match the Error schema.
		if msg := extractAPIErrorMessage(respBody); msg != "" {
			return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// extractAPIErrorMessage parses the standard JSON Error envelope
// ({error: code, message: human-readable}) declared by the OpenAPI spec
// and returns "code: message" when present. Returns "" when the body
// isn't JSON-shaped or doesn't carry the envelope.
func extractAPIErrorMessage(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var env struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	switch {
	case env.Error != "" && env.Message != "":
		return env.Error + ": " + env.Message
	case env.Message != "":
		return env.Message
	case env.Error != "":
		return env.Error
	default:
		return ""
	}
}

// FetchServerPluginVersion queries the API for the latest plugin semver.
// Returns the semver base (e.g., "0.2.0") without build metadata.
// Returns empty string if the server is unreachable or returns an error.
func FetchServerPluginVersion(cfg *config.Config) string {
	if cfg == nil || cfg.APIKey == "" || cfg.APIURL == "" {
		return ""
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/plugin", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	var result struct {
		Version string `json:"version"`
		SemVer  string `json:"semver"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	// Prefer the dedicated semver field (new servers), fall back to
	// stripping build metadata from the full version (old servers).
	if result.SemVer != "" {
		return result.SemVer
	}
	if idx := strings.Index(result.Version, "+"); idx != -1 {
		return result.Version[:idx]
	}
	return result.Version
}

// PostOnboardingMilestone records an onboarding milestone via the Polaris API.
// This is fire-and-forget: errors are silently discarded so callers are never
// blocked or shown a failure on behalf of a telemetry-style call.
func PostOnboardingMilestone(cfg *config.Config, milestone string) {
	if cfg == nil || cfg.APIKey == "" || cfg.APIURL == "" {
		return
	}

	payload, err := json.Marshal(map[string]string{"milestone": milestone})
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", cfg.APIURL+"/api/v1/onboarding/milestone", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if cfg.ResolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.ResolvedOrgID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// FetchLatestCLIVersion queries GitHub releases for the latest CLI version.
// Returns the version string (e.g., "0.7.4") or empty string on error.
func FetchLatestCLIVersion() string {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/revelara-ai/rvl-cli/releases/latest", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	var result struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	return strings.TrimPrefix(result.TagName, "v")
}

// FetchSigningKey fetches the Ed25519 public key used to sign plugin tarballs.
// Returns (nil, nil) when the server explicitly has no signing support (404).
// Returns (nil, err) on network errors, unexpected non-200 responses, or decode
// failures — callers must treat a non-nil error as fail-closed.
func FetchSigningKey(cfg *config.Config) (ed25519.PublicKey, error) {
	if cfg == nil || cfg.APIURL == "" {
		return nil, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/plugin/signing-key", nil)
	if err != nil {
		return nil, fmt.Errorf("create signing-key request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch signing key: %w", err)
	}
	defer resp.Body.Close()

	// 404: signing key endpoint not configured. Fail-closed to prevent verification bypass.
	// Self-hosted deployments can set RVL_ALLOW_UNSIGNED_PLUGIN=1 to opt out.
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("fetch signing key: server returned 404 (signing not configured); set RVL_ALLOW_UNSIGNED_PLUGIN=1 to install unsigned plugins")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch signing key: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode signing key response: %w", err)
	}

	if result.Algorithm != "EdDSA" || result.PublicKey == "" {
		return nil, fmt.Errorf("signing key response missing algorithm or public_key")
	}

	keyBytes, err := hex.DecodeString(result.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode signing key hex: %w", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signing key has wrong length: got %d, want %d", len(keyBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(keyBytes), nil
}
