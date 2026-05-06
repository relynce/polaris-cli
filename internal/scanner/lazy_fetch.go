package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// LazyFetchTTL is the freshness window for the org-matcher cache.
// PRD §Phase 2 — Matcher delivery (option c lazy-fetch).
const LazyFetchTTL = 24 * time.Hour

// LazyFetchOrgMatchers refreshes the local cache of org-generated
// matchers if the manifest is missing or stale. On API or filesystem
// failure it logs a warning and returns nil so the scanner can proceed
// with compiled-in matchers only.
//
// apiURL is the base Polaris API URL (e.g., https://api.revelara.ai).
// apiKey is the user's API key. orgID, when non-empty, is sent as the
// X-Organization-ID header.
func LazyFetchOrgMatchers(apiURL, apiKey, orgID string) {
	cacheDir, err := OrgMatcherCacheDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: lazy-fetch: cannot resolve cache dir: %v\n", err)
		return
	}

	if !needsRefresh(cacheDir) {
		return
	}

	matchers, err := fetchOrgMatchers(apiURL, apiKey, orgID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: lazy-fetch: %v (continuing with compiled-in matchers only)\n", err)
		return
	}

	if err := writeMatchers(cacheDir, matchers); err != nil {
		fmt.Fprintf(os.Stderr, "scanner: lazy-fetch: write cache: %v\n", err)
		return
	}
}

func needsRefresh(cacheDir string) bool {
	manifest := filepath.Join(cacheDir, "manifest.json")
	info, err := os.Stat(manifest)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) > LazyFetchTTL
}

type listResponse struct {
	Matchers []json.RawMessage `json:"matchers"`
}

func fetchOrgMatchers(apiURL, apiKey, orgID string) ([]json.RawMessage, error) {
	if apiURL == "" {
		return nil, fmt.Errorf("API URL not configured")
	}
	req, err := http.NewRequest("GET", apiURL+"/api/v1/scanner/matchers", nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	if orgID != "" {
		req.Header.Set("X-Organization-ID", orgID)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("API returned %d (auth issue; run 'rvl login' if needed)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}
	var lr listResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return lr.Matchers, nil
}

type rawMatcherDef struct {
	Slug       string          `json:"slug"`
	Definition json.RawMessage `json:"definition"`
}

// writeMatchers writes one file per matcher into cacheDir plus a
// manifest with the current timestamp.
func writeMatchers(cacheDir string, raws []json.RawMessage) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	// Wipe the directory of stale matchers (definition may have
	// changed; slug may have been retracted).
	entries, _ := os.ReadDir(cacheDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(cacheDir, e.Name()))
	}

	type manifestEntry struct {
		Slug      string `json:"slug"`
		FetchedAt string `json:"fetched_at"`
	}
	manifest := struct {
		FetchedAt string          `json:"fetched_at"`
		Matchers  []manifestEntry `json:"matchers"`
	}{FetchedAt: time.Now().UTC().Format(time.RFC3339)}

	for _, r := range raws {
		var entry rawMatcherDef
		if err := json.Unmarshal(r, &entry); err != nil {
			fmt.Fprintf(os.Stderr, "scanner: lazy-fetch: skip malformed matcher: %v\n", err)
			continue
		}
		// The server returns {id, slug, ..., definition: <matcher json>}.
		// What we cache on disk is the matcher definition itself, named
		// after the slug — that's what loader.go consumes.
		if entry.Slug == "" || len(entry.Definition) == 0 {
			continue
		}
		path := filepath.Join(cacheDir, sanitizeSlugForFile(entry.Slug)+".json")
		if err := os.WriteFile(path, entry.Definition, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "scanner: lazy-fetch: write %s: %v\n", path, err)
			continue
		}
		manifest.Matchers = append(manifest.Matchers, manifestEntry{
			Slug: entry.Slug, FetchedAt: manifest.FetchedAt,
		})
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cacheDir, "manifest.json"), manifestBytes, 0o644)
}

// sanitizeSlugForFile keeps the slug useful as a filename without
// trusting it (slugs are server-generated but a future bug could
// produce path-traversal characters).
func sanitizeSlugForFile(slug string) string {
	out := make([]byte, 0, len(slug))
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}
