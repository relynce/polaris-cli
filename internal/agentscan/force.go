package agentscan

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// This file implements the emergency force-through for the agent gate
// (po-66evv.6). Two mechanisms, both audited:
//
//   - RVL_FORCE=1 in the environment (CI / shell one-liner).
//   - A one-shot marker file written by `rvl scan force-next`, consumed
//     by the next agent gate run. This exists because GUI git clients
//     cannot easily set an env var for the hook process.
//
// Force-through SKIPS the scan entirely (spec: Gate policy) - it is the
// emergency path for shipping a lesser risk to fix a greater one, so it
// must not pay the scan's wall-clock or cost. It is distinct from
// `git commit --no-verify` (which skips all hooks and leaves no record):
// a force-through is written to the local audit trail.

// ForceMarkerName is the one-shot marker file, stored in the repo's git
// dir so it is per-worktree and never committed.
const ForceMarkerName = "rvl-force-next"

// forceMarker is the JSON payload recorded in the marker file.
type forceMarker struct {
	CreatedAt string `json:"created_at"`
	User      string `json:"user"`
}

// resolveGitDir returns the absolute git dir for root, resolved via
// `git rev-parse --git-dir` so linked worktrees (where .git is a file)
// and core.hooksPath-style layouts land in the correct per-worktree dir.
func resolveGitDir(root string) (string, error) {
	out, err := runGit(root, "rev-parse", "--git-dir")
	if err != nil {
		return "", fmt.Errorf("resolve git dir: %w", err)
	}
	gitDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	return gitDir, nil
}

// currentUser returns git config user.name, falling back to $USER, then
// "unknown". Used only for the audit record.
func currentUser(root string) string {
	if out, err := runGit(root, "config", "user.name"); err == nil {
		if name := strings.TrimSpace(string(out)); name != "" {
			return name
		}
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if env := os.Getenv("USER"); env != "" {
		return env
	}
	return "unknown"
}

// ForceState reports whether a force-through is in effect and by which
// mechanism ("env" or "marker"). The env var takes precedence as the
// reported mechanism, but a present marker is still reported as
// consumable via MarkerPresent so the caller consumes it either way and
// it cannot silently apply to a later run.
func ForceState(root string) (mechanism string, forced bool, err error) {
	if os.Getenv("RVL_FORCE") == "1" {
		return "env", true, nil
	}
	present, err := MarkerPresent(root)
	if err != nil {
		return "", false, err
	}
	if present {
		return "marker", true, nil
	}
	return "", false, nil
}

// MarkerPresent reports whether the one-shot marker exists.
func MarkerPresent(root string) (bool, error) {
	gitDir, err := resolveGitDir(root)
	if err != nil {
		return false, err
	}
	_, statErr := os.Stat(filepath.Join(gitDir, ForceMarkerName))
	if statErr == nil {
		return true, nil
	}
	if os.IsNotExist(statErr) {
		return false, nil
	}
	return false, statErr
}

// WriteForceMarker creates the one-shot marker in the git dir and
// returns its path. Overwriting an existing marker is fine (idempotent).
func WriteForceMarker(root string) (string, error) {
	gitDir, err := resolveGitDir(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(gitDir, ForceMarkerName)
	payload, err := json.Marshal(forceMarker{
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		User:      currentUser(root),
	})
	if err != nil {
		return "", fmt.Errorf("marshal force marker: %w", err)
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("write force marker: %w", err)
	}
	return path, nil
}

// ConsumeForceMarker removes the one-shot marker. A missing marker is
// not an error (exactly-once consumption is idempotent), so calling it
// after an env-mechanism force still clears any stale marker.
func ConsumeForceMarker(root string) error {
	gitDir, err := resolveGitDir(root)
	if err != nil {
		return err
	}
	rmErr := os.Remove(filepath.Join(gitDir, ForceMarkerName))
	if rmErr != nil && !os.IsNotExist(rmErr) {
		return fmt.Errorf("consume force marker: %w", rmErr)
	}
	return nil
}
