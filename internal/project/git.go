package project

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// DetectGitRoot returns the git repo root, or empty string if not in a git repo
func DetectGitRoot() string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// DetectGitRootFrom returns the git repo root containing dir, or empty string
// if dir is not inside a git repo. An empty dir means the current directory.
func DetectGitRootFrom(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// DetectProjectName extracts a project name from git remote or directory name
func DetectProjectName(gitRoot string) string {
	// Try git remote
	out, err := exec.Command("git", "-C", gitRoot, "remote", "get-url", "origin").Output()
	if err == nil {
		remote := strings.TrimSpace(string(out))
		// Extract repo name from URL
		// Handles: git@github.com:user/repo.git, https://github.com/user/repo.git, etc.
		remote = strings.TrimSuffix(remote, ".git")
		parts := strings.Split(remote, "/")
		if len(parts) > 0 {
			name := parts[len(parts)-1]
			// Also handle SSH style with ':'
			if idx := strings.LastIndex(name, ":"); idx >= 0 {
				name = name[idx+1:]
			}
			if name != "" {
				return name
			}
		}
	}

	// Fall back to directory name
	return filepath.Base(gitRoot)
}
