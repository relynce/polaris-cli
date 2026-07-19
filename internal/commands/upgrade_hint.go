package commands

import (
	"os"
	"path/filepath"
	"strings"
)

// Upgrade commands per install method. The releases page is printed separately
// and unconditionally, so an unrecognized install path just omits the command.
const (
	upgradeCmdBrew = "brew upgrade --cask revelara-ai/tap/rvl"
	upgradeCmdGo   = "go install github.com/revelara-ai/rvl-cli/cmd/rvl@latest"
)

// upgradeCommand returns the upgrade instruction matching how this binary was
// installed, or "" when the method cannot be determined (po-t1mu7). Symlinks
// are resolved first: the brew cask links $(brew --prefix)/bin/rvl into the
// Caskroom, so the resolved path is the reliable signal.
func upgradeCommand() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return upgradeCommandForPath(exe, os.Getenv)
}

// upgradeCommandForPath classifies an executable path. Split from
// upgradeCommand for testability.
func upgradeCommandForPath(exe string, getenv func(string) string) string {
	slashed := filepath.ToSlash(exe)
	lower := strings.ToLower(slashed)

	// Homebrew: cask binaries resolve into a Caskroom (formulae into a
	// Cellar); prefix match covers /opt/homebrew, /usr/local/Homebrew, and
	// /home/linuxbrew/.linuxbrew.
	for _, marker := range []string{"/caskroom/", "/cellar/", "/homebrew/", "/.linuxbrew/"} {
		if strings.Contains(lower, marker) {
			return upgradeCmdBrew
		}
	}

	// go install: GOBIN wins, then every GOPATH entry's bin/, then the
	// default ~/go/bin.
	var goBins []string
	if gobin := getenv("GOBIN"); gobin != "" {
		goBins = append(goBins, gobin)
	}
	if gopath := getenv("GOPATH"); gopath != "" {
		for _, p := range filepath.SplitList(gopath) {
			if p != "" {
				goBins = append(goBins, filepath.Join(p, "bin"))
			}
		}
	}
	if home := getenv("HOME"); home != "" {
		goBins = append(goBins, filepath.Join(home, "go", "bin"))
	}
	dir := filepath.ToSlash(filepath.Dir(exe))
	for _, b := range goBins {
		if dir == filepath.ToSlash(b) {
			return upgradeCmdGo
		}
	}

	return ""
}
