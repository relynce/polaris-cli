package commands

import "testing"

func TestUpgradeCommandForPath(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	noEnv := env(map[string]string{"HOME": "/home/u"})

	cases := []struct {
		name   string
		path   string
		getenv func(string) string
		want   string
	}{
		{"brew cask apple silicon", "/opt/homebrew/Caskroom/rvl/0.8.19/rvl", noEnv, upgradeCmdBrew},
		{"brew cask intel mac", "/usr/local/Caskroom/rvl/0.8.19/rvl", noEnv, upgradeCmdBrew},
		{"brew cellar formula", "/opt/homebrew/Cellar/rvl/0.8.19/bin/rvl", noEnv, upgradeCmdBrew},
		{"linuxbrew", "/home/linuxbrew/.linuxbrew/bin/rvl", noEnv, upgradeCmdBrew},
		{"go default home bin", "/home/u/go/bin/rvl", noEnv, upgradeCmdGo},
		{"gobin set", "/custom/gobin/rvl", env(map[string]string{"GOBIN": "/custom/gobin"}), upgradeCmdGo},
		{"gopath bin", "/work/gopath/bin/rvl", env(map[string]string{"GOPATH": "/work/gopath"}), upgradeCmdGo},
		{"multi gopath second entry", "/second/bin/rvl", env(map[string]string{"GOPATH": "/first:/second"}), upgradeCmdGo},
		{"unknown system path", "/usr/bin/rvl", noEnv, ""},
		{"unknown manual install", "/usr/local/bin/rvl", noEnv, ""},
		{"go-like but not bin dir", "/home/u/go/src/rvl", noEnv, ""},
	}
	for _, tc := range cases {
		if got := upgradeCommandForPath(tc.path, tc.getenv); got != tc.want {
			t.Errorf("%s: upgradeCommandForPath(%q) = %q, want %q", tc.name, tc.path, got, tc.want)
		}
	}
}
