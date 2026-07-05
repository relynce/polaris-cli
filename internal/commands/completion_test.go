package commands

import (
	"strings"
	"testing"
)

// realTopLevelCommands is the set of user-facing top-level commands the CLI
// dispatches in cmd/rvl/main.go. Shell completion must offer all of them.
// po-i24do.8: report, review, stpa, and migrate were previously missing.
var realTopLevelCommands = []string{
	"init", "login", "logout", "status", "scan", "review", "risk",
	"control", "report", "knowledge", "incident", "evidence", "stpa",
	"commands", "plugin", "completion", "config", "migrate", "version",
}

func TestBashCompletionListsAllCommands(t *testing.T) {
	for _, c := range realTopLevelCommands {
		if !strings.Contains(bashCompletion, " "+c+" ") &&
			!strings.Contains(bashCompletion, " "+c+`"`) &&
			!strings.Contains(bashCompletion, `"`+c+" ") {
			t.Errorf("bash completion missing command %q", c)
		}
	}
}

func TestZshCompletionListsAllCommands(t *testing.T) {
	for _, c := range realTopLevelCommands {
		if !strings.Contains(zshCompletion, "'"+c+":") {
			t.Errorf("zsh completion missing command %q", c)
		}
	}
}

func TestFishCompletionListsAllCommands(t *testing.T) {
	for _, c := range realTopLevelCommands {
		if !strings.Contains(fishCompletion, `-a "`+c+`"`) {
			t.Errorf("fish completion missing command %q", c)
		}
	}
}

func TestCompletionIncludesStpaSubcommands(t *testing.T) {
	for _, sub := range []string{"list-ucas", "submit"} {
		if !strings.Contains(zshCompletion, "'"+sub+"'") {
			t.Errorf("zsh stpa subcommand %q missing", sub)
		}
		if !strings.Contains(fishCompletion, `stpa" -a "`+sub+`"`) {
			t.Errorf("fish stpa subcommand %q missing", sub)
		}
	}
}
