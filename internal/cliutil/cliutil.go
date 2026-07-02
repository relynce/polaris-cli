// Package cliutil holds small helpers shared by every rvl command
// dispatcher so help handling and usage errors behave identically
// across command groups.
//
// Exit-code convention (documented in the root help and README):
//
//	0  success, including help output (help / -h / --help)
//	1  runtime failure (API error, auth failure, network problem)
//	2  usage error (unknown command, unknown flag, invalid argument)
//
// The documented `rvl scan --local` gate codes (0 = clean, 1 = critical/high
// finding, 2 = scanner error) and the `rvl review --enforce` / --fail-closed
// contracts are unchanged and take precedence within those commands.
package cliutil

import (
	"fmt"
	"os"
)

// Exit codes for the CLI-wide contract. See package comment.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// WantsHelp reports whether the user asked for help: the first argument
// is "help", or any argument is "-h"/"--help". Dispatchers must check
// this before loading config or touching the network so `rvl <group>
// --help` prints usage to stdout and exits 0 with zero API calls.
func WantsHelp(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "help" {
		return true
	}
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// ExitUnknownFlag prints the standard unknown-flag error with a pointer
// to the group's help and exits with the usage-error code (2).
// helpCmd is the command to suggest, e.g. "rvl risk".
func ExitUnknownFlag(flag, helpCmd string) {
	fmt.Fprintf(os.Stderr, "unknown flag: %s\n", flag)
	fmt.Fprintf(os.Stderr, "Run '%s --help' for usage.\n", helpCmd)
	os.Exit(ExitUsage)
}
