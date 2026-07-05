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
	"strings"
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

// ValidateFormat checks that format is one of allowed, returning a usage
// error otherwise. po-i24do.11: several commands silently rendered a table
// on an invalid --format instead of failing, hiding typos like
// `--format=jsonn`. Callers should treat the error as a usage error
// (exit code 2), mirroring `rvl review`.
func ValidateFormat(format string, allowed ...string) error {
	for _, a := range allowed {
		if format == a {
			return nil
		}
	}
	return fmt.Errorf("invalid --format %q (valid: %s)", format, strings.Join(allowed, ", "))
}

// FlagValue resolves the value for a flag that may be written either as
// "--flag=value" or "--flag value". Given the full args slice and the
// current index i (pointing at args[i], which must equal name or start with
// name+"="), it returns the value and the index of the last token consumed
// (i itself for the =form, i+1 for the space form). It errors if the space
// form is used with no following token. po-i24do.11: used to normalize the
// equals-only parsers to accept both syntaxes like `rvl review` does.
func FlagValue(args []string, i int, name string) (value string, next int, err error) {
	arg := args[i]
	if arg == name {
		if i+1 >= len(args) {
			return "", i, fmt.Errorf("%s requires a value", name)
		}
		return args[i+1], i + 1, nil
	}
	if strings.HasPrefix(arg, name+"=") {
		return strings.TrimPrefix(arg, name+"="), i, nil
	}
	// Caller dispatched incorrectly; treat as programmer error surfaced as
	// an unknown flag rather than panicking.
	return "", i, fmt.Errorf("unknown flag: %s", arg)
}

// ExitUnknownFlag prints the standard unknown-flag error with a pointer
// to the group's help and exits with the usage-error code (2).
// helpCmd is the command to suggest, e.g. "rvl risk".
func ExitUnknownFlag(flag, helpCmd string) {
	fmt.Fprintf(os.Stderr, "unknown flag: %s\n", flag)
	fmt.Fprintf(os.Stderr, "Run '%s --help' for usage.\n", helpCmd)
	os.Exit(ExitUsage)
}
