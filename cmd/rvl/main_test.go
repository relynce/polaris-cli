package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// rvlBin is the path to the freshly built CLI binary used by the
// agent-contract tests below (po-cj4s7).
var rvlBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rvl-contract-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdtemp: %v\n", err)
		os.Exit(1)
	}
	rvlBin = filepath.Join(dir, "rvl-under-test")
	build := exec.Command("go", "build", "-o", rvlBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// runRvl executes the built binary with an isolated HOME (no config
// file) and an unroutable API URL. RVL_API_KEY is set so that any code
// path that wrongly loads config and calls the API fails loudly with a
// connection error (exit 1) instead of the "not configured" path; a
// truly network-free path is unaffected.
func runRvl(t *testing.T, home string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(rvlBin, args...)
	// Filter out any inherited HOME / RVL_* values first: in a Go child
	// process the FIRST occurrence of a duplicated env key wins, so a
	// plain append would not override them.
	var env []string
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		switch key {
		case "HOME", "RVL_API_KEY", "RVL_API_URL", "RVL_ORG_NAME", "RVL_SKIP_MIGRATION":
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env,
		"HOME="+home,
		"RVL_SKIP_MIGRATION=1",
		"RVL_API_KEY=test-key-do-not-use",
		"RVL_API_URL=http://127.0.0.1:9", // discard port: instant connection refused
	)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// TestHelpContract verifies that every command group answers
// help/-h/--help by printing usage on stdout and exiting 0 without
// touching config or the network (the API URL points at a closed port,
// so any accidental API call would exit non-zero).
func TestHelpContract(t *testing.T) {
	groups := []string{
		"risk", "incident", "evidence", "plugin", "status", "scan",
		"review", "control", "knowledge", "stpa", "config",
		"completion", "commands", "init", "migrate", "login", "logout",
	}
	forms := [][]string{{"--help"}, {"-h"}, {"help"}}
	home := t.TempDir()

	for _, group := range groups {
		for _, form := range forms {
			name := group + " " + strings.Join(form, " ")
			t.Run(name, func(t *testing.T) {
				args := append([]string{group}, form...)
				stdout, stderr, code := runRvl(t, home, args...)
				if code != 0 {
					t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr)
				}
				if !strings.Contains(stdout, "Usage") {
					t.Errorf("expected usage text on stdout, got stdout=%q stderr=%q", stdout, stderr)
				}
			})
		}
	}

	t.Run("root help", func(t *testing.T) {
		for _, form := range []string{"help", "--help", "-h"} {
			stdout, stderr, code := runRvl(t, home, form)
			if code != 0 {
				t.Fatalf("rvl %s: expected exit 0, got %d (stderr: %s)", form, code, stderr)
			}
			if !strings.Contains(stdout, "Usage") {
				t.Errorf("rvl %s: expected usage on stdout, got %q", form, stdout)
			}
		}
	})

	// Nested help must also short-circuit before any network call.
	t.Run("nested subcommand help", func(t *testing.T) {
		for _, args := range [][]string{
			{"risk", "list", "--help"},
			{"knowledge", "search", "--help"},
			{"plugin", "install", "--help"},
		} {
			stdout, stderr, code := runRvl(t, home, args...)
			if code != 0 {
				t.Fatalf("%v: expected exit 0, got %d (stderr: %s)", args, code, stderr)
			}
			if !strings.Contains(stdout, "Usage") {
				t.Errorf("%v: expected usage on stdout, got %q", args, stdout)
			}
		}
	})
}

// TestUsageErrorContract verifies unknown commands/flags and invalid
// arguments exit 2 with a diagnostic on stderr, again without network.
func TestUsageErrorContract(t *testing.T) {
	home := t.TempDir()
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{"unknown root command", []string{"bogus"}, "Unknown command: bogus"},
		{"unknown risk subcommand", []string{"risk", "bogus"}, "Unknown risk command: bogus"},
		{"risk list unknown flag", []string{"risk", "list", "--org-id=x"}, "unknown flag: --org-id=x"},
		{"risk list bad limit", []string{"risk", "list", "--limit=abc"}, "--limit expects a positive integer"},
		{"risk ready unknown flag", []string{"risk", "ready", "--bogus"}, "unknown flag: --bogus"},
		{"risk stale unknown flag", []string{"risk", "stale", "--service=x"}, "unknown flag: --service=x"},
		{"incident search unknown flag", []string{"incident", "search", "q", "--bogus"}, "unknown flag: --bogus"},
		{"evidence list unknown flag", []string{"evidence", "list", "--bogus"}, "unknown flag: --bogus"},
		{"control list unknown flag", []string{"control", "list", "--bogus"}, "unknown flag: --bogus"},
		{"knowledge search unknown flag", []string{"knowledge", "search", "q", "--bogus"}, "unknown flag: --bogus"},
		{"commands unknown flag", []string{"commands", "--bogus"}, "unknown flag: --bogus"},
		{"status unknown flag", []string{"status", "--bogus"}, "unknown flag: --bogus"},
		{"scan unknown flag", []string{"scan", "--bogus"}, "unknown flag: --bogus"},
		{"scan missing service value", []string{"scan", "--service"}, "--service requires a value"},
		{"scan local missing base value", []string{"scan", "--local", "--base"}, "--base requires a value"},
		{"review unknown flag", []string{"review", "--bogus"}, "unknown flag: --bogus"},
		{"review missing commit value", []string{"review", "--commit"}, "--commit requires a value"},
		{"review bad format", []string{"review", "--format=bogus"}, "--format must be text or json"},
		{"stpa list-ucas bad limit", []string{"stpa", "list-ucas", "--limit=abc"}, "--limit expects a positive integer"},
		{"knowledge enrich bad limit", []string{"knowledge", "enrich", "--limit=abc"}, "--limit expects a positive integer"},
		{"knowledge graph bad depth", []string{"knowledge", "graph", "risk", "R-1", "--depth=abc"}, "--depth expects a positive integer"},
		{"knowledge graph-search bad limit", []string{"knowledge", "graph-search", "q", "--limit=abc"}, "--limit expects a positive integer"},
		{"knowledge foresight bad min-strength", []string{"knowledge", "foresight", "--min-strength=2"}, "--min-strength expects a number between 0 and 1"},
		{"migrate unknown flag", []string{"migrate", "--bogus"}, "unknown flag: --bogus"},
		{"unknown plugin subcommand", []string{"plugin", "bogus"}, "Unknown plugin command: bogus"},
		{"unknown config key", []string{"config", "set", "bogus", "v"}, "Unknown config key: bogus"},
		{"unknown completion shell", []string{"completion", "powershell"}, "Unknown shell: powershell"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stderr, code := runRvl(t, home, tt.args...)
			if code != 2 {
				t.Fatalf("expected exit 2, got %d (stderr: %s)", code, stderr)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("expected stderr to contain %q, got %q", tt.wantStderr, stderr)
			}
		})
	}
}

// TestEnrichAllFetchesFailExitsOne verifies `rvl knowledge enrich`
// treats a total fetch failure (here: every request refused by the
// unroutable test API URL) as a runtime failure per the exit-code
// contract: errors on stderr and exit 1, not a false success.
func TestEnrichAllFetchesFailExitsOne(t *testing.T) {
	home := t.TempDir()
	_, stderr, code := runRvl(t, home, "knowledge", "enrich")
	if code != 1 {
		t.Fatalf("expected exit 1 when every fetch fails, got %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "Error:") {
		t.Errorf("expected fetch errors on stderr, got %q", stderr)
	}
}

// TestConfigSetMasksAPIKey verifies `rvl config set api_key` never
// echoes the full plaintext key back to the terminal.
func TestConfigSetMasksAPIKey(t *testing.T) {
	home := t.TempDir()
	secret := "pk_live_supersecret1234567890"

	stdout, stderr, code := runRvl(t, home, "config", "set", "api_key", secret)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr)
	}
	if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
		t.Errorf("full API key echoed to terminal: stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "Set api_key = pk_live_...") {
		t.Errorf("expected masked echo, got %q", stdout)
	}

	// Non-sensitive keys still echo their value.
	stdout, _, code = runRvl(t, home, "config", "set", "org_name", "acme-corp")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(stdout, "Set org_name = acme-corp") {
		t.Errorf("expected full echo for org_name, got %q", stdout)
	}
}
