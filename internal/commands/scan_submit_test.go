package commands

import (
	"os"
	"testing"
	"time"
)

// TestDeriveIdempotencyKeyStable pins po-zphjg's contract: two scan
// requests with the same body produce the same key, and the field
// itself is excluded from the hashed body (otherwise the key would
// depend on whether the caller had pre-set the key, defeating dedup).
func TestDeriveIdempotencyKeyStable(t *testing.T) {
	a := &ScanRequest{
		Service:  "test-service",
		ScanType: "full",
		Findings: []interface{}{
			map[string]interface{}{"title": "x", "category": "deployment"},
		},
	}
	b := &ScanRequest{
		Service:  "test-service",
		ScanType: "full",
		Findings: []interface{}{
			map[string]interface{}{"title": "x", "category": "deployment"},
		},
	}

	keyA := deriveIdempotencyKey(a)
	keyB := deriveIdempotencyKey(b)
	if keyA == "" {
		t.Fatal("expected non-empty key from a valid request")
	}
	if keyA != keyB {
		t.Fatalf("expected identical bodies to derive the same key; got %q vs %q", keyA, keyB)
	}

	// Setting a different value on one request must not change its
	// derived key - the function clears the field before hashing.
	a.IdempotencyKey = "pre-set"
	if got := deriveIdempotencyKey(a); got != keyA {
		t.Fatalf("expected derived key to ignore pre-set IdempotencyKey; got %q want %q", got, keyA)
	}

	// Changing meaningful content should change the key.
	b.Service = "other-service"
	if got := deriveIdempotencyKey(b); got == keyA {
		t.Fatalf("expected different service to produce different key; both were %q", got)
	}
}

// TestResolveScanTimeoutPrecedence covers the resolution order for
// po-p3k56: flag wins, then env, then the 60s default. Invalid values
// are non-fatal - the scan continues with the default.
func TestResolveScanTimeoutPrecedence(t *testing.T) {
	t.Setenv("RVL_SCAN_TIMEOUT", "")

	if got := resolveScanTimeout(""); got != defaultScanTimeout {
		t.Errorf("no flag, no env: got %s want %s", got, defaultScanTimeout)
	}

	t.Setenv("RVL_SCAN_TIMEOUT", "45s")
	if got := resolveScanTimeout(""); got != 45*time.Second {
		t.Errorf("env-only: got %s want 45s", got)
	}

	if got := resolveScanTimeout("90s"); got != 90*time.Second {
		t.Errorf("flag overrides env: got %s want 90s", got)
	}

	// Invalid flag falls through to env when env is valid.
	t.Setenv("RVL_SCAN_TIMEOUT", "45s")
	// Stderr gets a warning we ignore in tests.
	devNull, _ := os.Open(os.DevNull)
	if devNull != nil {
		defer devNull.Close()
	}
	if got := resolveScanTimeout("not-a-duration"); got != 45*time.Second {
		t.Errorf("invalid flag, valid env: got %s want 45s", got)
	}

	// Invalid flag AND invalid env falls through to default.
	t.Setenv("RVL_SCAN_TIMEOUT", "garbage")
	if got := resolveScanTimeout("also-garbage"); got != defaultScanTimeout {
		t.Errorf("all invalid: got %s want %s", got, defaultScanTimeout)
	}

	// Negative or zero durations are rejected as invalid.
	t.Setenv("RVL_SCAN_TIMEOUT", "")
	if got := resolveScanTimeout("0s"); got != defaultScanTimeout {
		t.Errorf("zero duration: got %s want %s", got, defaultScanTimeout)
	}
}
