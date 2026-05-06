package scanner

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLocationFingerprintIsTier2Compatible(t *testing.T) {
	// PRD §Deterministic Fingerprinting: format must mirror Polaris's
	// computeLocationFingerprint. Hashes basename:line|service.
	fp := LocationFingerprint("internal/scanner/engine.go", 42, "polaris")
	if !strings.HasPrefix(fp, "loc-") {
		t.Errorf("fingerprint=%q, want loc- prefix", fp)
	}
	if len(fp) != len("loc-")+16 { // 8 bytes hex = 16 chars
		t.Errorf("fingerprint=%q, want 20 chars total", fp)
	}
}

func TestLocationFingerprintIsCrossPlatformStable(t *testing.T) {
	// The same file:line:service should hash identically regardless of
	// the path separator the caller uses. PRD §Path normalization.
	a := LocationFingerprint("internal/scanner/engine.go", 42, "polaris")
	b := LocationFingerprint(filepath.FromSlash("internal/scanner/engine.go"), 42, "polaris")
	if a != b {
		t.Errorf("forward-slash and OS-native paths produced different fingerprints: %q vs %q", a, b)
	}
}

func TestLocationFingerprintIgnoresDirectoryStructure(t *testing.T) {
	// PRD: Tier 2 uses basename only, so two same-named files in different
	// directories collide intentionally. Documenting this contract.
	a := LocationFingerprint("a/b/engine.go", 42, "svc")
	b := LocationFingerprint("c/d/engine.go", 42, "svc")
	if a != b {
		t.Errorf("expected basename-only fingerprint, got different hashes: %q vs %q", a, b)
	}
}

func TestLocationFingerprintIsServiceScoped(t *testing.T) {
	a := LocationFingerprint("engine.go", 42, "svc-a")
	b := LocationFingerprint("engine.go", 42, "svc-b")
	if a == b {
		t.Errorf("expected service-scoped fingerprints, got the same hash for different services: %q", a)
	}
}

func TestLocationFingerprintEmptyOnInvalidInput(t *testing.T) {
	if got := LocationFingerprint("", 1, "svc"); got != "" {
		t.Errorf("empty path should produce empty fingerprint, got %q", got)
	}
	if got := LocationFingerprint("f.go", 0, "svc"); got != "" {
		t.Errorf("zero line should produce empty fingerprint, got %q", got)
	}
}

func TestNormalizePathToForwardSlash(t *testing.T) {
	// On Unix this is a no-op, but the test guards against accidental
	// changes to NormalizePath that break Windows scans.
	if got := NormalizePath("a/b/c.go"); got != "a/b/c.go" {
		t.Errorf("NormalizePath(forward-slash)=%q, want unchanged", got)
	}
}

func TestNegateScopeRejectsFileScope(t *testing.T) {
	// PRD §Negation Scope: 'file' scope is forbidden.
	err := NegateScope{Kind: "file"}.Validate()
	if err == nil {
		t.Fatal("Validate() accepted file scope; PRD forbids it")
	}
	if !strings.Contains(err.Error(), "file") {
		t.Errorf("error message should reference 'file' scope; got %q", err)
	}
}

func TestNegateScopeAcceptsValidKinds(t *testing.T) {
	cases := []NegateScope{
		{Kind: ""},
		{Kind: "line"},
		{Kind: "window", Window: 10},
		{Kind: "block"},
	}
	for _, c := range cases {
		if err := c.Validate(); err != nil {
			t.Errorf("Validate(%+v)=%v, want nil", c, err)
		}
	}
}

func TestNegateScopeRejectsZeroWindow(t *testing.T) {
	if err := (NegateScope{Kind: "window", Window: 0}).Validate(); err == nil {
		t.Error("Validate({window, Window=0}) should fail")
	}
}
