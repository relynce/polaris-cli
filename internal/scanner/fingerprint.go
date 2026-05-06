package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

// LocationFingerprint computes a Tier-2-compatible fingerprint that mirrors
// Polaris's server-side computeLocationFingerprint in
// internal/api/risk_service.go. By emitting the same shape, local-scanner
// findings dedup against AI-scanner findings for the same code location.
//
// Format: "loc-<hex(SHA256(basename|line|service)[:8])>"
//
// Only basename (not full path) is used so fingerprints are stable across
// platforms. Note that this means two files with the same name in different
// directories will collide intentionally — Polaris already accepts that
// trade-off in its multi-tier strategy.
func LocationFingerprint(filePath string, lineNumber int, service string) string {
	if filePath == "" || lineNumber <= 0 {
		return ""
	}
	// Take basename in a path-separator-agnostic way.
	base := filepath.Base(filepath.FromSlash(filePath))
	input := fmt.Sprintf("%s:%d|%s", base, lineNumber, strings.ToLower(strings.TrimSpace(service)))
	hash := sha256.Sum256([]byte(input))
	return "loc-" + hex.EncodeToString(hash[:8])
}

// NormalizePath returns the path in forward-slash form. The scanner emits all
// evidence paths normalized so Windows-host scans display consistently in
// Polaris and produce the same fingerprint as Unix-host scans.
func NormalizePath(p string) string {
	return filepath.ToSlash(p)
}
