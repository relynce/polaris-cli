package plugin

import (
	"strconv"
	"strings"
)

// SemVerBase strips build metadata (after +) from a version string.
// "0.2.0+abc123f" -> "0.2.0"
// "dev-abc123f+abc123f" -> "dev-abc123f"
func SemVerBase(version string) string {
	base, _, _ := strings.Cut(version, "+")
	return base
}

// SemVerNewer returns true if available is a newer semver than installed.
// Both versions should be MAJOR.MINOR.PATCH format (build metadata is stripped).
// Returns false if either version is not valid semver (e.g., "dev" builds),
// in which case it falls back to string inequality on the base portion.
func SemVerNewer(installed, available string) bool {
	iParts := parseSemVer(SemVerBase(installed))
	aParts := parseSemVer(SemVerBase(available))
	if iParts == nil || aParts == nil {
		return SemVerBase(installed) != SemVerBase(available)
	}
	for i := 0; i < 3; i++ {
		if aParts[i] > iParts[i] {
			return true
		}
		if aParts[i] < iParts[i] {
			return false
		}
	}
	return false // equal
}

func parseSemVer(v string) []int {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	result := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		result[i] = n
	}
	return result
}
