package scanner

import (
	"fmt"
	"path"
	"strings"
)

// Rollup helpers used by Matcher.RollupKey. Each helper takes a Candidate
// and returns a stable string key; convert.go groups Candidates that share
// the same (Slug, RollupKey(c)) into one ScanFinding.
//
// A helper that returns "" tells convert.go to fall back to per-location
// grouping for that specific Candidate. This lets a matcher partially roll
// up (e.g., known files collapse, unknown files stay per-line).

// RollupByProject collapses every Candidate from a matcher into a single
// ScanFinding regardless of where it occurred. Use for cross-cutting
// matchers whose answer is one global fact about the project
// (e.g., missing-circuit-breaker: "no CB library is imported anywhere").
func RollupByProject(_ Candidate) string {
	return "project"
}

// RollupByFile groups Candidates per source file. Use when one file
// repeatedly trips the same pattern for the same underlying reason
// (e.g., raw-sql-no-params in a query-builder helper).
func RollupByFile(c Candidate) string {
	return c.File
}

// RollupByPackage approximates the Go package containing the file by
// using its directory. Files at the repo root collapse under "<root>".
// Use for matchers like no-error-wrapping where one team-owned package
// should produce one Finding instead of one per function.
func RollupByPackage(c Candidate) string {
	if c.File == "" {
		return ""
	}
	dir := path.Dir(c.File)
	if dir == "" || dir == "." {
		return "<root>"
	}
	return dir
}

// RollupByFunction groups Candidates by enclosing function (AST matchers).
// Matchers must set Candidate.EnclosingFunction; if empty, the helper
// returns "" and convert.go falls back to per-location grouping.
func RollupByFunction(c Candidate) string {
	if c.EnclosingFunction == "" {
		return ""
	}
	return c.File + "::" + c.EnclosingFunction
}

// RollupByK8sWorkload groups by Kubernetes (Kind, Name) so the same
// Deployment patched across dev/staging/prod overlays collapses into
// one Finding. Matchers must set K8sKind and K8sName.
func RollupByK8sWorkload(c Candidate) string {
	if c.K8sKind == "" || c.K8sName == "" {
		return ""
	}
	return c.K8sKind + "/" + c.K8sName
}

// RollupByImageRef groups by container image reference. The reference
// is lower-cased for case-insensitive comparison. Matchers must set
// Candidate.ImageRef.
func RollupByImageRef(c Candidate) string {
	if c.ImageRef == "" {
		return ""
	}
	return strings.ToLower(c.ImageRef)
}

// RollupByColumn groups by SQL (Table, Column). Use for schema matchers
// like integer-column-not-bigint where a column's migration trail
// (CREATE TABLE plus subsequent ALTERs) should produce one Finding scoped
// to the column's current latest state. Matchers must set SQLTable and
// SQLColumn.
func RollupByColumn(c Candidate) string {
	if c.SQLColumn == "" {
		return ""
	}
	if c.SQLTable == "" {
		return c.SQLColumn
	}
	return c.SQLTable + "." + c.SQLColumn
}

// rollupKeyFor returns the grouping key for a Candidate. Non-empty
// Matcher.RollupKey result wins; otherwise we fall back to per-location
// (preserving pre-W2 behavior for matchers that haven't opted in).
func rollupKeyFor(m Matcher, c Candidate) string {
	if m.RollupKey != nil {
		if k := m.RollupKey(c); k != "" {
			return k
		}
	}
	return fmt.Sprintf("%s:%d", c.File, c.LineNumber)
}
