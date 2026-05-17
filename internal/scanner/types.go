// Package scanner implements the local reliability scanner that runs
// pattern matchers against a codebase without an LLM. See PRD
// docs/PRD/local-reliability-scanner.md (in polaris) for design context.
package scanner

import "regexp"

// Impl declares how a Matcher executes. The engine dispatches to a different
// driver per kind.
type Impl string

const (
	ImplRegex     Impl = "regex"
	ImplAST       Impl = "ast"
	ImplHeuristic Impl = "heuristic"
)

// NegateScope controls the proximity within which a NegateRegex must match
// to suppress a primary finding. PRD §Negation Scope is authoritative.
//
// Valid forms:
//
//	{Kind: "line"}                 — same line as the primary match
//	{Kind: "window", Window: 10}   — within Window lines of the primary match
//	{Kind: "block"}                — within the same AST block (AST matchers only)
//
// "file" scope is forbidden: it silently suppresses real findings whenever
// any other instance in the same file is correctly configured.
type NegateScope struct {
	Kind   string
	Window int
}

// DefaultNegateScope is window:10. This is what regex matchers use when they
// declare a NegateRegex without an explicit scope.
var DefaultNegateScope = NegateScope{Kind: "window", Window: 10}

// Validate returns an error if the scope is malformed or uses the forbidden
// "file" kind.
func (s NegateScope) Validate() error {
	switch s.Kind {
	case "":
		return nil
	case "line":
		return nil
	case "window":
		if s.Window <= 0 {
			return errInvalidScope("window scope requires Window > 0")
		}
		return nil
	case "block":
		return nil
	case "file":
		return errInvalidScope("'file' negate scope is forbidden (PRD §Negation Scope)")
	default:
		return errInvalidScope("unknown negate scope kind: " + s.Kind)
	}
}

type errInvalidScope string

func (e errInvalidScope) Error() string { return string(e) }

// Pattern is a single regex check (with optional same-scope negation) inside
// a Matcher. A Matcher may have multiple Patterns; any one match produces a
// Candidate.
type Pattern struct {
	Regex       *regexp.Regexp
	Label       string
	NegateRegex *regexp.Regexp
	NegateScope NegateScope
}

// Provenance describes why a matcher exists: which real-world failure mode
// it detects, how often that mode appears in incident data, and what
// reliability controls it relates to. Phase 2 generated matchers also
// populate the Source* fields so findings link back to the originating
// knowledge-graph patterns.
type Provenance struct {
	FailureDescription  string
	IncidentFrequency   string
	TypicalBlastRadius  string
	TypicalMTTR         string
	SourcePatternTypes  []string
	RelatedControls     []string
	SourcePatternIDs    []string
	OrgIncidentCount    int
	OrgAffectedServices []string
}

// Matcher is a single check the scanner runs against the codebase. Matchers
// are mostly data; AST and heuristic matchers carry a code-only Check
// function which is intentionally not serialized. Future org-generated
// matchers ship as JSON and use only the regex Patterns field — the
// generator (Phase 2) will not produce matchers that require semantic
// understanding.
type Matcher struct {
	Slug            string
	Description     string
	Category        string
	ControlCodes    []string
	Languages       []string
	FilePatterns    []string
	ExcludePatterns []string
	AppliesToTests  bool
	Confidence      string
	Severity        string
	Impl            Impl
	Patterns        []Pattern
	Provenance      Provenance
	Source          string // "curated" (Phase 1) or "org-generated" (Phase 2)

	// po-qs96.2: Floor matchers signal compliance/security failures that
	// are not reliability tradeoffs. When the org or service has
	// strict_enforcement: true, findings from floor matchers bypass the
	// standard waiver path and require emergency override. When
	// strict_enforcement is false (default), floor: true is metadata
	// only — the finding scores and waives like any other matcher.
	// Initial floor set: raw-sql-no-params, hardcoded-connection-string,
	// terraform-no-encryption.
	Floor bool

	// Check is invoked when Impl is ImplAST or ImplHeuristic. The
	// function is responsible for parsing/inspecting src and returning
	// any Candidates it finds.
	//
	//   - absPath is the file's absolute path on disk. Matchers that
	//     need to inspect sibling files (e.g., rollback-migration
	//     looking for *.down.sql next to *.up.sql) use this.
	//   - relPath is forward-slash, relative to the scan root.
	//   - src is the file contents.
	//
	// The field is not serialized to JSON; AST matchers built from
	// org-generated JSON cannot supply a function pointer.
	Check func(absPath, relPath string, src []byte) []Candidate `json:"-"`

	// RollupKey, when non-nil, groups Candidates emitted by this matcher
	// into one ScanFinding per (Slug, RollupKey(c)) pair. Each grouped
	// Candidate becomes one Evidence entry. The default (nil) preserves
	// today's behavior of one Finding per (Slug, File, LineNumber).
	//
	// Matchers should use a helper from rollup.go (RollupByProject,
	// RollupByFile, RollupByPackage, RollupByFunction, RollupByK8sWorkload,
	// RollupByImageRef, RollupByColumn) rather than building keys ad hoc,
	// so behavior stays uniform across matchers.
	//
	// Not serialized; org-generated matchers (Phase 2) inherit a default
	// based on Impl.
	RollupKey func(c Candidate) string `json:"-"`
}

// Candidate is what the engine emits per match: enough information for
// convert.go to produce a ScanFinding.
type Candidate struct {
	Slug        string
	File        string // relative path, forward-slash form
	LineNumber  int
	Snippet     string
	Description string

	// Optional metadata used by rollup helpers in rollup.go. Matchers
	// populate the field that matches their rollup strategy:
	//
	//   - EnclosingFunction: AST matchers that group per function
	//     (e.g., panic-in-goroutine collapsing multiple goroutine launches
	//     in one function into one Finding).
	//   - K8sKind, K8sName: k8s YAML matchers that collapse the same
	//     workload across overlay files into one Finding.
	//   - ImageRef: k8s/dockerfile matchers that collapse mutable-tag
	//     uses of the same image across files.
	//   - SQLTable, SQLColumn: migration matchers that collapse a column's
	//     historical migration trail into one Finding scoped to the
	//     latest-state column.
	//
	// Empty values are safe — rollup helpers fall back to file:line.
	EnclosingFunction string
	K8sKind           string
	K8sName           string
	ImageRef          string
	SQLTable          string
	SQLColumn         string
}

// ScanOptions configures one engine invocation.
type ScanOptions struct {
	Root            string
	Service         string
	Languages       []string // override auto-detected (empty = auto)
	OnlyFiles       []string // for --changed-only; empty = walk everything
	OnlyMatchers    []string // for --matchers; empty = all applicable
	ExcludeMatchers map[string]bool
	ExcludePaths    []string
	ConfidenceMin   string // "low" | "medium" | "high"; "" = no filter
	IncludeTests    bool   // global override for AppliesToTests=false matchers
}

// ScanStats reports what the engine did. Useful for --list-matchers preview
// and for the summary table.
type ScanStats struct {
	FilesScanned int
	BytesScanned int64
	MatchersRun  int
	DurationMS   int64
}
