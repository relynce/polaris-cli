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

	// Check is invoked when Impl is ImplAST or ImplHeuristic. The
	// function is responsible for parsing/inspecting src and returning
	// any Candidates it finds. relPath is forward-slash, relative to the
	// scan root. AllSrc gives heuristic matchers access to the full
	// in-memory file contents (keyed by relPath); AST matchers ignore
	// it. The field is not serialized to JSON.
	Check func(relPath string, src []byte, allSrc map[string][]byte) []Candidate `json:"-"`
}

// Candidate is what the engine emits per match: enough information for
// convert.go to produce a ScanFinding.
type Candidate struct {
	Slug        string
	File        string // relative path, forward-slash form
	LineNumber  int
	Snippet     string
	Description string
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
