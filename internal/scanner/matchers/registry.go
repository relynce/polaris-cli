// Package matchers holds the curated, compiled-in matcher set. Adding a new
// matcher means adding a Matcher value to one of the domain files in this
// package and registering it via the package-level init function. The
// engine only sees matchers via AllMatchers().
package matchers

import "github.com/revelara-ai/rvl-cli/internal/scanner"

// AllMatchers returns the complete curated matcher set in stable order.
// Used by:
//
//   - scanner.Scan() (engine input)
//   - --list-matchers (human-readable listing)
//   - tests
//
// New matchers must be added to one of the domain functions below, NOT by
// appending to a package-level slice elsewhere. Centralizing registration
// here keeps the registry as the single source of truth.
func AllMatchers() []scanner.Matcher {
	var out []scanner.Matcher
	out = append(out, faultToleranceMatchers()...)
	out = append(out, concurrencyASTMatchers()...)
	out = append(out, heuristicMatchers()...)
	return out
}

// heuristicMatchers returns matchers that need cross-cutting analysis
// per file (e.g., import-set inspection) rather than line-level regex
// or AST block walking. They ship at lower confidence because the
// heuristic by design accepts some false positives.
func heuristicMatchers() []scanner.Matcher {
	return []scanner.Matcher{
		missingCircuitBreaker(),
	}
}
