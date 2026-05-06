package matchers

import (
	"regexp"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// faultToleranceMatchers returns the curated matchers in the
// fault_tolerance category. Each matcher's Provenance.IncidentFrequency
// values are placeholders pending the corpus-validation pass (po-fayz.16).
func faultToleranceMatchers() []scanner.Matcher {
	return []scanner.Matcher{
		missingTimeoutGo(),
		swallowedErrorGo(),
		missingRetryGo(),
		unhandledPromiseJS(),
		emptyCatchMulti(),
		globalStateMutationGo(),
	}
}

// missingTimeoutGo flags Go http.Client construction that lacks an explicit
// Timeout field. Negation is window:10 lines because the field appears
// inside the struct literal's brace block.
//
// Detection rationale: Timeout misconfiguration is a leading root cause in
// cascading-failure postmortems. A client without an explicit Timeout has
// an effectively-infinite default, so a slow upstream blocks the caller's
// goroutines until the entire pool is exhausted.
func missingTimeoutGo() scanner.Matcher {
	primary := regexp.MustCompile(`(?m)\bhttp\.Client\s*{`)
	negate := regexp.MustCompile(`Timeout\s*:`)

	return scanner.Matcher{
		Slug:         "missing-timeout",
		Description:  "HTTP clients without explicit timeout",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-018"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "high",
		Severity:     "high",
		Impl:         scanner.ImplRegex,
		Source:       "curated",
		Patterns: []scanner.Pattern{
			{
				Regex:       primary,
				Label:       "http.Client constructed without Timeout field",
				NegateRegex: negate,
				NegateScope: scanner.NegateScope{Kind: "window", Window: 10},
			},
		},
		Provenance: scanner.Provenance{
			FailureDescription: "HTTP client timeout misconfiguration leading to connection pool exhaustion and cascading failure",
			IncidentFrequency:  "Frequently cited in connection-exhaustion and cascading-failure postmortems (corpus-validation pending in po-fayz.16)",
			TypicalBlastRadius: "service-level to multi-service",
			TypicalMTTR:        "30-90 minutes",
			SourcePatternTypes: []string{"causal_chain", "failure_mode"},
			RelatedControls:    []string{"RC-018"},
		},
	}
}

// swallowedErrorGo flags `if err != nil { return nil }` and the
// `if err != nil { return nil, nil }` two-arg variant. These silently
// drop error context, masking incidents and extending MTTR.
//
// Caveat: This regex catches the dominant inline form. It misses
// `_ = err` and complex multi-statement swallowers. PRD §Starter
// Matcher Set notes the limitation; remediation is per-matcher
// confidence not engine changes.
func swallowedErrorGo() scanner.Matcher {
	primary := regexp.MustCompile(`(?m)if\s+err\s*!=\s*nil\s*\{\s*return\s+nil(\s*,\s*nil)?\s*\}`)
	return scanner.Matcher{
		Slug:         "swallowed-error",
		Description:  "Error swallowed: 'if err != nil { return nil }' drops error context",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-021"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "high",
		Severity:     "medium",
		Impl:         scanner.ImplRegex,
		Source:       "curated",
		Patterns: []scanner.Pattern{{
			Regex:       primary,
			Label:       "error returned but its value lost (return nil)",
			NegateScope: scanner.NegateScope{Kind: "line"},
		}},
		Provenance: scanner.Provenance{
			FailureDescription: "Silent failure masks the root cause and extends mean time to detect",
			IncidentFrequency:  "Commonly cited in 'long time to detect' incident retrospectives (corpus-validation pending)",
			TypicalBlastRadius: "varies by call site",
			TypicalMTTR:        "extended by dropped error context",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-021"},
		},
	}
}

// missingRetryGo flags Go HTTP client calls without a wrapping retry
// helper from common libraries. This is a low-confidence matcher: a
// false positive on intentional fail-fast paths is inherent in the
// approach. Negation matches well-known retry libraries on the same
// line.
func missingRetryGo() scanner.Matcher {
	primary := regexp.MustCompile(`(?m)\b(?:http\.(?:Get|Post|Head)|client\.Do)\s*\(`)
	negate := regexp.MustCompile(`\b(retry|backoff|Retry|Backoff)\b`)
	return scanner.Matcher{
		Slug:         "missing-retry",
		Description:  "External call without retry/backoff",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-019"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "medium",
		Severity:     "medium",
		Impl:         scanner.ImplRegex,
		Source:       "curated",
		Patterns: []scanner.Pattern{{
			Regex:       primary,
			Label:       "external call without retry library on nearby lines",
			NegateRegex: negate,
			NegateScope: scanner.NegateScope{Kind: "window", Window: 8},
		}},
		Provenance: scanner.Provenance{
			FailureDescription: "Transient failures (DNS/TLS/503) become hard failures without retry+backoff",
			IncidentFrequency:  "Common in cloud-provider outage postmortems (corpus-validation pending)",
			TypicalBlastRadius: "service-level",
			TypicalMTTR:        "elevated until retry is added or upstream recovers",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-019"},
		},
	}
}

// unhandledPromiseJS flags Promise chains without a .catch() or
// surrounding try/catch (for await-style usage). Looks for .then(...)
// or top-level fetch() without a downstream .catch within window.
func unhandledPromiseJS() scanner.Matcher {
	primary := regexp.MustCompile(`(?m)\b(?:fetch|axios\.\w+|\.then)\s*\(`)
	negate := regexp.MustCompile(`(?:\.catch\s*\(|try\s*\{|\bawait\b.*\btry\b)`)
	return scanner.Matcher{
		Slug:         "unhandled-promise",
		Description:  "Promise chain without .catch() or try/catch",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-021"},
		Languages:    []string{"JavaScript", "TypeScript"},
		FilePatterns: []string{"**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.mjs"},
		Confidence:   "medium",
		Severity:     "medium",
		Impl:         scanner.ImplRegex,
		Source:       "curated",
		Patterns: []scanner.Pattern{{
			Regex:       primary,
			Label:       "Promise chain without nearby .catch or try/catch",
			NegateRegex: negate,
			NegateScope: scanner.NegateScope{Kind: "window", Window: 6},
		}},
		Provenance: scanner.Provenance{
			FailureDescription: "Unhandled promise rejection crashes Node.js processes (or surfaces as silent UI errors)",
			IncidentFrequency:  "Common in event-driven architecture failures (corpus-validation pending)",
			TypicalBlastRadius: "process-level",
			TypicalMTTR:        "varies",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-021"},
		},
	}
}

// emptyCatchMulti flags empty catch/except blocks across Java,
// JS/TS, and Python. These have the same effect as Go's
// swallowed-error: silent failure masks root cause.
func emptyCatchMulti() scanner.Matcher {
	// Matches catch (...) { } and except (...): pass
	javaJS := regexp.MustCompile(`(?m)catch\s*\([^)]*\)\s*\{\s*\}`)
	pythonPass := regexp.MustCompile(`(?m)except[^:]*:\s*\n\s*pass\s*(?:\n|$)`)
	return scanner.Matcher{
		Slug:         "empty-catch",
		Description:  "Empty catch/except block: silent failure",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-021"},
		Languages:    []string{"Java", "JavaScript", "TypeScript", "Python"},
		FilePatterns: []string{"**/*.java", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.py"},
		Confidence:   "high",
		Severity:     "medium",
		Impl:         scanner.ImplRegex,
		Source:       "curated",
		Patterns: []scanner.Pattern{
			{Regex: javaJS, Label: "empty catch block", NegateScope: scanner.NegateScope{Kind: "line"}},
			{Regex: pythonPass, Label: "except: pass swallows the exception", NegateScope: scanner.NegateScope{Kind: "line"}},
		},
		Provenance: scanner.Provenance{
			FailureDescription: "Silent exception handling masks errors and extends MTTR",
			IncidentFrequency:  "Frequently cited in 'error was silently ignored' postmortems",
			TypicalBlastRadius: "varies by call site",
			TypicalMTTR:        "extended by missing diagnostics",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-021"},
		},
	}
}

// globalStateMutationGo is now implemented via AST inspection — see
// globalStateMutationASTGo in state_mutation_ast.go. The function is
// retained as a thin shim for the registry to keep the slug stable.
func globalStateMutationGo() scanner.Matcher {
	return globalStateMutationASTGo()
}
