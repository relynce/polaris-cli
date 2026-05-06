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
