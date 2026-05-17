package matchers

import (
	"regexp"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// observabilityMatchers returns matchers in the monitoring_gaps
// category.
func observabilityMatchers() []scanner.Matcher {
	return []scanner.Matcher{
		missingHealthEndpoint(),
		noStructuredLogging(),
	}
}

// missingHealthEndpoint is now implemented as a heuristic that
// inspects all route registrations in a file. See
// missingHealthEndpointHeuristic in health_endpoint_heuristic.go.
// The shim here keeps the registry stable.
func missingHealthEndpoint() scanner.Matcher {
	return missingHealthEndpointHeuristic()
}

// noStructuredLogging flags fmt.Println / console.log usage in
// non-test code. Unstructured logs are unsearchable during incidents.
// Confidence: low — many codebases use these intentionally for CLI
// output. Test files are skipped via AppliesToTests=false.
func noStructuredLogging() scanner.Matcher {
	primary := regexp.MustCompile(`(?m)\bfmt\.Println\(|\bfmt\.Printf\(|\bconsole\.log\(`)
	return scanner.Matcher{
		Slug:         "no-structured-logging",
		Description:  "fmt.Println / console.log in non-test code",
		Category:     "monitoring_gaps",
		ControlCodes: []string{"RC-002"},
		Languages:    []string{"Go", "JavaScript", "TypeScript"},
		FilePatterns: []string{"**/*.go", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"},
		ExcludePatterns: []string{
			"**/cmd/**",   // CLI entry points legitimately print
			"**/main.go",
		},
		AppliesToTests: false,
		Confidence:     "low",
		Severity:       "low",
		Impl:           scanner.ImplRegex,
		Source:         "curated",
		Patterns: []scanner.Pattern{{
			Regex:       primary,
			Label:       "unstructured log call in production code",
			NegateScope: scanner.NegateScope{Kind: "line"},
		}},
		Provenance: scanner.Provenance{
			FailureDescription: "Unstructured logs are unsearchable during incidents and extend MTTR",
			IncidentFrequency:  "Universal in 'couldn't find the relevant logs' retrospectives",
			TypicalBlastRadius: "search latency",
			TypicalMTTR:        "elevated",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-002"},
		},
		// Rollup per package: 200+ findings per scan is unactionable.
		// One Finding per Go package directs the developer at one
		// migration target ("this package still prints; switch to slog").
		RollupKey: scanner.RollupByPackage,
	}
}
