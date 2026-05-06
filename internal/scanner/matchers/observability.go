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

// missingHealthEndpoint flags files that register HTTP routes via
// common Go libraries but do NOT register a /health or /healthz path
// nearby. The check is per-file and conservative (does not chase
// imports), so it only fires when the file actually has route
// declarations.
func missingHealthEndpoint() scanner.Matcher {
	primary := regexp.MustCompile(`(?m)\b(?:http\.HandleFunc|mux\.Handle\b|router\.(?:GET|POST|HandleFunc|Handle)|app\.(?:get|post|use))\s*\(`)
	negate := regexp.MustCompile(`/healthz|/health\b|/readyz|/livez`)
	return scanner.Matcher{
		Slug:         "missing-health-endpoint",
		Description:  "HTTP route registration without /health or /healthz",
		Category:     "monitoring_gaps",
		ControlCodes: []string{"RC-002"},
		Languages:    []string{"Go", "JavaScript", "TypeScript"},
		FilePatterns: []string{"**/*.go", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"},
		Confidence:   "medium",
		Severity:     "medium",
		Impl:         scanner.ImplRegex,
		Source:       "curated",
		Patterns: []scanner.Pattern{{
			Regex:       primary,
			Label:       "HTTP route registration without /health* nearby",
			NegateRegex: negate,
			NegateScope: scanner.NegateScope{Kind: "window", Window: 50},
		}},
		Provenance: scanner.Provenance{
			FailureDescription: "Services without health endpoints get traffic during startup or degradation",
			IncidentFrequency:  "Common in 'deployed but not ready' incidents",
			TypicalBlastRadius: "service-level",
			TypicalMTTR:        "rollback latency",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-002"},
		},
	}
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
	}
}
