package matchers

import (
	"regexp"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// securityMatchers returns matchers in the service_fragility category
// that double as low-grade security checks. These overlap with full
// security tools (Snyk, Semgrep) but the scanner catches the high-signal
// cases as part of reliability scanning.
func securityMatchers() []scanner.Matcher {
	return []scanner.Matcher{
		hardcodedConnectionString(),
		rawSQLNoParams(),
	}
}

// hardcodedConnectionString flags database/Redis/AMQP connection
// strings as string literals. Hardcoded credentials prevent rotation
// and failover.
func hardcodedConnectionString() scanner.Matcher {
	// Match common driver URI formats with credentials. The authority
	// section must include `user:password@host`; we permit any path or
	// query suffix because the injection vector is the embedded
	// credentials, not the URL shape.
	primary := regexp.MustCompile(`["'](?:postgres(?:ql)?|mysql|mongodb|redis|amqp|amqps|kafka)://[^@\s"']*@[^"']+["']`)
	return scanner.Matcher{
		Slug:           "hardcoded-connection-string",
		Description:    "Hardcoded DB/Redis/AMQP connection string with credentials",
		Category:       "service_fragility",
		ControlCodes:   []string{"RC-039"},
		Languages:      []string{"Go", "Java", "Python", "JavaScript", "TypeScript"},
		FilePatterns:   []string{"**/*.go", "**/*.java", "**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"},
		AppliesToTests: true, // PRD: leaks in fixtures matter too
		Confidence:     "high",
		Severity:       "high",
		Impl:           scanner.ImplRegex,
		Source:         "curated",
		Floor:          true, // po-qs96.2: credential exposure is a compliance/security failure, not a reliability tradeoff
		Patterns: []scanner.Pattern{{
			Regex:       primary,
			Label:       "credential-bearing connection string literal",
			NegateScope: scanner.NegateScope{Kind: "line"},
		}},
		Provenance: scanner.Provenance{
			FailureDescription: "Hardcoded credentials prevent rotation and block failover",
			IncidentFrequency:  "Present in 'couldn't rotate credentials' and 'couldn't failover' incidents",
			TypicalBlastRadius: "service-level",
			TypicalMTTR:        "elevated; redeploy required to rotate",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-039"},
		},
	}
}

// rawSQLNoParams flags SQL queries built via string concatenation or
// template-literal interpolation. The injection vector is "static SQL
// fragment + dynamic value", so we look for a SQL keyword inside a
// string literal that is adjacent to + (Go/Java/Python concat) or
// inside a backtick string with ${...} (JS/TS template literal).
func rawSQLNoParams() scanner.Matcher {
	// Three complementary patterns; any firing produces a candidate.
	concat := regexp.MustCompile(`(?i)"[^"]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"]*"\s*\+|\+\s*"[^"]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"]*"`)
	tpl := regexp.MustCompile("(?is)`[^`]*\\b(?:SELECT|INSERT\\s+INTO|UPDATE|DELETE\\s+FROM)\\b[^`]*\\$\\{[^`]*`")
	// fmt.Sprintf("...SELECT...%d...", x), Python f"...SELECT...{x}...".
	formatfn := regexp.MustCompile(`(?i)(?:fmt\.Sprintf|String\.format|f")\s*\(?\s*["` + "`" + `][^"` + "`" + `]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"` + "`" + `]*%[sdv]`)
	return scanner.Matcher{
		Slug:           "raw-sql-no-params",
		Description:    "SQL constructed via string concatenation/interpolation",
		Category:       "service_fragility",
		ControlCodes:   []string{"RC-040"},
		Languages:      []string{"Go", "Java", "Python", "JavaScript", "TypeScript"},
		FilePatterns:   []string{"**/*.go", "**/*.java", "**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"},
		AppliesToTests: true, // PRD: SQL injection in test helpers reused by integration suites matters
		Confidence:     "high",
		Severity:       "high",
		Impl:           scanner.ImplRegex,
		Source:         "curated",
		Floor:          true, // po-qs96.2: SQL injection is a compliance/security failure, not a reliability tradeoff
		Patterns: []scanner.Pattern{
			{
				Regex:       concat,
				Label:       "SQL string fragment adjacent to + concatenation",
				NegateScope: scanner.NegateScope{Kind: "line"},
			},
			{
				Regex:       tpl,
				Label:       "SQL inside backtick template literal with ${} interpolation",
				NegateScope: scanner.NegateScope{Kind: "line"},
			},
			{
				Regex:       formatfn,
				Label:       "SQL inside fmt.Sprintf/String.format/f-string with format placeholder",
				NegateScope: scanner.NegateScope{Kind: "line"},
			},
		},
		Provenance: scanner.Provenance{
			FailureDescription: "SQL injection vector and query-plan-cache misses under load",
			IncidentFrequency:  "Top OWASP risk",
			TypicalBlastRadius: "data-level",
			TypicalMTTR:        "extended on data-corruption recovery",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-040"},
		},
	}
}
