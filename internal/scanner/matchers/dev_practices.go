package matchers

import (
	"regexp"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// devPracticesMatchers returns matchers in the development_practices
// category. These tend to be lower-confidence: legitimate
// language-idiomatic patterns may match.
func devPracticesMatchers() []scanner.Matcher {
	return []scanner.Matcher{
		noErrorWrapping(),
	}
}

// noErrorWrapping flags `return err` lines that aren't preceded by an
// `fmt.Errorf` or an `errors.` wrap call on the same line. High false
// positive rate (legitimate leaf returns); ships at low confidence.
func noErrorWrapping() scanner.Matcher {
	primary := regexp.MustCompile(`(?m)^\s*return\s+err\s*$`)
	negate := regexp.MustCompile(`(?:fmt\.Errorf|errors\.Wrap|errors\.WithMessage|fmt\.Errorf\(.*%w)`)
	return scanner.Matcher{
		Slug:         "no-error-wrapping",
		Description:  "return err without fmt.Errorf wrapping (caller loses context)",
		Category:     "development_practices",
		ControlCodes: []string{"RC-021"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "low",
		Severity:     "low",
		Impl:         scanner.ImplRegex,
		Source:       "curated",
		Patterns: []scanner.Pattern{{
			Regex:       primary,
			Label:       "bare 'return err' without preceding wrap",
			NegateRegex: negate,
			NegateScope: scanner.NegateScope{Kind: "window", Window: 3},
		}},
		Provenance: scanner.Provenance{
			FailureDescription: "Unwrapped errors lose call-site context, extending debug time during incidents",
			IncidentFrequency:  "Stylistic; correlates with extended postmortem investigation time",
			TypicalBlastRadius: "investigation latency",
			TypicalMTTR:        "elevated",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-021"},
		},
	}
}
