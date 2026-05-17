package matchers

import (
	"go/parser"
	"go/token"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// knownCBLibraries are import paths for Go circuit-breaker libraries.
// A file that imports any of these is considered "covered" for the
// missing-circuit-breaker heuristic.
var knownCBLibraries = []string{
	"github.com/sony/gobreaker",
	"github.com/cep21/circuit",
	"github.com/mercari/go-circuitbreaker",
	"github.com/afex/hystrix-go",
	"github.com/eapache/go-resiliency",
	"github.com/slok/goresilience",
}

// outboundCallImports are imports that suggest the file makes outbound
// calls and therefore should be wrapped by a circuit breaker.
var outboundCallImports = []string{
	"net/http",
	"google.golang.org/grpc",
	"go.mongodb.org/mongo-driver",
	"github.com/redis/go-redis",
	"github.com/go-redis/redis",
	"database/sql",
}

// missingCircuitBreaker is the heuristic matcher: flag files that import
// outbound-call libraries but do NOT import any known circuit-breaker
// library. Confidence is intentionally low — false positives on
// intentional fail-fast paths are inherent in the approach.
func missingCircuitBreaker() scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, relPath, src, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		var importsOutbound bool
		var importsCB bool
		var firstOutboundLine int
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, ob := range outboundCallImports {
				if path == ob || strings.HasPrefix(path, ob+"/") {
					importsOutbound = true
					if firstOutboundLine == 0 {
						firstOutboundLine = fset.Position(imp.Pos()).Line
					}
				}
			}
			for _, cb := range knownCBLibraries {
				if path == cb || strings.HasPrefix(path, cb+"/") {
					importsCB = true
				}
			}
		}
		if !importsOutbound || importsCB {
			return nil
		}
		return []scanner.Candidate{{
			Slug:        "missing-circuit-breaker",
			File:        relPath,
			LineNumber:  firstOutboundLine,
			Snippet:     "imports outbound-call library without a known circuit breaker",
			Description: "file makes outbound calls but no circuit-breaker library is imported",
		}}
	}

	return scanner.Matcher{
		Slug:         "missing-circuit-breaker",
		Description:  "External calls without circuit-breaker library imported",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-019"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "low",
		Severity:     "medium",
		Impl:         scanner.ImplHeuristic,
		Source:       "curated",
		Check:        check,
		// Project-level finding: "no circuit breaker library is imported
		// anywhere in this module." One Finding per scan with every
		// outbound-call importing file rolled into Evidence[]. Replaces
		// the prior 116-per-scan output on polaris.
		RollupKey: scanner.RollupByProject,
		Provenance: scanner.Provenance{
			FailureDescription: "Absence of circuit breakers turns single-service failures into multi-service cascades. Heuristic detection cannot identify call-graph wrapping; this matcher errs toward false positives by design.",
			IncidentFrequency:  "Common in dependency-failure causal chains (corpus-validation pending)",
			TypicalBlastRadius: "service-level to multi-service",
			TypicalMTTR:        "varies",
			SourcePatternTypes: []string{"causal_chain"},
			RelatedControls:    []string{"RC-019"},
		},
	}
}
