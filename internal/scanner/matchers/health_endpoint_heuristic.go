package matchers

import (
	"regexp"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// routeRegistrationRe captures HTTP route registrations across the
// common Go and JS/TS frameworks. Group 1 is the route path string.
var routeRegistrationRe = regexp.MustCompile(
	`(?m)\b(?:` +
		`http\.HandleFunc|` +
		`mux\.Handle(?:Func)?|` +
		`router\.(?:GET|POST|PUT|DELETE|PATCH|HandleFunc|Handle)|` +
		`(?:srv|server|s|app|r)\.(?:Handle(?:Func)?|GET|POST|PUT|DELETE|PATCH|use|get|post)` +
		`)\s*\(\s*["` + "`" + `]([^"` + "`" + `]+)["` + "`" + `]`)

// healthPathRe matches paths the heuristic considers to be health/readiness/liveness endpoints.
var healthPathRe = regexp.MustCompile(`^/(?:health(?:z)?|readyz?|livez?|ping|status)(?:/.*)?$`)

// dedicatedSinglePurposePrefixes are the path prefixes we treat as
// single-purpose servers — when a file's only route registrations
// fall under these prefixes, the absence of a /health endpoint is
// intentional, not a bug. These servers are typically scraped by
// orchestration via their existing endpoint (e.g., /metrics doubles
// as a liveness signal for prometheus).
var dedicatedSinglePurposePrefixes = []string{
	"/metrics",
	"/debug/",
	"/debug/pprof",
	"/_/",         // Some operational tools use this prefix
	"/internal/",
}

// missingHealthEndpointHeuristic walks every route registration in a
// file. The heuristic fires only when:
//
//  1. The file contains at least one HTTP route registration, AND
//  2. None of those routes match a health/readiness/liveness path, AND
//  3. The file is NOT a dedicated single-purpose server (every route
//     falls under /metrics, /debug/, etc.).
//
// This avoids the previous regex-with-window false positive on
// `startMetricsServer` style functions where a separate, intentional
// server registers only /metrics and the main app's /health lives
// elsewhere.
func missingHealthEndpointHeuristic() scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		matches := routeRegistrationRe.FindAllSubmatchIndex(src, -1)
		if len(matches) == 0 {
			return nil
		}
		var (
			paths      []string
			firstByte  = matches[0][0]
			firstLine  int
			anyHealth  bool
		)
		for _, m := range matches {
			pathStart, pathEnd := m[2], m[3]
			if pathStart < 0 {
				continue
			}
			path := string(src[pathStart:pathEnd])
			paths = append(paths, path)
			if healthPathRe.MatchString(path) {
				anyHealth = true
			}
		}
		if anyHealth || len(paths) == 0 {
			return nil
		}
		if allPathsAreDedicatedSinglePurpose(paths) {
			return nil
		}
		// Compute line of the first route registration for the finding.
		firstLine = countLines(src[:firstByte]) + 1
		return []scanner.Candidate{{
			Slug:        "missing-health-endpoint",
			File:        relPath,
			LineNumber:  firstLine,
			Snippet:     "no /health* route registered alongside " + summarizePaths(paths),
			Description: "HTTP routes registered but no /health, /healthz, /readyz, or /livez among them",
		}}
	}

	return scanner.Matcher{
		Slug:         "missing-health-endpoint",
		Description:  "HTTP route registrations without a /health or /healthz path",
		Category:     "monitoring_gaps",
		ControlCodes: []string{"RC-002"},
		Languages:    []string{"Go", "JavaScript", "TypeScript"},
		FilePatterns: []string{"**/*.go", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"},
		Confidence:   "medium",
		Severity:     "medium",
		Impl:         scanner.ImplHeuristic,
		Source:       "curated",
		Check:        check,
		Provenance: scanner.Provenance{
			FailureDescription: "Services without health endpoints get traffic during startup or degradation",
			IncidentFrequency:  "Common in 'deployed but not ready' incidents",
			TypicalBlastRadius: "service-level",
			TypicalMTTR:        "rollback latency",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-002"},
		},
		// Rollup per project: one finding per scan ("the service has no
		// health endpoint anywhere"). The polaris repo had this firing
		// once per binary-with-routes file (5x) which over-reports a
		// single architectural fact.
		RollupKey: scanner.RollupByProject,
	}
}

func allPathsAreDedicatedSinglePurpose(paths []string) bool {
	for _, p := range paths {
		matched := false
		for _, prefix := range dedicatedSinglePurposePrefixes {
			if strings.HasPrefix(p, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func countLines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}

func summarizePaths(paths []string) string {
	if len(paths) <= 3 {
		return "[" + strings.Join(paths, ", ") + "]"
	}
	return "[" + strings.Join(paths[:3], ", ") + ", ...]"
}
