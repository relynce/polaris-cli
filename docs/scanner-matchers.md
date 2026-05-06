# Writing Scanner Matchers

This guide covers how to add a curated matcher to the local reliability
scanner. It's for engineers contributing to rvl-cli; user-authored
matchers are out of scope for v1 (the
`.revelara.yaml scanner.exclude_matchers` config is the supported way
for users to suppress findings, and Phase 2 covers org-generated
matchers via the Polaris matcher-generation pipeline).

If you want to suppress a noisy matcher rather than write a new one,
see [local-scanner.md](./local-scanner.md#revelarayaml-configuration).

> Note: this guide uses internal code names where they refer to
> specific source code or services. **Polaris** is the internal code
> name for the Revelara backend service; references like "the Polaris
> RiskCategory enum" or "the Polaris matcher-generation pipeline" are
> talking about specific Go packages in the polaris repo. User-facing
> copy in the CLI itself uses the **Revelara** brand.

## Mental model

The scanner walks files matching a glob, runs each applicable matcher
against the file's contents, and emits a `Candidate` per match. The
engine converts candidates to `ScanFinding` structs that flow into
the backend's risk register.

A matcher is **data, not code** — a `scanner.Matcher` struct value
declared in `internal/scanner/matchers/<domain>.go`. It carries:

- Identity (slug, description, category, control codes)
- Selection criteria (languages, file patterns, confidence threshold)
- Detection logic (regex patterns, or an AST/heuristic `Check` function)
- Provenance (which incident pattern this matcher detects)

Three implementation strategies are supported, in increasing order of
cost and capability:

| Impl | Use when | Examples |
|------|----------|----------|
| `regex` | the pattern is line-local or fits in a window of N lines | `missing-timeout`, `swallowed-error`, `raw-sql-no-params` |
| `ast` | the pattern needs block scope or syntactic structure | `panic-in-goroutine`, `unbounded-concurrency`, `global-state-mutation` |
| `heuristic` | the pattern needs cross-cutting per-file analysis | `missing-circuit-breaker` (import set), `dockerfile-no-healthcheck`, k8s YAML doc inspection |

## Minimum-viable regex matcher

Start here. About 90% of the curated set is regex-based.

```go
// internal/scanner/matchers/fault_tolerance.go

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
			IncidentFrequency:  "Commonly cited in 'long time to detect' incident retrospectives",
			TypicalBlastRadius: "varies by call site",
			TypicalMTTR:        "extended by dropped error context",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-021"},
		},
	}
}
```

Add the matcher to its category function in
`internal/scanner/matchers/<domain>.go`, register it in `registry.go`
(or its category sub-function), and write a unit test in
`<domain>_test.go`.

## Field reference

### Identity

- **`Slug`** — kebab-case unique identifier. Stable: changing it
  breaks fingerprint dedup. Conventionally `<verb>-<noun>` or
  `missing-<thing>`.
- **`Description`** — one-sentence summary that's used as the finding
  title. Keep it under 80 chars.
- **`Category`** — one of `fault_tolerance`, `change_management`,
  `monitoring_gaps`, `service_fragility`, `disaster_recovery`,
  `development_practices`. Must match the Polaris RiskCategory enum.
- **`ControlCodes`** — `[]string` of `RC-XXX` codes the finding maps
  to. Polaris uses these to score the risk and link it to remediation
  guidance.

### Selection

- **`Languages`** — `[]string` of language names matching
  `project.DetectLanguages` output: `Go`, `JavaScript`, `TypeScript`,
  `Python`, `Java`, `Rust`, etc. **Use proper case, not lowercase.**
  Empty means language-agnostic (run whenever `FilePatterns` matches).
- **`FilePatterns`** — `[]string` of glob patterns. Supports `**/`
  for deep-walk. Examples: `["**/*.go"]`, `["Dockerfile",
  "Dockerfile.*", "**/Dockerfile"]`, `["**/*.yaml", "**/*.yml"]`.
- **`ExcludePatterns`** — `[]string` of glob patterns to skip.
  Useful for vendored or generated subdirs the matcher would
  false-positive on.
- **`AppliesToTests`** — `bool`, default false. Test files
  (`*_test.go`, `*.test.{js,ts}`, `test_*.py`, `*Test.java`) are
  skipped unless the matcher opts in. Some matchers should run in
  tests (leaked credentials, SQL injection in fixtures).

### Severity and confidence

- **`Confidence`** — `"high"` / `"medium"` / `"low"`. The
  `.revelara.yaml scanner.confidence_threshold` lets users filter
  matchers below a threshold; ship low-confidence matchers as `low`
  so they're opt-in for strict CI.
- **`Severity`** — `"critical"` / `"high"` / `"medium"` / `"low"`.
  Only critical and high trigger the CI gate (exit 1).

### Detection

- **`Impl`** — `scanner.ImplRegex` (default), `ImplAST`, or
  `ImplHeuristic`. Determines which dispatch path the engine uses.
- **`Patterns`** — `[]scanner.Pattern` for regex matchers. Each
  Pattern is one regex with an optional same-scope negation. Ignored
  for AST and heuristic matchers.
- **`Check`** — function pointer for AST and heuristic matchers.
  Receives `(absPath, relPath, src)` and returns `[]Candidate`.
  See the AST and heuristic sections below.

### Source

- **`Source`** — `"curated"` for matchers shipped in this repo,
  `"org-generated"` for Phase 2 matchers fetched from Polaris.
  Curated matchers always set this to `"curated"`.

### Provenance

The `Provenance` struct describes WHY the matcher exists. Listed in
`--list-matchers` output and embedded in finding narratives.

```go
Provenance: scanner.Provenance{
    FailureDescription: "Plain-language description of the failure mode",
    IncidentFrequency:  "How often this pattern appears in real incidents",
    TypicalBlastRadius: "service-level / multi-service / data-level / etc.",
    TypicalMTTR:        "30-60 minutes / hours / days",
    SourcePatternTypes: []string{"causal_chain", "failure_mode"},
    RelatedControls:    []string{"RC-018"},
},
```

For now, frequency/MTTR/blast-radius values are placeholders pending
the corpus-validation pass (po-fayz.16). When you write a new matcher,
quote the corpus pattern that justifies it. See
`docs/research/matcher-corpus-validation.md` in the polaris repo for
the methodology.

## Negation scopes

Most matchers fire on a primary regex AND suppress the finding when a
negation regex matches *nearby*. The `NegateScope` field controls
"nearby":

```go
Patterns: []scanner.Pattern{{
    Regex:       regexp.MustCompile(`\bhttp\.Client\s*\{`),
    Label:       "http.Client constructed without Timeout field",
    NegateRegex: regexp.MustCompile(`Timeout\s*:`),
    NegateScope: scanner.NegateScope{Kind: "window", Window: 10},
}},
```

| Scope kind | Meaning | When to use |
|------------|---------|-------------|
| `line` | negation must match on the same physical line as the primary | inline patterns where the "good" form is a one-liner: `if err != nil { return nil }` vs `if err != nil { return err }` |
| `window` | negation matches if found within `Window` lines of the primary | struct literals where the field appears within the brace block: `http.Client{` ... `Timeout:` |
| `block` | negation matches within the same AST block (AST matchers only) | reserved for AST matchers |

`file` scope is **explicitly forbidden** at registry-load time. The
engine refuses to run a matcher with a file-level negate because it
silently suppresses real findings whenever any other instance in the
same file is correctly configured.

## AST matchers

Use AST when the pattern needs syntactic structure that regex can't
reliably capture: block scope, expression types, function-call shape,
etc.

```go
// internal/scanner/matchers/concurrency_ast.go

func panicInGoroutine() scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, relPath, src, parser.ParseComments)
		if err != nil {
			return nil // unparseable; regex matchers may still cover it
		}
		var out []scanner.Candidate
		ast.Inspect(f, func(n ast.Node) bool {
			gs, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			lit, ok := gs.Call.Fun.(*ast.FuncLit)
			if !ok {
				return true // can't inspect non-literal goroutines
			}
			if hasDeferRecover(lit.Body) {
				return true
			}
			pos := fset.Position(gs.Pos())
			out = append(out, scanner.Candidate{
				Slug:        "panic-in-goroutine",
				File:        relPath,
				LineNumber:  pos.Line,
				Snippet:     "go func() { ... }() with no defer recover",
				Description: "goroutine spawned without defer recover",
			})
			return true
		})
		return out
	}

	return scanner.Matcher{
		Slug:        "panic-in-goroutine",
		Description: "Goroutine without defer recover()",
		// ... rest of the fields ...
		Impl:  scanner.ImplAST,
		Check: check,
		// Patterns: nil — AST matchers don't use the regex slice.
	}
}
```

AST matchers must be conservative: a parse error (e.g., a generated
file with bad syntax) returns `nil`, not a fake finding. The regex
matchers on the same file may still cover the case.

## Heuristic matchers

Use heuristic when the pattern needs per-file analysis that's not
expressible as line-local regex but doesn't need a full AST walk.

The most common case is import-presence: detect that a file imports
something problematic without something compensating.

```go
// internal/scanner/matchers/circuit_breaker.go

func missingCircuitBreaker() scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, relPath, src, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		var importsOutbound, importsCB bool
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if isOutboundLib(path) {
				importsOutbound = true
			}
			if isCircuitBreakerLib(path) {
				importsCB = true
			}
		}
		if !importsOutbound || importsCB {
			return nil
		}
		return []scanner.Candidate{{
			Slug:        "missing-circuit-breaker",
			File:        relPath,
			LineNumber:  1,
			Description: "outbound calls without a circuit-breaker library",
		}}
	}
	// ... rest of the matcher ...
}
```

Heuristic matchers should ship at lower confidence than regex/AST
matchers because they're more vulnerable to false positives.

## Sibling-file analysis

When the matcher needs to inspect a file's siblings (e.g.,
`rollback-migration-missing-down` checking that every `*.up.sql` has a
corresponding `*.down.sql`), use the `absPath` parameter:

```go
check := func(absPath, relPath string, _ []byte) []scanner.Candidate {
    base := filepath.Base(relPath)
    sibling := strings.TrimSuffix(base, ".up.sql") + ".down.sql"
    dir := filepath.Dir(absPath)
    if _, err := os.Stat(filepath.Join(dir, sibling)); err == nil {
        return nil
    }
    return []scanner.Candidate{{ /* ... */ }}
}
```

The `absPath` argument is the file's absolute path on disk. Avoid
walking the entire filesystem from inside a Check function — that
defeats the engine's parallel walker. Use sibling-file checks only.

## Testing

Each matcher must have a unit test in `<domain>_test.go`. Use
table-driven tests with positive and negative cases. The
`scanner.MatcherFiresOnSource(m, relPath, src)` helper drives regex
matchers; AST and heuristic matchers should call `m.Check` directly.

```go
func TestSwallowedErrorGo(t *testing.T) {
    m := swallowedErrorGo()
    cases := []struct {
        name string
        src  string
        want bool
    }{
        {"bad: return nil", "if err != nil { return nil }", true},
        {"bad: return nil, nil", "if err != nil { return nil, nil }", true},
        {"good: return err", "if err != nil { return err }", false},
        {"good: log and return", "if err != nil { log.Print(err); return err }", false},
    }
    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            got := scanner.MatcherFiresOnSource(m, "test.go", []byte(c.src))
            if got != c.want {
                t.Errorf("fired=%v, want %v\nsrc=%q", got, c.want, c.src)
            }
        })
    }
}
```

For each new matcher, include at least:

- One positive case demonstrating the bug shape
- One negative case showing the canonical correct form
- One negative case for the expected-to-be-suppressed-by-negation form
- Edge cases that you expect to be false positives (so we catch
  regressions if the matcher gets retuned)

## Acceptance test

The package-level acceptance test at
`internal/scanner/acceptance_test.go` builds the rvl binary, runs it
against `testdata/phase1_acceptance/`, and asserts the canonical
findings appear. When you add a new matcher whose target pattern
isn't already in the fixture, consider whether to extend the fixture.
The test is gated under `-tags=acceptance`; run with `make
scanner-acceptance`.

## Registering the matcher

After writing the matcher and tests:

1. Add the matcher constructor to its domain function (e.g.,
   `faultToleranceMatchers()` in `fault_tolerance.go`).
2. If you're adding a new domain (rare), add a `<domain>.go` and
   `<domain>_test.go`, then register the domain function in
   `internal/scanner/matchers/registry.go`.
3. Run `go test -short ./internal/scanner/...` to confirm everything
   compiles and the unit tests pass.
4. Run `make scanner-acceptance` to confirm the integration test still
   passes.
5. Run `./rvl scan --local --list-matchers` and grep for your new slug
   to confirm it shows in the catalog with correct provenance.
6. Run the scanner against a real repo (microservices-demo is a good
   one) to spot-check for false positives.

## Style guidelines

- **Slugs are kebab-case, semantic.** `missing-timeout`, not
  `http_client_no_timeout` or `Timeout`. Match the existing pattern.
- **Categories are stable.** Don't invent new categories without
  syncing with Polaris's RiskCategory enum.
- **Don't be aggressive with file patterns.** A matcher with
  `["**/*"]` will run on every file in the repo, which slows scans and
  multiplies false positives.
- **Prefer high-confidence narrow matchers over broad low-confidence
  ones.** If you can't pin down the bug shape precisely enough to ship
  high-confidence, the matcher might not be ready.
- **Document corpus provenance.** Quote the incident pattern that
  justifies the matcher. If you can't find one, the matcher is more
  likely a code-quality lint than a reliability matcher and may belong
  in a different tool.

## See also

- [Local scanner user guide](./local-scanner.md)
- PRD: `docs/PRD/local-reliability-scanner.md` (in the polaris repo)
- Corpus validation methodology:
  `docs/research/matcher-corpus-validation.md` (in the polaris repo)
- Engine source: `internal/scanner/engine.go`
- Type definitions: `internal/scanner/types.go`
- Existing matchers: `internal/scanner/matchers/`
