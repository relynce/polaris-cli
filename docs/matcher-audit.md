# Scanner Matcher Audit

Reference dataset: `rvl scan --local` against the polaris repo on 2026-05-17, which emitted **755 findings** (205 High / 140 Medium / 410 Low). The server rejected the submission at the 200-finding cap. Goals:

1. **Meaningful**: every finding maps to a real reliability problem grounded in incident patterns (Bar 1).
2. **Actionable**: when a finding fires, the developer knows what to change (Bar 2).
3. **Consolidated**: occurrences of one problem produce one finding with N occurrences, not N findings.

The decision per matcher is one of `KEEP` (no change), `FIX-ROLLUP` (W2 work), `FIX-SCOPE` (W3 work), `FIX-PRECISION` (logic change in matcher), or `RETIRE` (problem cannot be salvaged). Multiple flags allowed.

## Summary table (26 matchers)

| # | Slug | Category | Sev | Polaris hits | Decision | Target rollup key | Notes |
|---|------|----------|-----|-------------:|----------|-------------------|-------|
| 1 | `missing-timeout` | fault_tolerance | High | 0 | KEEP | — | Already tuned; window-negated regex. |
| 2 | `swallowed-error` | fault_tolerance | Medium | 8 | KEEP | — | Each is a distinct bug. 8 is manageable. |
| 3 | `missing-retry` | fault_tolerance | Medium | 1 | KEEP | — | Low noise. |
| 4 | `unhandled-promise` | fault_tolerance | Medium | 0 | KEEP | — | JS/TS only; Go-heavy repo. |
| 5 | `empty-catch` | fault_tolerance | Medium | 0 | KEEP | — | Java/JS/Python only. |
| 6 | `panic-in-goroutine` | fault_tolerance | High | 31 | FIX-SCOPE + FIX-ROLLUP | enclosing function | Exempt callers of `safego.Go`/`safego.GoCtx`. Roll up multiple goroutine launches in one function. Expected: ~12. |
| 7 | `unbounded-concurrency` | fault_tolerance | High | 2 | KEEP | — | High signal, low count. |
| 8 | `global-state-mutation` | fault_tolerance | Medium | 2 | KEEP | — | Already filters startup-only functions. |
| 9 | `missing-health-endpoint` | monitoring_gaps | Medium | 5 | FIX-SCOPE + FIX-ROLLUP | binary entry point | Exclude frontend bundle output. One finding per service binary. Expected: 1. |
| 10 | `no-structured-logging` | monitoring_gaps | Low | 253 | FIX-ROLLUP + FIX-SCOPE | package | The biggest noise source after no-error-wrapping. Rollup per Go package. Exclude frontend bundle output. Expected: ~20. |
| 11 | `hardcoded-connection-string` | service_fragility | High | 15 | FIX-SCOPE | — | All 15 hits are in `*_test.go`, `testdata/`, or local-dev backfill scripts. Skip `*_test.go` entirely. Allow-list well-known local-dev creds (`postgres:postgres@localhost`, `incident:incident@localhost`). Expected: 0-2. |
| 12 | `raw-sql-no-params` | service_fragility | High | 66 | FIX-SCOPE + FIX-PRECISION + FIX-ROLLUP | file | Exclude frontend build output (`.svelte-kit/output/`). Improve regex to accept `$%d` and ", $%d" placeholder-index building (the dominant Go pattern in `internal/search/repository.go`). Rollup per file. Expected: ~12. |
| 13 | `no-error-wrapping` | development_practices | Low | 157 | FIX-PRECISION + FIX-ROLLUP | package | Largest single source of noise. Raise the bar: only fire on functions exposed at an API boundary (HTTP handler, gRPC handler, public package method) where context loss actually matters. Rollup per package for the rest. Expected: ~8. |
| 14 | `rollback-migration-missing-down` | change_management | High | 0 | KEEP | — | Schema-only matcher. |
| 15 | `integer-column-not-bigint` | service_fragility | High | 69 | FIX-PRECISION + FIX-SCOPE + FIX-ROLLUP | column name (current schema) | Migration-aware: read migrations forward, only flag columns whose final state is INTEGER. Skip `scripts/*demo*.sql`, `scripts/*seed*.sql`, `scripts/reset_*.sql`. Rollup per column. Expected: ~7. |
| 16 | `missing-circuit-breaker` | fault_tolerance | Medium | 116 | FIX-ROLLUP | project | Already a cross-cutting heuristic; output shape is wrong. One finding per scan: "No circuit breaker library imported in this module." List affected files in occurrences. Expected: 1. |
| 17 | `k8s-no-readiness-probe` | change_management | High | 8 | FIX-ROLLUP | (kind, name) | One finding per logical deployment, with all overlay files in occurrences. Expected: ~3. |
| 18 | `k8s-no-liveness-probe` | change_management | Medium | 8 | FIX-ROLLUP | (kind, name) | Same. Expected: ~3. |
| 19 | `k8s-missing-memory-limit` | change_management | High | 5 | FIX-ROLLUP | (kind, name, container) | Same pattern. Expected: ~2. |
| 20 | `k8s-missing-cpu-limit` | change_management | High | 5 | FIX-ROLLUP | (kind, name, container) | Same pattern. Expected: ~2. |
| 21 | `k8s-limit-below-request` | change_management | High | 0 | KEEP | — | Add rollup when first hit appears. |
| 22 | `k8s-mutable-image-tag` | change_management | High | 4 | FIX-SCOPE + FIX-ROLLUP | image ref | Exclude `internal/stpa/builder/testdata/`. Rollup per image reference. Expected: ~2. |
| 23 | `dockerfile-no-healthcheck` | change_management | Medium | 0 | KEEP | — | |
| 24 | `dockerfile-mutable-base-image` | change_management | High | 0 | KEEP | — | |
| 25 | `terraform-no-encryption` | disaster_recovery | High | 0 | KEEP | — | No terraform in polaris. |
| 26 | `unbounded-buffer` | fault_tolerance | Medium | 0 | KEEP | — | |

## Decision distribution

- **KEEP**: 11 matchers (8 are zero-hit dormant; 3 are already low-noise).
- **FIX-ROLLUP**: 10 matchers.
- **FIX-SCOPE**: 6 matchers.
- **FIX-PRECISION**: 3 matchers.
- **RETIRE**: 0. Every problem this audit found is fixable via rollup, scope, or precision tuning.

## Projected post-fix count on polaris

Sum of "Expected" column for fired matchers, plus untouched KEEP-counts:

| Matcher | Before | After |
|---------|-------:|------:|
| panic-in-goroutine | 31 | ~12 |
| unbounded-concurrency | 2 | 2 |
| global-state-mutation | 2 | 2 |
| swallowed-error | 8 | 8 |
| missing-retry | 1 | 1 |
| missing-circuit-breaker | 116 | 1 |
| missing-health-endpoint | 5 | 1 |
| no-structured-logging | 253 | ~20 |
| hardcoded-connection-string | 15 | ~1 |
| raw-sql-no-params | 66 | ~12 |
| no-error-wrapping | 157 | ~8 |
| integer-column-not-bigint | 69 | ~7 |
| k8s-no-readiness-probe | 8 | ~3 |
| k8s-no-liveness-probe | 8 | ~3 |
| k8s-missing-memory-limit | 5 | ~2 |
| k8s-missing-cpu-limit | 5 | ~2 |
| k8s-mutable-image-tag | 4 | ~2 |
| **Total** | **755** | **~87** |

Comfortably under 200 with real signal preserved. Each finding represents one decision point with one fix.

## What W2 (rollup) needs

`scanner.Matcher` grows an optional field:

```go
type Matcher struct {
    // ...existing fields...

    // RollupKey, if non-nil, groups Candidate emissions into one Finding
    // per unique key. The default (nil) preserves today's behavior:
    // one Finding per (slug, file, line).
    RollupKey func(c Candidate) string
}
```

`internal/scanner/convert.go` is the only place that needs to change: replace its current `(slug, file, line)` dedup with `(slug, RollupKey(c) || fmt.Sprintf("%s:%d", c.File, c.Line))` grouping, and populate `ScanFinding.Occurrences[]` from the grouped Candidates.

Rollup-key helpers to share across matchers (probably in a new `internal/scanner/rollup.go`):

- `RollupByProject(c) string` returns `"project"` (single bucket).
- `RollupByPackage(c) string` returns the Go package import path containing `c.File`.
- `RollupByFile(c) string` returns `c.File`.
- `RollupByFunction(c) string` returns `fmt.Sprintf("%s::%s", c.File, c.EnclosingFunction)` (AST matchers already know this).
- `RollupByK8sWorkload(c) string` returns `fmt.Sprintf("%s/%s", c.K8sKind, c.K8sName)` (k8s matchers parse these).
- `RollupByImageRef(c) string` returns the parsed image reference.
- `RollupByColumn(c) string` returns `fmt.Sprintf("%s.%s", c.SQLTable, c.SQLColumn)`.

The matchers that need new metadata exposed on `Candidate` (enclosing function, k8s kind/name, image ref, sql table/column) already compute these for their match logic; they just need to surface them on the Candidate struct.

## What W3 (scope filters) needs

Two layers:

**Global default-exclude globs** in `internal/scanner/engine.go` walker (override via `--include-paths`):

```
*_test.go, *_test.py, *.test.ts, *.spec.ts
testdata/, fixtures/
node_modules/, vendor/
dist/, build/, frontend/build/, frontend/.svelte-kit/
*.min.js, *.bundle.js
archive/
```

**Per-matcher exemptions** (added to the matcher's existing scope-filter logic):

- `hardcoded-connection-string`: skip `*_test.go` and the allow-list of well-known local-dev credentials.
- `panic-in-goroutine`: extend the existing whitelist (Serve/Shutdown/Wait/Run) to include any goroutine launched via `safego.Go` or `safego.GoCtx`.
- `integer-column-not-bigint`: skip `scripts/*demo*.sql`, `scripts/*seed*.sql`, `scripts/reset_*.sql`. Migration-aware logic in W3 implementation.
- `raw-sql-no-params`: include the placeholder-index window in the negated lookahead.
- `k8s-mutable-image-tag`: extend the existing skaffold/helm exclusion to also skip `internal/stpa/builder/testdata/`.

## Calibration check

After W2+W3 ship, the post-fix count on polaris should land in the **60-100 range**. If it lands above 150, that signals a regression: re-audit. If it lands below 30, the matchers are too quiet and we may have over-rolled-up a real signal.
