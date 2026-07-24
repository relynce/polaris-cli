package agentscan

import (
	"path"
	"strings"
)

// Built-in lens IDs. These are stable identifiers: repo config selects
// lenses by ID and findings are stamped with them, so renaming one is a
// breaking change.
const (
	LensGo            = "go"
	LensJavaScript    = "javascript"
	LensPython        = "python"
	LensObservability = "observability"
	LensGeneral       = "general"
)

// MaxLenses caps how many lenses a single scan fans out to (spec: fixed
// decision 3, "parallel, cap 4").
const MaxLenses = 4

// languageByExt maps a changed file's extension to the language lens
// that reviews it. The javascript lens covers TypeScript.
var languageByExt = map[string]string{
	".go":  LensGo,
	".js":  LensJavaScript,
	".jsx": LensJavaScript,
	".ts":  LensJavaScript,
	".tsx": LensJavaScript,
	".mjs": LensJavaScript,
	".py":  LensPython,
}

// languageLensOrder is the deterministic tie-break order when two
// languages have equal changed-file counts.
var languageLensOrder = []string{LensGo, LensJavaScript, LensPython}

// builtinLenses is the lens catalog. RuleVocab is a CLOSED set of
// stable kebab-case slugs: waivers key on (rule, file-glob) (spec:
// Waivers), so renaming or removing a slug silently breaks user
// waivers. Add new slugs when a lens's charter grows; never rename.
var builtinLenses = []Lens{
	{
		ID:   LensGo,
		Name: "Go reliability",
		Focus: "You are reviewing a change through the Go reliability lens. " +
			"Judge the semantic content of the change for Go-specific failure modes: " +
			"error handling that silently swallows or discards failures, goroutine and " +
			"channel misuse, missing timeouts or context propagation on blocking calls, " +
			"resource lifecycle mistakes, and data races. Weigh how the change behaves " +
			"under load, partial failure, and cancellation, not just on the happy path.",
		RuleVocab: []string{
			"silent-error-swallow",
			"missing-timeout",
			"nil-deref-hazard",
			"unbounded-goroutine",
			"resource-leak",
			"race-hazard",
			"unchecked-type-assertion",
			"panic-path",
			"missing-context-propagation",
			"blocking-call-hazard",
			"defer-in-loop",
			"shared-state-mutation",
		},
	},
	{
		ID:   LensJavaScript,
		Name: "JavaScript/TypeScript reliability",
		Focus: "You are reviewing a change through the JavaScript/TypeScript reliability lens. " +
			"Judge the change for asynchronous failure modes: unhandled promise rejections, " +
			"missing awaits, catch blocks that silently discard errors, event-loop-blocking " +
			"work, and listener or resource leaks. Consider both Node.js backend behavior " +
			"under partial failure and client-side resilience where the change touches UI code.",
		RuleVocab: []string{
			"unhandled-promise-rejection",
			"missing-await",
			"silent-catch",
			"missing-timeout",
			"event-loop-block",
			"listener-leak",
			"resource-leak",
			"race-hazard",
			"unbounded-concurrency",
			"stale-closure-hazard",
			"missing-error-boundary",
			"type-coercion-hazard",
		},
	},
	{
		ID:   LensPython,
		Name: "Python reliability",
		Focus: "You are reviewing a change through the Python reliability lens. " +
			"Judge the change for Python-specific failure modes: bare or over-broad " +
			"exception handling that hides failures, blocking calls inside async code, " +
			"missing awaits, resource lifecycle mistakes, mutable shared state, and " +
			"unbounded growth. Consider behavior under cancellation, retries, and " +
			"concurrent execution, not just the happy path.",
		RuleVocab: []string{
			"bare-except-swallow",
			"missing-timeout",
			"blocking-call-in-async",
			"missing-await",
			"mutable-default-argument",
			"resource-leak",
			"race-hazard",
			"global-state-mutation",
			"unbounded-memory-growth",
			"n-plus-one-query",
			"silent-none-return",
			"import-time-side-effect",
		},
	},
	{
		ID:   LensObservability,
		Name: "Observability",
		Focus: "You are reviewing a change through the observability lens. " +
			"Judge whether the change keeps its behavior visible in production: new or " +
			"altered code paths that emit no logs, metrics, or traces; semantic changes " +
			"whose effects would be invisible to operators; missing audit signals for " +
			"security- or compliance-relevant actions; and gaps that leave alerting or " +
			"SLOs blind to a new failure mode. A change that can fail silently in " +
			"production is a finding even when its logic is correct.",
		RuleVocab: []string{
			"missing-instrumentation",
			"semantics-change-unlogged",
			"missing-audit-signal",
			"alert-gap",
			"unobserved-failure-path",
			"missing-error-context",
			"log-level-mismatch",
			"cardinality-explosion",
			"metric-semantics-drift",
			"trace-gap",
			"sensitive-data-in-logs",
			"slo-blind-spot",
		},
	},
	{
		ID:   LensGeneral,
		Name: "General reliability",
		Focus: "You are reviewing a change through the general reliability lens. " +
			"Judge the change for cross-cutting operational risk: migration and deploy " +
			"safety, configuration drift, silent behavioral regressions, backward-" +
			"compatibility and rollback hazards, and failure modes that only appear in " +
			"production sequencing such as partial deploys, mixed versions, and replays. " +
			"Focus on what could break when this change ships, rolls back, or interacts " +
			"with existing data and configuration.",
		RuleVocab: []string{
			"migration-safety",
			"config-drift",
			"semantic-regression",
			"deploy-hazard",
			"silent-failure-mode",
			"backward-compat-break",
			"rollback-hazard",
			"data-loss-hazard",
			"idempotency-break",
			"dependency-risk",
			"feature-flag-hazard",
			"error-handling-regression",
		},
	},
}

// BuiltinLenses returns the full lens catalog.
func BuiltinLenses() []Lens {
	out := make([]Lens, len(builtinLenses))
	copy(out, builtinLenses)
	return out
}

// LensByID looks up a built-in lens by its stable ID.
func LensByID(id string) (Lens, bool) {
	for _, l := range builtinLenses {
		if l.ID == id {
			return l, true
		}
	}
	return Lens{}, false
}

// SelectLenses picks the lenses for a change set (spec: Lenses and
// templates): at most one language lens, chosen by changed-code-file
// count majority (ties break in languageLensOrder), plus observability
// and general, capped at MaxLenses. When no code files changed, no
// language lens is selected. Order is deterministic: language,
// observability, general.
func SelectLenses(files []ChangedFile) []Lens {
	counts := make(map[string]int)
	for _, f := range files {
		ext := strings.ToLower(path.Ext(f.Path))
		if id, ok := languageByExt[ext]; ok {
			counts[id]++
		}
	}

	var selected []Lens
	best, bestCount := "", 0
	for _, id := range languageLensOrder {
		if counts[id] > bestCount {
			best, bestCount = id, counts[id]
		}
	}
	if best != "" {
		if l, ok := LensByID(best); ok {
			selected = append(selected, l)
		}
	}
	for _, id := range []string{LensObservability, LensGeneral} {
		if l, ok := LensByID(id); ok {
			selected = append(selected, l)
		}
	}
	if len(selected) > MaxLenses {
		selected = selected[:MaxLenses]
	}
	return selected
}
