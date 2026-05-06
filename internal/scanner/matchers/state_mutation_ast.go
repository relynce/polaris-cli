package matchers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// globalStateMutationASTGo flags package-level vars that are *mutated*
// from function bodies — not merely declared. The previous regex
// implementation fired on every `var x = ...` at package scope, which
// produced false positives on immutable list/map literals. This AST
// matcher requires actual evidence of mutation.
//
// Detection:
//  1. Collect every package-level var declaration's identifier names.
//  2. Skip names whose declared type or initializer signals
//     concurrent-safe usage (sync.Mutex, sync.RWMutex, atomic.*).
//  3. Walk function bodies for AssignStmt / IncDecStmt whose LHS
//     references a package-level var. Each such mutation is a finding.
//
// The matcher reports the mutation site, not the declaration, because
// that is the line the developer needs to look at.
func globalStateMutationASTGo() scanner.Matcher {
	check := func(relPath string, src []byte, _ map[string][]byte) []scanner.Candidate {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, relPath, src, parser.ParseComments)
		if err != nil {
			return nil
		}

		// Collect package-level var names. A name is "concurrent-safe"
		// (skipped) when its declared type or initializer contains a
		// sync/atomic reference.
		pkgVars := map[string]bool{}
		safeVars := map[string]bool{}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			// Two-pass: a var (...) block where any spec references
			// sync/atomic marks ALL its specs safe. The canonical Go
			// pattern groups a Mutex with the state it protects in
			// the same block precisely to communicate "these are
			// protected together."
			blockHasSyncSibling := false
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if exprMentionsConcurrentSafe(vs.Type) || anyExprMentionsConcurrentSafe(vs.Values) {
					blockHasSyncSibling = true
					break
				}
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				safe := blockHasSyncSibling ||
					exprMentionsConcurrentSafe(vs.Type) ||
					anyExprMentionsConcurrentSafe(vs.Values)
				for _, name := range vs.Names {
					if name.Name == "" || name.Name == "_" {
						continue
					}
					pkgVars[name.Name] = true
					if safe {
						safeVars[name.Name] = true
					}
				}
			}
		}
		if len(pkgVars) == 0 {
			return nil
		}

		// Build a single-file call graph so we can suppress mutations
		// in functions only reachable from main()/init()/initializer-named
		// roots (po-fayz.27). Functions reachable from goroutine spawns
		// or HTTP route registrations are 'concurrent' and remain
		// flagged.
		startupOnly := computeStartupOnlyFunctions(f)

		// Walk function bodies for assignments / inc-dec to package vars.
		var out []scanner.Candidate
		seen := map[string]bool{} // dedup by file:line
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			// Skip explicit init-like names AND functions transitively
			// reachable only from those names.
			if fd.Recv == nil && fd.Name != nil {
				if isInitLikeFuncName(fd.Name.Name) || startupOnly[fd.Name.Name] {
					continue
				}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch s := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range s.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && pkgVars[id.Name] && !safeVars[id.Name] {
							pos := fset.Position(s.Pos())
							key := id.Name + ":" + posKey(pos)
							if seen[key] {
								continue
							}
							seen[key] = true
							out = append(out, scanner.Candidate{
								Slug:        "global-state-mutation",
								File:        relPath,
								LineNumber:  pos.Line,
								Snippet:     "package-level var '" + id.Name + "' assigned outside init()",
								Description: "package-level var '" + id.Name + "' mutated; concurrent access risks data races",
							})
						}
					}
				case *ast.IncDecStmt:
					if id, ok := s.X.(*ast.Ident); ok && pkgVars[id.Name] && !safeVars[id.Name] {
						pos := fset.Position(s.Pos())
						key := id.Name + ":" + posKey(pos)
						if seen[key] {
							return true
						}
						seen[key] = true
						out = append(out, scanner.Candidate{
							Slug:        "global-state-mutation",
							File:        relPath,
							LineNumber:  pos.Line,
							Snippet:     "package-level var '" + id.Name + "' incremented/decremented outside init()",
							Description: "package-level var '" + id.Name + "' mutated; concurrent access risks data races",
						})
					}
				}
				return true
			})
		}
		return out
	}

	return scanner.Matcher{
		Slug:         "global-state-mutation",
		Description:  "Package-level var mutated from function body (concurrent risk)",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-022"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "medium",
		Severity:     "medium",
		Impl:         scanner.ImplAST,
		Source:       "curated",
		Check:        check,
		Provenance: scanner.Provenance{
			FailureDescription: "Concurrent mutation of package-level state causes data races and intermittent corruption",
			IncidentFrequency:  "Observed in 'intermittent corruption' incident patterns (corpus-validation pending)",
			TypicalBlastRadius: "service-level",
			TypicalMTTR:        "elevated; race-condition incidents are hard to reproduce",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-022"},
		},
	}
}

// computeStartupOnlyFunctions builds a single-file call graph and
// returns the set of function names that are transitively reachable
// only from {main, init, initialize*, setup*, configure*, bootstrap*,
// load*Config/Settings/Env}. A function is 'startup-only' iff every
// caller in this file is itself startup-only AND it is never the
// target of a goroutine spawn (`go funcName(...)`) or an HTTP route
// handler argument.
//
// Limitations: single-file. Cross-file call sites are invisible, so
// a helper called from main() in this file but ALSO called from a
// goroutine in another file is incorrectly suppressed. This is the
// same scope limit as the rest of the matcher package; whole-package
// reachability is a future enhancement.
func computeStartupOnlyFunctions(f *ast.File) map[string]bool {
	// Pass 1: collect all top-level function names, the set of
	// callees referenced from within each function's body, and the
	// set of names spawned via 'go fn()' or registered as HTTP
	// handlers (these are 'concurrent entry points').
	calleesByFunc := map[string]map[string]bool{}
	concurrentEntries := map[string]bool{}
	allFuncs := map[string]bool{}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil {
			continue
		}
		name := fd.Name.Name
		allFuncs[name] = true
		callees := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.CallExpr:
				if id, ok := s.Fun.(*ast.Ident); ok {
					callees[id.Name] = true
				}
				// Route registration patterns: 'mux.HandleFunc(...,
				// myHandler)' — second arg is the function reference.
				// Conservative: only mark as concurrent entry when the
				// CALLED function is a known router method.
				if isRouteRegistrationCall(s) {
					for _, arg := range s.Args {
						if id, ok := arg.(*ast.Ident); ok {
							concurrentEntries[id.Name] = true
						}
					}
				}
			case *ast.GoStmt:
				// 'go funcName(...)' — funcName is a concurrent entry.
				// 'go func() { ... }()' — anonymous, no name to track.
				if call := s.Call; call != nil {
					if id, ok := call.Fun.(*ast.Ident); ok {
						concurrentEntries[id.Name] = true
					}
				}
			}
			return true
		})
		calleesByFunc[name] = callees
	}

	// Pass 2: identify roots (init-like names) and propagate
	// reachability. A function is startup-only iff:
	//   (a) it is an init-like root, OR
	//   (b) every function that calls it is startup-only AND it is
	//       not a concurrent entry point.
	//
	// We compute the inverse: 'reachable from a non-startup root'.
	// Anything not so reachable is startup-only.
	reachableFromConcurrent := map[string]bool{}

	// Seed with concurrent entries: anything spawned via 'go' or
	// registered as a handler is reachable from concurrency.
	queue := make([]string, 0, len(concurrentEntries))
	for name := range concurrentEntries {
		if allFuncs[name] {
			reachableFromConcurrent[name] = true
			queue = append(queue, name)
		}
	}
	// Also: any function NOT init-like AND NOT only called from
	// init-like callers is treated as 'public surface' that may be
	// invoked concurrently. We model this conservatively by checking
	// who calls each function in the file; if a function has no
	// caller in this file at all, it's external API — assume
	// concurrent.
	callersOf := map[string][]string{}
	for caller, callees := range calleesByFunc {
		for callee := range callees {
			callersOf[callee] = append(callersOf[callee], caller)
		}
	}
	for name := range allFuncs {
		if isInitLikeFuncName(name) {
			continue
		}
		if len(callersOf[name]) == 0 {
			// No caller in this file — exported or used cross-file;
			// treat as concurrent.
			reachableFromConcurrent[name] = true
			queue = append(queue, name)
		}
	}

	// BFS: anything called BY a concurrent function is also concurrent.
	for len(queue) > 0 {
		caller := queue[0]
		queue = queue[1:]
		for callee := range calleesByFunc[caller] {
			if !allFuncs[callee] || reachableFromConcurrent[callee] {
				continue
			}
			reachableFromConcurrent[callee] = true
			queue = append(queue, callee)
		}
	}

	// startupOnly = allFuncs - reachableFromConcurrent - init-like
	// (which are skipped at the call site separately).
	out := map[string]bool{}
	for name := range allFuncs {
		if reachableFromConcurrent[name] {
			continue
		}
		if isInitLikeFuncName(name) {
			continue
		}
		out[name] = true
	}
	return out
}

// isRouteRegistrationCall recognizes the common HTTP route
// registration shapes whose argument is a handler function we should
// mark as a concurrent entry point. Conservative: only matches the
// well-known stdlib / gorilla mux / chi / echo patterns.
func isRouteRegistrationCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "HandleFunc", "Handle", "GET", "POST", "PUT", "DELETE", "PATCH":
		return true
	}
	return false
}

// isInitLikeFuncName reports whether a top-level function name
// identifies it as a startup initializer (where package-level
// mutation is documented configuration, not concurrent state). These
// functions run before goroutines are spawned, so race risks don't
// apply.
//
// Matches:
//   - "init"   — Go's special init function
//   - "main"   — program entry point, also one-shot
//   - prefixes followed by an uppercase letter: "initialize*",
//     "setup*", "configure*", "bootstrap*", "load*Config",
//     "load*Settings"
//
// The matcher is conservative: a function named "loadCatalog" still
// triggers because catalogs are typically reloaded concurrently;
// only the "load*Config"/"load*Settings" forms are treated as
// startup-only.
func isInitLikeFuncName(name string) bool {
	switch name {
	case "init", "main":
		return true
	}
	for _, prefix := range []string{"initialize", "Initialize", "setup", "Setup", "configure", "Configure", "bootstrap", "Bootstrap"} {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			next := name[len(prefix)]
			if (next >= 'A' && next <= 'Z') || prefix == "initialize" || prefix == "setup" || prefix == "configure" || prefix == "bootstrap" {
				return true
			}
		}
	}
	if strings.HasPrefix(name, "load") || strings.HasPrefix(name, "Load") {
		// loadConfig / loadSettings / loadEnv only — not load* in general.
		rest := name[4:]
		for _, suffix := range []string{"Config", "Settings", "Env", "Env"} {
			if rest == suffix {
				return true
			}
		}
	}
	return false
}

// exprMentionsConcurrentSafe reports whether the AST expression
// contains a reference to a sync.* or atomic.* type or value. Used to
// filter out vars that are intentionally concurrency-safe.
func exprMentionsConcurrentSafe(e ast.Expr) bool {
	if e == nil {
		return false
	}
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, _ := sel.X.(*ast.Ident)
		if pkg == nil {
			return true
		}
		if pkg.Name == "sync" || pkg.Name == "atomic" {
			found = true
			return false
		}
		// sync/atomic typed via "sync_atomic" or aliases; also catch
		// the common "var x atomic.Int64" shape where sel.X is the
		// package alias.
		if strings.Contains(strings.ToLower(pkg.Name), "atomic") {
			found = true
			return false
		}
		return true
	})
	return found
}

func anyExprMentionsConcurrentSafe(exprs []ast.Expr) bool {
	for _, e := range exprs {
		if exprMentionsConcurrentSafe(e) {
			return true
		}
	}
	return false
}

func posKey(pos token.Position) string {
	// Stable string for set keys; keeping it small avoids allocations
	// on hot paths.
	return pos.Filename + ":" + itoa(pos.Line)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	const max = 20
	var b [max]byte
	pos := max
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
