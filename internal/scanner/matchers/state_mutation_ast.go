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

		// Walk function bodies for assignments / inc-dec to package vars.
		var out []scanner.Candidate
		seen := map[string]bool{} // dedup by file:line
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			// Skip init() — initialization is the documented place to
			// set package state.
			if fd.Recv == nil && fd.Name != nil && fd.Name.Name == "init" {
				continue
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
