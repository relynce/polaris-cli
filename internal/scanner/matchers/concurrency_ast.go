package matchers

import (
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// concurrencyASTMatchers returns matchers that need to walk Go syntax
// trees to detect block-scoped patterns (per-file regex cannot do this
// reliably without unacceptable false-positive rates).
func concurrencyASTMatchers() []scanner.Matcher {
	return []scanner.Matcher{
		panicInGoroutine(),
		unboundedConcurrency(),
	}
}

// panicInGoroutine flags `go func() { ... }()` whose function body does
// NOT contain a deferred recover. Without recover, an uncaught panic
// inside the goroutine crashes the entire process — observed in
// "unexpected restart loop" incidents.
func panicInGoroutine() scanner.Matcher {
	check := func(relPath string, src []byte, _ map[string][]byte) []scanner.Candidate {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, relPath, src, parser.ParseComments)
		if err != nil {
			return nil // unparseable; the regex matchers may still cover it
		}
		var out []scanner.Candidate
		ast.Inspect(f, func(n ast.Node) bool {
			gs, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			lit, ok := gs.Call.Fun.(*ast.FuncLit)
			if !ok {
				// `go someFunc()` — can't inspect the body, conservatively
				// skip rather than false-positive on every call site.
				return true
			}
			if hasDeferRecover(lit.Body) {
				return true
			}
			// Whitelist: server-lifecycle goroutines (the canonical
			// "go func() { srv.Serve(lis) }()" / shutdown drains) are
			// known not to panic in practice. Suppress to avoid noise
			// on every gRPC and HTTP server in a real codebase.
			if bodyIsServerLifecycleOnly(lit.Body) {
				return true
			}
			pos := fset.Position(gs.Pos())
			out = append(out, scanner.Candidate{
				Slug:        "panic-in-goroutine",
				File:        relPath,
				LineNumber:  pos.Line,
				Snippet:     "go func() { ... }() with no defer recover",
				Description: "goroutine spawned without defer recover; uncaught panic crashes the process",
			})
			return true
		})
		return out
	}

	return scanner.Matcher{
		Slug:         "panic-in-goroutine",
		Description:  "Goroutine without defer recover()",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-021"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "high",
		Severity:     "high",
		Impl:         scanner.ImplAST,
		Source:       "curated",
		Check:        check,
		Provenance: scanner.Provenance{
			FailureDescription: "Unrecovered panic in a goroutine crashes the host process",
			IncidentFrequency:  "Observed in 'unexpected restart loop' incidents (corpus-validation pending)",
			TypicalBlastRadius: "process-level",
			TypicalMTTR:        "minutes-to-hours depending on visibility",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-021"},
		},
	}
}

// hasDeferRecover reports whether body contains a `defer` statement
// whose call expression is recover() (directly or wrapped inside a
// FuncLit).
func hasDeferRecover(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ds, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		if callIsRecover(ds.Call) {
			found = true
			return false
		}
		// `defer func() { recover() }()` wraps recover in a literal.
		if lit, ok := ds.Call.Fun.(*ast.FuncLit); ok && lit.Body != nil {
			ast.Inspect(lit.Body, func(n ast.Node) bool {
				if ce, ok := n.(*ast.CallExpr); ok && callIsRecover(ce) {
					found = true
					return false
				}
				return true
			})
		}
		return true
	})
	return found
}

func callIsRecover(call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "recover"
}

// serverLifecycleSelectors is the set of method names that, when they
// are the primary call inside a goroutine, indicate the goroutine
// is a server-lifecycle helper — running a Serve loop, draining a
// graceful shutdown, or waiting on a context. These calls don't
// panic in practice; flagging them as missing-recover produces noise
// on every gRPC/HTTP server in a real codebase.
var serverLifecycleSelectors = map[string]bool{
	"Serve":              true, // srv.Serve(lis) — gRPC, http.Server
	"ListenAndServe":     true, // http.Server.ListenAndServe
	"ListenAndServeTLS":  true,
	"GracefulStop":       true, // gRPC graceful drain
	"Shutdown":           true, // http.Server.Shutdown
	"Stop":               true, // gRPC.Server.Stop, also various library stops
	"Wait":               true, // sync.WaitGroup.Wait, errgroup.Group.Wait
	"Run":                true, // ListenAndServe-equivalent for some web frameworks
}

// loggingFunctionNames are call names treated as benign side effects
// — they don't change whether a goroutine body counts as
// "server-lifecycle only" but their presence isn't disqualifying.
var loggingFunctionNames = map[string]bool{
	"Println": true, "Printf": true, "Print": true,
	"Info": true, "Infof": true, "Infoln": true,
	"Warn": true, "Warnf": true, "Warnln": true,
	"Error": true, "Errorf": true, "Errorln": true,
	"Debug": true, "Debugf": true, "Debugln": true,
	"Fatal": true, "Fatalf": true, "Fatalln": true,
}

// bodyIsServerLifecycleOnly reports whether body's call expressions
// are exclusively (a) a recognized server-lifecycle method, (b) a
// log call, or (c) a builtin like `close` or `cancel`. If yes, the
// goroutine is a known-safe server lifecycle helper and the
// panic-in-goroutine matcher suppresses it.
//
// The check is conservative: any non-whitelisted call disqualifies
// the body. Channel sends, returns, and assignments are allowed —
// only call expressions are inspected.
func bodyIsServerLifecycleOnly(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	sawLifecycle := false
	allowed := true
	ast.Inspect(body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !callIsLifecycleAllowed(ce) {
			allowed = false
			return false
		}
		if callIsServerLifecycleSelector(ce) {
			sawLifecycle = true
		}
		return true
	})
	return allowed && sawLifecycle
}

// callIsLifecycleAllowed reports whether a single call is one of the
// allowed call shapes inside a server-lifecycle goroutine.
func callIsLifecycleAllowed(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		// pkg.Method() or recv.Method()
		name := fn.Sel.Name
		if serverLifecycleSelectors[name] || loggingFunctionNames[name] {
			return true
		}
		// log.Print et al. — conservative: any selector ending in a
		// known logging name is allowed.
		return false
	case *ast.Ident:
		// Bare identifier: builtin or top-level function call.
		switch fn.Name {
		case "close", "cancel", "recover":
			return true
		}
		return false
	}
	return false
}

// callIsServerLifecycleSelector reports whether the call is one of
// the explicit server-lifecycle methods (Serve, Shutdown, etc.) —
// i.e., a "primary operation" that justifies treating the goroutine
// as known-safe. A goroutine that only logs and never serves does
// not qualify; we still want the matcher to fire on those.
func callIsServerLifecycleSelector(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return serverLifecycleSelectors[sel.Sel.Name]
}

// unboundedConcurrency flags GoStmt nodes nested inside ForStmt or
// RangeStmt where no semaphore-acquire pattern appears in the same
// loop body. Matches the common goroutine-leak pattern that causes OOM
// kills under burst traffic.
func unboundedConcurrency() scanner.Matcher {
	check := func(relPath string, src []byte, _ map[string][]byte) []scanner.Candidate {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, relPath, src, parser.ParseComments)
		if err != nil {
			return nil
		}
		var out []scanner.Candidate
		ast.Inspect(f, func(n ast.Node) bool {
			var body *ast.BlockStmt
			switch v := n.(type) {
			case *ast.ForStmt:
				body = v.Body
			case *ast.RangeStmt:
				body = v.Body
			default:
				return true
			}
			if body == nil {
				return true
			}
			// Find go statements inside the loop body.
			var goStmts []*ast.GoStmt
			ast.Inspect(body, func(inner ast.Node) bool {
				if gs, ok := inner.(*ast.GoStmt); ok {
					goStmts = append(goStmts, gs)
				}
				return true
			})
			if len(goStmts) == 0 {
				return true
			}
			// Skip if the body uses semaphore-like gating: a buffered
			// channel send before each go, or a sync.Semaphore acquire.
			if loopHasSemaphoreGating(body) {
				return true
			}
			for _, gs := range goStmts {
				pos := fset.Position(gs.Pos())
				out = append(out, scanner.Candidate{
					Slug:        "unbounded-concurrency",
					File:        relPath,
					LineNumber:  pos.Line,
					Snippet:     "goroutine spawned in loop without semaphore",
					Description: "goroutine inside for/range with no concurrency bound",
				})
			}
			return true
		})
		return out
	}

	return scanner.Matcher{
		Slug:         "unbounded-concurrency",
		Description:  "Goroutine in loop without concurrency bound",
		Category:     "fault_tolerance",
		ControlCodes: []string{"RC-022"},
		Languages:    []string{"Go"},
		FilePatterns: []string{"**/*.go"},
		Confidence:   "high",
		Severity:     "high",
		Impl:         scanner.ImplAST,
		Source:       "curated",
		Check:        check,
		Provenance: scanner.Provenance{
			FailureDescription: "Goroutine leak under burst traffic causes OOM kills",
			IncidentFrequency:  "Observed in Go services handling bursty traffic (corpus-validation pending)",
			TypicalBlastRadius: "pod-level to node-level",
			TypicalMTTR:        "30-60 minutes",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-022"},
		},
	}
}

// loopHasSemaphoreGating heuristically detects common Go semaphore
// patterns inside a loop body: a buffered channel send (`sem <- ...`)
// or a sync/semaphore.Weighted Acquire call.
func loopHasSemaphoreGating(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		// Channel send: sem <- struct{}{} or similar.
		if _, ok := n.(*ast.SendStmt); ok {
			found = true
			return false
		}
		// sync/semaphore.Weighted.Acquire(...) call.
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Acquire" {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}
