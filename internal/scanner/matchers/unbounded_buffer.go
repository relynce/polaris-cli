package matchers

import (
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// unboundedBuffer flags `make(chan T)` (zero-capacity) channels that
// are referenced in 2+ goroutines OR sent to from a goroutine. Without
// a buffer, a slow consumer blocks every producer indefinitely; without
// a bounded buffer, a fast producer eats unbounded memory before the
// consumer catches up.
//
// Corpus pattern: "Kazoo Connection Drop Due to Pipe Buffer Overflow"
// (9x in po-fayz.16 survey). The pattern generalizes to any channel
// or buffered IO without a documented capacity bound.
//
// Detection (Go AST):
//  1. Find `make(chan T)` calls (no buffer arg) inside the file.
//  2. Track the declared identifier (the channel variable).
//  3. If the same file contains a `go` statement whose body sends to
//     that identifier (a `<-` in send position), fire.
//  4. Skip signaling channels (chan struct{}) — these are intentional
//     unbuffered synchronization, not data pipelines.
func unboundedBuffer() scanner.Matcher {
	check := func(_ string, relPath string, src []byte) []scanner.Candidate {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, relPath, src, parser.ParseComments)
		if err != nil {
			return nil
		}

		// Pass 1: collect (identName -> declarationPos) for all
		// `make(chan T)` calls (no buffer argument). Skip
		// `make(chan struct{})` (signaling channels).
		channelDecls := map[string]token.Position{}
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			fnIdent, ok := call.Fun.(*ast.Ident)
			if !ok || fnIdent.Name != "make" {
				return true
			}
			// `make(chan T)` has 1 arg (the type); `make(chan T, n)`
			// has 2. We want zero-capacity.
			if len(call.Args) != 1 {
				return true
			}
			ct, ok := call.Args[0].(*ast.ChanType)
			if !ok {
				return true
			}
			// Skip signaling channels.
			if isStructTypeEmpty(ct.Value) {
				return true
			}
			channelDecls[id.Name] = fset.Position(as.Pos())
			return true
		})
		if len(channelDecls) == 0 {
			return nil
		}

		// Pass 2: for each goroutine body, find SendStmts whose channel
		// is one of the tracked identifiers. Fire on the channel decl
		// site (that's where the developer would add the buffer).
		var out []scanner.Candidate
		seen := map[string]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			gs, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			lit, ok := gs.Call.Fun.(*ast.FuncLit)
			if !ok {
				return true
			}
			ast.Inspect(lit.Body, func(inner ast.Node) bool {
				ss, ok := inner.(*ast.SendStmt)
				if !ok {
					return true
				}
				id, ok := ss.Chan.(*ast.Ident)
				if !ok {
					return true
				}
				pos, declared := channelDecls[id.Name]
				if !declared {
					return true
				}
				key := id.Name + ":" + posKey(pos)
				if seen[key] {
					return true
				}
				seen[key] = true
				out = append(out, scanner.Candidate{
					Slug:        "unbounded-buffer",
					File:        relPath,
					LineNumber:  pos.Line,
					Snippet:     "channel '" + id.Name + "' has no buffer; goroutine sends without backpressure",
					Description: "channel declared without buffer capacity, sent to from a goroutine — slow consumers block the producer",
				})
				return true
			})
			return true
		})
		return out
	}

	return scanner.Matcher{
		Slug:         "unbounded-buffer",
		Description:  "Unbuffered channel sent to from a goroutine (no backpressure)",
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
			FailureDescription: "Unbuffered channels create lockstep producer-consumer coupling; slow consumers block all producers",
			IncidentFrequency:  "Pattern 'Kazoo Connection Drop (Pipe Buffer Overflow)' 9x in corpus survey (po-fayz.16)",
			TypicalBlastRadius: "service-level (all goroutines blocked on a single channel)",
			TypicalMTTR:        "60-120 minutes",
			SourcePatternTypes: []string{"failure_mode"},
			RelatedControls:    []string{"RC-022"},
		},
	}
}

// isStructTypeEmpty reports whether the AST expression is the empty
// struct type `struct{}`. Signaling channels (`chan struct{}`) are
// intentionally unbuffered and shouldn't trigger the matcher.
func isStructTypeEmpty(e ast.Expr) bool {
	st, ok := e.(*ast.StructType)
	if !ok {
		return false
	}
	return st.Fields == nil || st.Fields.NumFields() == 0
}
