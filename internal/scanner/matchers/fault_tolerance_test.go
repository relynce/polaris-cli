package matchers

import (
	"testing"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// matcherCheck runs all of m's regex patterns against src and returns true
// if any pattern produces a candidate (with its negation applied via the
// engine's same-scope logic).
func matcherCheck(t *testing.T, m scanner.Matcher, src string) bool {
	t.Helper()
	return scanner.MatcherFiresOnSource(m, "test.go", []byte(src))
}

func TestMissingTimeoutGo(t *testing.T) {
	m := missingTimeoutGo()

	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: no timeout", "var c = &http.Client{}", true},
		{"good: timeout literal", "var c = &http.Client{Timeout: 5 * time.Second}", false},
		{"good: timeout in multiline struct", "var c = &http.Client{\n\tTimeout: 5 * time.Second,\n}", false},
		{"good: not http.Client", "var c = &foo.Client{}", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := matcherCheck(t, m, c.src)
			if got != c.want {
				t.Errorf("fired=%v, want %v\nsrc=%q", got, c.want, c.src)
			}
		})
	}
}

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
			got := matcherCheck(t, m, c.src)
			if got != c.want {
				t.Errorf("fired=%v, want %v\nsrc=%q", got, c.want, c.src)
			}
		})
	}
}

func TestMissingRetryGo(t *testing.T) {
	m := missingRetryGo()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: bare http.Get", "resp, err := http.Get(url)", true},
		{"good: with retry helper above", "for retry := 0; retry < 3; retry++ {\n\tresp, err := http.Get(url)\n}", false},
		{"good: backoff library nearby", "// uses backoff.\nresp, err := http.Get(url)", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := matcherCheck(t, m, c.src)
			if got != c.want {
				t.Errorf("fired=%v, want %v\nsrc=%q", got, c.want, c.src)
			}
		})
	}
}

func TestUnhandledPromiseJS(t *testing.T) {
	m := unhandledPromiseJS()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: bare fetch", "fetch('/api')", true},
		{"good: fetch with .catch nearby", "fetch('/api').then(r => r.json()).catch(e => log(e))", false},
		{"good: try/catch around await", "try {\n  const r = await fetch('/api');\n} catch (e) { log(e); }", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := matcherCheck(t, m, c.src)
			if got != c.want {
				t.Errorf("fired=%v, want %v\nsrc=%q", got, c.want, c.src)
			}
		})
	}
}

func TestEmptyCatchMulti(t *testing.T) {
	m := emptyCatchMulti()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: empty Java catch", "try { foo(); } catch (Exception e) {}", true},
		{"bad: python except pass", "try:\n    foo()\nexcept Exception:\n    pass\n", true},
		{"good: catch logs", "try { foo(); } catch (Exception e) { log.error(e); }", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := matcherCheck(t, m, c.src)
			if got != c.want {
				t.Errorf("fired=%v, want %v\nsrc=%q", got, c.want, c.src)
			}
		})
	}
}

func TestGlobalStateMutationGo(t *testing.T) {
	m := globalStateMutationGo()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"good: declared but never mutated (immutable list)",
			`package x
var validEnvs = []string{"a", "b"}
func F() string { return validEnvs[0] }`,
			false},
		{"good: only initialized, never assigned later",
			`package x
var counter = 0
func F() int { return counter }`,
			false},
		{"bad: assigned in function body",
			`package x
var counter = 0
func F() { counter = 1 }`,
			true},
		{"bad: incremented in function body",
			`package x
var counter = 0
func F() { counter++ }`,
			true},
		{"good: assigned only in init()",
			`package x
var loaded bool
func init() { loaded = true }`,
			false},
		{"good: assigned in main()",
			`package x
var baseURL string
func main() { baseURL = "http://example.com" }`,
			false},
		{"good: assigned in initializeLogger",
			`package x
var log Logger
func initializeLogger() { log = Logger{} }`,
			false},
		{"good: assigned in InitializeLogger",
			`package x
var log Logger
func InitializeLogger() { log = Logger{} }`,
			false},
		{"good: assigned in setupConfig",
			`package x
var cfg Config
func setupConfig() { cfg = Config{} }`,
			false},
		{"good: assigned in loadConfig",
			`package x
var cfg Config
func loadConfig() { cfg = Config{} }`,
			false},
		{"bad: assigned in loadCatalog (not initializer-named)",
			`package x
var catalog []string
func loadCatalog() { catalog = []string{"x"} }`,
			true},
		{"good: var with sync.Mutex type",
			`package x
import "sync"
var (
    mu sync.Mutex
    counter = 0
)
func F() { mu.Lock(); counter = counter + 1; mu.Unlock() }`,
			false},
		{"good: atomic typed var",
			`package x
import "sync/atomic"
var counter atomic.Int64
func F() { counter.Add(1) }`,
			false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cands := m.Check("test.go", []byte(c.src), nil)
			got := len(cands) > 0
			if got != c.want {
				t.Errorf("fired=%v, want %v\nsrc=%s\ncands=%+v", got, c.want, c.src, cands)
			}
		})
	}
}
