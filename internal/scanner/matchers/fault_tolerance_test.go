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
		{"bad: mutable counter", "var counter = 0", true},
		{"good: sync.Mutex nearby", "import \"sync\"\nvar (\n\tmu sync.Mutex\n\tcounter = 0\n)", false},
		{"good: atomic counter", "import \"sync/atomic\"\nvar counter atomic.Int64\nvar n = atomic.AddInt64(&counter, 1)", false},
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
