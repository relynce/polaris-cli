package matchers

import "testing"

func cbMatcherFires(t *testing.T, src string) bool {
	t.Helper()
	m := missingCircuitBreaker()
	cands := m.Check("test.go", []byte(src), nil)
	return len(cands) > 0
}

func TestMissingCircuitBreakerFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: imports net/http, no CB",
			`package x
import "net/http"
var _ = http.DefaultClient
`,
			true},
		{"good: imports net/http and gobreaker",
			`package x
import (
    "net/http"
    "github.com/sony/gobreaker"
)
var _ = http.DefaultClient
var _ = gobreaker.NewCircuitBreaker(nil)
`,
			false},
		{"good: imports net/http and hystrix",
			`package x
import (
    "net/http"
    "github.com/afex/hystrix-go/hystrix"
)
var _ = http.DefaultClient
var _ = hystrix.Do
`,
			false},
		{"skip: no outbound imports",
			`package x
import "fmt"
var _ = fmt.Println
`,
			false},
		{"bad: imports grpc without CB",
			`package x
import "google.golang.org/grpc"
var _ = grpc.Dial
`,
			true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cbMatcherFires(t, c.src); got != c.want {
				t.Errorf("fired=%v, want %v", got, c.want)
			}
		})
	}
}
