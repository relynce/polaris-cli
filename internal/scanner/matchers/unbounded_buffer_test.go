package matchers

import "testing"

func TestUnboundedBuffer(t *testing.T) {
	m := unboundedBuffer()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: unbuffered chan int sent from goroutine",
			`package x
func F() {
    ch := make(chan int)
    go func() { ch <- 1 }()
}`,
			true},
		{"good: buffered chan int",
			`package x
func F() {
    ch := make(chan int, 100)
    go func() { ch <- 1 }()
}`,
			false},
		{"good: signaling chan struct{} (intentional)",
			`package x
func F() {
    done := make(chan struct{})
    go func() { done <- struct{}{} }()
}`,
			false},
		{"good: unbuffered chan with no goroutine sender",
			`package x
func F() {
    ch := make(chan int)
    ch <- 1
    close(ch)
}`,
			false},
		{"bad: unbuffered chan string from goroutine in loop",
			`package x
func F(items []string) {
    ch := make(chan string)
    for _, item := range items {
        go func(s string) { ch <- s }(item)
    }
}`,
			true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cands := m.Check("/abs/test.go", "test.go", []byte(c.src))
			got := len(cands) > 0
			if got != c.want {
				t.Errorf("fired=%v, want %v\nsrc=%s\ncands=%+v", got, c.want, c.src, cands)
			}
		})
	}
}
