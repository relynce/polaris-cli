package matchers

import "testing"

const goPreamble = "package x\n\n"

func panicInGoroutineFires(t *testing.T, body string) bool {
	t.Helper()
	m := panicInGoroutine()
	src := []byte(goPreamble + body)
	cands := m.Check("test.go", src, nil)
	return len(cands) > 0
}

func unboundedConcurrencyFires(t *testing.T, body string) bool {
	t.Helper()
	m := unboundedConcurrency()
	src := []byte(goPreamble + body)
	cands := m.Check("test.go", src, nil)
	return len(cands) > 0
}

func TestPanicInGoroutineFires(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"bad: bare go func without recover",
			"func F() { go func() { panic(\"x\") }() }",
			true},
		{"good: defer recover present",
			"func F() { go func() { defer func() { recover() }(); panic(\"x\") }() }",
			false},
		{"good: defer recover bare",
			"func F() { go func() { defer recover(); doWork() }() }",
			false},
		{"skip: go funcCall (not a FuncLit)",
			"func F() { go doWork() }",
			false},
		{"bad: nested goroutine without recover",
			"func F() { go func() { go func() { panic(\"x\") }() }() }",
			true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := panicInGoroutineFires(t, c.body); got != c.want {
				t.Errorf("fired=%v, want %v\nbody=%s", got, c.want, c.body)
			}
		})
	}
}

func TestUnboundedConcurrencyFires(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"bad: go in for",
			"func F() { for i := 0; i < 10; i++ { go work() } }",
			true},
		{"bad: go in range",
			"func F() { for _, x := range items { go process(x) } }",
			true},
		{"good: channel-based gating in loop",
			"func F() { sem := make(chan struct{}, 4); for i := 0; i < 10; i++ { sem <- struct{}{}; go work() } }",
			false},
		{"good: semaphore.Acquire in loop",
			"func F() { for i := 0; i < 10; i++ { sem.Acquire(ctx, 1); go work() } }",
			false},
		{"skip: go outside any loop",
			"func F() { go work() }",
			false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := unboundedConcurrencyFires(t, c.body); got != c.want {
				t.Errorf("fired=%v, want %v\nbody=%s", got, c.want, c.body)
			}
		})
	}
}
