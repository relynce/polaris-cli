package matchers

import (
	"testing"

	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

func TestMissingHealthEndpoint(t *testing.T) {
	m := missingHealthEndpoint()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: routes without health",
			"http.HandleFunc(\"/api/users\", users)\nhttp.HandleFunc(\"/api/orders\", orders)",
			true},
		{"good: routes including health",
			"http.HandleFunc(\"/api/users\", users)\nhttp.HandleFunc(\"/healthz\", health)",
			false},
		{"skip: no route registrations",
			"package main\nfunc main() {}",
			false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanner.MatcherFiresOnSource(m, "test.go", []byte(c.src))
			if got != c.want {
				t.Errorf("fired=%v, want %v", got, c.want)
			}
		})
	}
}

func TestNoStructuredLogging(t *testing.T) {
	m := noStructuredLogging()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: fmt.Println in handler",
			"func handle() { fmt.Println(\"hello\") }",
			true},
		{"bad: console.log",
			"export function f() { console.log('x'); }",
			true},
		{"good: structured logger",
			"func handle() { log.Info(\"hello\") }",
			false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanner.MatcherFiresOnSource(m, "test.go", []byte(c.src))
			if got != c.want {
				t.Errorf("fired=%v, want %v", got, c.want)
			}
		})
	}
}

func TestHardcodedConnectionString(t *testing.T) {
	m := hardcodedConnectionString()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: postgres URL with creds",
			`var dsn = "postgres://user:secret@db.prod:5432/app"`,
			true},
		{"bad: redis URL with creds",
			`const url = "redis://default:hunter2@redis.prod:6379/0"`,
			true},
		{"good: env-driven",
			`var dsn = os.Getenv("DATABASE_URL")`,
			false},
		{"skip: postgres URL no auth (likely example)",
			`var dsn = "postgres://localhost/app"`,
			false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanner.MatcherFiresOnSource(m, "test.go", []byte(c.src))
			if got != c.want {
				t.Errorf("fired=%v, want %v", got, c.want)
			}
		})
	}
}

func TestRawSQLNoParams(t *testing.T) {
	m := rawSQLNoParams()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: fmt.Sprintf SELECT",
			`q := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)`,
			true},
		{"bad: string concat SELECT",
			`q := "SELECT * FROM users WHERE id = " + id`,
			true},
		{"good: parameterized",
			`db.QueryRow("SELECT * FROM users WHERE id = $1", id)`,
			false},
		{"good: javascript template literal SELECT (still bad)",
			"const q = `SELECT * FROM u WHERE id = ${id}`",
			true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanner.MatcherFiresOnSource(m, "test.go", []byte(c.src))
			if got != c.want {
				t.Errorf("fired=%v, want %v", got, c.want)
			}
		})
	}
}

func TestNoErrorWrapping(t *testing.T) {
	m := noErrorWrapping()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: bare return err",
			"if err != nil {\n\treturn err\n}",
			true},
		{"good: wrapped via fmt.Errorf",
			"if err != nil {\n\treturn fmt.Errorf(\"x: %w\", err)\n}",
			false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanner.MatcherFiresOnSource(m, "test.go", []byte(c.src))
			if got != c.want {
				t.Errorf("fired=%v, want %v", got, c.want)
			}
		})
	}
}
