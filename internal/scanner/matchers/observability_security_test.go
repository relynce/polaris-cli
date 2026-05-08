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
		{"good: routes including healthz",
			"http.HandleFunc(\"/api/users\", users)\nhttp.HandleFunc(\"/healthz\", health)",
			false},
		{"good: routes including readyz",
			"http.HandleFunc(\"/api/users\", users)\nhttp.HandleFunc(\"/readyz\", ready)",
			false},
		{"skip: no route registrations",
			"package main\nfunc main() {}",
			false},
		{"good: dedicated metrics server (only /metrics route)",
			`func startMetricsServer(addr string) *http.Server {
    mux := http.NewServeMux()
    mux.Handle("/metrics", promhttp.Handler())
    return &http.Server{Addr: addr, Handler: mux}
}`,
			false},
		{"good: dedicated debug server with pprof routes",
			`mux.Handle("/debug/pprof/", pprof.Index)
mux.Handle("/debug/pprof/profile", pprof.Profile)`,
			false},
		{"bad: mixed routes, /metrics + business but no health",
			`mux.Handle("/metrics", promhttp.Handler())
mux.HandleFunc("/api/users", users)`,
			true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cands := m.Check("/abs/test.go", "test.go", []byte(c.src))
			got := len(cands) > 0
			if got != c.want {
				t.Errorf("fired=%v, want %v\ncands=%+v", got, c.want, cands)
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

		// po-qfmh.2: false-positive suppression for the patterns observed
		// in polaris that the original regex flagged as score-100 risks
		// (R-101, R-124, R-167, …). Each `good:` case below corresponds
		// to a verified safe pattern; each `bad:` case confirms real
		// injection is still detected.

		{"good: fmt.Sprintf with column-list constant and $N (R-101 pattern)",
			"const ucaColumns = `id, content, created_at`\n" +
				"query := fmt.Sprintf(`SELECT %s FROM ucas WHERE id = $1`, ucaColumns)",
			false},
		{"good: dynamic WHERE accumulator with $%d positions (R-124 pattern)",
			`baseWhere := "organization_id = $1"
args := []interface{}{orgID}
if statusFilter != "" {
    baseWhere += fmt.Sprintf(" AND status = $%d", argNum)
    args = append(args, statusFilter)
}
countQuery := "SELECT COUNT(*) FROM import_jobs WHERE " + baseWhere
db.QueryRow(ctx, countQuery, args...).Scan(&n)`,
			false},
		{"good: const SET clause concat near parameterized Exec (R-168 pattern)",
			`const setStatus = "status = $3, updated_at = NOW()"
ct, err := db.Exec(ctx,
    "UPDATE scanner_matchers SET "+setStatus+" WHERE id = $1 AND organization_id = $2",
    id, orgID, status)`,
			false},
		{"good: error message concat next to parameterized Exec (R-167 pattern)",
			`_, err := db.Exec(ctx,
    "UPDATE scanner_matchers SET status = $3 WHERE id = $1 AND organization_id = $2",
    id, orgID, status)
if err != nil {
    writeJSONError(w, "update: "+err.Error(), http.StatusInternalServerError)
}`,
			false},
		{"good: allowlisted table name with $N (account_org_reaper pattern)",
			`for _, table := range noActionOrgChildren {
    stmt := fmt.Sprintf(` + "`DELETE FROM %s WHERE organization_id = $1`" + `, table)
    tx.Exec(ctx, stmt, orgID)
}`,
			false},

		{"bad: real injection in fmt.Sprintf with no $N anywhere",
			`func unsafe(id string) string {
    return fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
}`,
			true},
		{"bad: real injection via concat with no $N anywhere",
			`func unsafe(name string) {
    q := "SELECT * FROM users WHERE name = '" + name + "'"
    db.Exec(q)
}`,
			true},
		{"bad: UPDATE injection with no $N anywhere",
			`func unsafe(name, role string) {
    q := "UPDATE users SET role = '" + role + "' WHERE name = '" + name + "'"
    db.Exec(q)
}`,
			true},

		{"good: lowercase 'update' in english error message far from any SQL",
			`if err != nil {
    return fmt.Errorf("failed to update: " + err.Error())
}`,
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
