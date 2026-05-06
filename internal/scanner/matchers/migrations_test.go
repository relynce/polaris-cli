package matchers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackMigrationMissingDown(t *testing.T) {
	m := rollbackMigrationMissingDown()
	dir := t.TempDir()
	must := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	upWithDown := must("001_users.up.sql", "CREATE TABLE users();")
	must("001_users.down.sql", "DROP TABLE users;")
	upMissingDown := must("002_orders.up.sql", "CREATE TABLE orders();")
	upUnderscoreWithSibling := must("003_logs_up.sql", "CREATE TABLE logs();")
	must("003_logs_down.sql", "DROP TABLE logs;")
	upUnderscoreMissing := must("004_events_up.sql", "CREATE TABLE events();")

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"good: up with down sibling (.up.sql)", upWithDown, false},
		{"bad: up missing down (.up.sql)", upMissingDown, true},
		{"good: up with down sibling (_up.sql)", upUnderscoreWithSibling, false},
		{"bad: up missing down (_up.sql)", upUnderscoreMissing, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rel := filepath.Base(c.path)
			cands := m.Check(c.path, rel, nil)
			got := len(cands) > 0
			if got != c.want {
				t.Errorf("fired=%v, want %v\npath=%s", got, c.want, c.path)
			}
		})
	}
}

func TestIntegerColumnNotBigint(t *testing.T) {
	m := integerColumnNotBigint()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bad: id INTEGER",
			`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT
);`,
			true},
		{"bad: user_id INT",
			`CREATE TABLE orders (
    order_id BIGINT,
    user_id INT NOT NULL
);`,
			true},
		{"bad: count INTEGER",
			`CREATE TABLE stats (
    name TEXT,
    count INTEGER
);`,
			true},
		{"bad: id SERIAL (32-bit)",
			`CREATE TABLE events (
    id SERIAL,
    payload TEXT
);`,
			true},
		{"good: id BIGINT",
			`CREATE TABLE users (
    id BIGINT PRIMARY KEY
);`,
			false},
		{"good: id BIGSERIAL",
			`CREATE TABLE events (
    id BIGSERIAL
);`,
			false},
		{"good: TEXT column with 'count' substring not as name",
			`CREATE TABLE x (
    description TEXT
);`,
			false},
		{"good: comment shouldn't trigger",
			`-- count INTEGER would be bad here
CREATE TABLE y (id BIGINT);`,
			false},
		{"good: ad-hoc column unrelated to growth",
			`CREATE TABLE x (
    width INTEGER,
    height INTEGER
);`,
			false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cands := m.Check("/abs/migration.sql", "migration.sql", []byte(c.src))
			got := len(cands) > 0
			if got != c.want {
				t.Errorf("fired=%v, want %v\nsrc=%s\ncands=%+v", got, c.want, c.src, cands)
			}
		})
	}
}
