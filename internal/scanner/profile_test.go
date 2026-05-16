package scanner

import (
	"sort"
	"strings"
	"testing"
)

func ms(slug string, impl Impl) Matcher {
	return Matcher{Slug: slug, Impl: impl}
}

func sortedSlice(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestResolveProfileBuiltinFast(t *testing.T) {
	all := []Matcher{
		ms("r1", ImplRegex),
		ms("r2", ImplRegex),
		ms("a1", ImplAST),
		ms("h1", ImplHeuristic),
	}
	got, err := ResolveProfile("fast", all, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"r1", "r2"}
	if g := sortedSlice(got); strings.Join(g, ",") != strings.Join(want, ",") {
		t.Errorf("fast = %v, want %v", g, want)
	}
}

func TestResolveProfileBuiltinFull(t *testing.T) {
	all := []Matcher{
		ms("r1", ImplRegex),
		ms("a1", ImplAST),
		ms("h1", ImplHeuristic),
	}
	got, err := ResolveProfile("full", all, nil)
	if err != nil {
		t.Fatal(err)
	}
	// full means "no restriction" — empty slice / nil signals "all".
	if len(got) != 0 {
		t.Errorf("full should return empty allowlist (no filter), got %v", got)
	}
}

func TestResolveProfileUserOverridesBuiltin(t *testing.T) {
	all := []Matcher{
		ms("r1", ImplRegex),
		ms("a1", ImplAST),
		ms("h1", ImplHeuristic),
	}
	user := map[string][]string{
		"fast": {"a1", "h1"}, // override built-in
	}
	got, err := ResolveProfile("fast", all, user)
	if err != nil {
		t.Fatal(err)
	}
	if g := sortedSlice(got); strings.Join(g, ",") != "a1,h1" {
		t.Errorf("user override = %v, want a1,h1", g)
	}
}

func TestResolveProfileUserNewName(t *testing.T) {
	all := []Matcher{ms("r1", ImplRegex)}
	user := map[string][]string{
		"my-custom": {"r1"},
	}
	got, err := ResolveProfile("my-custom", all, user)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "r1" {
		t.Errorf("my-custom = %v, want [r1]", got)
	}
}

func TestResolveProfileUnknownErrors(t *testing.T) {
	all := []Matcher{ms("r1", ImplRegex)}
	_, err := ResolveProfile("nope", all, nil)
	if err == nil {
		t.Fatal("unknown profile should error")
	}
	// Error should list available profiles.
	msg := err.Error()
	if !strings.Contains(msg, "fast") || !strings.Contains(msg, "full") {
		t.Errorf("error %q should list available profiles", msg)
	}
}

func TestResolveProfileEmptyName(t *testing.T) {
	all := []Matcher{ms("r1", ImplRegex)}
	got, err := ResolveProfile("", all, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("empty profile name should mean no filter, got %v", got)
	}
}
