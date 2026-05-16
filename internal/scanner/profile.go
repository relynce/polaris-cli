package scanner

import (
	"fmt"
	"sort"
)

// BuiltinProfileNames lists the profile names this package recognizes
// without user configuration. Used in error messages so callers can
// tell users what's available.
//
// Profile semantics (po-3vsvk):
//
//	fast — regex-impl matchers only. Cheap; intended for every commit.
//	full — all matchers. No filter. Intended for PR open / pre-merge.
//
// Future profiles (deploy, etc.) can ship by adding to this list and
// adding the corresponding branch in builtinProfileSlugs.
var BuiltinProfileNames = []string{"fast", "full"}

// ResolveProfile returns the slug allowlist for the named profile. An
// empty result (nil or len==0) means "no filter / run all matchers"
// and is the correct answer for built-in `full` and for an empty name.
//
// User profiles in userOverrides override built-ins of the same name.
// Custom profile names that aren't built-in must be present in
// userOverrides; otherwise the call errors.
func ResolveProfile(name string, all []Matcher, userOverrides map[string][]string) ([]string, error) {
	if name == "" {
		return nil, nil
	}
	if slugs, ok := userOverrides[name]; ok {
		return append([]string(nil), slugs...), nil
	}
	switch name {
	case "fast":
		return builtinFast(all), nil
	case "full":
		return nil, nil
	}
	avail := append([]string(nil), BuiltinProfileNames...)
	for k := range userOverrides {
		avail = append(avail, k)
	}
	sort.Strings(avail)
	return nil, fmt.Errorf("unknown profile %q (available: %v)", name, avail)
}

// builtinFast returns the slugs of all regex-impl matchers. They're
// cheap to run on every commit.
func builtinFast(all []Matcher) []string {
	var out []string
	for _, m := range all {
		if m.Impl == ImplRegex {
			out = append(out, m.Slug)
		}
	}
	return out
}
