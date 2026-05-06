package scanner

// loader.go is a placeholder for org-generated matcher loading landed in
// po-fayz.22. The tracer bullet (po-fayz.2) returns an empty slice so the
// engine can call LoadOrgMatchers unconditionally.

// LoadOrgMatchers reads JSON matcher definitions from dir and returns them
// as a slice of Matcher. Unimplemented in po-fayz.2 — returns an empty
// slice so the engine can merge unconditionally.
func LoadOrgMatchers(dir string) ([]Matcher, error) {
	return nil, nil
}
