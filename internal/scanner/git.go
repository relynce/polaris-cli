package scanner

// git.go is a placeholder for the --changed-only base-ref resolver landed in
// po-fayz.9. The tracer bullet (po-fayz.2) wires the option but does not
// invoke git diff yet.

// ResolveChangedFiles returns the set of files that have changed relative to
// baseRef. Unimplemented in po-fayz.2 — returns nil to signal "scan
// everything". po-fayz.9 fills this in.
func ResolveChangedFiles(root, baseRef string) ([]string, error) {
	return nil, nil
}
