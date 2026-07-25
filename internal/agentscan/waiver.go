package agentscan

import (
	"path"
	"strings"
	"time"
)

// This file applies (rule, file-glob) waivers to aggregated findings
// before the gate decision (po-66evv.7). A waived finding is still
// reported, but it never gates.
//
// The waiver KEY is the lens rule slug, not an LLM-generated title:
// titles are nondeterministic, so a title-hash waiver could never stick
// across runs. Rule slugs come from each lens's closed RuleVocab (see
// lens.go), which is why some slugs (missing-timeout, resource-leak,
// race-hazard, missing-await) are deliberately shared across language
// lenses: one waiver then spans every lens that can emit the rule.
//
// Glob semantics MIRROR the local scanner's waiverMatchesPath
// (internal/commands/scan_local.go): path.Match forward-slash matching
// plus a `**/` prefix that matches the basename at any depth. Keeping
// the two waiver engines identical means one .revelara.yaml waivers
// list behaves the same for both scanners.

// Waiver is one (rule, paths, expiry) suppression. Rule matches
// Finding.Rule (case-insensitive). Paths are forward-slash globs; an
// empty Paths list matches any file. Expires is a YYYY-MM-DD date after
// which the waiver is inert; empty means open-ended.
type Waiver struct {
	Rule    string
	Paths   []string
	Expires string
	Reason  string
}

// WaivedFinding pairs a suppressed finding with the waiver that matched
// it, for the scan report and the audit trail.
type WaivedFinding struct {
	Finding Finding
	Waiver  Waiver
}

// waiverActive reports whether w is still in force at now. An empty or
// unparseable Expires is treated as open-ended (active), matching the
// local scanner's activeWaivers behavior.
func waiverActive(w Waiver, now time.Time) bool {
	if strings.TrimSpace(w.Expires) == "" {
		return true
	}
	exp, err := time.Parse("2006-01-02", strings.TrimSpace(w.Expires))
	if err != nil {
		return true
	}
	return !now.After(exp)
}

// ApplyWaivers partitions findings into those that survive (kept) and
// those a waiver suppressed (waived). A finding is waived when an active
// waiver's Rule equals the finding's Rule (case-insensitive) AND the
// waiver's path globs match the finding's File (empty Paths = any file).
// Expired waivers are inert. The first matching active waiver wins.
func ApplyWaivers(findings []Finding, waivers []Waiver, now time.Time) (kept []Finding, waived []WaivedFinding) {
	if len(findings) == 0 {
		return findings, nil
	}
	// Precompute the active subset once.
	active := make([]Waiver, 0, len(waivers))
	for _, w := range waivers {
		if waiverActive(w, now) {
			active = append(active, w)
		}
	}
	kept = make([]Finding, 0, len(findings))
	for _, f := range findings {
		if w, ok := matchWaiver(f, active); ok {
			waived = append(waived, WaivedFinding{Finding: f, Waiver: w})
			continue
		}
		kept = append(kept, f)
	}
	return kept, waived
}

// matchWaiver returns the first active waiver that covers f, if any.
func matchWaiver(f Finding, active []Waiver) (Waiver, bool) {
	rule := strings.ToLower(strings.TrimSpace(f.Rule))
	if rule == "" {
		return Waiver{}, false
	}
	for _, w := range active {
		if rule != strings.ToLower(strings.TrimSpace(w.Rule)) {
			continue
		}
		if len(w.Paths) == 0 || waiverMatchesPath(w.Paths, f.File) {
			return w, true
		}
	}
	return Waiver{}, false
}

// waiverMatchesPath mirrors the local scanner's glob semantics exactly:
// path.Match on the full path, plus a `**/` prefix that matches the
// basename at any depth (so `**/*.go` waives pkg/foo/bar.go).
func waiverMatchesPath(globs []string, p string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, p); ok {
			return true
		}
		if strings.HasPrefix(g, "**/") {
			suffix := strings.TrimPrefix(g, "**/")
			if ok, _ := path.Match(suffix, path.Base(p)); ok {
				return true
			}
		}
	}
	return false
}
