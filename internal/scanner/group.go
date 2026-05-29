package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// FindingGroup aggregates ScanFindings that share a matcher slug + category.
// It is the "clustered" view of scan results — one entry per matcher
// finding type, with the per-instance locations rolled up. The polaris
// scan-submission wire format remains a flat ScanFinding list; FindingGroup
// is for human and CI presentation that wants "X type of issue: 50
// instances" rather than 50 separate rows.
type FindingGroup struct {
	Slug          string   `json:"slug"`
	Title         string   `json:"title"`
	Category      string   `json:"category"`
	Impact        string   `json:"impact,omitempty"`
	Likelihood    string   `json:"likelihood,omitempty"`
	Confidence    string   `json:"confidence,omitempty"`
	ControlCodes  []string `json:"control_codes,omitempty"`
	InstanceCount int      `json:"instance_count"`
	Locations     []string `json:"locations,omitempty"` // "path:line", first-seen order, deduplicated
}

// Group clusters findings by (category, slug). Within each cluster the
// scoring axes (Impact, Likelihood, Confidence) are pulled from the
// first finding in the cluster — they're matcher-level properties and
// are stable across instances of the same slug. Locations are emitted
// in first-seen order, deduplicated against "path:line" duplicates.
//
// Returned slice is sorted by:
//  1. Category ascending
//  2. InstanceCount descending (loudest finding in each category first)
//  3. Title ascending
//
// Empty / nil input returns an empty slice.
func Group(findings []ScanFinding) []FindingGroup {
	if len(findings) == 0 {
		return nil
	}
	type key struct {
		category, slug string
	}
	byKey := make(map[key]*FindingGroup, len(findings))
	order := make([]key, 0, len(findings))
	seenLoc := make(map[key]map[string]bool, len(findings))

	for _, f := range findings {
		category := f.Category
		if category == "" {
			category = "uncategorized"
		}
		k := key{category, f.Slug}
		g, ok := byKey[k]
		if !ok {
			g = &FindingGroup{
				Slug:         f.Slug,
				Title:        f.Title,
				Category:     category,
				Impact:       f.Impact,
				Likelihood:   f.Likelihood,
				Confidence:   f.Confidence,
				ControlCodes: append([]string(nil), f.ControlCodes...),
			}
			byKey[k] = g
			order = append(order, k)
			seenLoc[k] = map[string]bool{}
		}
		g.InstanceCount++
		if len(f.Evidence) > 0 && f.Evidence[0].Path != "" {
			loc := fmt.Sprintf("%s:%d", f.Evidence[0].Path, f.Evidence[0].LineNumber)
			if !seenLoc[k][loc] {
				seenLoc[k][loc] = true
				g.Locations = append(g.Locations, loc)
			}
		}
	}

	out := make([]FindingGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		if out[i].InstanceCount != out[j].InstanceCount {
			return out[i].InstanceCount > out[j].InstanceCount
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// DeduplicateFindings collapses findings that share (Slug, primary evidence
// path, primary evidence line) into one finding. The highest RiskScore
// instance is kept. When scores are equal the first alphabetically by
// Slug+Path wins (deterministic). CorroboratedByAgents records which
// additional Component values (treated as agent identifiers) reported the
// same finding. The returned slice preserves the relative order of
// first-seen winners.
//
// For project-level findings that have no Evidence or an empty Evidence path,
// the dedup key is just the Slug (or Title when Slug is empty); all such
// findings with the same key collapse.
//
// LLM-generated findings from --scan-dir do not carry a Slug. Without a
// Title fallback every slug-less finding would share the key {"","",0} and
// the entire batch would collapse to one winner — the po-ta8wj.3 regression.
//
// po-ta8wj.3.
func DeduplicateFindings(findings []ScanFinding) []ScanFinding {
	if len(findings) == 0 {
		return findings
	}

	type dedupKey struct {
		slug string
		path string
		line int
	}

	evidencePath := func(f ScanFinding) string {
		if len(f.Evidence) > 0 {
			return f.Evidence[0].Path
		}
		return ""
	}

	// slugOrTitle returns the Slug when set; otherwise falls back to the Title.
	// This ensures LLM-generated findings (no Slug) are keyed by their title
	// rather than all collapsing into the empty-slug bucket.
	slugOrTitle := func(f ScanFinding) string {
		if f.Slug != "" {
			return f.Slug
		}
		return f.Title
	}

	keyFor := func(f ScanFinding) dedupKey {
		if len(f.Evidence) > 0 && f.Evidence[0].Path != "" {
			return dedupKey{slugOrTitle(f), f.Evidence[0].Path, f.Evidence[0].LineNumber}
		}
		return dedupKey{slugOrTitle(f), "", 0}
	}

	// Track insertion order for first-seen winners.
	type entry struct {
		idx     int // position in the winners slice
		finding ScanFinding
	}
	winners := make(map[dedupKey]*entry, len(findings))
	order := make([]dedupKey, 0, len(findings))

	for _, f := range findings {
		k := keyFor(f)
		w, exists := winners[k]
		if !exists {
			// First time we see this key: it becomes the winner.
			idx := len(order)
			winners[k] = &entry{idx: idx, finding: f}
			order = append(order, k)
			continue
		}

		// Duplicate: decide whether the new finding beats the current winner.
		winner := w.finding
		replace := f.RiskScore > winner.RiskScore
		if !replace && f.RiskScore == winner.RiskScore {
			// Tiebreak: alphabetically by (Slug|Title)+Path — keep lexically earlier.
			winKey := slugOrTitle(winner) + evidencePath(winner)
			newKey := slugOrTitle(f) + evidencePath(f)
			replace = newKey < winKey
		}

		var loserComponent string
		if replace {
			loserComponent = winner.Component
			// Carry corroboration from loser to new winner.
			corroboration := mergeStrings(f.CorroboratedByAgents, winner.CorroboratedByAgents)
			if loserComponent != "" && loserComponent != f.Component {
				corroboration = appendUnique(corroboration, loserComponent)
			}
			newWinner := f
			newWinner.CorroboratedByAgents = nilIfEmpty(corroboration)
			w.finding = newWinner
		} else {
			loserComponent = f.Component
			// Accumulate corroboration on existing winner.
			corroboration := mergeStrings(winner.CorroboratedByAgents, f.CorroboratedByAgents)
			if loserComponent != "" && loserComponent != winner.Component {
				corroboration = appendUnique(corroboration, loserComponent)
			}
			winner.CorroboratedByAgents = nilIfEmpty(corroboration)
			w.finding = winner
		}
	}

	// Rebuild output in insertion order to ensure stability.
	result := make([]ScanFinding, 0, len(order))
	for _, k := range order {
		result = append(result, winners[k].finding)
	}
	return result
}

func mergeStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var out []string
	for _, s := range a {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func appendUnique(slice []string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return slice
	}
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
