package scanner

import (
	"fmt"
	"sort"
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
