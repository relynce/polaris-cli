package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// po-gli2z: client-side finding normalization.
//
// The STPA fields on scan findings (uca_type, causal_factors,
// loss_scenario, loss_category, estimated_fix_complexity,
// constraint_type) used to be guarded only by a transform step in the
// polaris scan skill PROMPT (scan.md Step 4B). Agents may skip prompt
// steps; when that happened, type-mismatched fields either killed the
// submit at the server boundary or were silently dropped server-side, so
// a beta user's scans came back "green" while the STPA view had no data.
//
// This file moves that transform into the CLI and extends it with enum
// validation, running on every submit path that carries raw findings
// (--stdin, --file, --scan-dir).
//
// DESIGN DECISION (submit + warn, never silently drop, never reject the
// finding): a finding whose STPA field cannot be coerced is still
// submitted, with only the invalid field removed. Rejecting the whole
// finding would recreate the original failure mode (valid reliability
// data lost because of one malformed optional field), and failing the
// scan would block CI on data that is advisory. Instead the loss is made
// impossible to miss: a per-finding [dropped] line naming the finding and
// field, an STPA-loss warning banner, and counts in the submit summary.
// Exit codes are unchanged (submission is observability, not gating -
// consistent with scan_agent_submit.go).

// stpaEnumValues mirrors the STPA field spec in polaris
// internal/skills/files/scan.md ("STPA fields").
var stpaEnumValues = map[string][]string{
	"uca_type":                 {"not_provided", "providing_incorrectly", "wrong_timing", "wrong_duration"},
	"loss_category":            {"zero_tolerance", "error_budget_managed"},
	"estimated_fix_complexity": {"low", "medium", "high"},
	"constraint_type":          {"primary", "secondary"},
}

// stpaFieldSet is the full set of STPA fields; a dropped field in this
// set means STPA data was lost and trips the warning banner.
var stpaFieldSet = map[string]bool{
	"uca_type":                 true,
	"causal_factors":           true,
	"loss_scenario":            true,
	"loss_category":            true,
	"estimated_fix_complexity": true,
	"constraint_type":          true,
}

// findingIssue records one per-finding normalization event.
type findingIssue struct {
	Index  int    // 0-based index into the findings slice
	Title  string // finding title (or a positional fallback)
	Field  string
	Action string // "coerced" or "dropped"
	Detail string
}

// findingNormReport aggregates normalization results for the submit
// summary and the loss banner.
type findingNormReport struct {
	Total           int
	WithSTPA        int // findings carrying at least one STPA field
	CoercedFindings int // findings with >=1 coerced field
	DroppedFindings int // findings with >=1 dropped field
	DroppedFields   int // total dropped fields
	Issues          []findingIssue
}

// STPALost reports whether any STPA field was dropped (as opposed to
// coerced): the condition that means the product STPA view is missing
// data the agent produced.
func (r *findingNormReport) STPALost() bool {
	for _, is := range r.Issues {
		if is.Action == "dropped" && stpaFieldSet[is.Field] {
			return true
		}
	}
	return false
}

// normalizeFindings validates and coerces known problem fields on raw
// findings in place, replacing the prompt-side Step 4B transform.
// Coercions: evidence string/[]string -> []ScanEvidence objects,
// causal_factors string -> array, loss_scenario array -> joined string,
// enum casing/whitespace, numeric-as-string risk_score and evidence
// line_number. Uncoercible fields are removed and recorded as dropped.
func normalizeFindings(findings []interface{}) findingNormReport {
	rep := findingNormReport{Total: len(findings)}

	for i, raw := range findings {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}

		title, _ := m["title"].(string)
		if title == "" {
			title = fmt.Sprintf("finding #%d", i+1)
		}

		coerced := false
		dropped := 0
		note := func(action, field, detail string) {
			rep.Issues = append(rep.Issues, findingIssue{
				Index: i, Title: title, Field: field, Action: action, Detail: detail,
			})
			if action == "coerced" {
				coerced = true
			} else {
				dropped++
			}
		}

		// Count STPA presence before any drop, so the summary reflects
		// what the agent produced, not what survived.
		for field := range stpaFieldSet {
			if v, present := m[field]; present && v != nil {
				rep.WithSTPA++
				break
			}
		}

		normalizeEvidence(m, note)
		normalizeCausalFactors(m, note)
		normalizeLossScenario(m, note)
		normalizeSTPAEnums(m, note)
		normalizeRiskScore(m, note)

		if coerced {
			rep.CoercedFindings++
		}
		if dropped > 0 {
			rep.DroppedFindings++
			rep.DroppedFields += dropped
		}
	}
	return rep
}

// normalizeEvidence coerces evidence emitted as a bare string or a
// []string into []ScanEvidence objects (scan.md Step 4B), and fixes
// numeric-as-string line_number on evidence objects.
func normalizeEvidence(m map[string]interface{}, note func(action, field, detail string)) {
	switch ev := m["evidence"].(type) {
	case string:
		if ev == "" {
			m["evidence"] = []interface{}{}
		} else {
			m["evidence"] = []interface{}{
				map[string]interface{}{"type": "code", "description": ev},
			}
		}
		note("coerced", "evidence", "bare string wrapped into evidence object array")
	case []interface{}:
		for j, item := range ev {
			switch it := item.(type) {
			case string:
				if it == "" {
					continue
				}
				ev[j] = map[string]interface{}{"type": "code", "description": it}
				note("coerced", "evidence", fmt.Sprintf("string item %d wrapped into evidence object", j))
			case map[string]interface{}:
				if ln, ok := it["line_number"].(string); ok {
					if n, err := strconv.Atoi(strings.TrimSpace(ln)); err == nil {
						it["line_number"] = n
						note("coerced", "evidence", fmt.Sprintf("line_number %q converted to number", ln))
					} else {
						delete(it, "line_number")
						note("dropped", "evidence", fmt.Sprintf("non-numeric line_number %q removed", ln))
					}
				}
			}
		}
	}
}

// normalizeCausalFactors coerces a bare string into a one-element array
// (scan.md Step 4B) and stringifies scalar items; uncoercible shapes are
// removed and reported.
func normalizeCausalFactors(m map[string]interface{}, note func(action, field, detail string)) {
	switch cf := m["causal_factors"].(type) {
	case nil:
		return
	case string:
		if cf == "" {
			delete(m, "causal_factors")
			return
		}
		m["causal_factors"] = []interface{}{cf}
		note("coerced", "causal_factors", "bare string wrapped into array")
	case []interface{}:
		out := make([]interface{}, 0, len(cf))
		for j, item := range cf {
			switch item.(type) {
			case string:
				out = append(out, item)
			case float64, bool:
				out = append(out, fmt.Sprint(item))
				note("coerced", "causal_factors", fmt.Sprintf("scalar item %d stringified", j))
			default:
				note("dropped", "causal_factors", fmt.Sprintf("item %d is not a string (%T); removed", j, item))
			}
		}
		m["causal_factors"] = out
	default:
		note("dropped", "causal_factors", fmt.Sprintf("expected array of strings, got %T; removed", cf))
		delete(m, "causal_factors")
	}
}

// normalizeLossScenario coerces an array-of-strings loss_scenario into a
// joined string and stringifies scalars; other shapes are removed.
func normalizeLossScenario(m map[string]interface{}, note func(action, field, detail string)) {
	switch ls := m["loss_scenario"].(type) {
	case nil, string:
		return
	case []interface{}:
		parts := make([]string, 0, len(ls))
		for _, item := range ls {
			s, ok := item.(string)
			if !ok {
				note("dropped", "loss_scenario", fmt.Sprintf("array contains non-string (%T); removed", item))
				delete(m, "loss_scenario")
				return
			}
			if s != "" {
				parts = append(parts, s)
			}
		}
		m["loss_scenario"] = strings.Join(parts, "; ")
		note("coerced", "loss_scenario", "string array joined into one string")
	case float64, bool:
		m["loss_scenario"] = fmt.Sprint(ls)
		note("coerced", "loss_scenario", "scalar stringified")
	default:
		note("dropped", "loss_scenario", fmt.Sprintf("expected string, got %T; removed", ls))
		delete(m, "loss_scenario")
	}
}

// normalizeSTPAEnums lowercases/trims the four STPA enum fields, maps
// spaces and hyphens to underscores, and drops values outside the
// allowed sets with a per-finding issue.
func normalizeSTPAEnums(m map[string]interface{}, note func(action, field, detail string)) {
	for field, allowed := range stpaEnumValues {
		v, present := m[field]
		if !present || v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok {
			note("dropped", field, fmt.Sprintf("expected string, got %T; removed", v))
			delete(m, field)
			continue
		}
		norm := strings.ToLower(strings.TrimSpace(s))
		norm = strings.NewReplacer(" ", "_", "-", "_").Replace(norm)
		if norm == "" {
			// Empty carries no data; removing it is not loss.
			delete(m, field)
			continue
		}
		valid := false
		for _, a := range allowed {
			if norm == a {
				valid = true
				break
			}
		}
		if !valid {
			note("dropped", field, fmt.Sprintf("invalid value %q (expected %s); removed", s, strings.Join(allowed, "|")))
			delete(m, field)
			continue
		}
		if norm != s {
			m[field] = norm
			note("coerced", field, fmt.Sprintf("%q normalized to %q", s, norm))
		}
	}
}

// normalizeRiskScore fixes numeric-as-string risk_score values.
func normalizeRiskScore(m map[string]interface{}, note func(action, field, detail string)) {
	s, ok := m["risk_score"].(string)
	if !ok {
		return
	}
	trimmed := strings.TrimSpace(s)
	if n, err := strconv.Atoi(trimmed); err == nil {
		m["risk_score"] = n
		note("coerced", "risk_score", fmt.Sprintf("%q converted to number", s))
		return
	}
	if f, err := strconv.ParseFloat(trimmed, 64); err == nil {
		m["risk_score"] = int(f)
		note("coerced", "risk_score", fmt.Sprintf("%q converted to number", s))
		return
	}
	note("dropped", "risk_score", fmt.Sprintf("non-numeric value %q removed", s))
	delete(m, "risk_score")
}

// printNormalizationIssues emits one stderr line per coerced/dropped
// field, naming the finding and field (po-gli2z: the user must be able to
// see exactly what changed or was lost).
func printNormalizationIssues(rep findingNormReport) {
	for _, is := range rep.Issues {
		fmt.Fprintf(os.Stderr, "  [%s] finding #%d (%s): %s: %s\n",
			is.Action, is.Index+1, is.Title, is.Field, is.Detail)
	}
}

// normalizationSummary renders the one-line counts for the submit
// summary: total findings, findings with STPA fields, coerced, dropped.
func normalizationSummary(rep findingNormReport) string {
	return fmt.Sprintf("%d total, %d with STPA fields, %d coerced, %d with dropped field(s)",
		rep.Total, rep.WithSTPA, rep.CoercedFindings, rep.DroppedFindings)
}

// printSTPALossBanner prints the unmissable warning block when STPA data
// was dropped. Deliberately loud: the original bug was a green scan with
// an empty STPA view.
func printSTPALossBanner(rep findingNormReport) {
	if !rep.STPALost() {
		return
	}
	line := strings.Repeat("=", 68)
	fmt.Fprintln(os.Stderr, line)
	fmt.Fprintf(os.Stderr, "WARNING: STPA DATA LOST\n")
	fmt.Fprintf(os.Stderr, "%d field(s) on %d finding(s) could not be coerced and were removed\n",
		rep.DroppedFields, rep.DroppedFindings)
	fmt.Fprintln(os.Stderr, "before submission. The affected findings were submitted WITHOUT")
	fmt.Fprintln(os.Stderr, "that STPA data, so the STPA view will be missing it. See the")
	fmt.Fprintln(os.Stderr, "[dropped] lines above for the exact findings and fields; fix the")
	fmt.Fprintln(os.Stderr, "source JSON and re-submit to backfill.")
	fmt.Fprintln(os.Stderr, line)
}
