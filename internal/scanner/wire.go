// Package scanner holds the scan wire types and base-ref resolution
// shared by the scan submission transport and the agent scan
// (internal/agentscan via internal/commands/scan_agent*.go).
//
// The local matcher scanner that this package used to implement was
// retired in favor of `rvl scan --agent`; only the pieces the agent
// path and the submit transport reuse survive here: the ScanFinding /
// ScanEvidence / ScanProvenance wire types, the finding status consts,
// the --changed-only base-ref resolver, and DeduplicateFindings.
package scanner

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Finding status values (po-i7mz2). "new" = the finding lands inside a
// changed hunk vs the base ref; "pre-existing" = in a changed file but
// outside any hunk, or in an unchanged file. Empty means classification
// did not run.
const (
	StatusNew         = "new"
	StatusPreExisting = "pre-existing"
)

// ScanFinding mirrors the shape Polaris expects on POST /api/v1/risks/scan.
type ScanFinding struct {
	Title          string          `json:"title"`
	Category       string          `json:"category"`
	Likelihood     string          `json:"likelihood"`
	Impact         string          `json:"impact"`
	Narrative      string          `json:"narrative,omitempty"`
	Component      string          `json:"component,omitempty"`
	LinkedServices []string        `json:"linked_services,omitempty"`
	ControlCodes   []string        `json:"control_codes,omitempty"`
	Evidence       []ScanEvidence  `json:"evidence,omitempty"`
	Fingerprint    string          `json:"fingerprint,omitempty"`
	Provenance     *ScanProvenance `json:"provenance,omitempty"`

	// Slug + Confidence on the wire so the polaris Path 5 scorer reads
	// the finding's confidence and slug-keyed logic works.
	Slug       string `json:"slug,omitempty"`
	Confidence string `json:"confidence,omitempty"`

	// Status classifies change-aware findings (see the consts above).
	Status string `json:"status,omitempty"`

	// RiskScore is the analysis-provided Path 5 score (Path 1); used by
	// DeduplicateFindings to keep the highest-scoring instance.
	RiskScore int `json:"risk_score,omitempty"`

	// CorroboratedByAgents lists agents/lenses that reported the same
	// (slug, evidence path, evidence line) tuple; populated by
	// DeduplicateFindings.
	CorroboratedByAgents []string `json:"corroborated_by_agents,omitempty"`
}

// ScanProvenance carries the provenance fields that influence the
// Polaris Path 5 scoring formula.
type ScanProvenance struct {
	IncidentFrequency  string   `json:"incident_frequency,omitempty"`
	TypicalBlastRadius string   `json:"typical_blast_radius,omitempty"`
	TypicalMTTR        string   `json:"typical_mttr,omitempty"`
	SourcePatternIDs   []string `json:"source_pattern_ids,omitempty"`
	OrgIncidentCount   int      `json:"org_incident_count,omitempty"`
}

// ScanEvidence mirrors Polaris's ScanEvidence shape.
type ScanEvidence struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	LineNumber  int    `json:"line_number,omitempty"`
	Description string `json:"description,omitempty"`
}

// --- base-ref resolution (--changed-only) ---

// BaseRefSource is the resolution chain order, used for diagnostics.
type BaseRefSource string

const (
	BaseRefFromFlag      BaseRefSource = "--base flag"
	BaseRefFromRVLEnv    BaseRefSource = "RVL_BASE_REF env var"
	BaseRefFromGitHub    BaseRefSource = "GITHUB_BASE_REF env var (PR events)"
	BaseRefFromGitLab    BaseRefSource = "CI_MERGE_REQUEST_TARGET_BRANCH_NAME env var"
	BaseRefFromConfig    BaseRefSource = ".revelara.yaml scanner.base_ref"
	BaseRefSourceUnknown BaseRefSource = "unknown"
)

// BaseRefResolution captures what the resolver chose, why, and which
// fallbacks it tried before that.
type BaseRefResolution struct {
	Ref     string
	Source  BaseRefSource
	Tried   []BaseRefSource
	Missing []BaseRefSource
}

// ErrNoBaseRef is returned by ResolveBaseRef when no source produces a
// reachable ref.
var ErrNoBaseRef = errors.New("no reachable base ref")

// ChangedOnlyConfig is the input for --changed-only resolution.
type ChangedOnlyConfig struct {
	Root        string
	FlagBaseRef string
	YAMLBaseRef string
	Env         map[string]string
}

// ResolveBaseRef walks the resolution chain and returns the first
// reachable base ref.
func ResolveBaseRef(cfg ChangedOnlyConfig) (BaseRefResolution, error) {
	if cfg.Env == nil {
		cfg.Env = make(map[string]string)
	}
	chain := []struct {
		source BaseRefSource
		value  string
	}{
		{BaseRefFromFlag, strings.TrimSpace(cfg.FlagBaseRef)},
		{BaseRefFromRVLEnv, strings.TrimSpace(cfg.Env["RVL_BASE_REF"])},
		{BaseRefFromGitHub, strings.TrimSpace(cfg.Env["GITHUB_BASE_REF"])},
		{BaseRefFromGitLab, strings.TrimSpace(cfg.Env["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"])},
		{BaseRefFromConfig, strings.TrimSpace(cfg.YAMLBaseRef)},
	}
	res := BaseRefResolution{}
	for _, step := range chain {
		res.Tried = append(res.Tried, step.source)
		if step.value == "" {
			res.Missing = append(res.Missing, step.source)
			continue
		}
		if !gitRefReachable(cfg.Root, step.value) {
			// A bare branch name may need an origin/ prefix in shallow clones.
			if !strings.HasPrefix(step.value, "origin/") && gitRefReachable(cfg.Root, "origin/"+step.value) {
				res.Ref = "origin/" + step.value
				res.Source = step.source
				return res, nil
			}
			res.Missing = append(res.Missing, step.source)
			continue
		}
		res.Ref = step.value
		res.Source = step.source
		return res, nil
	}
	return res, ErrNoBaseRef
}

// FormatNoBaseRefDiagnostic renders the user-facing diagnostic when no
// base ref is reachable.
func FormatNoBaseRefDiagnostic(res BaseRefResolution) string {
	var sb strings.Builder
	sb.WriteString("error: --changed-only requires a reachable base ref, but none was found.\n")
	sb.WriteString("  Tried:")
	for i, src := range res.Tried {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, " %s", src)
	}
	sb.WriteString("\n")
	sb.WriteString("  Fix: set fetch-depth: 0 in your checkout step, or pass --base <ref> explicitly.\n")
	sb.WriteString("  Or:  pass --scan-all-on-missing-base to fall back to a full scan.\n")
	return sb.String()
}

// gitRefReachable reports whether ref resolves to a commit in root's
// local repository.
func gitRefReachable(root, ref string) bool {
	if strings.HasPrefix(ref, "-") {
		return false
	}
	cmd := exec.Command("git", "-C", root, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// --- finding dedup (shared by --scan-dir merge and agent submit) ---

// DeduplicateFindings collapses findings that share a (slug|title, path,
// line) key, keeping the highest RiskScore (first-seen wins ties by
// lexical order) and merging corroboration.
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

	// slugOrTitle keys slug-less (LLM) findings by title so they do not
	// all collapse into the empty-slug bucket.
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

	type entry struct {
		idx     int
		finding ScanFinding
	}
	winners := make(map[dedupKey]*entry, len(findings))
	order := make([]dedupKey, 0, len(findings))

	for _, f := range findings {
		k := keyFor(f)
		w, exists := winners[k]
		if !exists {
			idx := len(order)
			winners[k] = &entry{idx: idx, finding: f}
			order = append(order, k)
			continue
		}

		winner := w.finding
		replace := f.RiskScore > winner.RiskScore
		if !replace && f.RiskScore == winner.RiskScore {
			winKey := slugOrTitle(winner) + evidencePath(winner)
			newKey := slugOrTitle(f) + evidencePath(f)
			replace = newKey < winKey
		}

		var loserComponent string
		if replace {
			loserComponent = winner.Component
			corroboration := mergeStrings(f.CorroboratedByAgents, winner.CorroboratedByAgents)
			if loserComponent != "" && loserComponent != f.Component {
				corroboration = appendUnique(corroboration, loserComponent)
			}
			newWinner := f
			newWinner.CorroboratedByAgents = nilIfEmpty(corroboration)
			w.finding = newWinner
		} else {
			loserComponent = f.Component
			corroboration := mergeStrings(winner.CorroboratedByAgents, f.CorroboratedByAgents)
			if loserComponent != "" && loserComponent != winner.Component {
				corroboration = appendUnique(corroboration, loserComponent)
			}
			winner.CorroboratedByAgents = nilIfEmpty(corroboration)
			w.finding = winner
		}
	}

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
