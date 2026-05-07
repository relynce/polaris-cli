package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// ScanFinding mirrors the shape Polaris expects on POST /api/v1/risks/scan.
// Defined here (rather than imported from the existing commands package) to
// keep scanner free of HTTP concerns. CmdScan converts to its local
// ScanRequest.Findings shape via ToInterface().
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

	// po-qs96.* fix: matcher Slug and Confidence on the wire so the
	// polaris Path 5 scorer reads matcher confidence (not severity-as-
	// confidence) and yaml/floor logic on rvl-cli matches by slug
	// (not by title-substring against the matcher description).
	Slug       string `json:"slug,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// ScanProvenance carries the matcher provenance fields that influence the
// Polaris Path 5 scoring formula. Mirrors the polaris-side ScanProvenance
// type exactly (internal/api/risk_handlers.go). Descriptive provenance
// (FailureDescription, RelatedControls) lives in Narrative because it does
// not enter the score formula.
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

// Convert turns Candidates into ScanFindings, one finding per Candidate.
// Service is the project name (used to compute fingerprints and to qualify
// linked_services). matchers is the registry the engine ran with — used to
// look up category, severity, controls, and provenance for each candidate
// slug.
func Convert(cands []Candidate, matchers []Matcher, service string) []ScanFinding {
	if len(cands) == 0 {
		return nil
	}
	bySlug := make(map[string]Matcher, len(matchers))
	for _, m := range matchers {
		bySlug[m.Slug] = m
	}

	// Group candidates by (slug, file, line) to emit one finding per
	// distinct location. Multiple matches at the same location dedup.
	type key struct {
		slug, file string
		line       int
	}
	seen := make(map[key]bool)

	out := make([]ScanFinding, 0, len(cands))
	for _, c := range cands {
		k := key{c.Slug, c.File, c.LineNumber}
		if seen[k] {
			continue
		}
		seen[k] = true

		m, ok := bySlug[c.Slug]
		if !ok {
			continue
		}
		likelihood, impact := likelihoodAndImpactForSeverity(m.Severity)
		f := ScanFinding{
			Title:        titleFor(m, c),
			Category:     m.Category,
			Likelihood:   likelihood,
			Impact:       impact,
			ControlCodes: append([]string(nil), m.ControlCodes...),
			Narrative:    narrativeFor(m, c),
			Evidence: []ScanEvidence{{
				Type:        "code",
				Path:        c.File,
				LineNumber:  c.LineNumber,
				Description: c.Description,
			}},
			Fingerprint: LocationFingerprint(c.File, c.LineNumber, service),
			Provenance:  provenanceForFinding(m),
			Slug:        m.Slug,
			Confidence:  m.Confidence,
		}
		out = append(out, f)
	}

	// Stable order: file, line, slug.
	sort.SliceStable(out, func(i, j int) bool {
		ai := out[i].Evidence[0]
		bj := out[j].Evidence[0]
		if ai.Path != bj.Path {
			return ai.Path < bj.Path
		}
		if ai.LineNumber != bj.LineNumber {
			return ai.LineNumber < bj.LineNumber
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func titleFor(m Matcher, c Candidate) string {
	if m.Description == "" {
		return m.Slug
	}
	return m.Description
}

// provenanceForFinding returns a *ScanProvenance for serialization when the
// matcher carries any scoring-relevant provenance data, and nil otherwise.
// Polaris's Path 5 scorer tolerates partial provenance (likelihood and impact
// axes are derived independently), but a fully empty struct should serialize
// as omitted to keep submission payloads compact.
func provenanceForFinding(m Matcher) *ScanProvenance {
	p := m.Provenance
	if p.IncidentFrequency == "" && p.TypicalBlastRadius == "" && p.TypicalMTTR == "" &&
		len(p.SourcePatternIDs) == 0 && p.OrgIncidentCount == 0 {
		return nil
	}
	return &ScanProvenance{
		IncidentFrequency:  p.IncidentFrequency,
		TypicalBlastRadius: p.TypicalBlastRadius,
		TypicalMTTR:        p.TypicalMTTR,
		SourcePatternIDs:   append([]string(nil), p.SourcePatternIDs...),
		OrgIncidentCount:   p.OrgIncidentCount,
	}
}

func likelihoodAndImpactForSeverity(severity string) (string, string) {
	switch strings.ToLower(severity) {
	case "critical":
		return "high", "critical"
	case "high":
		return "high", "high"
	case "medium":
		return "medium", "medium"
	case "low":
		return "low", "low"
	}
	return "medium", "medium"
}

func narrativeFor(m Matcher, c Candidate) string {
	var sb strings.Builder
	if m.Description != "" {
		sb.WriteString(m.Description)
		sb.WriteString(".\n\n")
	}
	if m.Provenance.FailureDescription != "" {
		fmt.Fprintf(&sb, "Failure mode: %s\n", m.Provenance.FailureDescription)
	}
	if m.Provenance.IncidentFrequency != "" {
		fmt.Fprintf(&sb, "Incident frequency: %s\n", m.Provenance.IncidentFrequency)
	}
	if m.Provenance.TypicalBlastRadius != "" {
		fmt.Fprintf(&sb, "Typical blast radius: %s\n", m.Provenance.TypicalBlastRadius)
	}
	if m.Provenance.TypicalMTTR != "" {
		fmt.Fprintf(&sb, "Typical MTTR: %s\n", m.Provenance.TypicalMTTR)
	}
	if len(m.Provenance.RelatedControls) > 0 {
		fmt.Fprintf(&sb, "Related controls: %s\n", strings.Join(m.Provenance.RelatedControls, ", "))
	}
	if c.Snippet != "" {
		fmt.Fprintf(&sb, "\nMatched: %s\n", c.Snippet)
	}
	if m.Source != "" {
		fmt.Fprintf(&sb, "\nMatcher source: %s (slug=%s, confidence=%s)\n", m.Source, m.Slug, m.Confidence)
	}
	return strings.TrimSpace(sb.String())
}
