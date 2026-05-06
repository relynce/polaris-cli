package scanner

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// matcherJSON mirrors the on-the-wire shape produced by Polaris's
// scanner_gen.MatcherJSON. Decoupled from the scanner_gen package
// because the CLI cannot import polaris-internal code; field names
// must stay in sync with that struct.
type matcherJSON struct {
	Slug         string `json:"slug"`
	Description  string `json:"description"`
	Category     string `json:"category"`
	ControlCodes []string `json:"control_codes"`
	Languages    []string `json:"languages,omitempty"`
	FilePatterns []string `json:"file_patterns,omitempty"`
	Confidence   string `json:"confidence"`
	Severity     string `json:"severity"`
	Source       string `json:"source"`
	Patterns     []struct {
		Regex       string `json:"regex"`
		Label       string `json:"label"`
		NegateRegex string `json:"negate_regex,omitempty"`
	} `json:"patterns"`
	Provenance struct {
		FailureDescription  string   `json:"failure_description,omitempty"`
		IncidentFrequency   string   `json:"incident_frequency,omitempty"`
		TypicalBlastRadius  string   `json:"typical_blast_radius,omitempty"`
		TypicalMTTR         string   `json:"typical_mttr,omitempty"`
		SourcePatternTypes  []string `json:"source_pattern_types,omitempty"`
		RelatedControls     []string `json:"related_controls,omitempty"`
		SourcePatternIDs    []string `json:"source_pattern_ids,omitempty"`
		OrgIncidentCount    int      `json:"org_incident_count,omitempty"`
		OrgAffectedServices []string `json:"org_affected_services,omitempty"`
	} `json:"provenance"`
}

// LoadOrgMatchers reads JSON matcher definitions from dir (typically
// ~/.revelara/matchers/org/) and returns them as compiled scanner
// Matchers ready to merge with AllMatchers() at scan time.
//
// Files are named <slug>.json. A manifest.json (if present) records
// the cache freshness; loader doesn't validate the manifest because
// the CLI's lazy-fetch step already handled invalidation before
// invoking us.
//
// Soft failures: malformed JSON or invalid regex on a single file
// produces a warning and skips that matcher. The scan continues with
// the rest of the matchers loaded.
func LoadOrgMatchers(dir string) ([]Matcher, error) {
	if dir == "" {
		return nil, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, nil
	}

	var out []Matcher
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") || d.Name() == "manifest.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scanner: skip org matcher %s: %v\n", filepath.Base(path), err)
			return nil
		}
		var raw matcherJSON
		if err := json.Unmarshal(data, &raw); err != nil {
			fmt.Fprintf(os.Stderr, "scanner: skip org matcher %s: invalid JSON: %v\n", filepath.Base(path), err)
			return nil
		}
		m, err := compileOrgMatcher(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scanner: skip org matcher %s: %v\n", filepath.Base(path), err)
			return nil
		}
		out = append(out, m)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// compileOrgMatcher turns raw JSON into a Matcher. Org matchers are
// regex-only by construction (PRD §Phase 2 generator does not produce
// AST or heuristic matchers); we set Impl=ImplRegex unconditionally
// and reject patterns whose regex doesn't compile.
func compileOrgMatcher(raw matcherJSON) (Matcher, error) {
	if raw.Slug == "" {
		return Matcher{}, fmt.Errorf("missing slug")
	}
	if len(raw.Patterns) == 0 {
		return Matcher{}, fmt.Errorf("matcher %s has no patterns", raw.Slug)
	}
	pats := make([]Pattern, 0, len(raw.Patterns))
	for _, rp := range raw.Patterns {
		re, err := regexp.Compile(rp.Regex)
		if err != nil {
			return Matcher{}, fmt.Errorf("matcher %s: regex compile: %w", raw.Slug, err)
		}
		var neg *regexp.Regexp
		if rp.NegateRegex != "" {
			neg, err = regexp.Compile(rp.NegateRegex)
			if err != nil {
				return Matcher{}, fmt.Errorf("matcher %s: negate regex compile: %w", raw.Slug, err)
			}
		}
		pats = append(pats, Pattern{
			Regex:       re,
			Label:       rp.Label,
			NegateRegex: neg,
			NegateScope: NegateScope{Kind: "window", Window: 10},
		})
	}
	source := raw.Source
	if source == "" {
		source = "org-generated"
	}
	return Matcher{
		Slug:         raw.Slug,
		Description:  raw.Description,
		Category:     raw.Category,
		ControlCodes: raw.ControlCodes,
		Languages:    raw.Languages,
		FilePatterns: raw.FilePatterns,
		Confidence:   raw.Confidence,
		Severity:     raw.Severity,
		Impl:         ImplRegex,
		Source:       source,
		Patterns:     pats,
		Provenance: Provenance{
			FailureDescription:  raw.Provenance.FailureDescription,
			IncidentFrequency:   raw.Provenance.IncidentFrequency,
			TypicalBlastRadius:  raw.Provenance.TypicalBlastRadius,
			TypicalMTTR:         raw.Provenance.TypicalMTTR,
			SourcePatternTypes:  raw.Provenance.SourcePatternTypes,
			RelatedControls:     raw.Provenance.RelatedControls,
			SourcePatternIDs:    raw.Provenance.SourcePatternIDs,
			OrgIncidentCount:    raw.Provenance.OrgIncidentCount,
			OrgAffectedServices: raw.Provenance.OrgAffectedServices,
		},
	}, nil
}

// OrgMatcherCacheDir returns the canonical on-disk location for
// org-generated matcher JSON files. Scoped to the user's home so the
// cache survives across rvl-cli invocations and CI checkouts in the
// same runner.
func OrgMatcherCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".revelara", "matchers", "org"), nil
}
