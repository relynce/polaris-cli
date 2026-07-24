// Package agentscan implements the change-scoped agentic risk scan
// (`rvl scan --agent`): change-set computation (staged, revision range,
// pre-push refs), staged-snapshot materialization, lens selection and
// prompt templating, headless agent adapters, and the gate policy.
//
// Spec: polaris docs/superpowers/specs/2026-07-24-agent-scan-git-hook-design.md
// Epic: po-66evv. The types in this file are the shared contract between
// the pipeline stages; keep them free of stage-specific logic.
package agentscan

import "time"

// ChangeKind classifies one file's role in a change set.
type ChangeKind string

const (
	ChangeAdded    ChangeKind = "added"
	ChangeModified ChangeKind = "modified"
	ChangeDeleted  ChangeKind = "deleted"
	ChangeRenamed  ChangeKind = "renamed"
)

// ChangedFile is one file in a change set. Path is repo-relative,
// forward-slash. OldPath is set only for renames.
type ChangedFile struct {
	Path    string
	OldPath string
	Kind    ChangeKind
}

// ChangeSet is the unit the scan operates on: the unified diff text
// plus the classified file list. BaseDesc is a human-readable
// description of what the diff spans (e.g. "staged", "main...HEAD")
// used in prompts and notices.
type ChangeSet struct {
	Diff     string
	Files    []ChangedFile
	BaseDesc string
}

// Present returns the non-deleted files (those that exist on the new
// side of the diff and can be materialized into a snapshot).
func (cs ChangeSet) Present() []ChangedFile {
	var out []ChangedFile
	for _, f := range cs.Files {
		if f.Kind != ChangeDeleted {
			out = append(out, f)
		}
	}
	return out
}

// Deleted returns the paths removed by the change set. Deletions are
// listed in prompts but never materialized or Read.
func (cs ChangeSet) Deleted() []string {
	var out []string
	for _, f := range cs.Files {
		if f.Kind == ChangeDeleted {
			out = append(out, f.Path)
		}
	}
	return out
}

// Lens is one reviewing perspective. RuleVocab is the closed set of
// stable finding slugs this lens may emit; waivers key on (rule, file
// glob), so vocabulary stability is part of the contract (spec:
// Waivers).
type Lens struct {
	ID        string
	Name      string
	Focus     string
	RuleVocab []string
}

// Finding is one agent-reported risk, the JSON shape lenses are
// instructed to emit. Rule must come from the lens's RuleVocab.
type Finding struct {
	Rule           string `json:"rule"`
	Severity       string `json:"severity"` // critical|high|medium|low
	File           string `json:"file"`
	Line           int    `json:"line,omitempty"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation,omitempty"`
	Lens           string `json:"lens,omitempty"` // stamped by the orchestrator
}

// DroppedFinding is a finding rejected by ValidateFindings (rule not
// in the lens vocabulary, bad severity, or file outside the change
// set) together with the reason, kept for the scan report. Drops are
// not errors: the lens ran, its non-conforming output just does not
// gate.
type DroppedFinding struct {
	Finding Finding
	Reason  string
}

// LensResult is one lens invocation's outcome. Err is set when the
// agent process failed or its output could not be parsed; the gate
// policy decides whether that fails open or closed (spec: Gate policy).
// Dropped (added with the adapter stage, po-66evv.4) holds findings
// rejected by validation; Findings holds only conforming, lens-stamped
// findings.
type LensResult struct {
	Lens     Lens
	Findings []Finding
	Summary  string
	CostUSD  float64
	Wall     time.Duration
	Err      error
	Dropped  []DroppedFinding
}
