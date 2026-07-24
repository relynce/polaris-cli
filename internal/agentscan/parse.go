package agentscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// findingsPayload is the JSON object every lens is instructed to emit
// (templates/scan.md, Output format).
type findingsPayload struct {
	Findings []Finding `json:"findings"`
	Summary  string    `json:"summary"`
}

// ExtractFindings parses the findings payload out of raw agent output.
// Adapter-agnostic and deliberately fence-tolerant: despite the "JSON
// only" instruction, the general lens wrapped its output in a ```json
// fence during the design experiment, so this accepts (a) a bare JSON
// object, (b) a fenced object, and (c) an object embedded in prose —
// all via one scan for the first balanced {...} containing a
// "findings" key.
func ExtractFindings(raw string) ([]Finding, string, error) {
	candidate, err := extractJSONObject(raw)
	if err != nil {
		return nil, "", err
	}
	var p findingsPayload
	if err := json.Unmarshal([]byte(candidate), &p); err != nil {
		return nil, "", fmt.Errorf("parse findings JSON: %w", err)
	}
	return p.Findings, p.Summary, nil
}

// extractJSONObject returns the first balanced JSON object in raw that
// contains a "findings" key.
func extractJSONObject(raw string) (string, error) {
	for start := 0; start < len(raw); start++ {
		if raw[start] != '{' {
			continue
		}
		end, ok := balancedObjectEnd(raw, start)
		if !ok {
			continue // unbalanced from here; try the next brace
		}
		candidate := raw[start : end+1]
		if strings.Contains(candidate, `"findings"`) {
			return candidate, nil
		}
		start = end // skip a balanced object without findings entirely
	}
	return "", errors.New("no findings JSON object in agent output")
}

// balancedObjectEnd finds the index of the brace closing the object
// that opens at start, tracking JSON string literals so braces inside
// strings do not count.
func balancedObjectEnd(s string, start int) (int, bool) {
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// validSeverities is the closed severity set from the output schema.
var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// ValidateFindings enforces the promises the prompt makes to the model
// (templates/scan.md): rule must be in the lens's closed vocabulary,
// severity must be one of the schema's four levels (case-normalized),
// and file must be part of the change set — scope discipline is a gate
// guarantee, so a finding pointing outside the change set is dropped,
// not trusted. Kept findings are stamped with the lens ID; Finding.Lens
// is orchestrator-owned and any model-supplied value is overwritten.
func ValidateFindings(l Lens, cs ChangeSet, findings []Finding) (kept []Finding, dropped []DroppedFinding) {
	vocab := make(map[string]bool, len(l.RuleVocab))
	for _, r := range l.RuleVocab {
		vocab[r] = true
	}
	inChangeSet := make(map[string]bool, len(cs.Files))
	for _, f := range cs.Files {
		inChangeSet[f.Path] = true
	}
	for _, f := range findings {
		if !vocab[f.Rule] {
			dropped = append(dropped, DroppedFinding{
				Finding: f,
				Reason:  fmt.Sprintf("rule %q is not in the %s lens vocabulary", f.Rule, l.ID),
			})
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if !validSeverities[sev] {
			dropped = append(dropped, DroppedFinding{
				Finding: f,
				Reason:  fmt.Sprintf("severity %q is not one of critical, high, medium, low", f.Severity),
			})
			continue
		}
		if !inChangeSet[f.File] {
			dropped = append(dropped, DroppedFinding{
				Finding: f,
				Reason:  fmt.Sprintf("file %q is not in the change set", f.File),
			})
			continue
		}
		f.Severity = sev
		f.Lens = l.ID
		kept = append(kept, f)
	}
	return kept, dropped
}

// RunLens runs one lens end to end: render the prompt, invoke the
// adapter, extract and validate findings. Err is set for render,
// invoke, and extract failures, wrapped with the lens ID and preserving
// the adapter's error taxonomy for errors.Is (ErrAgentUnavailable,
// ErrAgentTimeout). Validation drops are not errors; they land in
// Dropped. CostUSD is preserved even when a later stage fails — spend
// happened regardless.
func RunLens(ctx context.Context, a Adapter, l Lens, cs ChangeSet, snapshotDir string) (res LensResult) {
	res.Lens = l
	start := time.Now()
	defer func() { res.Wall = time.Since(start) }()

	prompt, err := RenderPrompt(l, cs, snapshotDir)
	if err != nil {
		res.Err = fmt.Errorf("lens %s: %w", l.ID, err)
		return res
	}
	inv, err := a.Invoke(ctx, prompt, snapshotDir)
	res.CostUSD = inv.CostUSD
	if err != nil {
		res.Err = fmt.Errorf("lens %s: %s: %w", l.ID, a.Name(), err)
		return res
	}
	findings, summary, err := ExtractFindings(inv.Raw)
	if err != nil {
		res.Err = fmt.Errorf("lens %s: %w", l.ID, err)
		return res
	}
	res.Summary = summary
	res.Findings, res.Dropped = ValidateFindings(l, cs, findings)
	return res
}
