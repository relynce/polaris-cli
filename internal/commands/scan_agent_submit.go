package commands

import (
	"fmt"
	"os"

	"github.com/revelara-ai/rvl-cli/internal/agentscan"
	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/project"
	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// This file implements `rvl scan --agent --submit` (po-66evv.11): the
// opt-in POST of agent-scan findings to /api/v1/risks/scan, reusing the
// local scanner's submitScan transport. Submission is observability, not
// gating: it runs after the gate decision, never changes the exit code,
// and a submission failure is a warning.
//
// KNOWN GAP (documented, filed as a polaris follow-up): the ScanRequest
// schema has no field for the gate OUTCOME (blocked / fail-open /
// degraded). We carry mode via ScanMode and mark findings new via
// Status, but the fail-open banner and force-through events cannot be
// represented without abusing the findings endpoint. Force-throughs are
// recorded in the local audit trail (po-66evv.6); surfacing gate-outcome
// and fail-open events to the backend needs a server-side endpoint.

// mapAgentFindings converts aggregated agent findings into the wire
// ScanFinding shape (scanner.ScanFinding, which carries the JSON tags
// the endpoint expects), returned as []interface{} for ScanRequest.
//
// Mapping decisions:
//   - Slug        <- Rule   (the stable lens rule slug; waiver/scoring key)
//   - Impact      <- Severity
//   - Confidence  = "agent" (distinguishes agent findings from matcher
//     findings, which carry a matcher confidence)
//   - Category    <- Lens   (the emitting lens id; the closest analog to
//     the local scanner's matcher category)
//   - Evidence    = one code evidence entry {path, line, title}
//   - Narrative   <- Description, with the recommendation appended
//   - Status      = "new"   (agent findings are change-scoped by
//     construction, so every one is a new-in-this-change finding)
//   - CorroboratedByAgents = [Lens]
//   - Provenance.SourcePatternIDs = ["agent-scan/<lens>"]
func mapAgentFindings(findings []agentscan.Finding) []interface{} {
	out := make([]interface{}, 0, len(findings))
	for _, f := range findings {
		narrative := f.Description
		if f.Recommendation != "" {
			narrative = f.Description + "\n\nRecommendation: " + f.Recommendation
		}
		sf := scanner.ScanFinding{
			Title:      f.Title,
			Category:   f.Lens,
			Impact:     f.Severity,
			Slug:       f.Rule,
			Confidence: "agent",
			Narrative:  narrative,
			Status:     scanner.StatusNew,
			Evidence: []scanner.ScanEvidence{{
				Type:        "code",
				Path:        f.File,
				LineNumber:  f.Line,
				Description: f.Title,
			}},
			CorroboratedByAgents: []string{f.Lens},
			Provenance: &scanner.ScanProvenance{
				SourcePatternIDs: []string{"agent-scan/" + f.Lens},
			},
		}
		out = append(out, sf)
	}
	return out
}

// resolveSubmitService resolves the service name for submission from the
// --service flag or the target's .revelara.yaml project. Returns "" when
// none is available (the caller warns and skips submit).
func resolveSubmitService(flagService, target string) string {
	service := flagService
	projectCfg := project.LoadProjectConfigFrom(target)
	if projectCfg != nil && projectCfg.Project != "" {
		service = projectCfg.Project
	}
	return service
}

// submitAgentScan POSTs the aggregated findings to the risks scan
// endpoint. It never affects the gate: all failures warn and return.
func submitAgentScan(res agentscan.PipelineResult, service, mode, timeoutFlag string) {
	if service == "" {
		fmt.Fprintln(os.Stderr, "warning: --submit skipped: no service (pass --service or add project to .revelara.yaml)")
		return
	}
	if len(res.Findings) == 0 {
		fmt.Fprintln(os.Stderr, "note: --submit: no findings to submit")
		return
	}
	apiCfg := api.LoadAndResolveConfig()
	scanReq := ScanRequest{
		Service:  service,
		ScanType: ScanTypeIncremental, // change-scoped
		ScanMode: mode,
		Findings: mapAgentFindings(res.Findings),
		Metadata: ScanMetadata{
			ScannerID:    "rvl-agent-scan",
			SkillName:    "rvl-agent-scan",
			SkillVersion: scannerVersion,
		},
	}
	resp, err := submitScan(apiCfg, &scanReq, resolveScanTimeout(timeoutFlag))
	if err != nil {
		// Observability only: a submit failure must not change the gate
		// or the exit code.
		fmt.Fprintf(os.Stderr, "warning: --submit failed (gate result unaffected): %v\n", err)
		return
	}
	fmt.Printf("Submitted %d agent finding(s) to Revelara (scan %s, service %s)\n",
		len(res.Findings), resp.ScanID, resp.Service)
}
