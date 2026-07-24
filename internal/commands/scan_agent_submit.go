package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/agentscan"
	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/project"
	"github.com/revelara-ai/rvl-cli/internal/scanner"
)

// scannerVersion is the scanner submission version string, sent as the
// SkillVersion on agent-scan submissions. (Relocated here when the local
// matcher scanner was retired; it is the only remaining user.)
const scannerVersion = "0.1.0"

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
// SCORING CONSISTENCY (po-fc2qs): the server's Path 5 scorer reads the
// finding's LIKELIHOOD (risk_service.go:2367 feeds Severity: likelihood),
// not impact. It also treats a non-empty Confidence literally. The prior
// mapping set Impact<-severity, left Likelihood empty (defaulting to
// Medium), and set Confidence="agent" (hitting the 0.85 default
// modulator) - so every finding collapsed to score 42 regardless of the
// lens severity. This mirrors the matcher path instead:
//   - Likelihood + Impact <- severity via the SAME mapping matchers use
//     (scanner.likelihoodAndImpactForSeverity: critical->(high,critical),
//     high->(high,high), medium->(medium,medium), low->(low,low)), so the
//     lens severity actually drives the score.
//   - Confidence left EMPTY: risk_service.go:2344-2354 then falls through
//     to confidence = likelihood, the documented AI-agent path. Never the
//     literal "agent".
//   - Slug <- Rule (stable lens slug; scoring/waiver key)
//   - Category <- Lens; one code Evidence entry; Narrative <- Description
//     (+ recommendation); Status "new"; CorroboratedByAgents = [Lens];
//     Provenance.SourcePatternIDs = ["agent-scan/<lens>"].
//
// Provenance grounding (IncidentFrequency / TypicalBlastRadius /
// TypicalMTTR) is intentionally NOT populated here yet: without it both
// axes take the severity-fallback branch, which is exactly how an
// ungrounded matcher finding scores - consistent, if not yet enriched.
func mapAgentFindings(findings []agentscan.Finding) []interface{} {
	out := make([]interface{}, 0, len(findings))
	for _, f := range findings {
		narrative := f.Description
		if f.Recommendation != "" {
			narrative = f.Description + "\n\nRecommendation: " + f.Recommendation
		}
		likelihood, impact := likelihoodImpactForSeverity(f.Severity)
		sf := scanner.ScanFinding{
			Title:      f.Title,
			Category:   f.Lens,
			Likelihood: likelihood,
			Impact:     impact,
			Slug:       f.Rule,
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

// likelihoodImpactForSeverity mirrors the matcher path's severity->axes
// mapping (rvl-cli internal/scanner/convert.go:206-218), kept local
// because that function is unexported. Consistency with the matcher
// mapping is the point: agent and matcher findings must seed Path 5 the
// same way.
func likelihoodImpactForSeverity(severity string) (string, string) {
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

// submitAgentScan POSTs the aggregated findings to the risks scan
// endpoint. It never affects the gate: all failures warn and return.
// The service and business criticality both come from the target's
// .revelara.yaml (business criticality feeds the Path 5 multiplier the
// same way the local scan supplies it, scan.go:748-749).
func submitAgentScan(res agentscan.PipelineResult, flagService, absTarget, mode, timeoutFlag string) {
	projectCfg := project.LoadProjectConfigFrom(absTarget)
	service := flagService
	if projectCfg != nil && projectCfg.Project != "" {
		service = projectCfg.Project
	}
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
	// po-fc2qs: business criticality is the only .revelara.yaml input to
	// the Path 5 business multiplier; without it agent findings always
	// score at criticality 0 (x1.0). Mirror the local scan (scan.go:748).
	if projectCfg != nil {
		if crit := projectCfg.CriticalityScore(); crit > 0 {
			scanReq.BusinessCriticality = &crit
		}
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
