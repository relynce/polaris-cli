package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/agentscan"
	"github.com/revelara-ai/rvl-cli/internal/config"
)

// scan_agent_score.go implements agentscan.Scorer against the data-grounded
// POST /api/v1/findings/score endpoint (po-7si2t.6). The server scores each
// finding by its rule and returns an absolute band, replacing the LLM's
// relative severity label before the gate. Authenticated with the CLI's API
// key (same transport shape as submitScan). Fail-open is the caller's job:
// RunPipeline keeps the agent severities if Score returns an error.

const defaultScoreTimeout = 30 * time.Second

type serverScorer struct {
	cfg                 *config.Config
	service             string
	businessCriticality float64
	timeout             time.Duration
}

type findingScoreReqItem struct {
	Rule string `json:"rule"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

type findingScoreRequest struct {
	Service             string                `json:"service"`
	BusinessCriticality float64               `json:"business_criticality"`
	Findings            []findingScoreReqItem `json:"findings"`
}

type findingScoreRespItem struct {
	Rule  string `json:"rule"`
	Score int    `json:"score"`
	Band  string `json:"band"`
}

type findingScoreResponse struct {
	Scored []findingScoreRespItem `json:"scored"`
}

// Score POSTs the findings to /api/v1/findings/score and maps each returned
// band back onto its finding by position (the endpoint preserves request
// order, scoring one item per request finding). On any transport, status, or
// decode error it returns the error; RunPipeline treats that as fail-open.
func (s *serverScorer) Score(ctx context.Context, findings []agentscan.Finding) ([]agentscan.Finding, error) {
	req := findingScoreRequest{Service: s.service, BusinessCriticality: s.businessCriticality}
	for _, f := range findings {
		req.Findings = append(req.Findings, findingScoreReqItem{Rule: f.Rule, File: f.File, Line: f.Line})
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal score request: %w", err)
	}

	timeout := s.timeout
	if timeout <= 0 {
		timeout = defaultScoreTimeout
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.APIURL+"/api/v1/findings/score", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create score request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+s.cfg.APIKey)
	if s.cfg.ResolvedOrgID != "" {
		httpReq.Header.Set("X-Organization-ID", s.cfg.ResolvedOrgID)
	}

	resp, err := (&http.Client{Timeout: timeout}).Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("score request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read score response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("score endpoint returned status %d", resp.StatusCode)
	}

	var scored findingScoreResponse
	if err := json.Unmarshal(respBody, &scored); err != nil {
		return nil, fmt.Errorf("parse score response: %w", err)
	}

	// Map bands back by position. A short/empty response leaves the
	// corresponding finding on its agent severity rather than blanking it.
	out := make([]agentscan.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if i < len(scored.Scored) && scored.Scored[i].Band != "" {
			out[i].Severity = scored.Scored[i].Band
		}
	}
	return out, nil
}
