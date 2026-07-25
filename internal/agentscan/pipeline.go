package agentscan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// This file is the pipeline orchestrator for `rvl scan --agent`
// (po-66evv.5): it chains the hygiene stages in their contractual order
// (see the comment atop hygiene.go), fans chunk x lens invocations out
// in parallel against one shared snapshot, aggregates findings, and
// computes the gate decision (spec: Gate policy).

// Gate policy constants (spec: Gate policy). Mode eval never blocks;
// FailOn defaults to high.
const (
	GateModeEnforce = "enforce"
	GateModeEval    = "eval"
	DefaultFailOn   = "high"

	// DefaultMaxInvocations caps the chunk x lens fan-out so a huge
	// chunked diff cannot launch unbounded agent processes.
	DefaultMaxInvocations = 12

	// DefaultConcurrency bounds how many agent invocations run at once
	// (po-ksrjz). Unbounded parallelism let a large diff launch up to
	// MaxInvocations claude processes simultaneously; they contend for the
	// API and rate-limit each other into per-lens timeouts. 4 keeps the
	// common 3-lens case fully parallel while capping larger diffs.
	DefaultConcurrency = 4

	// DefaultMaxPrePushRefs caps how many pushed refs a single pre-push
	// invocation scans, so `git push --all` cannot fan out unbounded
	// per-ref scans (po-66evv.9).
	DefaultMaxPrePushRefs = 3

	// baseDescStaged is the BaseDesc value StagedChangeSet produces; the
	// pipeline keys snapshot mode on it (index vs HEAD tree).
	baseDescStaged = "staged"
)

// severityRank orders the gate severities: critical > high > medium >
// low. Unknown severities rank 0 and never gate (ValidateFindings drops
// them before aggregation anyway).
var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// KnownSeverity reports whether s is one of the four gate severities
// (valid as a fail_on threshold).
func KnownSeverity(s string) bool {
	_, ok := severityRank[s]
	return ok
}

// PipelineConfig configures one RunPipeline run. Zero values take
// defaults: FailOn "high", Mode enforce, MaxInvocations 12, size limits
// per hygiene.go. Adapter and Root are required.
type PipelineConfig struct {
	Root                string
	Adapter             Adapter
	FailOn              string // minimum blocking severity: critical|high|medium|low
	Mode                string // enforce (default) or eval
	StrictErrors        bool   // infra errors fail the gate closed instead of open
	SoftLimit           int    // diff lines before chunking (0 = DefaultSoftLimitLines)
	HardLimit           int    // diff lines before file-list degrade (0 = DefaultHardLimitLines)
	ExtraGeneratedGlobs []string
	BudgetWarnUSD       float64 // warn when total cost exceeds this (0 = no warning)
	MaxInvocations      int     // chunk x lens cap (0 = DefaultMaxInvocations)
	// Concurrency bounds simultaneous agent invocations (0 =
	// DefaultConcurrency). Lower values trade wall-clock for fewer API
	// rate-limit-driven per-lens timeouts (po-ksrjz).
	Concurrency int
	// Waivers suppress matching findings before the gate (po-66evv.7).
	// Keyed on rule slug + file glob; a waived finding is reported but
	// never gates. Populated by the CLI from .revelara.yaml waivers.
	Waivers []Waiver
	// Progress, when non-nil, receives progress events during the run so
	// the CLI can show live affordances (the agent takes ~1-2 min per
	// lens). The pipeline serializes calls, so the callback need not be
	// concurrency-safe itself.
	Progress func(ProgressEvent)
	// SnapshotTreeish overrides the tree the snapshot reads in range
	// mode (po-66evv.9). Empty means HEAD (the --changed-only default);
	// pre-push sets it to the pushed sha, since the pushed ref may not be
	// the checked-out branch. Ignored in staged mode (index is read).
	SnapshotTreeish string
	// Scorer, when non-nil, replaces each finding's agent-assigned severity
	// with a server-computed, data-grounded band before the gate (po-7si2t.6).
	// RunPipeline is fail-open: a Score error keeps the agent severities.
	Scorer Scorer
}

// Scorer replaces agent-assigned finding severities with server-computed,
// data-grounded bands (po-7si2t.6). The server scores each finding by its rule
// via /api/v1/findings/score, returning an absolute band rather than the LLM's
// relative label. Score must return the findings in the same order it received
// them (the gate maps by position). Any error is treated as fail-open by the
// caller: the agent severities are kept and the gate is unaffected.
type Scorer interface {
	Score(ctx context.Context, findings []Finding) ([]Finding, error)
}

// applyServerSeverity replaces res.Findings' severities with server-computed
// bands via cfg.Scorer (po-7si2t.6). It is fail-open: with no scorer, no
// findings, or any Score error, the agent severities are left untouched (a
// notice is recorded on error) so scoring can never change the gate outcome
// unexpectedly.
func applyServerSeverity(ctx context.Context, cfg PipelineConfig, res *PipelineResult) {
	if cfg.Scorer == nil || len(res.Findings) == 0 {
		return
	}
	scored, err := cfg.Scorer.Score(ctx, res.Findings)
	if err != nil {
		res.Notices = append(res.Notices, "server severity scoring unavailable; using agent severities")
		return
	}
	res.Findings = scored
}

// runLensResilient runs a lens and, on a transient failure (timeout /
// rate-limit / agent error), retries exactly once (po-ksrjz). A missing agent
// binary and parent-context cancellation are not retried. The retry's result
// is returned with Retried set so the pipeline can surface it.
func runLensResilient(ctx context.Context, a Adapter, l Lens, cs ChangeSet, snapshotDir string) LensResult {
	r := RunLens(ctx, a, l, cs, snapshotDir)
	if r.Err == nil || !isRetryableLensErr(r.Err) || ctx.Err() != nil {
		return r
	}
	retry := RunLens(ctx, a, l, cs, snapshotDir)
	retry.Retried = true
	return retry
}

// countRetried returns how many lens results came from a retry.
func countRetried(results []LensResult) int {
	n := 0
	for _, r := range results {
		if r.Retried {
			n++
		}
	}
	return n
}

// isRetryableLensErr reports whether a lens error is worth one retry: agent
// timeouts and transient invoke/agent errors are; a missing agent binary and a
// user-cancelled parent context are not.
func isRetryableLensErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrAgentUnavailable) || errors.Is(err, context.Canceled) {
		return false
	}
	return true
}

// PipelineResult is everything one scan produced. Notices MUST be
// surfaced by the caller (degrades must never read as a full scan), and
// when Banner is non-empty it must be the LAST line printed.
type PipelineResult struct {
	LensResults []LensResult
	// Findings is the aggregated, deduped (rule+file+line, highest
	// severity wins) union of all conforming lens findings, sorted
	// severity-descending.
	Findings   []Finding
	Skipped    bool
	SkipNotice string
	Notices    []string
	// TotalCostUSD sums adapter-reported cost across ALL lens results,
	// including errored ones: spend happened regardless.
	TotalCostUSD float64
	// Degraded is true when infra errors prevented some or all lens
	// coverage. FileListMode is true when the diff exceeded the hard
	// limit and only file names were sent; the gate summary line must
	// flag it so a degraded scan never reads as a full one.
	Degraded     bool
	FileListMode bool
	// InfraErrors holds every fail-open-class error (probe failure,
	// setup failure, or LensResult.Err). All lens errors are infra class
	// for v1 gating; the CLI report distinguishes their flavors.
	InfraErrors []error
	// Waived lists findings a waiver suppressed (po-66evv.7). They are
	// reported but excluded from Findings and never gate.
	Waived []WaivedFinding
	// Gate decision (ComputeGate output, copied here for the caller).
	Blocked    bool
	BlockedOn  []Finding
	GateReason string
	Banner     string
}

// ProgressKind identifies a progress event (po: live output affordances).
type ProgressKind string

const (
	// ProgressChangeSet fires once the filtered change set is known.
	ProgressChangeSet ProgressKind = "changeset"
	// ProgressLenses fires once lenses are selected, before the fan-out.
	ProgressLenses ProgressKind = "lenses"
	// ProgressLensDone fires as each lens invocation completes.
	ProgressLensDone ProgressKind = "lens-done"
)

// ProgressEvent is one live-progress notification. Fields are populated
// per Kind: ChangeSet sets Files; Lenses sets Lenses; LensDone sets Lens,
// Findings, Duration, and Err.
type ProgressEvent struct {
	Kind     ProgressKind
	Files    int
	Lenses   []string
	Lens     string
	Findings int
	Duration time.Duration
	Err      error
}

// GateDecision is ComputeGate's verdict. Banner is the fail-open
// warning text, set only when infra errors occurred and the gate did
// not block; callers print it as the LAST output line.
type GateDecision struct {
	Blocked   bool
	BlockedOn []Finding
	Reason    string
	Banner    string
}

// ComputeGate is the pure gate-policy function (spec: Gate policy):
//
//   - BlockedOn always lists aggregated findings at or above FailOn
//     (default high), so eval mode can report what would have blocked.
//   - Mode enforce blocks on any BlockedOn finding; mode eval NEVER
//     blocks, not even with StrictErrors set.
//   - Infra errors fail open by default; StrictErrors flips them to
//     fail-closed (enforce mode only).
//   - When infra errors occurred and the gate did not block, Banner
//     carries the fail-open warning.
func ComputeGate(cfg PipelineConfig, res PipelineResult) GateDecision {
	failOn := cfg.FailOn
	if failOn == "" {
		failOn = DefaultFailOn
	}
	mode := cfg.Mode
	if mode == "" {
		mode = GateModeEnforce
	}
	threshold := severityRank[failOn]
	if threshold == 0 {
		threshold = severityRank[DefaultFailOn]
	}

	var d GateDecision
	for _, f := range res.Findings {
		if severityRank[f.Severity] >= threshold {
			d.BlockedOn = append(d.BlockedOn, f)
		}
	}
	if mode == GateModeEnforce {
		var reasons []string
		if len(d.BlockedOn) > 0 {
			reasons = append(reasons, fmt.Sprintf("%d finding(s) at or above fail_on=%s", len(d.BlockedOn), failOn))
		}
		if cfg.StrictErrors && len(res.InfraErrors) > 0 {
			reasons = append(reasons, fmt.Sprintf("strict_errors: %d infra error(s) fail the gate closed", len(res.InfraErrors)))
		}
		if len(reasons) > 0 {
			d.Blocked = true
			d.Reason = strings.Join(reasons, "; ")
		}
	}
	if !d.Blocked && len(res.InfraErrors) > 0 {
		d.Banner = FailOpenBanner(len(res.InfraErrors))
	}
	return d
}

// FailOpenBanner is the exact fail-open warning line (spec: Gate
// policy, "red single-line banner emitted as the last line of output").
func FailOpenBanner(lensErrors int) string {
	return fmt.Sprintf("AGENT SCAN INCOMPLETE (%d lens errors) - gate passed OPEN; findings may be missing", lensErrors)
}

// AvailabilityChecker is an optional Adapter extension: one cheap
// up-front availability probe (e.g. LookPath) so a fan-out of N lenses
// does not produce N identical ErrAgentUnavailable results. When the
// probe fails, no invocation is attempted and the single error goes
// through the normal infra-error gate path.
type AvailabilityChecker interface {
	CheckAvailability() error
}

// RunPipeline runs the full agent-scan pipeline over an
// already-computed change set (StagedChangeSet or RangeChangeSet;
// cs.BaseDesc selects the snapshot source: "staged" reads the index,
// anything else reads the HEAD tree, matching the base...HEAD range
// semantics).
//
// Stage order follows the hygiene.go contract: SkipReason, generated
// filter, empty check, secret refusal, size budget, lens selection,
// availability probe, snapshot, parallel chunk x lens fan-out, cost and
// finding aggregation, gate.
//
// Error contract:
//   - Secrets refusal returns a *SecretsError (errors.Is
//     ErrSecretsDetected). HARD refusal: it never goes through the
//     fail-open path; the caller decides exit semantics per mode.
//   - Parent-context cancellation returns ctx.Err() (user abort).
//   - Every other failure (probe, git, snapshot, lens) is recorded in
//     InfraErrors and gated per StrictErrors; RunPipeline returns nil.
func RunPipeline(ctx context.Context, cfg PipelineConfig, cs ChangeSet) (PipelineResult, error) {
	var res PipelineResult
	if err := ctx.Err(); err != nil {
		return res, err
	}

	// Progress emitter: nil-safe and serialized, since lens-done events
	// fire from parallel goroutines.
	var progressMu sync.Mutex
	emit := func(e ProgressEvent) {
		if cfg.Progress == nil {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		cfg.Progress(e)
	}

	// 1. In-progress git state: merge/rebase/cherry-pick scans are out
	// of scope in v1; skip with a notice before doing anything else.
	if reason, skip := SkipReason(cfg.Root); skip {
		res.Skipped = true
		res.SkipNotice = "agent scan skipped: " + reason
		return res, nil
	}

	// 2. Generated-content filter.
	filtered, droppedFiles, err := FilterGenerated(cfg.Root, cs, cfg.ExtraGeneratedGlobs)
	if err != nil {
		return finishInfra(cfg, res, fmt.Errorf("generated-content filter: %w", err)), nil
	}
	if len(droppedFiles) > 0 {
		parts := make([]string, len(droppedFiles))
		for i, d := range droppedFiles {
			parts[i] = fmt.Sprintf("%s (%s)", d.Path, d.Reason)
		}
		res.Notices = append(res.Notices,
			fmt.Sprintf("generated content excluded from the scan: %s", strings.Join(parts, "; ")))
	}

	// 3. Empty filtered change set: nothing to scan, explicit notice.
	if len(filtered.Files) == 0 {
		res.Skipped = true
		if len(droppedFiles) > 0 {
			res.SkipNotice = fmt.Sprintf(
				"agent scan skipped: all %d changed file(s) are generated content; nothing to scan",
				len(droppedFiles))
		} else {
			res.SkipNotice = "agent scan skipped: the change set is empty; nothing to scan"
		}
		return res, nil
	}

	// 4. Secret refusal. Hard stop: never routed through fail-open.
	if err := CheckSecrets(filtered); err != nil {
		return res, err
	}

	// 5. Size budget: chunking or file-list degrade, with notices.
	budget := ApplyBudget(filtered, cfg.SoftLimit, cfg.HardLimit)
	res.Notices = append(res.Notices, budget.Notices...)
	res.FileListMode = budget.FileListMode
	chunks := budget.Chunks
	if len(chunks) == 0 {
		chunks = []ChangeSet{budget.ChangeSet}
	}

	emit(ProgressEvent{Kind: ProgressChangeSet, Files: len(filtered.Files)})

	// 6. Lens selection on the filtered file list.
	lenses := SelectLenses(filtered.Files)
	lensIDs := make([]string, len(lenses))
	for i, l := range lenses {
		lensIDs[i] = l.ID
	}
	emit(ProgressEvent{Kind: ProgressLenses, Lenses: lensIDs})

	// 7. One up-front availability probe (po-66evv.5 handoff contract).
	if probe, ok := cfg.Adapter.(AvailabilityChecker); ok {
		if aerr := probe.CheckAvailability(); aerr != nil {
			return finishInfra(cfg, res, aerr), nil
		}
	}

	// 8. Snapshot: staged mode reads the index, range mode reads the
	// HEAD tree (the new side of base...HEAD). Check err before
	// deferring cleanup: on error dir is "" and cleanup is nil.
	var snapDir string
	var cleanup func()
	if cs.BaseDesc == baseDescStaged {
		snapDir, cleanup, err = SnapshotIndex(cfg.Root, filtered.Present())
	} else {
		treeish := cfg.SnapshotTreeish
		if treeish == "" {
			treeish = "HEAD"
		}
		snapDir, cleanup, err = SnapshotTree(cfg.Root, treeish, filtered.Present())
	}
	if err != nil {
		return finishInfra(cfg, res, fmt.Errorf("snapshot: %w", err)), nil
	}
	defer cleanup()

	// 9. Chunk x lens fan-out, capped at MaxInvocations with a loud
	// notice so partial coverage is never silent.
	maxInv := cfg.MaxInvocations
	if maxInv <= 0 {
		maxInv = DefaultMaxInvocations
	}
	type invocation struct {
		chunk ChangeSet
		lens  Lens
	}
	var invs []invocation
	for _, chunk := range chunks {
		for _, l := range lenses {
			invs = append(invs, invocation{chunk: chunk, lens: l})
		}
	}
	if len(invs) > maxInv {
		res.Notices = append(res.Notices, fmt.Sprintf(
			"INVOCATION CAP: running %d of %d chunk x lens invocations (max_invocations=%d); "+
				"%d invocation(s) skipped, so coverage of this change is partial",
			maxInv, len(invs), maxInv, len(invs)-maxInv))
		invs = invs[:maxInv]
	}

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	results := make([]LensResult, len(invs))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, inv := range invs {
		wg.Add(1)
		go func(i int, inv invocation) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := runLensResilient(ctx, cfg.Adapter, inv.lens, inv.chunk, snapDir)
			results[i] = r
			emit(ProgressEvent{
				Kind:     ProgressLensDone,
				Lens:     inv.lens.ID,
				Findings: len(r.Findings),
				Duration: r.Wall,
				Err:      r.Err,
			})
		}(i, inv)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		// Parent-context cancellation is a user abort, not a lens
		// failure; it must not fail open.
		return res, err
	}
	res.LensResults = results
	if n := countRetried(results); n > 0 {
		res.Notices = append(res.Notices, fmt.Sprintf("%d lens invocation(s) retried after a transient failure", n))
	}

	// 10. Cost is summed across ALL results, including errored ones,
	// before any filtering: spend happened regardless.
	for _, r := range results {
		res.TotalCostUSD += r.CostUSD
	}
	if cfg.BudgetWarnUSD > 0 && res.TotalCostUSD > cfg.BudgetWarnUSD {
		res.Notices = append(res.Notices, fmt.Sprintf(
			"total agent cost $%.2f exceeds budget_warn_usd $%.2f", res.TotalCostUSD, cfg.BudgetWarnUSD))
	}

	// 11. All lens errors are infra class for v1 gating (the CLI report
	// distinguishes timeout/unavailable from parse/agent errors).
	for _, r := range results {
		if r.Err != nil {
			res.InfraErrors = append(res.InfraErrors, r.Err)
		}
	}
	res.Degraded = len(res.InfraErrors) > 0

	// 12. Aggregate conforming findings across lenses and chunks.
	var all []Finding
	for _, r := range results {
		all = append(all, r.Findings...)
	}
	res.Findings = dedupeFindings(all)

	applyServerSeverity(ctx, cfg, &res)

	// po-66evv.7: apply (rule, file-glob) waivers before the gate so
	// waived findings are reported but never gate. Expired waivers are
	// inert (waiverActive). ComputeGate then sees only kept findings.
	if len(cfg.Waivers) > 0 {
		kept, waived := ApplyWaivers(res.Findings, cfg.Waivers, time.Now())
		res.Findings = kept
		res.Waived = waived
		if len(waived) > 0 {
			res.Notices = append(res.Notices, fmt.Sprintf("%d finding(s) waived by .revelara.yaml waivers", len(waived)))
		}
	}

	return applyGate(cfg, res), nil
}

// finishInfra records a pre-fan-out failure (probe, git, snapshot) as a
// single infra error and computes the gate over what we have. This
// keeps environmental breakage on the fail-open path (StrictErrors
// still fails it closed) instead of hard-blocking commits.
func finishInfra(cfg PipelineConfig, res PipelineResult, err error) PipelineResult {
	res.InfraErrors = append(res.InfraErrors, err)
	res.Degraded = true
	res.Notices = append(res.Notices, "no lens was invoked: "+err.Error())
	return applyGate(cfg, res)
}

// applyGate copies the ComputeGate decision onto the result.
func applyGate(cfg PipelineConfig, res PipelineResult) PipelineResult {
	d := ComputeGate(cfg, res)
	res.Blocked = d.Blocked
	res.BlockedOn = d.BlockedOn
	res.GateReason = d.Reason
	res.Banner = d.Banner
	return res
}

// dedupeFindings deduplicates aggregated findings by (rule, file, line),
// keeping the highest-severity occurrence (first seen wins ties), and
// sorts the result severity-descending, then by file, line, and rule
// for deterministic output.
func dedupeFindings(in []Finding) []Finding {
	type key struct {
		rule, file string
		line       int
	}
	index := map[key]int{}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		k := key{rule: f.Rule, file: f.File, line: f.Line}
		if i, ok := index[k]; ok {
			if severityRank[f.Severity] > severityRank[out[i].Severity] {
				out[i] = f
			}
			continue
		}
		index[k] = len(out)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank[out[i].Severity] != severityRank[out[j].Severity] {
			return severityRank[out[i].Severity] > severityRank[out[j].Severity]
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Rule < out[j].Rule
	})
	if len(out) == 0 {
		return nil
	}
	return out
}
