package commands

import (
	"fmt"
	"io"
)

// po-72d5d: polaris deduplicates scan submissions by idempotency_key
// (server migration 200_scan_idempotency). When the same scan-parts and
// metadata are submitted twice inside the dedup window, the second
// submission gets the first one's stored ScanResponse back and no risk
// processing runs at all.
//
// Until the server started marking those bodies with `cached: true`, a
// replay was indistinguishable from a fresh scan, so this CLI reprinted
// "[NEW] R-0XX ..." for risks that had been created on an earlier run.
// That is actively misleading: it reads as "your change introduced these"
// when nothing was created or updated by the command that just ran.
//
// The rendering below makes a replay unmistakable in three places: the
// headline, the findings heading, and the per-risk status marker.

// scanSubmitHeadline is the first line of the human-readable scan output.
// Servers that predate the `cached` field always yield the original
// wording, so nothing changes for them.
func scanSubmitHeadline(cached bool) string {
	if cached {
		return "Scan replayed from server cache (cached: no new processing; risks below are the previous result)"
	}
	return "Scan submitted successfully"
}

// scanStatusMarker renders the per-finding status column. On a replay the
// marker is prefixed with "was" so an eye scanning for "[NEW]" does not
// find one: the status describes what happened on the ORIGINAL scan, not
// on this invocation.
func scanStatusMarker(status string, cached bool) string {
	var marker string
	switch status {
	case "created":
		marker = "NEW"
	case "updated":
		marker = "UPD"
	default:
		return "---"
	}
	if cached {
		return "was " + marker
	}
	return marker
}

// printScanFindings writes the findings block. Risk rows go to out;
// per-finding server warnings go to errOut (po-gli2z: they were parsed
// but never printed, so a server-side partial accept of a finding's
// fields was invisible).
func printScanFindings(out, errOut io.Writer, response *ScanResponse) {
	if response == nil || len(response.Findings) == 0 {
		return
	}
	if response.Cached {
		fmt.Fprintln(out, "Findings (cached: from the earlier scan, nothing was created or updated by this run):")
	} else {
		fmt.Fprintln(out, "Findings:")
	}
	for _, f := range response.Findings {
		fmt.Fprintf(out, "  [%s] %s: %s (score: %d, %s)\n",
			scanStatusMarker(f.Status, response.Cached), f.RiskCode, f.Title, f.Score, f.Priority)
		for _, w := range f.Warnings {
			fmt.Fprintf(errOut, "        warning [%s]: %s\n", f.RiskCode, w)
		}
	}
	fmt.Fprintln(out)
}

// noteCachedScan writes the cache-replay warning to errOut for the output
// modes whose stdout is machine-readable (--ci, --agent --format json).
// Those modes pass the `cached` field through in the JSON body already;
// this line is for the human reading the CI log.
func noteCachedScan(errOut io.Writer, response *ScanResponse) {
	if response == nil || !response.Cached {
		return
	}
	fmt.Fprintln(errOut, "note: cached scan replay (no new processing); findings are the previous result for this identical submission")
}
