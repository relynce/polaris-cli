# Local Reliability Scanner

The `rvl scan --local` command runs a built-in pattern matcher set against
a codebase without an LLM, network call, or API key. It produces structured
findings you can submit to Revelara, gate CI on, or pipe to other tools.

This guide covers everyday usage, the report format, and the
`.revelara.yaml` scanner section.

## Quick start

```bash
# Run against the current directory, print human-readable report
rvl scan --local

# Scan a specific repo
rvl scan --local --target /path/to/repo

# Run AND submit findings to Revelara in one step
rvl scan --local --target /path/to/repo --submit

# CI-friendly: emit JSON, no styling
rvl scan --local --target /path/to/repo --format json
```

The first run takes ~30ms per 100 files. A 500-file Go repo finishes in
under a second.

## What the scanner checks

22 curated matchers across six reliability categories, each grounded in
real-world incident patterns. Run `rvl scan --local --list-matchers` to
see the full set with provenance (incident frequency, blast radius, MTTR).

| Category | Sample checks |
|----------|---------------|
| `fault_tolerance` | missing-timeout, swallowed-error, panic-in-goroutine, unbounded-buffer, missing-circuit-breaker |
| `change_management` | no-readiness-probe, missing-resource-limits, dockerfile-no-healthcheck, rollback-migration-missing-down |
| `monitoring_gaps` | missing-health-endpoint, no-structured-logging |
| `service_fragility` | hardcoded-connection-string, raw-sql-no-params, integer-column-not-bigint |
| `disaster_recovery` | terraform-no-encryption |
| `development_practices` | no-error-wrapping |

Every matcher carries a confidence level (`high`, `medium`, `low`) and a
severity. The CI gate (exit code 1) fires only on critical and high
findings; medium and low are advisory.

## Report format

The default output (when stdout is a TTY) renders through
[charmbracelet/glamour](https://github.com/charmbracelet/glamour) with
themed colors. Pipe to a file or `less` to see raw markdown.

### Sections

**Header** — target path, service name, files / bytes / matchers / duration.

**Summary** — severity breakdown with icons:

| Severity | Icon | Meaning |
|----------|------|---------|
| Critical | 🔴 | Imminent or in-progress failure mode. CI gate fires. |
| High | 🟠 | Strong reliability concern; needs remediation. CI gate fires. |
| Medium | 🟡 | Worth addressing during normal cleanup. Advisory. |
| Low | ⚪ | Stylistic or low-confidence; CI ignores. |

**Findings by Category** — matrix of category × severity, totals on the
right. Use this to triage by area: "We have 22 high-severity
change_management gaps; let's start there."

**Per-severity sections (Critical / High / Medium / Low)** — table with
three columns:

- **Category** — the matcher category
- **Finding** — the matcher's title
- **Locations** — count of distinct file:line hits

When a (Category, Finding) pair has multiple locations (e.g.,
`Kubernetes container without resource limits` firing on 12 Helm chart
files), the table collapses into one row with the count, and a
**Locations:** sub-list below breaks each group out into its file paths.

When every group is single-location (1 hit each), the sub-list is
skipped because the table already shows everything.

### Output formats

```bash
--format               # default; styled in TTY, raw markdown when piped
--format json          # ScanRequest-shaped JSON, identical to what
                       #   'rvl scan --stdin' accepts. Round-trippable.
--format markdown      # raw markdown, regardless of TTY
```

## CI integration

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | No findings, or only low/medium findings |
| 1 | At least one critical or high finding |
| 2 | Scanner error (bad config, no base ref, unreadable files) |

GitHub Actions:

```yaml
- name: Scan for reliability risks
  run: |
    rvl scan --local --target . --format json > scan.json
    rvl scan --local --target . --submit  # uses RVL_API_KEY
```

GitLab CI:

```yaml
reliability-scan:
  script:
    - rvl scan --local --target . --submit
```

### Sticky PR comment (po-qs96.4)

The `--pr-comment` flag emits the sticky-comment markdown to stdout. Pipe
it to `gh pr comment` (or equivalent) to post or update the comment on
the active PR. The comment begins with a hidden marker
(`<!-- rvl-sticky-comment:reliability -->`) so the CI script can find
and update the existing comment instead of creating duplicates.

GitHub Actions:

```yaml
- name: Reliability scan + PR comment
  if: github.event_name == 'pull_request'
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    rvl scan --local --target . --changed-only --submit --pr-comment > comment.md
    PR=${{ github.event.pull_request.number }}
    REPO=${{ github.repository }}
    # gh pr view returns HTML URLs (.../pull/N#issuecomment-MMM); extract
    # the numeric comment id and PATCH the API endpoint directly. Falls
    # back to creating a fresh comment on first run.
    EXISTING_ID=$(gh pr view "$PR" --repo "$REPO" --json comments \
      --jq '.comments[] | select(.body | startswith("<!-- rvl-sticky-comment:reliability -->")) | .url' \
      | head -n1 \
      | sed 's/.*#issuecomment-//')
    if [ -n "$EXISTING_ID" ]; then
      gh api -X PATCH "/repos/${REPO}/issues/comments/${EXISTING_ID}" \
        -f body="$(cat comment.md)"
    else
      gh pr comment "$PR" --repo "$REPO" -F comment.md
    fi
```

The status check still uses exit codes from the scanner: 0 (clean), 1
(critical/high finding present), 2 (scanner error). When the PR is over
budget, the comment surfaces "OVER BUDGET — waiver required to merge"
and the exit code follows the existing severity rules. To gate strictly
on budget, configure your CI to fail when the comment contains
"OVER BUDGET":

```yaml
- name: Enforce budget
  run: grep -q 'OVER BUDGET' comment.md && exit 1 || true
```

### Scan only changed files

For PR builds, scan only files changed since the base ref:

```bash
rvl scan --local --target . --changed-only
```

The base ref is resolved in this order, taking the first reachable ref:

1. `--base <ref>` flag
2. `RVL_BASE_REF` env var (generic CI override)
3. `GITHUB_BASE_REF` (set on PR events)
4. `CI_MERGE_REQUEST_TARGET_BRANCH_NAME` (GitLab MR)
5. `.revelara.yaml` `scanner.base_ref`

If none is reachable, the scanner exits 2 with a diagnostic message.
Pass `--scan-all-on-missing-base` to fall back to a full scan instead.

The scanner does **not** auto-fetch — your CI must arrange enough
checkout depth (`fetch-depth: 0` on `actions/checkout` is the simplest
fix).

## .revelara.yaml configuration

The scanner reads optional configuration from `.revelara.yaml` at the
git root of the target. Section is optional; absent means defaults.

```yaml
project: my-service
criticality: customer-facing
components:
  - name: api
    path: cmd/server/

scanner:
  # Suppress matchers known to be noisy in this repo.
  exclude_matchers:
    - no-error-wrapping
    - missing-circuit-breaker

  # Skip whole directory trees.
  exclude_paths:
    - legacy/
    - generated/

  # Drop matchers below this confidence level.
  # Valid values: low | medium | high
  confidence_threshold: medium

  # Default base ref for --changed-only.
  base_ref: origin/develop

  # Run matchers against test files.
  # By default, matchers opt in via Matcher.AppliesToTests.
  include_tests: false
```

Suppressed matcher slugs are echoed back to Revelara on `--submit` via
`ScanMetadata.ExcludedMatchers`. The Phase 2 feedback loop uses these
to mark org-generated matchers as noisy and stop regenerating them.

## Listing the matcher catalog

```bash
# Full catalog with provenance
rvl scan --local --list-matchers

# Only curated (Phase 1) matchers
rvl scan --local --list-matchers --source curated

# Only org-generated (Phase 2) matchers
rvl scan --local --list-matchers --source org-generated

# Machine-readable
rvl scan --local --list-matchers --format json
```

Each matcher entry shows:

- Slug, category, confidence, severity, source, applicable languages
- Description and control codes (RC-XXX)
- Provenance: incident frequency, typical blast radius, typical MTTR
- For org-generated matchers: the source pattern IDs and the org's
  incident count for that pattern

## Phase 2: org-generated matchers

When your organization has the `scanner_matcher_gen` feature flag
enabled, Revelara generates matchers from your knowledge graph
patterns. These are reviewed and approved at
`/settings/scanner/matchers` in the Revelara web app.

Approved matchers are fetched lazily by the CLI on each scan: the
local cache at `~/.revelara/matchers/org/` is refreshed if older
than 24 hours. Findings produced by these matchers carry a "Generated
from pattern" badge on the risk detail page, linking back to the
source knowledge graph pattern.

If the API is unreachable (offline, no auth), the scanner logs a
warning and proceeds with the compiled-in matchers only.

## Performance

Reference numbers from a 380-file, 11.6 MB repo:

| Mode | Duration |
|------|----------|
| Full scan, all 22 matchers | ~30ms (warm cache), ~300ms (cold) |
| `--changed-only` PR diff (~10 files) | ~10ms |
| `--list-matchers` | < 5ms |

The engine uses an 8-worker pool over files; matchers within a file
run sequentially.

## Submitting findings to Revelara

```bash
rvl scan --local --target . --submit
```

Submissions go to `POST /api/v1/risks/scan` using your configured API
key. The submission carries:

- All findings with title, category, severity, evidence (file:line),
  and a Tier-2 fingerprint that dedups against AI-agent findings for
  the same code location
- `ScanMetadata.MatcherVersion` — the matcher set version (for
  reproducibility / compliance audits)
- `ScanMetadata.ExcludedMatchers` — slugs the user suppressed, used by
  the Phase 2 feedback loop

Revelara scores findings via the knowledge graph, links them to
controls, and updates the risk register. The same findings show up at
`/risks` with the source attribution `rvl-local-scanner-<version>`.

## Troubleshooting

**`scanner: lazy-fetch: API returned 404`** — the Revelara API
your CLI is pointed at doesn't have the Phase 2 endpoints deployed
yet. Benign warning: the scanner continues with the compiled-in
matcher set.

**Exit code 2 with a base ref diagnostic** — `--changed-only` couldn't
find a reachable ref. Either set `--base origin/main` explicitly,
arrange `fetch-depth: 0` in CI, or pass
`--scan-all-on-missing-base` to fall back to a full scan.

**Findings I disagree with** — add the matcher slug to
`scanner.exclude_matchers` in `.revelara.yaml`. Suppressions are
echoed back to Revelara so the corpus-validation team can investigate
recurring false positives.

**Want JSON output but seeing styled markdown** — the `--format` flag
must come before any positional arguments:
`rvl scan --local --format json --target .`, not
`rvl scan --local --target . --format json` (that one works too,
actually — but the first form is the documented order).

## See also

- [Scanner matcher contributor guide](./scanner-matchers.md) — how
  to add a new matcher to the curated set
- PRD: `docs/PRD/local-reliability-scanner.md` (in the polaris repo)
- Help: `rvl help` for the full flag reference
