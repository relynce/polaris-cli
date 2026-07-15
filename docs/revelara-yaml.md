# `.revelara.yaml` configuration reference

Complete reference for the `.revelara.yaml` project configuration file:
every field, its type, default, valid values, what it does, and how it
interacts with CLI flags and environment variables.

`.revelara.yaml` is optional. If it is absent, every setting falls back
to its built-in default.

## Maturity

The file spans two maturity tiers. Know which one you are configuring:

| Tier | Fields | Consumed by |
|------|--------|-------------|
| **Stable** | `project`, `criticality`, `components` (top level) | `rvl scan`, `rvl review`, `rvl init`, and the `/rvl:*` skills |
| **Experimental (alpha)** | the entire `scanner:` section | `rvl scan --local` only |

The top-level identity fields are safe to rely on. The `scanner:` section
configures the **local scanner** (`rvl scan --local`), which is an
alpha-level feature: field names, defaults, and behavior may change
without notice between releases. See
[Experimental parameters](#experimental-parameters-alpha) below.

## Location and discovery

The file lives at the **git root** of the target (the directory returned
by `git rev-parse --show-toplevel`). The loader
(`internal/project/config.go`) loads this file:

- `.revelara.yaml` in the git root, if it exists

If none exist, config is treated as absent (all defaults). If the target
is not a git repository, the loader falls back to treating the target
directory itself as the root.

Generate a starter file with `rvl init`, which writes `project` plus
auto-detected `components`.

---

# Stable parameters

These top-level fields identify the service and are used across the
product: the `rvl scan` submit path, `rvl review`, and the `/rvl:*`
skills for consistent service naming.

```yaml
# Service name. Overrides the --service flag and becomes the service
# these findings are attributed to in Revelara. Set by `rvl init`.
project: my-service

# Business criticality of this service. Boosts risk scoring on submit.
# Valid: hobby | internal | customer-facing | critical
# Default: unset (treated as no boost)
criticality: customer-facing

# Components map file paths to sub-service names. A finding's evidence
# path is matched against these (longest-prefix wins) to set its
# linked_services as "<project>/<component>".
components:
  - name: api
    path: cmd/server/
  - name: worker
    path: cmd/worker/
  - name: frontend
    path: frontend/src/
```

## `project`
- **Type:** string
- **Default:** unset
- **Set by:** `rvl init`

The service name findings are attributed to. When set, it overrides the
`--service` flag on both `rvl scan` and `rvl review` (a mismatch prints a
warning and the config value wins). Also used as the prefix in component
`linked_services` (`<project>/<component>`).

## `criticality`
- **Type:** string enum
- **Valid values:** `hobby`, `internal`, `customer-facing`, `critical`
- **Default:** unset (behaves as `hobby`)

Maps to a business-criticality score used to boost risk scoring on
submit. Any unrecognized or empty value scores 0.0 (no boost).

| Value | Score |
|-------|-------|
| `hobby` | 0.0 |
| `internal` | 0.25 |
| `customer-facing` | 0.6 |
| `critical` | 1.0 |

On submit, a score greater than 0 is sent as `business_criticality`.

## `components`
- **Type:** list of `{ name, path }`
- **Default:** empty
- **Set by:** `rvl init` (auto-detected)

Maps file paths to sub-service names. Each finding's evidence path is
tested against every component path by **longest-prefix match** (a
nested `services/x/frontend/` beats a parent `services/x/`); the winner
sets the finding's `linked_services` to `<project>/<component>`. Findings
that already carry `linked_services`, or an explicit `component` field
set by a skill, are left untouched.

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | Component / sub-service name |
| `path` | string | Path prefix (relative to git root) |

## Precedence: service name

`.revelara.yaml` `project` > `--service` flag. A mismatch warns and the
config value wins.

---

# Experimental parameters (alpha)

> **Alpha.** Everything under `scanner:` configures the local scanner
> (`rvl scan --local`), an alpha-level feature that is **not production
> ready**. Field names, defaults, and behavior may change without notice
> between releases. Expect false positives and gaps; do not gate
> production CI on it yet.

The `scanner:` section is optional and is read only by `rvl scan
--local`. Non-local scans ignore it entirely.

```yaml
scanner:
  # Suppress specific matchers, no questions asked. Slugs listed here
  # never fire. Echoed to Revelara on --submit so the Phase 2 feedback
  # loop can stop regenerating noisy org matchers.
  exclude_matchers:
    - no-error-wrapping
    - missing-circuit-breaker

  # Skip whole directory trees. Prefix match against the file path.
  exclude_paths:
    - legacy/
    - generated/

  # Drop matchers whose confidence is below this level.
  # Valid: low | medium | high. Default: unset (no confidence filter).
  confidence_threshold: medium

  # Default base ref for --changed-only diffs. Lowest-priority source
  # in the base-ref resolution chain (see Precedence below).
  base_ref: origin/develop

  # Run matchers against test files. By default only matchers that opt
  # in via Matcher.AppliesToTests run on tests. Default: false.
  include_tests: false

  # CI gate behavior. enforce = critical/high findings exit non-zero.
  # eval = report findings but always exit 0. Valid: enforce | eval.
  # Default: enforce. --mode overrides this.
  mode: enforce

  # Named matcher profile to run by default.
  # Built-ins: fast (regex-impl matchers only, cheap, every-commit) and
  # full (all matchers, PR/pre-merge). Custom names must appear under
  # `profiles`. Default: unset (= full / no filter). --profile overrides.
  profile: fast

  # User-defined profiles, or overrides of a built-in name. Keys are
  # profile names; values are explicit matcher-slug allowlists. A key
  # named "fast" or "full" replaces that built-in's computed list.
  profiles:
    pr-critical:
      - hardcoded-connection-string
      - missing-timeout
      - swallowed-error

  # Per-service tolerance override for the Polaris CI budget gate.
  # Each field is optional; unset fields fall through to org defaults
  # (most-specific wins). Only sent to Polaris on --submit.
  tolerance:
    target: 200        # allowed finding budget for this service
    headroom_pct: 10   # % headroom before the gate trips

  # When true, floor matchers (a mandatory baseline set) cannot be
  # waived by any yaml/comment/label waiver; only an emergency override
  # clears them. Sent to Polaris on --submit. Default: unset (false).
  strict_enforcement: false

  # Time-bounded, reason-bearing waivers. Unlike exclude_matchers (silent
  # suppression), each active waiver that matches a finding is logged to
  # Polaris's waivers_audit table on --submit for accountability.
  waivers:
    - matcher: missing-timeout          # required: matcher slug to waive
      paths:                            # optional: glob scope (path.Match)
        - "internal/legacy/**/*.go"
      expires: "2026-12-31"             # optional YYYY-MM-DD; empty = open-ended
      reason: "legacy client scheduled for removal in Q4"  # required
```

## `scanner.exclude_matchers`
- **Type:** list of strings (matcher slugs)
- **Default:** empty

Hard suppression: listed matchers never fire. Suppressed slugs are
echoed to Revelara on `--submit` (`ScanMetadata.ExcludedMatchers`) so the
Phase 2 feedback loop can flag noisy org-generated matchers. Use this for
matchers you never want; use `waivers` for time-bounded, reasoned
exceptions you want on the audit record.

## `scanner.exclude_paths`
- **Type:** list of strings (path prefixes)
- **Default:** empty

Skip whole directory trees. Matched as a path prefix against each file.

## `scanner.confidence_threshold`
- **Type:** string enum
- **Valid values:** `low`, `medium`, `high`
- **Default:** unset (no confidence filter)

Drops any matcher whose confidence rank is below the threshold
(`low` < `medium` < `high`). Comparison is case-insensitive.

## `scanner.base_ref`
- **Type:** string (git ref)
- **Default:** unset

Default base ref for `--changed-only` scans. This is the **lowest**
priority source in the base-ref resolution chain (see
[Precedence](#precedence-chains-scanner) below).

## `scanner.include_tests`
- **Type:** bool
- **Default:** `false`

When `true`, matchers run against test files too. By default, only
matchers that opt in (`Matcher.AppliesToTests`) run on tests. Setting
`true` here is a global override; there is no way to set it back to false
per-matcher from config. `--include-tests` on the CLI can also enable it.

## `scanner.mode`
- **Type:** string enum
- **Valid values:** `enforce`, `eval`
- **Default:** `enforce`
- **CLI override:** `--mode` (CLI > config > default)

Controls the CI gate. `enforce` exits non-zero on critical/high findings.
`eval` reports findings but always exits 0, so you can roll the scanner
out to a team for visibility before turning the gate on. Validated
case-insensitively; an invalid value errors and names the source
(`scanner.mode` vs `--mode`) so you know where to fix it.

## `scanner.profile`
- **Type:** string
- **Valid built-ins:** `fast`, `full`
- **Default:** unset (equivalent to `full` / no filter)
- **CLI override:** `--profile` (CLI > config > implicit full)

Selects which matcher set runs.

| Profile | Meaning |
|---------|---------|
| `fast` | Regex-impl matchers only. Cheap; intended for every commit. |
| `full` | All matchers, no filter. Intended for PR open / pre-merge. |

A custom name must be defined under `profiles` or the scan errors with
the list of available names. When both `profile` and `--matchers` are
set, the profile's allowlist is **intersected** with `--matchers`;
otherwise the profile allowlist becomes the matcher set.

## `scanner.profiles`
- **Type:** map of `string -> list of strings` (name -> matcher slugs)
- **Default:** empty

User-defined profiles. A key equal to a built-in name (`fast`, `full`)
**replaces** that built-in's computed slug list. Any other key defines a
new profile selectable via `profile:` or `--profile`.

## `scanner.tolerance`
- **Type:** object `{ target, headroom_pct }`
- **Default:** unset (org defaults apply)
- **Sent to Polaris:** on `--submit` only

Per-service override of the Polaris CI budget gate. Each field is
independently optional; an unset field falls through to the org-level
default (most-specific wins). If no tolerance field and no
`strict_enforcement` is set, nothing is sent and the resolver uses org
defaults.

| Field | Type | Meaning |
|-------|------|---------|
| `target` | int | Allowed finding budget for this service |
| `headroom_pct` | int | Percent headroom before the gate trips |

## `scanner.strict_enforcement`
- **Type:** bool (nullable; unset is distinct from false)
- **Default:** unset
- **Sent to Polaris:** on `--submit`

When `true`, **floor matchers** (a mandatory baseline set) cannot be
suppressed by any waiver (yaml, PR comment, or label); they require an
emergency override to clear. Non-floor findings can still be waived.

## `scanner.waivers`
- **Type:** list of waiver entries
- **Default:** empty

Time-bounded, reasoned exceptions. Unlike `exclude_matchers`, each active
waiver that actually matches a finding is recorded to Polaris's
`waivers_audit` table on `--submit` (who / when / scope / reason), so EMs
and auditors have a trail.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `matcher` | string | yes | Matcher slug to waive |
| `paths` | list of strings | no | Glob scope. Empty = waiver applies repo-wide. |
| `expires` | string `YYYY-MM-DD` | no | Date after which the waiver is inactive. Empty = open-ended. |
| `reason` | string | yes | Audit justification |

Semantics:
- A waiver drops a finding only when the finding's **matcher slug**
  equals `matcher` (case-insensitive) **and** (no `paths`, or the
  finding's first evidence path matches a `paths` glob).
- Path globs use `path.Match` (forward-slash, OS-independent). A `**/`
  prefix also matches by basename, so `**/*.go` matches
  `pkg/foo/bar.go`.
- Waivers whose `expires` date is in the past are inactive.
- Under `strict_enforcement: true`, floor matchers are never waived
  regardless of any matching waiver.

## Precedence chains (scanner)

All of these apply only to `rvl scan --local`.

### Scan mode
`--mode` flag > `scanner.mode` > default (`enforce`).

### Matcher profile
`--profile` flag > `scanner.profile` > implicit `full` (no filter). If
`--matchers` is also given, the resolved profile intersects with it.

### Base ref (for `--changed-only`)
Highest to lowest:
1. `--base` flag
2. `RVL_BASE_REF` env var
3. `GITHUB_BASE_REF` env var (GitHub PR events)
4. `CI_MERGE_REQUEST_TARGET_BRANCH_NAME` env var (GitLab MRs)
5. `scanner.base_ref` in `.revelara.yaml`

If none resolve to a reachable ref, `--changed-only` exits 2 with a
diagnostic unless `--scan-all-on-missing-base` is set (then it falls back
to a full scan).

### Tolerance / strict_enforcement
`.revelara.yaml` values are sent to Polaris, which merges them over
org-level defaults (most-specific wins). Unset fields fall through.

---

## See also

- [Feature maturity](./maturity.md) - which fields and features are
  stable, beta, or alpha
- [Local scanner guide](./local-scanner.md) - running the alpha `--local`
  scanner, CI integration, report formats
- [Scanner matcher catalog](./scanner-matchers.md) - the matchers the
  `scanner:` fields target, and how to add one
