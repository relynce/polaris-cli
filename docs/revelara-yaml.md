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
| **Beta** | the `scanner:` section (`scanner.base_ref`, `scanner.agent`, `scanner.waivers`) | `rvl scan --agent` only |

The top-level identity fields are safe to rely on. The `scanner:` section
configures the **change-scoped agent scan** (`rvl scan --agent`); see
[Agent scan parameters](#agent-scan-parameters) below and the
[agent scan hooks guide](./agent-scan-hooks.md).

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

# Agent scan parameters

> The `scanner:` section configures `rvl scan --agent`, the change-scoped
> agentic reliability gate. A CLI flag overrides the matching config
> value; config overrides the built-in default. For installing the scan
> as a pre-commit / pre-push hook, the enforce vs eval modes, and CI
> usage, see the [agent scan hooks guide](./agent-scan-hooks.md).

The `scanner:` section is optional and is read only by `rvl scan --agent`.
Other scan modes ignore it.

```yaml
scanner:
  # Default base ref for `--changed-only` diffs. Lowest-priority source
  # in the base-ref resolution chain (see Precedence below).
  base_ref: origin/develop

  # Change-scoped agent scan settings.
  agent:
    preset: claude          # adapter preset: claude (default) | custom
    mode: enforce           # enforce (default) | eval (eval never blocks)
    fail_on: high           # critical | high | medium | low (min blocking severity)
    strict_errors: false    # true = agent/timeout errors fail the gate closed
    model: sonnet           # pinned agent model
    timeout_seconds: 180    # per-lens invocation timeout
    budget_warn_usd: 5.0    # warn when cumulative scan cost exceeds this
    generated_globs:        # extra generated-content globs to exclude
      - "gen/**"
    max_invocations: 12     # cap on chunk x lens fan-out

  # Time-bounded, reason-bearing waivers. A waived finding is still
  # reported but never gates the commit/push.
  waivers:
    - matcher: missing-timeout          # required: agent lens RULE SLUG to waive
      paths:                            # optional: glob scope (path.Match)
        - "internal/legacy/**/*.go"
      expires: "2026-12-31"             # optional YYYY-MM-DD; empty = open-ended
      reason: "legacy client scheduled for removal in Q4"  # required
```

## `scanner.base_ref`
- **Type:** string (git ref)
- **Default:** unset

Default base ref for `rvl scan --agent --changed-only`. This is the
**lowest** priority source in the base-ref resolution chain (see
[Precedence: base ref](#precedence-base-ref) below).

## `scanner.agent`
- **Type:** object
- **Default:** unset (all agent defaults apply)

Configures the change-scoped agent scan. Every key is optional; a CLI
flag overrides the matching config value, which overrides the built-in
default.

| Key | Type | Default | CLI override | Meaning |
|-----|------|---------|--------------|---------|
| `preset` | string | `claude` | `--agent-preset` | Adapter preset: `claude` or `custom`. |
| `mode` | enum | `enforce` | `--mode` | `enforce` blocks on findings at/above `fail_on`; `eval` reports but always exits 0. |
| `fail_on` | enum | `high` | `--fail-on` | Minimum blocking severity: `critical`, `high`, `medium`, `low`. |
| `strict_errors` | bool | `false` | — | When `true`, agent/timeout infra errors fail the gate **closed** instead of the default fail-open. |
| `model` | string | `sonnet` | `--model` | Pinned agent model. |
| `timeout_seconds` | int | `180` | `--timeout-seconds` | Per-lens invocation timeout. Must be positive. |
| `budget_warn_usd` | float | unset | — | Warn when cumulative agent cost for the scan exceeds this. |
| `generated_globs` | list of strings | empty | — | Extra generated-content globs excluded from the change set. |
| `max_invocations` | int | built-in cap | — | Cap on the chunk x lens fan-out. Must be positive. |

**Trust boundary.** There is deliberately no agent command, binary, or
template-path field under `scanner.agent`: anything that selects code to
execute is honored only from user-level sources (the `--agent-binary`
flag, or `RVL_AGENT_CMD` for the `custom` preset), never from
repo-tracked config.

## `scanner.waivers`
- **Type:** list of waiver entries
- **Default:** empty

Time-bounded, reasoned exceptions for the agent scan. A waived finding is
still reported but never gates the commit/push.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `matcher` | string | yes | The agent lens **rule slug** to waive (e.g. `missing-timeout`, `silent-error-swallow`). |
| `paths` | list of strings | no | Glob scope. Empty = waiver applies repo-wide. |
| `expires` | string `YYYY-MM-DD` | no | Date after which the waiver is inactive. Empty = open-ended. |
| `reason` | string | yes | Audit justification |

Semantics:
- A waiver drops a finding only when the finding's **rule slug** equals
  `matcher` (case-insensitive) **and** (no `paths`, or the finding's
  first evidence path matches a `paths` glob).
- Path globs use `path.Match` (forward-slash, OS-independent). A `**/`
  prefix also matches by basename, so `**/*.go` matches `pkg/foo/bar.go`.
- Waivers whose `expires` date is in the past are inactive.

## Precedence: base ref

For `rvl scan --agent --changed-only`, the base ref resolves highest to
lowest:

1. `--base` flag
2. `RVL_BASE_REF` env var
3. `GITHUB_BASE_REF` env var (GitHub PR events)
4. `CI_MERGE_REQUEST_TARGET_BRANCH_NAME` env var (GitLab MRs)
5. `scanner.base_ref` in `.revelara.yaml`

---

## See also

- [Feature maturity](./maturity.md) - which fields and features are
  stable, beta, or alpha
- [Agent scan hooks](./agent-scan-hooks.md) - running `rvl scan --agent`,
  installing it as a pre-commit / pre-push hook, modes, waivers, and CI
  usage
