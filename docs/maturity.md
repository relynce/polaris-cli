# Feature maturity

Not every `rvl` command and feature is at the same level of readiness.
This page is the single source of truth for which parts you can rely on,
which are close, and which are still experimental.

## Tiers

| Tier | Meaning |
|------|---------|
| **Production** | Tested and stable. Safe to depend on, including in CI. Breaking changes follow semver. |
| **Beta** | Defined and mostly solid, but not fully tested and verified. Usable, and likely to stay close to its current shape, but details may still change. |
| **Alpha** | Completely experimental. Expect rough edges, false positives, and changes without notice. Do not gate production workflows on it. |

## Commands

| Command | Tier | Notes |
|---------|------|-------|
| `rvl login` / `rvl logout` | Production | Auth and credential storage. |
| `rvl init` | Production | Project setup, `.revelara.yaml` generation, plugin install. |
| `rvl status` | Production | Connectivity and plugin health. |
| `rvl plugin` | Production | Install / update / list / remove agent plugins. |
| `rvl risk` | Production | List, show, resolve risks. |
| `rvl control` | Production | Query the reliability controls catalog. |
| `rvl knowledge` | Production | Search the org knowledge base. |
| `rvl evidence` | Production | Submit and manage control evidence. |
| `rvl config` | Production | View and edit CLI configuration. |
| `rvl scan` (default review mode) | Production | Agent-driven scan with interactive review of inferred findings. |
| `rvl review` | Production | Reliability-focused review of current changes. |
| `rvl scan --local` | **Alpha** | Local pattern matcher. See [feature notes](#features-and-flags). |

## Features and flags

| Feature / flag | Tier | Notes |
|----------------|------|-------|
| `rvl scan --local` and its `.revelara.yaml` `scanner:` section | **Alpha** | Built-in matcher set, no LLM. Expect false positives and gaps. The entire `scanner:` config block feeds only this path. See the [`.revelara.yaml` reference](./revelara-yaml.md#experimental-parameters-alpha). |
| Org-generated matchers (`scanner_matcher_gen` flag) | **Alpha** | Matchers generated from your knowledge graph, flag-gated and pre-GA even within the local scanner. |
| `rvl scan --auto-infer` | **Alpha** | Skips the interactive review step and accepts inferred findings unattended. |
| AI coding agent **subagent definitions** (`/rvl:*` expert agents) | **Beta** | The subagent definitions are well tested. Their host-side execution is not fully verified across every agent (see note below). |

### Note on Gemini subagents

The subagent *definitions* are beta, but when installed into the
**Google Gemini CLI** they run via Gemini's own `experimental.enableAgents`
setting, which executes subagents in "YOLO mode" (no per-tool
confirmation). That execution path is experimental on Gemini's side, so a
Gemini user is leaning on an experimental host behavior even though the
definitions themselves are solid. Other agent runtimes (e.g. Claude Code)
run the same definitions under their normal confirmation model.

## Configuration parameters

`.revelara.yaml` field maturity mirrors the features above:

- **Production**: `project`, `criticality`, `components` (top-level
  identity fields, used by `rvl scan`, `rvl review`, and the skills).
- **Alpha**: the entire `scanner:` section (local scanner only).

Full field-by-field detail is in the
[`.revelara.yaml` configuration reference](./revelara-yaml.md).
