# Agent scan as a git hook (`rvl scan --agent`)

`rvl scan --agent` runs a change-scoped reliability review with LLM lenses
(a language lens + observability + general) over just the staged or
pushed change set, and gates the commit/push on findings above a severity
threshold. This guide covers installing it as a pre-commit or pre-push
hook.

For the whole-repo agentic scan, use the `/rvl:scan` skill instead. For
the fast pattern-matcher scan, see [local-scanner.md](local-scanner.md).

## Prerequisites

- A headless coding agent on your `PATH`. The default preset is
  **`claude`** (Claude Code), invoked as `claude -p`. Make sure it is
  installed and logged in for **non-interactive** use — a hook has no
  TTY to complete an interactive login.
- Optional but recommended: a `.revelara.yaml` at the repo root with a
  `project` name and `criticality` (used for scoring and for `--submit`).

Verify your setup at any time:

```bash
rvl hook doctor
```

`doctor` is read-only and checks: you are in a git repo, the agent binary
is on `PATH`, the resolved agent-scan settings (model, mode, fail_on,
timeout), lefthook wiring, and any conflicting `.git/hooks`.

## Install

```bash
rvl hook install                 # pre-commit (default)
rvl hook install --pre-commit
rvl hook install --pre-push
rvl hook install --pre-commit --pre-push
rvl hook install --pre-commit --force   # overwrite an existing hook (backed up to <name>.pre-rvl)
```

`rvl hook install` is **lefthook-aware**:

- **If a `lefthook.yml` is present**, it does not touch `.git/hooks`.
  Instead it prints a ready-to-paste snippet to add to your
  `lefthook.yml`. Paste it in (see the pre-push note about `use_stdin`
  below). If it detects a secret-scan command (e.g. gitleaks), it tells
  you to order `agent-scan` **after** it.
- **If no lefthook config exists**, it writes a POSIX shim into the git
  hooks directory (resolved via `git rev-parse --git-path hooks`, so it
  honors `core.hooksPath` and linked worktrees). It refuses to clobber an
  existing hook without `--force`; with `--force`, the old hook is backed
  up to `<name>.pre-rvl`.

The installed command is:

```
rvl scan --agent --staged --mode enforce      # pre-commit
rvl scan --agent --pre-push                    # pre-push
```

To **uninstall**: delete the `.git/hooks/<name>` file, or remove the
`agent-scan` command from your `lefthook.yml`.

### lefthook snippet

Pre-commit:

```yaml
pre-commit:
  commands:
    # place AFTER any secret-scan command
    agent-scan:
      run: rvl scan --agent --staged --mode enforce
      # optional: scope to code files, e.g. glob: "**/*.{go,ts,py,js}"
```

Pre-push (note `use_stdin: true` — the hook must receive git's pushed-ref
lines on stdin):

```yaml
pre-push:
  commands:
    agent-scan:
      run: rvl scan --agent --pre-push
      use_stdin: true
```

## Modes: enforce vs eval

- **`--mode enforce`** (default): the gate **blocks** the commit/push when
  a finding is at or above `fail_on` (default `high`). Exit code 1.
- **`--mode eval`**: the gate **never blocks** — it runs, prints findings,
  and exits 0. Use this to try the gate on real work without trapping
  commits.

Set it per-run with `--mode`, or as the default in `.revelara.yaml` (see
below). To install a non-blocking hook, edit the installed command /
snippet to use `--mode eval`.

## Configuration (`.revelara.yaml`)

All keys are optional; flags override config, config overrides defaults.

```yaml
project: my-service           # service name (also used for --submit)
criticality: customer-facing  # hobby | internal | customer-facing | critical

scanner:
  agent:
    mode: enforce             # enforce (default) | eval
    fail_on: high             # critical | high | medium | low  (min blocking severity)
    strict_errors: false      # true = agent/timeout errors FAIL the gate closed instead of open
    model: sonnet             # pinned agent model
    timeout_seconds: 180      # per-lens invocation timeout
    generated_globs:          # extra generated-content globs to exclude
      - "gen/**"
    max_invocations: 12       # cap on chunk x lens fan-out
    preset: claude            # adapter preset: claude (default) | custom
    # NOTE: there is deliberately NO agent command/binary field here.
    # A custom command is a user-level setting only (see Custom agents).

  # Waivers are shared with the local scanner; agent findings key on the
  # lens RULE SLUG (e.g. missing-timeout, silent-error-swallow).
  waivers:
    - matcher: missing-timeout
      paths: ["internal/experimental/**"]
      reason: "spike code, not shipped"
      expires: "2026-12-31"     # optional; omit for open-ended
```

## Unblocking a blocked gate

When the gate blocks, you have three options:

1. **Fix the code** at the finding's `file:line`, re-stage, and re-run
   (`git add … && rvl scan --agent --staged`). The gate passes once
   nothing is at or above `fail_on`.
2. **Waive** an accepted risk by adding a `scanner.waivers` entry keyed on
   the finding's rule slug (see above). Waived findings are reported but
   never gate.
3. **Force through** in an emergency (ship a lesser risk to fix a greater
   one). Both mechanisms are recorded to a local audit trail
   (`rvl-audit.jsonl` in the git dir):

   ```bash
   RVL_FORCE=1 git commit ...          # env var, for CLI/CI
   rvl scan force-next                 # one-shot marker, for GUI git clients
   ```

`git commit --no-verify` also bypasses the hook, but leaves no audit
record — prefer the force-through above.

## Running it manually

```bash
rvl scan --agent --staged                       # the staged change set (pre-commit view)
rvl scan --agent --changed-only --base main     # committed changes vs a base ref
rvl scan --agent --staged --submit              # also POST findings to the risk register
rvl scan --agent --staged --format json         # machine-readable report on stdout
```

`--pre-push` is a **hook entrypoint**, not an interactive command: it
reads git's pushed-ref lines from stdin. Run by hand it will tell you so
and exit. To test it manually, feed it a ref line:

```bash
echo "refs/heads/$(git branch --show-current) $(git rev-parse HEAD) refs/heads/main $(git rev-parse origin/main)" \
  | rvl scan --agent --pre-push
```

## What to expect

- **Timing**: each lens invokes the agent and takes ~1-2 minutes; lenses
  run in parallel, so wall time is roughly the slowest lens. Live
  progress (change-set size, lens list, per-lens completion) streams to
  stderr during the run.
- **Scope**: only risks *introduced or worsened by the change* are
  flagged; pre-existing issues in surrounding code are out of scope.
- **Skips**: an empty change set, an all-generated change set, or a
  merge/rebase/cherry-pick in progress skip with a notice (exit 0).
- **Secrets**: if the diff appears to contain secrets, the scan refuses
  and no diff content leaves the machine — fix the secret and re-run.
- **Errors fail open by default**: if the agent is unavailable or times
  out, the gate passes with a warning banner (so a broken agent does not
  block all work). Set `strict_errors: true` to fail closed instead.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | pass, eval mode, skipped, or infra fail-open |
| 1 | blocked: a finding at/above `fail_on` in enforce mode (or a secret refusal in enforce, or `strict_errors` infra failure) |
| 2 | configuration/usage error |
| 130 | interrupted |

## Custom agents (advanced)

To use an agent other than `claude`, provide a command template via the
`RVL_AGENT_CMD` **environment variable** (a user-level source — repo
config can never supply a command, by design) and select the `custom`
preset:

```bash
export RVL_AGENT_CMD="my-agent --prompt {promptfile} --dir {snapshot_dir}"
rvl scan --agent --staged --agent-preset custom
```

The `{promptfile}` placeholder is required (the prompt is delivered via a
temp file, never on the command line). The command runs with the snapshot
directory as its working directory and must print the findings JSON to
stdout. GitHub Copilot's CLI can be wired this way today; a first-class
`copilot` preset is planned.
