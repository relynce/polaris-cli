# Revelara CLI

Connect your codebase to the [Revelara](https://dev.revelara.ai) reliability risk platform. Scan for risks, get remediation guidance, and manage your reliability posture from the terminal or your AI coding agent.

## Install

**Homebrew (macOS, recommended):**

```bash
brew install revelara-ai/tap/rvl
```

Upgrade later with `brew upgrade rvl`. No Go toolchain required.

**From release binary (Linux/macOS/Windows):**

Download the archive for your platform from [Releases](https://github.com/revelara-ai/rvl-cli/releases), extract it, and put `rvl` on your `PATH`.

**From source (requires Go 1.25+):**

```bash
go install github.com/revelara-ai/rvl-cli/cmd/rvl@latest
```

## Quick Start

```bash
# Authenticate with your Revelara account
rvl login

# Initialize a project and install the AI coding agent plugin
rvl init

# Verify connection and plugin status
rvl status
```

## AI Coding Agent Skills

After `rvl init` (or `rvl plugin install`), the following slash commands are available in Claude Code and other supported agents.

| Command | Description |
|---------|-------------|
| `/rvl:scan` | Multi-agent scan — detects risks, correlates with incidents, saves to register |
| `/rvl:fix R-XXX` | Guided remediation for a specific risk with expert consultation |
| `/rvl:ask <question>` | Reliability Q&A with automatic expert routing |
| `/rvl:risks` | View risk register (posture overview, ready-to-fix, or full list) |
| `/rvl:review` | Reliability-focused review of your current code changes |
| `/rvl:evidence` | Submit evidence that a control has been implemented |
| `/rvl:status` | Check CLI connectivity and plugin health |

When run inside a git repository, `rvl plugin install` (any agent, or `--all`) also
adds a managed Revelara block to the repo's `AGENTS.md` — read natively by most
agent runtimes — with the `rvl` context-tool cheat sheet and skill reference.
Claude Code installs additionally maintain the same block in `CLAUDE.md`. The
blocks are marker-delimited and updated in place on reinstall/update. Pass
`--no-context-files` to `rvl plugin install`/`update` to skip them.

## CLI Commands

| Command | Description |
|---------|-------------|
| `rvl login` | Authenticate with your Revelara account |
| `rvl logout` | Remove stored credentials |
| `rvl init` | Initialize project and install AI coding agent plugin |
| `rvl status` | Check connection and plugin status |
| `rvl plugin` | Manage agent plugins (install, update, list, remove) |
| `rvl risk` | Manage risks (list, show, resolve) |
| `rvl control` | Query the 61-control reliability catalog |
| `rvl knowledge` | Search your organization's knowledge base |
| `rvl evidence` | Submit and manage control implementation evidence |
| `rvl config` | View and edit configuration |
| `rvl version` | Show version info |

## Configuration

Credentials are stored in `~/.revelara/config.yaml` (mode 0600). The CLI never exposes credentials to LLM contexts.

### Environment Variables

For headless and CI environments with no config file, credentials can be supplied as environment variables. They take precedence over `~/.revelara/config.yaml`:

| Variable | Purpose |
|----------|---------|
| `RVL_API_KEY` | API key (equivalent to config `api_key`) |
| `RVL_API_URL` | API endpoint (equivalent to config `api_url`) |
| `RVL_ORG_NAME` | Organization name (equivalent to config `org_name`) |

```bash
# CI example: no `rvl login` needed
export RVL_API_KEY="$REVELARA_API_KEY_SECRET"
rvl scan --local --target . --format json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, including help output (`help`, `-h`, `--help`) |
| 1 | Runtime failure (API error, authentication failure, network problem) |
| 2 | Usage error (unknown command, unknown flag, invalid argument) |

Exceptions: `rvl scan --local` uses its documented CI-gate codes (0 = no critical/high findings, 1 = at least one critical/high finding, 2 = scanner error), and `rvl review` follows its `--enforce` / `--fail-closed` contract (advisory mode always exits 0). `rvl knowledge enrich` degrades gracefully: it exits 1 only when every parallel fetch fails; partial failures print warnings on stderr and exit 0.

## License

[Business Source License 1.1](LICENSE) — see LICENSE for details.
