# Revelara CLI

Connect your codebase to the [Revelara](https://dev.revelara.ai) reliability risk platform. Scan for risks, get remediation guidance, and manage your reliability posture from the terminal or your AI coding agent.

## Install

**From source (requires Go 1.25+):**

```bash
go install github.com/revelara-ai/rvl-cli/cmd/rvl@latest
```

**From release binary:**

Download from [Releases](https://github.com/revelara-ai/rvl-cli/releases) for your platform.

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

## License

[Business Source License 1.1](LICENSE) — see LICENSE for details.
