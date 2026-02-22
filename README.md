# Polaris CLI

Connect your codebase to the [Polaris](https://dev.relynce.ai) reliability risk platform. Scan for risks, get control guidance, and manage your reliability posture — all from the terminal or Claude Code.

## Install

**From source (requires Go 1.25+):**

```bash
go install github.com/relynce/polaris-cli@latest
```

**From release binary:**

Download from [Releases](https://github.com/relynce/polaris-cli/releases) for your platform.

## Quick Start

```bash
# Configure your API credentials
polaris login

# Initialize a project (downloads Claude Code skills)
polaris init

# Check connection and skill status
polaris status
```

## Claude Code Integration

After `polaris init`, the following slash commands are available in Claude Code:

| Command | Description |
|---------|-------------|
| `/polaris:detect-risks` | Scan codebase for reliability risks |
| `/polaris:risk-check` | Quick risk assessment |
| `/polaris:control-guidance RC-XXX` | Implementation guidance for a control |
| `/polaris:reliability-review` | Review code changes for reliability |
| `/polaris:incident-patterns` | Search historical incident patterns |
| `/polaris:sre-context` | Load full reliability context |
| `/polaris:submit-evidence` | Submit control implementation evidence |
| `/polaris:list-open` | List unresolved risks |

## Commands

| Command | Description |
|---------|-------------|
| `polaris login` | Configure API credentials |
| `polaris logout` | Remove stored credentials |
| `polaris init` | Initialize project and install skills |
| `polaris status` | Check connection and skill status |
| `polaris scan` | Submit risk scan findings |
| `polaris risk` | Manage risks (list, show, close, resolve) |
| `polaris control` | Query the 58-control reliability catalog |
| `polaris knowledge` | Search organizational knowledge base |
| `polaris evidence` | Submit and manage control evidence |
| `polaris config` | Manage configuration |
| `polaris version` | Show version info |

## Configuration

Credentials are stored in `~/.polaris/config.yaml` (mode 0600). The CLI never exposes credentials to LLM contexts.

## License

[Business Source License 1.1](LICENSE) — see LICENSE for details.
