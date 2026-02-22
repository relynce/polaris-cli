# Polaris Quickstart Guide

## Welcome to Polaris

Polaris is a reliability risk analysis platform that works in your browser and your IDE. Whether you're a developer, SRE, or engineering leader, Polaris gives you the insights you need to build more resilient systems.

## Accepting Your Invite and First Login

Polaris is currently invite-only. You'll receive an email invitation with a link to get started.

1. **Click the link** in your invitation email
2. **Create your account** — sign up with Google, GitHub, Microsoft, or email and password
3. **Verify your email** — check your inbox and click the verification link
4. **You're in.** You'll be directed to the main interface

## Your First Look Around

Polaris has five main sections accessible from the top navigation:

**Analysis** — Chat-based incident exploration. Ask questions about your organization's historical incidents and get AI-powered answers with sources cited.

**Documents** — Browse, search, and upload incident reports, postmortems, and RCAs. Upload your team's postmortems here to build shared learning.

**Knowledge** — Curated facts, procedures, and failure patterns extracted from incident analysis. Think of this as your team's reliability playbook.

**Risks** — Your risk register dashboard. See your team's current reliability posture, browse detected risks, and track compliance.

**Timeline** — Visual incident timelines. Explore patterns across years of incidents.

If you belong to multiple organizations, use the organization switcher in the header to switch between them.

## Setting Up Claude Code Integration

The Claude Code integration is how you scan your codebase for reliability risks. These scan results feed into the risk register, map to compliance controls, and populate the dashboards you see in the web UI. To get the most out of Polaris, you'll want to set this up.

### Prerequisites

- Claude Code installed and working on your machine
- A Polaris API key (create one below before installing the CLI)

### Step 1: Create an API Key

You'll need an API key to connect the CLI to your Polaris account.

1. Log in to Polaris at [dev.relynce.ai](https://dev.relynce.ai)
2. Click your profile picture in the top-right corner
3. Go to **API Keys**
4. Click **Create New Key**
5. Give your key a name (e.g., "My Laptop")
6. Click **Create**
7. **Copy your key immediately** — it's only shown once. If you lose it, delete and create a new one.

### Step 2: Install the CLI

Install the Polaris command-line tool:

```bash
go install github.com/relynce/polaris-cli@latest
```

Or download a pre-built binary from the [releases page](https://github.com/relynce/polaris-cli/releases).

### Step 3: Configure the CLI

Run the interactive setup — you'll need the API key you copied in Step 1:

```bash
polaris login
```

You'll be prompted for your API URL, API Key, and Organization name.

### Step 4: Verify Your Setup

```bash
polaris status
```

You should see a message confirming your connection.

### Step 5: Initialize Your Project

From within your project's git repository, run:

```bash
polaris init
```

This creates a `.polaris.yaml` project configuration file and installs the Polaris skills for Claude Code.

You can also run non-interactively:

```bash
polaris init --project my-service -y
```

#### Understanding `.polaris.yaml`

The `.polaris.yaml` file identifies your project:

```yaml
project: my-service
components:
  - name: api
    path: cmd/api/
  - name: worker
    path: cmd/worker/
```

- **`project`** — The service name used in the risk register. All risks detected in this repo are filed under this name.
- **`components`** — Optional list of sub-components for finer-grained visibility.

## Core Workflow: Detect, Understand, Resolve

### Detect: Find Risks in Your Code

Scan your codebase to identify potential reliability issues:

```
/polaris:detect-risks
```

This runs a full scan and saves findings to the risk register. The service name is auto-detected from your `.polaris.yaml`.

You can also scan a different project from your current session:

```
/polaris:detect-risks /path/to/other-project
```

For a quick read-only assessment without saving results:

```
/polaris:risk-check my-service
```

### Understand: Learn What the Risk Means

Get context on detected risks and learn how to fix them:

```
/polaris:control-guidance RC-015
```

Search historical incidents for patterns related to your risk:

```
/polaris:incident-patterns "database failover"
```

Load reliability context for your entire session:

```
/polaris:sre-context
```

Or visit the **Risks** tab in the web UI to browse the full risk register and see recommended actions.

### Resolve: Fix the Risk and Record It

1. Implement the fix recommended in the control guidance
2. Submit evidence that you've addressed the control:
   ```
   /polaris:submit-evidence RC-015
   ```
3. Review your changes for remaining reliability issues:
   ```
   /polaris:reliability-review
   ```

## Quick Reference: All Skills

| Skill | Description |
|-------|-------------|
| `/polaris:detect-risks [service or path]` | Full codebase scan, saves risks to the register |
| `/polaris:risk-check <service>` | Quick assessment without saving results |
| `/polaris:control-guidance RC-XXX` | Implementation guidance for a specific control |
| `/polaris:reliability-review` | Analyze your git diff for reliability issues |
| `/polaris:incident-patterns <query>` | Search historical incidents for patterns |
| `/polaris:sre-context` | Load full reliability context for your session |
| `/polaris:submit-evidence RC-XXX` | Record that you've implemented a control |
| `/polaris:list-open` | List open risks assigned to you |

## Troubleshooting

**"Not configured" error**

Run `polaris login` to set up your CLI credentials.

**"Connection failed" error**

Check that the Polaris server is reachable. Verify your API URL is correct with `polaris status`.

**"Invalid or expired API key" error**

Create a new API key in Settings -> API Keys. Your previous key is no longer valid.

**"Insufficient permissions" error**

Your API key may not have the required permissions. Delete the old key and create a new one.

**Skills don't show up in Claude Code**

Run `polaris init` to install skills. If you've already run init, try `polaris init --force` to reinstall. Restart Claude Code if needed.

## Next Steps

1. **Run Your First Scan** — Run `/polaris:detect-risks` on one of your team's services. This populates the risk register and compliance dashboards.

2. **Upload Your Postmortems** — Go to Documents and upload your team's incident reports and RCAs.

3. **Explore the Risk Register** — Visit the Risks tab to see detected risks mapped to compliance controls.

4. **Read the Full User Guide** — For comprehensive coverage of all features, see the [User Guide](user-guide.md).

## Questions?

If you get stuck, check the [Troubleshooting](#troubleshooting) section above or reach out to your Polaris administrator.
