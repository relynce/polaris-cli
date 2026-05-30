## Revelara

This project uses Revelara for reliability risk analysis. The following skills are available in Claude Code and other supported AI coding agents after `rvl plugin install`.

### Detection and Review
- `/rvl:scan` — Multi-agent codebase scan; detects risks and saves them to the register
- `/rvl:review` — Reliability-focused review of current code changes
- `/rvl:risks` — View the risk register (posture, ready-to-fix, or full list)

### Remediation
- `/rvl:fix R-XXX` — Guided remediation for a specific risk with expert consultation

### Reference and Research
- `/rvl:ask <question>` — Reliability Q&A with automatic expert routing
- `/rvl:evidence` — Submit evidence that a control has been implemented
- `/rvl:status` — Check CLI connectivity and plugin health

### Quick CLI Reference
- `rvl risk list` — See current risks
- `rvl risk show <code>` — Risk details with mapped controls
- `rvl control show <code>` — Control implementation guidance
