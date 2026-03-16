# ShieldAGI 2.0 — Quick Start Guide

Get your first autonomous security scan running in under 5 minutes.

## Prerequisites

- **Docker** 24+ with Docker Compose v2
- **Anthropic API key** with access to Claude Opus 4.6
- **OpenFang** runtime (ships with ShieldAGI)
- **Git** 2.30+

```bash
# Verify prerequisites
docker --version          # 24.0+
docker compose version    # v2.20+
git --version             # 2.30+
```

## 1. Install ShieldAGI

```bash
git clone https://github.com/shieldagi/shieldagi.git
cd shieldagi

# Set your API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Build the toolchain
cd tools && cargo build --release && cd ..
```

## 2. Connect a Repository

```bash
shieldagi connect <repo-url>
```

This single command kicks off the full 3-phase pipeline:

1. **Phase 1 — Reconnaissance**: Recon Scout maps the attack surface, Code Auditor runs static analysis
2. **Phase 2 — Attack**: Attack Executor proves vulnerabilities in a sandboxed clone
3. **Phase 3 — Remediation**: Vuln Reporter compiles findings, Shield Remediator fixes everything and opens a PR

The pipeline runs inside an isolated Docker sandbox network (172.28.0.0/16). No attacks ever touch production.

## 3. Read the Vulnerability Report

When the scan completes, find the report in two formats:

```bash
# Machine-readable JSON (used by the remediator)
cat workspace/reports/SHIELD-REPORT-*.json

# Human-readable Markdown
cat workspace/reports/SHIELD-REPORT-*.md
```

The report includes:
- Every vulnerability with CVSS v3.1 scoring
- Proof-of-concept payloads for confirmed exploits
- Remediation guidance mapped to playbooks
- Attack chains showing combined risk

## 4. Review the Pull Request

Shield Remediator creates a PR on a branch named `shieldagi/remediation-{timestamp}` with:

- A summary table of all fixes applied
- Before/after code snippets for each change
- Chain Walls middleware implementation
- Test results confirming nothing broke

Review the PR diff, verify the fixes, and merge when satisfied.

## 5. Activate Sentinel (Continuous Monitoring)

Once your code is patched, enable 24/7 monitoring:

```bash
shieldagi sentinel start
```

Sentinel runs every 5 minutes, analyzing traffic and logs for attack signatures. When it detects a threat, the Incident Responder automatically contains it.

Configure alert channels in `shieldagi.toml`:

```toml
[sentinel.channels]
telegram = true
slack = true
```

## 6. Configuration

Create `shieldagi.toml` in your project root:

```toml
[target]
repo = "https://github.com/your-org/your-app.git"
domain = "yourapp.com"
framework = "nextjs"  # nextjs | express | django | supabase

[model]
provider = "anthropic"
model = "claude-opus-4-6"

[scan]
max_duration_seconds = 3600
severity_threshold = "LOW"     # Minimum severity to report
skip_categories = []            # e.g., ["dependency"] to skip dep scan

[sandbox]
network = "172.28.0.0/16"
cpu_limit = "4"
memory_limit = "4G"

[remediation]
auto_pr = true
branch_prefix = "shieldagi/remediation"
run_tests = true

[sentinel]
enabled = true
cron = "*/5 * * * *"

[sentinel.channels]
telegram = true
slack = false

[dep_guardian]
enabled = true
cron = "0 */6 * * *"
auto_pr = true

[alerts]
telegram_bot_token = ""
telegram_chat_id = ""
slack_webhook_url = ""
```

## Next Steps

- Read [ARCHITECTURE.md](ARCHITECTURE.md) for how the system fits together
- Read [AGENT_REFERENCE.md](AGENT_REFERENCE.md) for detailed agent documentation
- Read [CHAIN_WALLS.md](CHAIN_WALLS.md) for the 7-layer defense middleware
- Read [DEPLOYMENT.md](DEPLOYMENT.md) for production setup
