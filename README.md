# ShieldAGI 2.0 — Autonomous Cyber Defense Platform

> Connect any web platform. Get military-grade protection. Zero human intervention.

ShieldAGI 2.0 is an autonomous cyber defense platform built from scratch on the [OpenFang Agent OS](https://github.com/RightNow-AI/openfang) (Rust, single binary). It connects to any web platform's codebase and infrastructure, identifies every exploitable vulnerability through real penetration testing, automatically remediates all findings using Claude Opus 4.6 via Claude Code, and maintains continuous 24/7 autonomous monitoring with instant self-healing.

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: RECON & ATTACK                                        │
│  Agents scan code + run real attacks in Docker sandbox           │
│  → recon-scout → code-auditor → attack-executor → vuln-reporter │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Vulnerability Report + Knowledge Graph
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: REMEDIATE & HARDEN                                    │
│  Opus 4.6 fixes every finding + implements Chain Walls           │
│  → shield-remediator → Git PR with all fixes                    │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Deploy fixes → re-scan → validate
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3: SENTINEL (24/7)                                       │
│  Autonomous Hands monitor, detect, and auto-patch               │
│  → sentinel (5min) → dep-guardian (6hr) → incident-responder    │
└─────────────────────────────────────────────────────────────────┘
         ↻ Threat detected → re-scan → re-patch → defend
```

## Quick start

```bash
# 1. Install OpenFang (ShieldAGI fork)
curl -fsSL https://openfang.sh/install | sh

# 2. Clone ShieldAGI
git clone https://github.com/your-org/shieldagi.git
cd shieldagi

# 3. Initialize with your Anthropic API key
openfang init  # Select claude-opus-4-6

# 4. Copy agents and hands into OpenFang
cp -r agents/* ~/.openfang/agents/
cp -r hands/* ~/.openfang/hands/

# 5. Start the sandbox
docker compose -f sandbox/docker-compose.yml up -d

# 6. Start OpenFang daemon
openfang start  # Dashboard at http://localhost:4200

# 7. Connect a target platform
openfang chat shield-remediator
> "Scan and protect https://github.com/user/repo"
```

## Architecture

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Agent OS | OpenFang v0.3.x (Rust fork) | Runtime, scheduler, WASM sandbox, RBAC |
| AI Backbone | Claude Opus 4.6 | Vuln reasoning, code analysis, fix generation |
| Code Agent | Claude Code integration | Direct source code modification |
| Pentest Tools | nmap, sqlmap, nuclei, semgrep, etc. | Attack simulation in Docker sandbox |
| Knowledge Store | SQLite + vector embeddings | Vuln patterns, remediation history |
| Channels | Telegram, Slack, Discord | Alerts, reports, commands |
| Dashboard | OpenFang built-in + Grafana | Real-time security monitoring |
| Infrastructure | Hetzner AX102 | Dedicated execution server |

## Target attack vectors

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS) — stored, reflected, DOM-based
- Cross-Site Request Forgery (CSRF)
- Broken Authentication
- Server-Side Request Forgery (SSRF)
- Rate Limiting / DDoS
- Directory / Path Traversal
- Insecure Direct Object References (IDOR)
- Security Misconfiguration (headers, CSP, CORS)
- Dependency Vulnerabilities (CVE monitoring)

## Supported frameworks

- **Next.js** — SSR injection, API route audit, middleware chain walls
- **Express** — Middleware chain, route-level protection
- **Supabase** — RLS policy validation, edge function scanning, storage ACL
- **Django** — ORM audit, CSRF middleware, settings hardening

## Repository structure

```
shieldagi/
├── agents/                 # OpenFang agent manifests
│   ├── recon-scout/        # Attack surface mapping
│   ├── code-auditor/       # Static code analysis
│   ├── attack-executor/    # Active exploitation (sandboxed)
│   ├── vuln-reporter/      # Finding compilation + scoring
│   └── shield-remediator/  # Autonomous code fixing
├── hands/                  # OpenFang autonomous Hands
│   ├── sentinel/           # 24/7 traffic + log monitoring
│   ├── dep-guardian/       # Dependency CVE watching
│   └── incident-responder/ # Auto-patch + alert
├── tools/                  # Custom Rust security tools
│   ├── src/                # Rust tool implementations
│   └── scripts/            # Helper scripts for tools
├── playbooks/              # Remediation playbooks per vector
├── chain-walls/            # Framework-specific middleware
│   ├── nextjs/
│   ├── express/
│   ├── supabase/
│   └── django/
├── sandbox/                # Docker isolation environment
├── dashboard/              # Grafana security dashboards
├── tests/                  # Vulnerable test app + integration tests
├── skills/                 # OpenFang SKILL.md files
└── docs/                   # Documentation
```

## License

Proprietary — All rights reserved.
