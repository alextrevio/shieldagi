# ShieldAGI 2.0 — Autonomous Cyber Defense Platform

> Connect any web platform. Get military-grade protection. Zero human intervention.

ShieldAGI 2.0 is an autonomous cyber defense platform built on the [OpenFang Agent OS](https://github.com/RightNow-AI/openfang) (Rust, single binary). It connects to any web platform's codebase and infrastructure, identifies every exploitable vulnerability through real penetration testing, automatically remediates all findings using Claude Opus 4.6 via Claude Code, and maintains continuous 24/7 autonomous monitoring with instant self-healing.

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
# One-command setup
shieldagi connect https://github.com/your-org/your-app

# Or step by step:
shieldagi scan https://github.com/your-org/your-app   # Phase 1 only
shieldagi fix                                           # Phase 2 (fix last report)
shieldagi sentinel start                                # Phase 3 (24/7 monitoring)
shieldagi status                                        # Check all agents
```

See [docs/QUICK_START.md](docs/QUICK_START.md) for the full 5-minute guide.

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

### 5 Agents

| Agent | Role |
|-------|------|
| **recon-scout** | Attack surface mapping — ports, services, endpoints |
| **code-auditor** | Static analysis with semgrep + custom rules |
| **attack-executor** | Active exploitation in Docker sandbox |
| **vuln-reporter** | Finding compilation, CVSS scoring, report generation |
| **shield-remediator** | Autonomous code fixing + Chain Walls injection |

### 3 Autonomous Hands

| Hand | Schedule | Role |
|------|----------|------|
| **sentinel** | Every 5 min | Traffic/log monitoring, anomaly detection |
| **dep-guardian** | Every 6 hours | Dependency CVE monitoring, auto-patching |
| **incident-responder** | Event-triggered | Containment, forensics, emergency patching |

### 25+ Custom Rust Security Tools

**Phase 1 — Scanning:**
`nmap_scan`, `sqlmap_attack`, `xss_inject`, `csrf_test`, `ssrf_probe`, `semgrep_scan`, `secret_scan`, `rls_validate`, `header_audit`, `dep_audit`, `brute_force`, `idor_test`, `path_traverse`, `log_analyzer`

**Phase 2 — Remediation:**
`remediation_engine`, `run_remediation`, `chain_walls_injector`, `pr_generator`, `verify_fix`, `detect_framework`, `report_types`

**Phase 3 — Monitoring:**
`run_sentinel_cycle`, `send_telegram_alert`, `respond_to_incident`, `check_dependencies`, `trigger_focused_scan`

**Utility:**
`cli_command`, `load_config`

### Chain Walls — 7-Layer Security Middleware

1. **Rate Limiter** — Prevents brute-force and DDoS
2. **Input Sanitizer** — Blocks SQLi/XSS payloads
3. **Auth Validator** — Enforces JWT authentication
4. **CSRF Guard** — Validates Origin/Referer headers
5. **RBAC Enforcer** — Role-based access control
6. **SSRF Shield** — Blocks internal IP/metadata requests
7. **Request Logger** — Audit trail for all requests

Auto-injected for: Next.js, Express, Django, Supabase

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
- Hardcoded Secrets / API Key Exposure

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
├── tools/                  # Custom Rust security tools (25+)
│   └── src/                # Rust tool implementations
├── playbooks/              # Remediation playbooks per vector
├── chain-walls/            # Framework-specific middleware
│   ├── nextjs/
│   ├── express/
│   ├── supabase/
│   └── django/
├── sandbox/                # Docker isolation environment
├── tests/                  # Integration tests + self-audit
├── docs/                   # Full documentation
├── deploy/                 # Production deployment configs
└── dashboard/              # Grafana security dashboards
```

## Documentation

- [Quick Start](docs/QUICK_START.md) — 5-minute setup guide
- [Architecture](docs/ARCHITECTURE.md) — System design and data flow
- [Agent Reference](docs/AGENT_REFERENCE.md) — All 5 agents documented
- [Hand Reference](docs/HAND_REFERENCE.md) — All 3 hands documented
- [Tool Reference](docs/TOOL_REFERENCE.md) — All 25+ tools with schemas
- [Chain Walls](docs/CHAIN_WALLS.md) — 7-layer middleware guide
- [Playbooks](docs/PLAYBOOKS.md) — Remediation playbook index
- [Deployment](docs/DEPLOYMENT.md) — Production deployment guide

## License

Proprietary — All rights reserved.
