# ShieldAGI 2.0 — System Architecture

## Pipeline Overview

ShieldAGI operates as a 3-phase autonomous security pipeline built on the OpenFang agent runtime.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PHASE 1: DISCOVERY                          │
│                                                                     │
│   ┌──────────────┐         ┌──────────────┐                        │
│   │ Recon Scout  │────────▶│ Code Auditor │                        │
│   │  (surface)   │         │  (static)    │                        │
│   └──────┬───────┘         └──────┬───────┘                        │
│          │    Knowledge Store     │                                  │
│          └──────────┬─────────────┘                                  │
├─────────────────────┼───────────────────────────────────────────────┤
│                     ▼                                               │
│                 PHASE 2: ATTACK                                     │
│                                                                     │
│          ┌──────────────────┐      ┌─────────────────────┐         │
│          │ Attack Executor  │─────▶│  Vuln Reporter      │         │
│          │  (exploitation)  │      │  (CVSS scoring)     │         │
│          └──────────────────┘      └──────────┬──────────┘         │
│           [Docker Sandbox]                     │                    │
│           172.28.0.0/16                        │                    │
├────────────────────────────────────────────────┼────────────────────┤
│                                                ▼                    │
│                 PHASE 3: REMEDIATION                                │
│                                                                     │
│          ┌──────────────────┐      ┌─────────────────────┐         │
│          │Shield Remediator │─────▶│   Git Pull Request  │         │
│          │ (code fixes +    │      │   + Chain Walls     │         │
│          │  chain walls)    │      └─────────────────────┘         │
│          └──────────────────┘                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

         ┌─────────────────────────────────────────┐
         │          CONTINUOUS MONITORING           │
         │                                          │
         │  ┌───────────┐  ┌──────────────────┐    │
         │  │ Sentinel  │─▶│Incident Responder│    │
         │  │ (*/5 min) │  │ (event-driven)   │    │
         │  └───────────┘  └──────────────────┘    │
         │                                          │
         │  ┌───────────────┐                      │
         │  │ Dep Guardian  │                      │
         │  │ (every 6hrs)  │                      │
         │  └───────────────┘                      │
         └─────────────────────────────────────────┘
```

## OpenFang Runtime

ShieldAGI runs on [OpenFang](https://github.com/openfang), an agent orchestration runtime. OpenFang provides:

- **Agents** — autonomous AI units with a system prompt, model binding, and tool access. Agents execute once per pipeline run and pass findings through the knowledge store.
- **Hands** — scheduled or event-driven background processes. Hands run on cron schedules or respond to events, operating independently of the main pipeline.
- **Tools** — Rust functions exposed to agents. Each tool has typed inputs/outputs and runs inside the sandbox.
- **Knowledge Store** — shared graph database for inter-agent communication. Agents write findings; downstream agents query them.

## Agents

| Agent | Role | Phase | Key Tools |
|-------|------|-------|-----------|
| **recon-scout** | Maps attack surface: ports, subdomains, tech stack, SSL, endpoints | Discovery | `nmap_scan`, `dns_enum`, `subdomain_discover`, `tech_fingerprint` |
| **code-auditor** | Static analysis: SQLi patterns, XSS vectors, secrets, deps, RLS gaps | Discovery | `semgrep_scan`, `ast_analyze`, `secret_scan`, `dep_audit`, `rls_validate`, `header_audit` |
| **attack-executor** | Proves vulnerabilities via real attacks in sandbox | Attack | `sqlmap_attack`, `xss_inject`, `csrf_test`, `ssrf_probe`, `brute_force`, `path_traverse`, `idor_test` |
| **vuln-reporter** | Compiles findings into unified CVSS-scored report | Attack | `report_generate`, `severity_score` |
| **shield-remediator** | Fixes every finding, implements Chain Walls, creates PR | Remediation | `remediation_engine`, `chain_walls_injector`, `pr_generator`, `verify_fix`, `claude_code_exec` |

All agents use Claude Opus 4.6 via the Anthropic API.

## Hands

| Hand | Schedule | Role |
|------|----------|------|
| **sentinel** | Every 5 minutes (`*/5 * * * *`) | Traffic/log monitoring, anomaly detection, threat classification |
| **dep-guardian** | Every 6 hours (`0 */6 * * *`) | Dependency vulnerability scanning, auto-patching, PR creation |
| **incident-responder** | Event-driven (`event:sentinel_alert`) | Threat verification, containment, forensics, emergency patching |

## Tool Categories

**Scanning** (Phase 1):
`nmap_scan`, `dns_enum`, `subdomain_discover`, `port_scan`, `tech_fingerprint`, `semgrep_scan`, `ast_analyze`, `secret_scan`, `dep_audit`, `rls_validate`, `header_audit`

**Attack** (Phase 2):
`sqlmap_attack`, `xss_inject`, `csrf_test`, `ssrf_probe`, `brute_force`, `path_traverse`, `idor_test`

**Reporting**:
`report_generate`, `severity_score`

**Remediation** (Phase 3):
`remediation_engine`, `run_remediation`, `chain_walls_injector`, `pr_generator`, `verify_fix`, `detect_framework`, `load_config`

**Monitoring** (Continuous):
`log_analyzer`, `traffic_monitor`, `anomaly_detect`, `threat_correlate`, `sentinel_runtime`, `incident_engine`, `trigger_focused_scan`

**Infrastructure**:
`knowledge_store`, `knowledge_query`, `alert_send`, `send_telegram_alert`, `git_clone`, `git_branch`, `git_commit`, `git_pr`, `run_tests`, `shell`, `file_read`, `file_write`, `web_fetch`

## Chain Walls — 7-Layer Defense

Chain Walls is a middleware stack injected into the target application during remediation. Each layer runs in order on every request:

| Layer | Name | Function |
|-------|------|----------|
| 1 | Rate Limiter | Sliding window rate limiting per IP and per user |
| 2 | Input Sanitizer | Strip/encode dangerous characters, validate types |
| 3 | Auth Validator | JWT verification, session freshness, token rotation |
| 4 | CSRF Guard | Token validation, origin check, SameSite enforcement |
| 5 | RBAC Enforcer | Role check + resource ownership validation |
| 6 | SSRF Shield | URL allowlist, private IP block, DNS rebinding guard |
| 7 | Request Logger | Structured logging with threat correlation ID |

Framework implementations: `chain-walls/nextjs/`, `chain-walls/express/`, `chain-walls/django/`, `chain-walls/supabase/`.

## Data Flow

```
Target Repo URL
      │
      ▼
┌─ recon-scout ──────────────────────────────────┐
│  nmap + dns + subdomains + tech fingerprint    │
│  Output: attack_surface.json → knowledge_store │
└────────────────────────────────────────────────┘
      │
      ▼
┌─ code-auditor ─────────────────────────────────┐
│  semgrep + ast + secrets + deps + headers      │
│  Output: static_findings.json → knowledge_store│
└────────────────────────────────────────────────┘
      │
      ▼
┌─ attack-executor ──────────────────────────────┐
│  sqlmap + xss + csrf + ssrf + brute + idor     │
│  Runs in sandbox (172.28.0.0/16)               │
│  Output: attack_results.json → knowledge_store │
└────────────────────────────────────────────────┘
      │
      ▼
┌─ vuln-reporter ────────────────────────────────┐
│  Dedup + correlate + CVSS score + report       │
│  Output: SHIELD-REPORT-{ts}.json               │
│          SHIELD-REPORT-{ts}.md                  │
└────────────────────────────────────────────────┘
      │
      ▼
┌─ shield-remediator ────────────────────────────┐
│  Apply playbooks + inject Chain Walls          │
│  Run tests + verify fixes                      │
│  Output: Git PR on shieldagi/remediation-{ts}  │
└────────────────────────────────────────────────┘
```

## Docker Sandbox Network

All attack simulation runs inside an isolated Docker network:

- **Network**: `172.28.0.0/16`, bridge driver, `internal: true` (no internet)
- **pentest-tools**: nmap, sqlmap, nuclei, nikto, ffuf, gobuster, semgrep, trufflehog, gitleaks, hydra
- **vulnerable-app**: Sandboxed clone of the target application
- **vulndb**: PostgreSQL 16 for the sandboxed app
- **redis**: Rate limiting tests

Resource limits: 4 CPUs, 4GB RAM per container. `no-new-privileges` security option enabled.
