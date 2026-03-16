# ShieldAGI 2.0 — Claude Code Master Prompt

You are building ShieldAGI 2.0, an autonomous cyber defense platform. This file contains context for Claude Code to continue development autonomously.

## Project State

### Completed (Phase A: Foundation)
- [x] Full repository structure with README
- [x] 5 agent manifests (recon-scout, code-auditor, attack-executor, vuln-reporter, shield-remediator)
- [x] 3 Hand manifests with SKILL.md (sentinel, dep-guardian, incident-responder)
- [x] 14 Rust tool definitions with schemas
- [x] Tool registry (lib.rs) with routing to all tools
- [x] 10 remediation playbooks (SQLi, XSS, CSRF, Auth, SSRF, Rate Limiting, Traversal, IDOR, Misconfig, Dependencies)
- [x] 4 Chain Walls implementations (Next.js, Express, Supabase Edge Functions, Django)
- [x] Docker sandbox (docker-compose.yml + Dockerfile.pentest)
- [x] Deliberately vulnerable test app (Express + PostgreSQL with all OWASP Top 10)
- [x] Integration test suite
- [x] Grafana dashboard configuration
- [x] OpenFang fork integration guide
- [x] Environment configuration template

### Completed (Phase B: Attack Engine)
- [x] All 14 Rust security tools fully implemented (no stubs)
- [x] nmap_scan, sqlmap_attack, xss_inject, csrf_test, ssrf_probe
- [x] semgrep_scan, secret_scan, rls_validate, header_audit, dep_audit
- [x] brute_force, idor_test, path_traverse, log_analyzer
- [x] Docker sandbox orchestration
- [x] End-to-end Phase 1 scan testing

### Completed (Phase C: Remediation Engine)
- [x] report_types.rs — VulnerabilityReport, Vulnerability, AttackChain structs with severity helpers
- [x] framework_detect.rs — Auto-detect Next.js/Express/Django/Supabase/Rust frameworks
- [x] remediation_engine.rs — 11 vulnerability category transformers with pattern-based code fixes
- [x] remediation_pipeline.rs — Full pipeline orchestrator (plan → fix → test → verify → PR)
- [x] chain_walls_injector.rs — Framework-specific Chain Walls auto-injection
- [x] pr_generator.rs — Detailed GitHub PR generation with diffs and summary tables
- [x] verify_fix.rs — Re-run attack tools to confirm fixes with confidence scoring
- [x] shield-remediator agent.toml updated with new tool allowlist

### Completed (Phase D: Sentinel — 24/7 Monitoring)
- [x] sentinel_runtime.rs — Log parsing, signature matching, baseline anomaly detection
- [x] telegram_alert.rs — Formatted security alerts via Telegram Bot API
- [x] incident_engine.rs — Automated incident response, IP blocking, forensics
- [x] dep_monitor.rs — Dependency monitoring, diff against previous scans, auto-patch PRs
- [x] continuous_loop.rs — Phase 3→1→2 feedback loop with 30-min cooldown
- [x] All Hand TOMLs updated with new tool allowlists

### Completed (Phase E: Production Hardening)
- [x] cli.rs — CLI onboarding (connect, status, scan, fix, sentinel subcommands)
- [x] config.rs — Centralized config from shieldagi.toml + .env + env vars
- [x] tests/self-audit.sh — Self-audit script
- [x] tests/integration/ — 5 integration test scripts (phase1, phase2, phase3, chain_walls, e2e)
- [x] docs/ — 8 documentation files (QUICK_START, ARCHITECTURE, AGENT_REFERENCE, HAND_REFERENCE, TOOL_REFERENCE, CHAIN_WALLS, PLAYBOOKS, DEPLOYMENT)
- [x] deploy/ — Production configs (docker-compose, nginx, systemd, setup.sh)
- [x] README.md updated with full documentation
- [x] lib.rs verified — all 25+ tools registered and routed

## Architecture Rules
- ALL pentesting tools run in Docker sandbox only (172.28.0.0/16 network)
- Agent communication via OpenFang knowledge_store (SQLite + vector embeddings)
- Every tool returns structured JSON matching its schema in lib.rs
- Chain Walls are framework-specific — detect framework first, then apply correct template
- The vulnerability report JSON schema is the contract between Phase 1 and Phase 2
- Sentinel Hand runs every 5 minutes, Dep Guardian every 6 hours
- Incident Responder is event-triggered, not scheduled

## Tech Stack
- OpenFang v0.3.x (Rust fork) — Agent OS
- Claude Opus 4.6 — AI backbone for all agents
- Docker — Sandbox isolation for attack execution
- nmap, sqlmap, nuclei, semgrep, trufflehog, gitleaks — Pentesting tools
- PostgreSQL + SQLite — Data persistence
- Redis — Rate limiting and caching
- Grafana — Dashboard
- Telegram/Slack — Alerting

## Tool Registry (25+ tools in tools/src/lib.rs)

### Phase 1 — Scanning (14 tools)
nmap_scan, sqlmap_attack, xss_inject, csrf_test, ssrf_probe, semgrep_scan, secret_scan, rls_validate, header_audit, dep_audit, brute_force, idor_test, path_traverse, log_analyzer

### Phase 2 — Remediation (7 tools)
remediation_engine, run_remediation, chain_walls_injector, pr_generator, verify_fix, detect_framework, report_types

### Phase 3 — Monitoring (5 tools)
run_sentinel_cycle, send_telegram_alert, respond_to_incident, check_dependencies, trigger_focused_scan

### Utility (2 tools)
cli_command, load_config
