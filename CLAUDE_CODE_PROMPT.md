# ShieldAGI 2.0 — Claude Code Master Prompt

You are building ShieldAGI 2.0, an autonomous cyber defense platform. This file contains context for Claude Code to continue development autonomously.

## Project State

### Completed (Phase A: Foundation)
- [x] Full repository structure with README
- [x] 5 agent manifests (recon-scout, code-auditor, attack-executor, vuln-reporter, shield-remediator)
- [x] 3 Hand manifests with SKILL.md (sentinel, dep-guardian, incident-responder)
- [x] 14 Rust tool definitions with schemas (nmap_scan + header_audit fully implemented, rest are stubs)
- [x] Tool registry (lib.rs) with routing to all tools
- [x] 10 remediation playbooks (SQLi, XSS, CSRF, Auth, SSRF, Rate Limiting, Traversal, IDOR, Misconfig, Dependencies)
- [x] 4 Chain Walls implementations (Next.js, Express, Supabase Edge Functions, Django)
- [x] Docker sandbox (docker-compose.yml + Dockerfile.pentest)
- [x] Deliberately vulnerable test app (Express + PostgreSQL with all OWASP Top 10)
- [x] Integration test suite (bash script testing all vulnerability vectors)
- [x] Grafana dashboard configuration
- [x] OpenFang fork integration guide
- [x] Environment configuration template

### Next: Phase B (Attack Engine) — Build these in order:
1. Implement `sqlmap_attack.rs` fully (parse sqlmap XML output, handle all injection types)
2. Implement `semgrep_scan.rs` (shell out to semgrep, parse JSON output, add custom ShieldAGI rules)
3. Implement `secret_scan.rs` (run trufflehog + gitleaks, merge results)
4. Implement `dep_audit.rs` (npm audit + pip-audit, parse JSON, cross-reference CVEs)
5. Implement `xss_inject.rs` (headless Chromium via puppeteer/playwright, DOM mutation detection)
6. Implement `csrf_test.rs` (craft cross-origin requests, check token/origin validation)
7. Implement `ssrf_probe.rs` (probe internal IPs, metadata endpoints, DNS rebinding)
8. Implement `brute_force.rs` (rate limit detection, common credential testing)
9. Implement `idor_test.rs` (multi-user context testing, sequential ID enumeration)
10. Implement `path_traverse.rs` (multi-encoding bypass, null byte injection)
11. Implement `rls_validate.rs` (Supabase schema inspection, policy completeness check)
12. Implement `log_analyzer.rs` (pattern matching against attack signature database)
13. Build Docker sandbox orchestration (programmatic container management from agents)
14. End-to-end test: full Phase 1 scan of vulnerable app, verify all vulns are found

### Phase C (Remediation):
1. Build Claude Code integration in shield-remediator agent
2. Implement the remediation pipeline (read report → plan fixes → apply → test → PR)
3. Build Chain Walls auto-injection (detect framework → insert correct middleware)
4. Build Git PR generation with detailed descriptions
5. Implement verify-after-fix loop (re-run attack tool to confirm)

### Phase D (Sentinel):
1. Wire up sentinel Hand with actual log ingestion
2. Build anomaly detection with rolling baselines
3. Wire up dep-guardian with CVE database queries
4. Build incident-responder auto-patching pipeline
5. Implement the continuous loop (Phase 3 → Phase 1 → Phase 2 → Phase 3)
6. Configure Telegram alerting

### Phase E (Production):
1. Test against real projects (Hoover, Arya AI, Selectia)
2. Build onboarding CLI: `shieldagi connect <repo-url>`
3. Performance optimization and parallel agent execution
4. Self-audit: run ShieldAGI against itself
5. Documentation and deployment guide

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
- Redis — Rate limiting
- Grafana — Dashboard
- Telegram/Slack — Alerting
