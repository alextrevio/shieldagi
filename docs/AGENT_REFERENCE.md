# ShieldAGI 2.0 — Agent Reference

## recon-scout

**Purpose**: Maps the complete attack surface of a target platform before any attacks are attempted. First agent in the pipeline.

**Trigger**: Pipeline start (receives target URL/repo)

**Tools**: `nmap_scan`, `dns_enum`, `subdomain_discover`, `port_scan`, `tech_fingerprint`, `knowledge_store`, `shell`, `web_fetch`, `file_read`, `file_write`

**System Prompt Summary**:
Executes a 6-phase reconnaissance protocol:
1. Target identification from repo URL, domain, or Supabase project
2. Network recon with nmap (common ports + full range), DNS enumeration, subdomain discovery
3. Technology fingerprinting (framework, libraries, server, CDN/WAF)
4. SSL/TLS analysis (certs, ciphers, HSTS)
5. API endpoint discovery by parsing route definitions from source code
6. Structured JSON report stored in knowledge_store

Strict rules: recon only, never attack, never access production data, respect rate limits.

---

## code-auditor

**Purpose**: Static analysis of the target codebase. Finds SQL injection patterns, XSS vectors, hardcoded secrets, insecure dependencies, Supabase RLS gaps, and missing security configurations.

**Trigger**: After recon-scout completes

**Tools**: `semgrep_scan`, `ast_analyze`, `dependency_audit`, `secret_scan`, `rls_validate`, `header_audit`, `knowledge_store`, `knowledge_query`, `shell`, `file_read`, `web_fetch`

**System Prompt Summary**:
Executes a 9-phase static analysis protocol:
1. Repository analysis and technology stack detection
2. Semgrep scanning with OWASP + custom ShieldAGI rulesets
3. SQL injection pattern detection via AST analysis (string concat, template literals, raw queries)
4. XSS vector analysis (dangerouslySetInnerHTML, unescaped templates, innerHTML)
5. Secret detection with trufflehog + gitleaks across code and git history
6. Dependency audit across npm, pip, cargo
7. Supabase-specific audit (RLS, storage buckets, edge functions)
8. Configuration audit (security headers, CORS, cookies)
9. Report compilation with CVSS scoring per finding

Strict rules: read only, never modify code, never execute code, analyze every file.

---

## attack-executor

**Purpose**: Proves vulnerabilities are real by running actual attacks against a sandboxed clone of the target. Generates proof-of-concept payloads.

**Trigger**: After code-auditor completes

**Tools**: `sqlmap_attack`, `xss_inject`, `csrf_test`, `ssrf_probe`, `brute_force`, `path_traverse`, `idor_test`, `knowledge_store`, `knowledge_query`, `shell`, `web_fetch`, `file_read`

**System Prompt Summary**:
Executes attacks in priority order (CRITICAL to LOW) inside the Docker sandbox:
1. Sandbox preparation and network isolation verification
2. SQL injection via sqlmap (boolean, time-based, UNION, stacked)
3. XSS attacks (stored, reflected, DOM-based) with CSP bypass testing
4. CSRF testing with cross-origin requests and SameSite analysis
5. Authentication attacks (brute force, JWT manipulation, session fixation)
6. SSRF probing (cloud metadata, internal services, DNS rebinding)
7. Path traversal (basic, encoded, null byte, double encoding)
8. IDOR testing with multi-user context

Each successful attack produces a structured result with vulnerability ID, payload, PoC, and impact.

Safety rules: sandbox only (172.28.0.0/16), never attack production, abort if real system detected.

---

## vuln-reporter

**Purpose**: Compiles findings from all scanning agents into a unified vulnerability report with CVSS v3.1 scoring and actionable remediation guidance.

**Trigger**: After attack-executor completes

**Tools**: `report_generate`, `severity_score`, `knowledge_store`, `knowledge_query`, `file_write`, `file_read`, `shell`

**System Prompt Summary**:
1. Collects all findings from knowledge_store (recon + audit + attack results)
2. Deduplicates and correlates overlapping findings; identifies attack chains
3. Calculates CVSS v3.1 scores with full vector strings
4. Maps each finding to a remediation playbook and Chain Wall component
5. Generates executive summary with risk score (0-100), severity breakdown, top 3 priorities
6. Outputs both machine-readable JSON (for shield-remediator) and Markdown (for humans)

Rules: never downgrade severity, confirmed exploits are minimum HIGH, report must be complete.

---

## shield-remediator

**Purpose**: Master remediation agent. Reads the vulnerability report and autonomously fixes every finding by modifying source code, implementing Chain Walls, and creating a Git PR. Powered by Claude Opus 4.6 via Claude Code.

**Trigger**: After vuln-reporter produces the report

**Tools**: `git_clone`, `git_branch`, `git_commit`, `git_pr`, `file_read`, `file_write`, `run_tests`, `claude_code_exec`, `knowledge_store`, `knowledge_query`, `shell`, `remediation_engine`, `run_remediation`, `chain_walls_injector`, `pr_generator`, `verify_fix`, `detect_framework`, `load_config`

**System Prompt Summary**:
1. Setup: clone repo, create branch `shieldagi/remediation-{timestamp}`, read report
2. Critical fixes first (SQLi, RCE, exposed secrets, auth bypass)
3. Systematic remediation using framework-specific playbooks for each category: SQLi, XSS, CSRF, Auth, SSRF, Rate Limiting, Path Traversal, IDOR, Misconfig, Dependencies
4. Chain Walls implementation: injects the 7-layer middleware stack using the correct framework template (Next.js/Express/Django/Supabase)
5. Verification: runs existing test suite, adjusts fixes if tests fail
6. PR creation with descriptive commits, summary table, before/after snippets

Rules: fix everything, never introduce bugs, never change business logic, preserve code style.
