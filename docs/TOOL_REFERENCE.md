# ShieldAGI 2.0 — Tool Reference

All tools are implemented in Rust (`tools/src/`) and exposed to agents via the OpenFang runtime.

## Phase 1: Scanning & Reconnaissance

### nmap_scan
**Description**: Network port scanner with service version detection. Wraps nmap with ShieldAGI-specific profiles.
**Inputs**: `target: string` (IP/domain), `ports: string` (range, e.g. "1-65535"), `mode: string` ("fast" | "thorough")
**Output**: JSON array of `{ port, service, version, state, protocol }`
**Example**:
```json
{ "target": "192.168.1.1", "ports": "80,443,3000,5432", "mode": "thorough" }
```

### dns_enum
**Description**: DNS record enumeration. Queries A, AAAA, CNAME, MX, TXT, NS, SOA records.
**Inputs**: `domain: string`
**Output**: JSON object with record type arrays
**Example**:
```json
{ "domain": "example.com" }
```

### subdomain_discover
**Description**: Subdomain enumeration via certificate transparency logs and wordlist brute-force.
**Inputs**: `domain: string`, `wordlist: string` (optional, defaults to built-in)
**Output**: JSON array of discovered subdomains with IP addresses
**Example**:
```json
{ "domain": "example.com" }
```

### port_scan
**Description**: Lightweight TCP port scanner for quick connectivity checks.
**Inputs**: `target: string`, `ports: Vec<u16>`
**Output**: JSON array of `{ port, open: bool }`
**Example**:
```json
{ "target": "10.0.0.1", "ports": [22, 80, 443, 8080] }
```

### tech_fingerprint
**Description**: Technology stack identification from HTTP responses, headers, and HTML content.
**Inputs**: `url: string`
**Output**: JSON with `{ framework, server, cdn, libraries: [], waf }`
**Example**:
```json
{ "url": "https://example.com" }
```

### semgrep_scan
**Description**: Static analysis using Semgrep with OWASP and custom ShieldAGI rulesets.
**Inputs**: `path: string` (repo root), `rulesets: Vec<string>` (e.g. ["owasp", "shieldagi-nextjs"])
**Output**: JSON array of findings with `{ rule_id, severity, file, line, message, snippet }`
**Example**:
```json
{ "path": "/workspace/target-repo", "rulesets": ["owasp", "shieldagi-nextjs"] }
```

### ast_analyze
**Description**: AST-based code analysis for detecting specific vulnerability patterns (SQLi, unsafe sinks).
**Inputs**: `path: string`, `patterns: Vec<string>` (e.g. ["sql_concat", "raw_query", "eval"])
**Output**: JSON array of `{ pattern, file, line, snippet, context }`
**Example**:
```json
{ "path": "/workspace/target-repo", "patterns": ["sql_concat", "template_literal_sql"] }
```

### secret_scan
**Description**: Secret detection using trufflehog and gitleaks. Scans files and git history.
**Inputs**: `path: string`, `scan_history: bool`
**Output**: JSON array of `{ type, file, line, commit_hash, snippet_redacted }`
**Example**:
```json
{ "path": "/workspace/target-repo", "scan_history": true }
```

### dep_audit
**Description**: Dependency vulnerability audit across package managers. Queries CVE databases.
**Inputs**: `path: string`, `package_manager: string` ("npm" | "pip" | "cargo")
**Output**: JSON array of `{ package, version, cve_id, severity, patched_version, advisory_url }`
**Example**:
```json
{ "path": "/workspace/target-repo", "package_manager": "npm" }
```

### rls_validate
**Description**: Supabase Row Level Security policy validation.
**Inputs**: `supabase_url: string`, `service_role_key: string`
**Output**: JSON with `{ tables_without_rls: [], permissive_policies: [], missing_operations: [] }`
**Example**:
```json
{ "supabase_url": "https://abc.supabase.co", "service_role_key": "..." }
```

### header_audit
**Description**: HTTP security header analysis for deployed URLs.
**Inputs**: `url: string`
**Output**: JSON with `{ present: {}, missing: [], misconfigured: [] }` for CSP, HSTS, X-Frame-Options, etc.
**Example**:
```json
{ "url": "https://example.com" }
```

---

## Phase 2: Attack Tools

### sqlmap_attack
**Description**: Automated SQL injection testing via sqlmap. Tests boolean, time-based, UNION, and stacked injection types.
**Inputs**: `url: string`, `method: string`, `parameter: string`, `cookie: string` (optional)
**Output**: JSON with `{ injectable: bool, db_type, injection_type, payload, tables_accessible: [] }`
**Example**:
```json
{ "url": "http://sandbox:3000/api/users", "method": "GET", "parameter": "id" }
```

### xss_inject
**Description**: XSS payload injection and reflection testing. Tests stored, reflected, and DOM-based XSS.
**Inputs**: `url: string`, `input_field: string`, `payload_category: string` ("script" | "event" | "svg")
**Output**: JSON with `{ reflected: bool, stored: bool, dom_based: bool, working_payload, execution_context }`
**Example**:
```json
{ "url": "http://sandbox:3000/search", "input_field": "q", "payload_category": "script" }
```

### csrf_test
**Description**: CSRF vulnerability testing. Crafts cross-origin requests and checks for token validation.
**Inputs**: `target_url: string`, `method: string`, `body: object` (optional)
**Output**: JSON with `{ vulnerable: bool, samesite_cookie: string, csrf_token_present: bool, poc_html: string }`
**Example**:
```json
{ "target_url": "http://sandbox:3000/api/settings", "method": "POST" }
```

### ssrf_probe
**Description**: SSRF vulnerability probing. Tests access to cloud metadata, internal services, and DNS rebinding.
**Inputs**: `url: string`, `parameter: string`, `targets: Vec<string>`
**Output**: JSON with `{ vulnerable: bool, accessible_targets: [], response_data }`
**Example**:
```json
{ "url": "http://sandbox:3000/api/fetch", "parameter": "url", "targets": ["http://169.254.169.254/latest/meta-data/"] }
```

### brute_force
**Description**: Authentication brute force testing. Tests rate limiting, common credentials, and JWT manipulation.
**Inputs**: `url: string`, `username_field: string`, `password_field: string`, `wordlist: string` (optional)
**Output**: JSON with `{ rate_limited: bool, lockout_after: number, weak_credentials: [], jwt_issues: [] }`
**Example**:
```json
{ "url": "http://sandbox:3000/api/login", "username_field": "email", "password_field": "password" }
```

### path_traverse
**Description**: Path traversal testing with encoding bypass attempts.
**Inputs**: `url: string`, `parameter: string`, `target_files: Vec<string>`
**Output**: JSON with `{ vulnerable: bool, accessible_files: [], working_payloads: [] }`
**Example**:
```json
{ "url": "http://sandbox:3000/api/files", "parameter": "path", "target_files": ["/etc/passwd"] }
```

### idor_test
**Description**: Insecure Direct Object Reference testing with multi-user context.
**Inputs**: `url: string`, `resource_param: string`, `auth_tokens: { user_a: string, user_b: string }`
**Output**: JSON with `{ vulnerable: bool, cross_accessible_resources: [], no_auth_accessible: [] }`
**Example**:
```json
{ "url": "http://sandbox:3000/api/documents/{id}", "resource_param": "id", "auth_tokens": { "user_a": "...", "user_b": "..." } }
```

---

## Reporting Tools

### report_generate
**Description**: Generates the unified vulnerability report in JSON and Markdown formats.
**Inputs**: `session_id: string`, `format: string` ("json" | "markdown" | "both")
**Output**: Report file path(s)
**Example**:
```json
{ "session_id": "scan-20260315", "format": "both" }
```

### severity_score
**Description**: Calculates CVSS v3.1 score from vector components.
**Inputs**: `vector: string` (e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
**Output**: JSON with `{ score: number, severity: string, vector_string: string }`
**Example**:
```json
{ "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" }
```

---

## Phase 3: Remediation Tools

### remediation_engine
**Description**: Core remediation logic. Reads a vulnerability and applies the matching playbook transforms.
**Inputs**: `vulnerability: object`, `playbook: string`, `target_file: string`
**Output**: JSON with `{ patched: bool, changes: [{ file, before, after }], tests_pass: bool }`
**Example**:
```json
{ "vulnerability": { "id": "SHIELD-0001", "category": "sqli" }, "playbook": "sqli_remediation", "target_file": "src/api/users.ts" }
```

### run_remediation
**Description**: Batch remediation runner. Processes the full report and applies all playbooks in dependency order.
**Inputs**: `report_path: string`, `repo_path: string`
**Output**: JSON summary of all applied fixes

### chain_walls_injector
**Description**: Injects the Chain Walls 7-layer middleware stack into the target application.
**Inputs**: `repo_path: string`, `framework: string` ("nextjs" | "express" | "django" | "supabase"), `config: object`
**Output**: JSON with `{ injected: bool, files_modified: [], layers_enabled: [] }`
**Example**:
```json
{ "repo_path": "/workspace/target-repo", "framework": "nextjs", "config": {} }
```

### pr_generator
**Description**: Creates a Git pull request with structured summary of all remediation changes.
**Inputs**: `repo_path: string`, `branch: string`, `vulnerabilities_fixed: Vec<object>`
**Output**: JSON with `{ pr_url: string, pr_number: number }`
**Example**:
```json
{ "repo_path": "/workspace/target-repo", "branch": "shieldagi/remediation-20260315" }
```

### verify_fix
**Description**: Verifies a specific fix by re-running the attack that exposed the vulnerability.
**Inputs**: `vulnerability_id: string`, `repo_path: string`
**Output**: JSON with `{ fixed: bool, verification_method, details }`
**Example**:
```json
{ "vulnerability_id": "SHIELD-0001", "repo_path": "/workspace/target-repo" }
```

### detect_framework
**Description**: Detects the target project's framework from manifest files and project structure.
**Inputs**: `repo_path: string`
**Output**: JSON with `{ framework: string, version: string, deployment: string }`
**Example**:
```json
{ "repo_path": "/workspace/target-repo" }
```

### load_config
**Description**: Loads and validates the `shieldagi.toml` configuration file.
**Inputs**: `path: string` (optional, defaults to project root)
**Output**: Parsed config object

---

## Monitoring Tools

### log_analyzer
**Description**: Ingests and analyzes application, web server, database, and auth logs for attack patterns.
**Inputs**: `log_sources: Vec<string>`, `time_range: string` (e.g. "5m", "1h")
**Output**: JSON with `{ entries_analyzed: number, patterns_found: [], anomalies: [] }`

### continuous_loop
**Description**: Sentinel runtime loop manager. Handles cycle scheduling and state persistence.
**Inputs**: `interval: string`, `callback: string`
**Output**: Cycle status

### sentinel_runtime
**Description**: Core sentinel execution engine. Runs the full monitoring pipeline per cycle.
**Inputs**: `config: object`
**Output**: Cycle report with threat classifications

### incident_engine
**Description**: Incident response orchestration. Manages containment, forensics, and escalation workflows.
**Inputs**: `alert: object`, `severity: string`
**Output**: Incident report JSON

### dep_monitor
**Description**: Continuous dependency monitoring between dep-guardian cycles.
**Inputs**: `repo_path: string`
**Output**: JSON with newly published advisories

### telegram_alert
**Description**: Sends formatted alert messages to Telegram channels.
**Inputs**: `bot_token: string`, `chat_id: string`, `message: string`, `severity: string`
**Output**: `{ sent: bool, message_id }`

---

## Infrastructure Tools

### knowledge_store
**Description**: Writes structured data to the shared knowledge graph for inter-agent communication.
**Inputs**: `key: string`, `data: object`, `tags: Vec<string>`
**Output**: `{ stored: bool, key }`

### knowledge_query
**Description**: Queries the knowledge graph for data stored by other agents.
**Inputs**: `query: string`, `tags: Vec<string>` (optional), `limit: number` (optional)
**Output**: Array of matching entries

### shell
**Description**: Executes shell commands inside the sandbox environment.
**Inputs**: `command: string`, `timeout: number` (seconds)
**Output**: `{ stdout, stderr, exit_code }`

### file_read / file_write
**Description**: Read/write files within the workspace.
**Inputs**: `path: string`, `content: string` (write only)
**Output**: File contents (read) or `{ written: bool }` (write)

### web_fetch
**Description**: HTTP requests for probing and data collection.
**Inputs**: `url: string`, `method: string`, `headers: object`, `body: string`
**Output**: `{ status, headers, body }`

### git_clone / git_branch / git_commit / git_pr
**Description**: Git operations for repository management and PR creation.
**Inputs**: Vary per operation (repo URL, branch name, commit message, PR title/body)
**Output**: Operation result

### run_tests
**Description**: Runs the target project's test suite (npm test, pytest, cargo test).
**Inputs**: `repo_path: string`, `command: string` (optional, auto-detected)
**Output**: `{ passed: bool, total, passed_count, failed_count, output }`
