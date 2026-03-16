/// ShieldAGI Tool Registry
///
/// This module registers all custom security tools with the OpenFang runtime.
/// Each tool wraps a real pentesting binary and provides structured JSON I/O.
///
/// To integrate with OpenFang fork:
/// 1. Add this crate as a dependency in openfang-runtime/Cargo.toml
/// 2. Call `register_shieldagi_tools()` in tool_runner.rs initialization
/// 3. Each tool becomes available to agents via their tool allowlist

pub mod report_types;
pub mod framework_detect;
pub mod cli;
pub mod config;
pub mod nmap_scan;
pub mod sqlmap_attack;
pub mod xss_inject;
pub mod csrf_test;
pub mod ssrf_probe;
pub mod semgrep_scan;
pub mod secret_scan;
pub mod rls_validate;
pub mod header_audit;
pub mod dep_audit;
pub mod brute_force;
pub mod idor_test;
pub mod path_traverse;
pub mod log_analyzer;
pub mod remediation_engine;
pub mod remediation_pipeline;
pub mod chain_walls_injector;
pub mod pr_generator;
pub mod verify_fix;
pub mod dep_monitor;
pub mod continuous_loop;
pub mod sentinel_runtime;
pub mod telegram_alert;
pub mod incident_engine;

use serde_json::json;

/// Tool definition matching OpenFang's ToolDefinition struct
pub struct ShieldToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Returns all ShieldAGI tool definitions for registration
pub fn get_shieldagi_tools() -> Vec<ShieldToolDef> {
    vec![
        ShieldToolDef {
            name: "nmap_scan".into(),
            description: "Scan target for open ports, services, versions, and OS detection using nmap".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "IP address or hostname to scan" },
                    "ports": { "type": "string", "description": "Port range: '1-1000', '80,443', '-' for all (default: 1-10000)" },
                    "scan_type": { "type": "string", "enum": ["quick", "service", "full", "vuln"], "description": "Scan intensity" },
                    "timeout": { "type": "integer", "description": "Max duration in seconds (default: 300)" }
                },
                "required": ["target"]
            }),
        },
        ShieldToolDef {
            name: "sqlmap_attack".into(),
            description: "Test endpoints for SQL injection vulnerabilities using sqlmap. SANDBOX ONLY.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "description": "Full URL with injectable parameter" },
                    "method": { "type": "string", "enum": ["GET", "POST"], "description": "HTTP method" },
                    "data": { "type": "string", "description": "POST data (if POST method)" },
                    "cookie": { "type": "string", "description": "Session cookie for authenticated testing" },
                    "level": { "type": "integer", "description": "Testing level 1-5 (default: 3)" },
                    "risk": { "type": "integer", "description": "Risk level 1-3 (default: 2)" },
                    "technique": { "type": "string", "description": "Injection technique: B=boolean, T=time, U=union, S=stacked, E=error" }
                },
                "required": ["target_url"]
            }),
        },
        ShieldToolDef {
            name: "xss_inject".into(),
            description: "Test for cross-site scripting vulnerabilities using headless browser injection".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "description": "URL to test for XSS" },
                    "input_fields": { "type": "array", "items": { "type": "string" }, "description": "Form field names to inject" },
                    "xss_type": { "type": "string", "enum": ["reflected", "stored", "dom", "all"], "description": "XSS variant to test" },
                    "payload_set": { "type": "string", "enum": ["basic", "advanced", "polyglot"], "description": "Payload complexity" },
                    "cookie": { "type": "string", "description": "Session cookie for authenticated testing" }
                },
                "required": ["target_url"]
            }),
        },
        ShieldToolDef {
            name: "csrf_test".into(),
            description: "Test endpoints for CSRF vulnerabilities by crafting cross-origin requests".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "description": "URL of the state-changing endpoint" },
                    "method": { "type": "string", "enum": ["POST", "PUT", "DELETE", "PATCH"] },
                    "data": { "type": "object", "description": "Request body for the state-changing action" },
                    "auth_cookie": { "type": "string", "description": "Valid session cookie to test with" },
                    "check_origin": { "type": "boolean", "description": "Test if Origin header is validated" },
                    "check_referer": { "type": "boolean", "description": "Test if Referer header is validated" }
                },
                "required": ["target_url", "method"]
            }),
        },
        ShieldToolDef {
            name: "ssrf_probe".into(),
            description: "Test endpoints for server-side request forgery by probing internal resources".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "description": "Endpoint that accepts URLs as input" },
                    "parameter": { "type": "string", "description": "Parameter name that takes URL input" },
                    "method": { "type": "string", "enum": ["GET", "POST"] },
                    "probes": { "type": "array", "items": { "type": "string" }, "description": "Internal URLs to probe (default: metadata, localhost services)" },
                    "cookie": { "type": "string", "description": "Session cookie" }
                },
                "required": ["target_url", "parameter"]
            }),
        },
        ShieldToolDef {
            name: "semgrep_scan".into(),
            description: "Run semgrep static analysis with OWASP and custom ShieldAGI rules".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo_path": { "type": "string", "description": "Path to cloned repository" },
                    "ruleset": { "type": "string", "enum": ["owasp", "shieldagi", "all"], "description": "Ruleset to apply (default: all)" },
                    "language": { "type": "string", "description": "Target language filter (e.g., 'javascript', 'python')" },
                    "severity": { "type": "string", "enum": ["ERROR", "WARNING", "INFO"], "description": "Minimum severity to report" }
                },
                "required": ["repo_path"]
            }),
        },
        ShieldToolDef {
            name: "secret_scan".into(),
            description: "Scan repository for hardcoded secrets, API keys, and credentials using trufflehog + gitleaks".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo_path": { "type": "string", "description": "Path to cloned repository" },
                    "scan_history": { "type": "boolean", "description": "Scan git commit history (default: true)" },
                    "include_patterns": { "type": "array", "items": { "type": "string" }, "description": "Additional secret patterns to search" }
                },
                "required": ["repo_path"]
            }),
        },
        ShieldToolDef {
            name: "rls_validate".into(),
            description: "Validate Supabase Row Level Security policies for completeness and correctness".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "supabase_url": { "type": "string", "description": "Supabase project URL" },
                    "service_key": { "type": "string", "description": "Supabase service_role key for schema inspection" },
                    "repo_path": { "type": "string", "description": "Path to repo with supabase/migrations" }
                },
                "required": ["supabase_url"]
            }),
        },
        ShieldToolDef {
            name: "header_audit".into(),
            description: "Audit HTTP security headers on target URL (CSP, HSTS, X-Frame-Options, etc.)".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "description": "URL to audit headers for" },
                    "follow_redirects": { "type": "boolean", "description": "Follow redirects (default: true)" }
                },
                "required": ["target_url"]
            }),
        },
        ShieldToolDef {
            name: "dep_audit".into(),
            description: "Audit project dependencies for known CVEs (npm, pip, cargo)".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo_path": { "type": "string", "description": "Path to cloned repository" },
                    "package_manager": { "type": "string", "enum": ["npm", "pip", "cargo", "auto"], "description": "Package manager (default: auto-detect)" }
                },
                "required": ["repo_path"]
            }),
        },
        ShieldToolDef {
            name: "brute_force".into(),
            description: "Test authentication endpoints for rate limiting and weak credentials. SANDBOX ONLY.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "description": "Login endpoint URL" },
                    "username_field": { "type": "string", "description": "Username form field name" },
                    "password_field": { "type": "string", "description": "Password form field name" },
                    "test_usernames": { "type": "array", "items": { "type": "string" }, "description": "Usernames to test" },
                    "max_attempts": { "type": "integer", "description": "Max attempts per username (default: 20)" },
                    "check_rate_limit": { "type": "boolean", "description": "Test rate limiting behavior (default: true)" }
                },
                "required": ["target_url"]
            }),
        },
        ShieldToolDef {
            name: "idor_test".into(),
            description: "Test API endpoints for Insecure Direct Object Reference vulnerabilities".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "endpoints": { "type": "array", "items": { "type": "string" }, "description": "API endpoints with resource IDs" },
                    "user_a_token": { "type": "string", "description": "Auth token for user A" },
                    "user_b_token": { "type": "string", "description": "Auth token for user B" },
                    "resource_ids": { "type": "array", "items": { "type": "string" }, "description": "Resource IDs owned by user A" }
                },
                "required": ["endpoints", "user_a_token", "user_b_token"]
            }),
        },
        ShieldToolDef {
            name: "path_traverse".into(),
            description: "Test for directory/path traversal vulnerabilities with encoded payloads".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "description": "URL with file path parameter" },
                    "parameter": { "type": "string", "description": "Parameter that accepts file paths" },
                    "method": { "type": "string", "enum": ["GET", "POST"] },
                    "encoding_levels": { "type": "integer", "description": "Max encoding bypass levels to try (default: 3)" }
                },
                "required": ["target_url", "parameter"]
            }),
        },
        ShieldToolDef {
            name: "log_analyzer".into(),
            description: "Analyze application and server logs for attack patterns and anomalies".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "log_source": { "type": "string", "description": "Path to log file or log API endpoint" },
                    "time_range_minutes": { "type": "integer", "description": "Analyze logs from last N minutes (default: 5)" },
                    "patterns": { "type": "array", "items": { "type": "string" }, "description": "Additional patterns to search for" },
                    "baseline_path": { "type": "string", "description": "Path to baseline metrics JSON" }
                },
                "required": ["log_source"]
            }),
        },
        ShieldToolDef {
            name: "remediation_engine".into(),
            description: "Apply automated security fixes from vulnerability report. Full pipeline: plan → fix → test → PR.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo_path": { "type": "string", "description": "Path to cloned repository" },
                    "report": { "type": "object", "description": "Vulnerability report from vuln-reporter agent" },
                    "branch_name": { "type": "string", "description": "Git branch name for fixes (default: auto-generated)" },
                    "auto_commit": { "type": "boolean", "description": "Auto-commit each fix (default: true)" },
                    "run_tests": { "type": "boolean", "description": "Run project tests after fixes (default: true)" },
                    "verify_fixes": { "type": "boolean", "description": "Re-run attack tools to verify fixes (default: true)" }
                },
                "required": ["repo_path", "report"]
            }),
        },
        ShieldToolDef {
            name: "run_remediation".into(),
            description: "Phase C pipeline orchestrator: reads a JSON report from disk, plans fix order, applies code transforms, runs tests, verifies fixes, and returns a PipelineReport.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "report_path": { "type": "string", "description": "Absolute path to the vulnerability report JSON file on disk" },
                    "repo_path": { "type": "string", "description": "Path to cloned repository" },
                    "branch_name": { "type": "string", "description": "Git branch name for the fix commits (default: auto-generated)" },
                    "run_tests": { "type": "boolean", "description": "Run project tests after each fix and once at the end (default: true)" },
                    "auto_verify": { "type": "boolean", "description": "Mark fixed vulns for verification by the verify_fix tool (default: true)" }
                },
                "required": ["report_path", "repo_path"]
            }),
        },
        ShieldToolDef {
            name: "chain_walls_injector".into(),
            description: "Detect framework and inject Chain Walls 7-layer security middleware into project".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo_path": { "type": "string", "description": "Path to target repository" },
                    "framework": { "type": "string", "enum": ["express", "nextjs", "django", "supabase"], "description": "Force framework (default: auto-detect)" },
                    "shieldagi_root": { "type": "string", "description": "Path to ShieldAGI installation (default: /opt/shieldagi)" }
                },
                "required": ["repo_path"]
            }),
        },
        ShieldToolDef {
            name: "pr_generator".into(),
            description: "Generate detailed GitHub Pull Request from remediation results with diffs and summary tables".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo_path": { "type": "string", "description": "Path to repository" },
                    "remediation_result": { "type": "object", "description": "Output from remediation_engine tool" },
                    "base_branch": { "type": "string", "description": "PR target branch (default: main)" },
                    "title": { "type": "string", "description": "Custom PR title (default: auto-generated)" },
                    "auto_push": { "type": "boolean", "description": "Push branch and create PR via gh CLI (default: false)" }
                },
                "required": ["repo_path", "remediation_result"]
            }),
        },
        ShieldToolDef {
            name: "detect_framework".into(),
            description: "Auto-detect the web framework(s) used in a repository (Next.js, Express, Django, Supabase, Rust web, etc.)".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo_path": { "type": "string", "description": "Path to cloned repository" }
                },
                "required": ["repo_path"]
            }),
        },
        ShieldToolDef {
            name: "verify_fix".into(),
            description: "Re-run attack tools against remediated endpoints to confirm vulnerabilities are fixed".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "mode": { "type": "string", "enum": ["single", "batch"], "description": "Verify one or multiple vulnerabilities" },
                    "vulnerability_id": { "type": "string", "description": "ID of the vulnerability to verify (single mode)" },
                    "category": { "type": "string", "description": "Vulnerability category: sqli, xss, csrf, ssrf, idor, path-traversal, auth, misconfig, secrets" },
                    "target_url": { "type": "string", "description": "Endpoint URL to test (must be sandbox)" },
                    "parameter": { "type": "string", "description": "Parameter name for injection tests" },
                    "vulnerabilities": { "type": "array", "description": "Array of vulnerabilities to verify (batch mode)" }
                },
                "required": ["mode"]
            }),
        },
    ]
}

/// Route tool calls to their implementations
pub async fn execute_shieldagi_tool(
    name: &str,
    input: &serde_json::Value,
) -> Result<String, String> {
    match name {
        "nmap_scan" => nmap_scan::tool_nmap_scan(input).await,
        "sqlmap_attack" => sqlmap_attack::tool_sqlmap_attack(input).await,
        "xss_inject" => xss_inject::tool_xss_inject(input).await,
        "csrf_test" => csrf_test::tool_csrf_test(input).await,
        "ssrf_probe" => ssrf_probe::tool_ssrf_probe(input).await,
        "semgrep_scan" => semgrep_scan::tool_semgrep_scan(input).await,
        "secret_scan" => secret_scan::tool_secret_scan(input).await,
        "rls_validate" => rls_validate::tool_rls_validate(input).await,
        "header_audit" => header_audit::tool_header_audit(input).await,
        "dep_audit" => dep_audit::tool_dep_audit(input).await,
        "brute_force" => brute_force::tool_brute_force(input).await,
        "idor_test" => idor_test::tool_idor_test(input).await,
        "path_traverse" => path_traverse::tool_path_traverse(input).await,
        "log_analyzer" => log_analyzer::tool_log_analyzer(input).await,
        "remediation_engine" => remediation_engine::tool_remediation_engine(input).await,
        "run_remediation" => remediation_pipeline::tool_run_remediation(input).await,
        "chain_walls_injector" => chain_walls_injector::tool_chain_walls_injector(input).await,
        "pr_generator" => pr_generator::tool_pr_generator(input).await,
        "verify_fix" => verify_fix::tool_verify_fix(input).await,
        "detect_framework" => framework_detect::tool_detect_framework(input).await,
        "cli_command" => cli::tool_cli_command(input).await,
        "load_config" => config::tool_load_config(input).await,
        _ => Err(format!("Unknown ShieldAGI tool: {}", name)),
    }
}
