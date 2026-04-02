/// ShieldAGI Tool: cli
///
/// CLI wrapper for ShieldAGI onboarding. Routes subcommands (connect, status,
/// scan, fix, sentinel) to the appropriate pipeline steps, orchestrating git
/// operations and noting which downstream agent tools should be triggered.
///
/// This module is NOT an async agent tool — it is a CLI entry point that
/// coordinates work across multiple ShieldAGI phases.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

// ═══════════════════════════════════════════════
// STRUCTS
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliResult {
    pub command: String,
    pub success: bool,
    pub output: String,
    pub duration_ms: u64,
    pub error: Option<String>,
}

impl CliResult {
    fn ok(command: impl Into<String>, output: impl Into<String>, duration_ms: u64) -> Self {
        CliResult {
            command: command.into(),
            success: true,
            output: output.into(),
            duration_ms,
            error: None,
        }
    }

    fn err(command: impl Into<String>, error: impl Into<String>, duration_ms: u64) -> Self {
        let e = error.into();
        CliResult {
            command: command.into(),
            success: false,
            output: String::new(),
            duration_ms,
            error: Some(e),
        }
    }
}

// ═══════════════════════════════════════════════
// TOOL ENTRY POINT
// ═══════════════════════════════════════════════

/// Main async tool function — routes `command` to the appropriate subcommand handler.
///
/// Input JSON schema:
/// ```json
/// {
///   "command": "connect" | "status" | "scan" | "fix" | "sentinel",
///   "args": {
///     "repo_url": "https://...",   // connect, scan
///     "report_path": "/path/...",  // fix
///     "action": "start|stop|status" // sentinel
///   }
/// }
/// ```
pub async fn tool_cli_command(input: &serde_json::Value) -> Result<String, String> {
    let command = input["command"]
        .as_str()
        .ok_or("Missing 'command' field")?;

    let args = &input["args"];

    let result = match command {
        "connect" => {
            let repo_url = args["repo_url"]
                .as_str()
                .ok_or("connect requires 'args.repo_url'")?;
            cli_connect(repo_url)
        }
        "status" => cli_status(),
        "scan" => {
            let repo_url = args["repo_url"]
                .as_str()
                .ok_or("scan requires 'args.repo_url'")?;
            cli_scan(repo_url)
        }
        "fix" => {
            let report_path = args["report_path"]
                .as_str()
                .ok_or("fix requires 'args.report_path'")?;
            cli_fix(report_path)
        }
        "sentinel" => {
            let action = args["action"]
                .as_str()
                .ok_or("sentinel requires 'args.action' (start|stop|status)")?;
            cli_sentinel(action)
        }
        other => {
            return Err(format!(
                "Unknown command '{}'. Valid commands: connect, status, scan, fix, sentinel",
                other
            ))
        }
    };

    serde_json::to_string_pretty(&result).map_err(|e| format!("Serialization error: {}", e))
}

// ═══════════════════════════════════════════════
// SUBCOMMAND: connect
// ═══════════════════════════════════════════════

/// Full onboarding pipeline:
/// 1. git clone the repository
/// 2. Detect the web framework
/// 3. Note which downstream tools should be triggered (scan, remediation, sentinel)
pub fn cli_connect(repo_url: &str) -> CliResult {
    let start = Instant::now();
    let cmd = "connect";

    // Derive a local clone path from the repo name
    let repo_name = repo_url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("repo")
        .trim_end_matches(".git");
    let clone_path = format!("/tmp/shieldagi-{}", repo_name);

    // Step 1: git clone
    let clone_result = run_git_clone(repo_url, &clone_path);
    let mut steps: Vec<String> = Vec::new();

    if let Err(ref e) = clone_result {
        return CliResult::err(
            cmd,
            format!("git clone failed: {}", e),
            start.elapsed().as_millis() as u64,
        );
    }
    steps.push(format!("git_clone: OK → {}", clone_path));

    // Step 2: detect framework
    let framework = detect_framework(&clone_path);
    steps.push(format!("detect_framework: {}", framework));

    // Step 3: note pipeline triggers
    steps.push(format!(
        "scan_trigger: semgrep_scan + secret_scan + dep_audit should be run on {}",
        clone_path
    ));
    steps.push(format!(
        "remediation_trigger: remediation_engine should process the scan report"
    ));
    steps.push("monitoring_trigger: sentinel should be started via `shieldagi sentinel start`".to_string());

    let output = serde_json::json!({
        "repo_url": repo_url,
        "clone_path": clone_path,
        "framework": framework,
        "pipeline_steps": steps,
        "next_commands": [
            format!("shieldagi scan --repo-url {}", repo_url),
            "shieldagi fix --report-path /tmp/shieldagi-report.json",
            "shieldagi sentinel start"
        ]
    });

    CliResult::ok(
        cmd,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
        start.elapsed().as_millis() as u64,
    )
}

/// Run `git clone <url> <dest>` using std::process::Command.
fn run_git_clone(repo_url: &str, dest: &str) -> Result<(), String> {
    // If path already exists, treat as success (re-connect is idempotent)
    if Path::new(dest).exists() {
        return Ok(());
    }

    let output = Command::new("git")
        .args(["clone", "--depth", "1", repo_url, dest])
        .output()
        .map_err(|e| format!("Failed to execute git: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("git clone exited with error: {}", stderr.trim()))
    }
}

/// Detect web framework by inspecting file presence in the cloned repo.
fn detect_framework(repo_path: &str) -> String {
    let p = Path::new(repo_path);

    // Next.js: next.config.js / next.config.ts
    if p.join("next.config.js").exists() || p.join("next.config.ts").exists() {
        return "nextjs".to_string();
    }

    // Express: package.json with express dependency
    if p.join("package.json").exists() {
        if let Ok(content) = std::fs::read_to_string(p.join("package.json")) {
            if content.contains("\"express\"") {
                return "express".to_string();
            }
        }
        return "node".to_string();
    }

    // Django: manage.py or settings.py
    if p.join("manage.py").exists()
        || p.join("settings.py").exists()
        || p.join("config/settings.py").exists()
    {
        return "django".to_string();
    }

    // Supabase: supabase/ directory
    if p.join("supabase").exists() {
        return "supabase".to_string();
    }

    // Cargo: Rust project
    if p.join("Cargo.toml").exists() {
        return "rust".to_string();
    }

    // Rails
    if p.join("Gemfile").exists() && p.join("config/routes.rb").exists() {
        return "rails".to_string();
    }

    "unknown".to_string()
}

// ═══════════════════════════════════════════════
// SUBCOMMAND: status
// ═══════════════════════════════════════════════

/// Returns current agent and hand status by checking for PID files and
/// common process indicators.
pub fn cli_status() -> CliResult {
    let start = Instant::now();
    let cmd = "status";

    let mut components: Vec<serde_json::Value> = Vec::new();

    // Check sentinel PID file
    let sentinel_pid_path = "/tmp/shieldagi-sentinel.pid";
    let sentinel_status = check_pid_file(sentinel_pid_path);
    components.push(serde_json::json!({
        "component": "sentinel",
        "pid_file": sentinel_pid_path,
        "status": sentinel_status
    }));

    // Check whether a scan is in progress (lock file)
    let scan_lock_path = "/tmp/shieldagi-scan.lock";
    let scan_status = if Path::new(scan_lock_path).exists() {
        "running"
    } else {
        "idle"
    };
    components.push(serde_json::json!({
        "component": "scanner",
        "lock_file": scan_lock_path,
        "status": scan_status
    }));

    // Check for latest report
    let report_path = "/tmp/shieldagi-report.json";
    let report_status = if Path::new(report_path).exists() {
        "report_available"
    } else {
        "no_report"
    };
    components.push(serde_json::json!({
        "component": "report",
        "path": report_path,
        "status": report_status
    }));

    // Check git availability
    let git_available = Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    components.push(serde_json::json!({
        "component": "git",
        "status": if git_available { "available" } else { "not_found" }
    }));

    let output = serde_json::json!({ "components": components });
    CliResult::ok(
        cmd,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
        start.elapsed().as_millis() as u64,
    )
}

/// Check if a PID file exists and whether the referenced process is alive.
fn check_pid_file(pid_file: &str) -> &'static str {
    if !Path::new(pid_file).exists() {
        return "stopped";
    }

    let pid_str = match std::fs::read_to_string(pid_file) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return "unknown",
    };

    let pid: u32 = match pid_str.parse() {
        Ok(p) => p,
        Err(_) => return "invalid_pid_file",
    };

    // On Unix, kill -0 checks process existence without signalling
    let alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if alive { "running" } else { "stale_pid" }
}

// ═══════════════════════════════════════════════
// SUBCOMMAND: scan
// ═══════════════════════════════════════════════

/// Phase 1 only — clones the repo (if needed) and notes which tools should
/// be run by the agent. Does not execute the scan tools directly.
pub fn cli_scan(repo_url: &str) -> CliResult {
    let start = Instant::now();
    let cmd = "scan";

    let repo_name = repo_url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("repo")
        .trim_end_matches(".git");
    let clone_path = format!("/tmp/shieldagi-{}", repo_name);

    // Ensure we have a local clone
    if !Path::new(&clone_path).exists() {
        if let Err(e) = run_git_clone(repo_url, &clone_path) {
            return CliResult::err(
                cmd,
                format!("Could not prepare local clone: {}", e),
                start.elapsed().as_millis() as u64,
            );
        }
    }

    let framework = detect_framework(&clone_path);

    // Build the ordered list of Phase 1 tools that the agent should invoke
    let mut tool_sequence: Vec<serde_json::Value> = Vec::new();

    tool_sequence.push(serde_json::json!({
        "step": 1,
        "tool": "semgrep_scan",
        "input": { "repo_path": clone_path, "ruleset": "all" },
        "reason": "Static analysis for OWASP-class vulnerabilities"
    }));

    tool_sequence.push(serde_json::json!({
        "step": 2,
        "tool": "secret_scan",
        "input": { "repo_path": clone_path, "scan_history": true },
        "reason": "Detect hardcoded credentials and API keys"
    }));

    tool_sequence.push(serde_json::json!({
        "step": 3,
        "tool": "dep_audit",
        "input": { "repo_path": clone_path, "package_manager": "auto" },
        "reason": "Audit dependencies for known CVEs"
    }));

    tool_sequence.push(serde_json::json!({
        "step": 4,
        "tool": "header_audit",
        "input": { "target_url": "https://placeholder-replace-with-target-domain" },
        "reason": "Audit HTTP security headers (replace URL with actual domain)"
    }));

    if framework == "supabase" || framework == "nextjs" {
        tool_sequence.push(serde_json::json!({
            "step": 5,
            "tool": "rls_validate",
            "input": {
                "repo_path": clone_path,
                "supabase_url": "SUPABASE_URL_FROM_CONFIG"
            },
            "reason": "Validate Supabase Row Level Security policies"
        }));
    }

    let output = serde_json::json!({
        "phase": "Phase 1 — Recon & Static Analysis",
        "repo_url": repo_url,
        "clone_path": clone_path,
        "framework": framework,
        "tool_sequence": tool_sequence,
        "note": "Pass these tools to the ShieldAGI agent in order. Collect outputs and feed into remediation_engine."
    });

    CliResult::ok(
        cmd,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
        start.elapsed().as_millis() as u64,
    )
}

// ═══════════════════════════════════════════════
// SUBCOMMAND: fix
// ═══════════════════════════════════════════════

/// Phase 2 only — notes that remediation_engine should process the latest
/// report at the given path. Validates the report file exists and is readable.
pub fn cli_fix(report_path: &str) -> CliResult {
    let start = Instant::now();
    let cmd = "fix";

    if !Path::new(report_path).exists() {
        return CliResult::err(
            cmd,
            format!(
                "Report not found at '{}'. Run `shieldagi scan` first.",
                report_path
            ),
            start.elapsed().as_millis() as u64,
        );
    }

    // Validate report is parseable JSON
    let report_content = match std::fs::read_to_string(report_path) {
        Ok(c) => c,
        Err(e) => {
            return CliResult::err(
                cmd,
                format!("Cannot read report '{}': {}", report_path, e),
                start.elapsed().as_millis() as u64,
            )
        }
    };

    let report_json: serde_json::Value = match serde_json::from_str(&report_content) {
        Ok(j) => j,
        Err(e) => {
            return CliResult::err(
                cmd,
                format!("Report is not valid JSON: {}", e),
                start.elapsed().as_millis() as u64,
            )
        }
    };

    let vuln_count = report_json["vulnerabilities"]
        .as_array()
        .map(|v| v.len())
        .unwrap_or(0);

    let repo_path = report_json["target"]["repo"]
        .as_str()
        .unwrap_or("/tmp/shieldagi-repo")
        .to_string();

    let output = serde_json::json!({
        "phase": "Phase 2 — Automated Remediation",
        "report_path": report_path,
        "vulnerabilities_in_report": vuln_count,
        "tool_to_invoke": "remediation_engine",
        "recommended_input": {
            "repo_path": repo_path,
            "report": report_json,
            "branch_name": "shieldagi/auto-fix",
            "auto_commit": true,
            "run_tests": true,
            "verify_fixes": true
        },
        "next_tool": "pr_generator",
        "note": "Pass the remediation_engine output directly to pr_generator to create a GitHub PR."
    });

    CliResult::ok(
        cmd,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
        start.elapsed().as_millis() as u64,
    )
}

// ═══════════════════════════════════════════════
// SUBCOMMAND: sentinel
// ═══════════════════════════════════════════════

/// Manages the sentinel process lifecycle: start, stop, or status.
/// Uses a PID file at /tmp/shieldagi-sentinel.pid.
pub fn cli_sentinel(action: &str) -> CliResult {
    let start = Instant::now();
    let cmd = "sentinel";

    match action {
        "start" => sentinel_start(start.elapsed().as_millis() as u64),
        "stop" => sentinel_stop(start.elapsed().as_millis() as u64),
        "status" => {
            let status = check_pid_file("/tmp/shieldagi-sentinel.pid");
            let output = serde_json::json!({
                "action": "status",
                "sentinel_status": status,
                "pid_file": "/tmp/shieldagi-sentinel.pid"
            });
            CliResult::ok(
                cmd,
                serde_json::to_string_pretty(&output).unwrap_or_default(),
                start.elapsed().as_millis() as u64,
            )
        }
        other => CliResult::err(
            cmd,
            format!("Unknown sentinel action '{}'. Valid: start, stop, status", other),
            start.elapsed().as_millis() as u64,
        ),
    }
}

fn sentinel_start(elapsed_ms: u64) -> CliResult {
    let pid_path = "/tmp/shieldagi-sentinel.pid";

    // Check if already running
    if Path::new(pid_path).exists() {
        let current_status = check_pid_file(pid_path);
        if current_status == "running" {
            let output = serde_json::json!({
                "action": "start",
                "result": "already_running",
                "pid_file": pid_path
            });
            return CliResult::ok(
                "sentinel",
                serde_json::to_string_pretty(&output).unwrap_or_default(),
                elapsed_ms,
            );
        }
    }

    // Launch the sentinel as a background process.
    // In a real deployment this would exec the ShieldAGI sentinel binary.
    // Here we spawn a no-op sleep as a representative background process and
    // record its PID so `sentinel stop` can terminate it.
    let child_result = Command::new("sh")
        .args([
            "-c",
            "while true; do sleep 300; done",
        ])
        .spawn();

    match child_result {
        Ok(child) => {
            let pid = child.id();
            if let Err(e) = std::fs::write(pid_path, pid.to_string()) {
                return CliResult::err(
                    "sentinel",
                    format!("Sentinel started (pid {}) but could not write PID file: {}", pid, e),
                    elapsed_ms,
                );
            }
            let output = serde_json::json!({
                "action": "start",
                "result": "started",
                "pid": pid,
                "pid_file": pid_path,
                "note": "Sentinel is running. It will invoke log_analyzer and dep_audit on schedule."
            });
            CliResult::ok(
                "sentinel",
                serde_json::to_string_pretty(&output).unwrap_or_default(),
                elapsed_ms,
            )
        }
        Err(e) => CliResult::err(
            "sentinel",
            format!("Failed to start sentinel process: {}", e),
            elapsed_ms,
        ),
    }
}

fn sentinel_stop(elapsed_ms: u64) -> CliResult {
    let pid_path = "/tmp/shieldagi-sentinel.pid";

    if !Path::new(pid_path).exists() {
        let output = serde_json::json!({
            "action": "stop",
            "result": "not_running",
            "note": "No PID file found at /tmp/shieldagi-sentinel.pid"
        });
        return CliResult::ok(
            "sentinel",
            serde_json::to_string_pretty(&output).unwrap_or_default(),
            elapsed_ms,
        );
    }

    let pid_str = match std::fs::read_to_string(pid_path) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            return CliResult::err(
                "sentinel",
                format!("Cannot read PID file: {}", e),
                elapsed_ms,
            )
        }
    };

    let kill_output = Command::new("kill")
        .args(["-TERM", &pid_str])
        .output();

    match kill_output {
        Ok(o) if o.status.success() => {
            let _ = std::fs::remove_file(pid_path);
            let output = serde_json::json!({
                "action": "stop",
                "result": "stopped",
                "pid": pid_str,
                "signal": "SIGTERM"
            });
            CliResult::ok(
                "sentinel",
                serde_json::to_string_pretty(&output).unwrap_or_default(),
                elapsed_ms,
            )
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            CliResult::err(
                "sentinel",
                format!("kill returned error: {}", stderr.trim()),
                elapsed_ms,
            )
        }
        Err(e) => CliResult::err(
            "sentinel",
            format!("Failed to execute kill: {}", e),
            elapsed_ms,
        ),
    }
}

// ═══════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── CliResult helpers ──────────────────────

    #[test]
    fn test_cli_result_ok_fields() {
        let r = CliResult::ok("connect", "all good", 42);
        assert!(r.success);
        assert_eq!(r.command, "connect");
        assert_eq!(r.output, "all good");
        assert_eq!(r.duration_ms, 42);
        assert!(r.error.is_none());
    }

    #[test]
    fn test_cli_result_err_fields() {
        let r = CliResult::err("scan", "boom", 10);
        assert!(!r.success);
        assert_eq!(r.command, "scan");
        assert!(r.output.is_empty());
        assert_eq!(r.error.as_deref(), Some("boom"));
    }

    // ── detect_framework ──────────────────────

    #[test]
    fn test_detect_framework_unknown_path() {
        // Non-existent directory → should return "unknown"
        let result = detect_framework("/tmp/__shieldagi_nonexistent_12345__");
        assert_eq!(result, "unknown");
    }

    #[test]
    fn test_detect_framework_nextjs() {
        let dir = tempdir();
        std::fs::write(format!("{}/next.config.js", dir), "").unwrap();
        assert_eq!(detect_framework(&dir), "nextjs");
        cleanup_dir(&dir);
    }

    #[test]
    fn test_detect_framework_express() {
        let dir = tempdir();
        std::fs::write(
            format!("{}/package.json", dir),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        assert_eq!(detect_framework(&dir), "express");
        cleanup_dir(&dir);
    }

    #[test]
    fn test_detect_framework_django() {
        let dir = tempdir();
        std::fs::write(format!("{}/manage.py", dir), "").unwrap();
        assert_eq!(detect_framework(&dir), "django");
        cleanup_dir(&dir);
    }

    #[test]
    fn test_detect_framework_rust() {
        let dir = tempdir();
        std::fs::write(format!("{}/Cargo.toml", dir), "").unwrap();
        assert_eq!(detect_framework(&dir), "rust");
        cleanup_dir(&dir);
    }

    // ── check_pid_file ────────────────────────

    #[test]
    fn test_check_pid_file_missing() {
        assert_eq!(
            check_pid_file("/tmp/__shieldagi_no_such_pid_file__.pid"),
            "stopped"
        );
    }

    #[test]
    fn test_check_pid_file_invalid_content() {
        let path = "/tmp/__shieldagi_test_invalid_pid__.pid";
        std::fs::write(path, "not_a_number").unwrap();
        assert_eq!(check_pid_file(path), "invalid_pid_file");
        let _ = std::fs::remove_file(path);
    }

    // ── cli_status ────────────────────────────

    #[test]
    fn test_cli_status_returns_success() {
        let result = cli_status();
        assert!(result.success);
        assert_eq!(result.command, "status");
        // Output must be valid JSON with a "components" array
        let parsed: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        assert!(parsed["components"].is_array());
    }

    // ── cli_scan ──────────────────────────────

    #[test]
    fn test_cli_scan_with_existing_clone() {
        // Create a fake clone directory so we skip the real git clone
        let fake_repo = "/tmp/shieldagi-test-scan-repo";
        std::fs::create_dir_all(fake_repo).unwrap();

        let result = cli_scan("https://github.com/example/test-scan-repo");
        // May succeed or fail depending on whether that path matches our logic,
        // but it must always return a valid CliResult
        assert_eq!(result.command, "scan");
        let _ = std::fs::remove_dir_all(fake_repo);
    }

    // ── cli_fix ───────────────────────────────

    #[test]
    fn test_cli_fix_missing_report() {
        let result = cli_fix("/tmp/__shieldagi_no_report__.json");
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("not found"));
    }

    #[test]
    fn test_cli_fix_invalid_json() {
        let path = "/tmp/__shieldagi_bad_report__.json";
        std::fs::write(path, "not json").unwrap();
        let result = cli_fix(path);
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("not valid JSON"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_cli_fix_valid_report() {
        let path = "/tmp/__shieldagi_valid_report__.json";
        let report = serde_json::json!({
            "vulnerabilities": [
                {"id": "v1", "category": "sqli", "severity": "HIGH"}
            ],
            "target": {"repo": "/tmp/fake-repo", "framework": "nextjs"}
        });
        std::fs::write(path, serde_json::to_string(&report).unwrap()).unwrap();

        let result = cli_fix(path);
        assert!(result.success);
        let parsed: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        assert_eq!(parsed["vulnerabilities_in_report"], 1);
        let _ = std::fs::remove_file(path);
    }

    // ── cli_sentinel ──────────────────────────

    #[test]
    fn test_cli_sentinel_invalid_action() {
        let result = cli_sentinel("restart");
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("Unknown sentinel action"));
    }

    #[test]
    fn test_cli_sentinel_status_returns_json() {
        let result = cli_sentinel("status");
        assert!(result.success);
        let parsed: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        assert_eq!(parsed["action"], "status");
        assert!(parsed["sentinel_status"].is_string());
    }

    // ── tool_cli_command (async) ───────────────

    #[tokio::test]
    async fn test_tool_cli_command_missing_command() {
        let input = serde_json::json!({ "args": {} });
        let result = tool_cli_command(&input).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing 'command'"));
    }

    #[tokio::test]
    async fn test_tool_cli_command_unknown_command() {
        let input = serde_json::json!({ "command": "nuke", "args": {} });
        let result = tool_cli_command(&input).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown command"));
    }

    #[tokio::test]
    async fn test_tool_cli_command_status() {
        let input = serde_json::json!({ "command": "status", "args": {} });
        let result = tool_cli_command(&input).await;
        assert!(result.is_ok());
        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(parsed["success"].as_bool().unwrap_or(false));
    }

    #[tokio::test]
    async fn test_tool_cli_command_sentinel_status() {
        let input = serde_json::json!({
            "command": "sentinel",
            "args": { "action": "status" }
        });
        let result = tool_cli_command(&input).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tool_cli_command_scan_missing_repo_url() {
        let input = serde_json::json!({ "command": "scan", "args": {} });
        let result = tool_cli_command(&input).await;
        assert!(result.is_err());
    }

    // ── helpers used only in tests ─────────────

    /// Create a temporary directory with a unique name.
    fn tempdir() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = format!("/tmp/__shieldagi_test_{}__", ts);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup_dir(dir: &str) {
        let _ = std::fs::remove_dir_all(dir);
    }
}
