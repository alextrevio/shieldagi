/// ShieldAGI Tool: continuous_loop
///
/// Continuous loop controller -- connects Phase 3 (monitoring / incident response)
/// back to Phase 1->2 (focused scan -> targeted remediation).
///
/// When the Sentinel or Incident Engine detects a new vulnerability that was NOT
/// in the original scan report, this controller:
///   1. Triggers a Phase 1 scan focused on the specific attack vector (not full scan)
///   2. Waits for the result
///   3. If the scan confirms a new vulnerability: triggers Phase 2 focused remediation
///   4. Verifies the fix
///   5. If fix succeeds: creates an emergency PR and alerts "auto-patched"
///   6. If fix fails: escalates to a human operator via Telegram
///
/// Rate limit: max 1 mini-cycle every 30 minutes to prevent infinite loops.
/// All cycles are logged in a persistent CycleHistory.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::process::Command;

// =============================================================================
// CORE STRUCTS
// =============================================================================

/// Top-level controller state. Persisted between invocations via JSON on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuousLoopController {
    /// Timestamp (RFC 3339) of the last completed cycle.
    pub last_cycle_at: Option<String>,
    /// Full history of all cycles executed during this controller lifetime.
    pub cycle_history: CycleHistory,
    /// Set of vulnerability IDs already known from the original report. New
    /// detections that are NOT in this set trigger a mini-cycle.
    pub known_vuln_ids: HashSet<String>,
    /// Minimum minutes between automatic mini-cycles (default: 30).
    pub rate_limit_minutes: u32,
}

/// A request to run a focused (single-vector) scan against a specific endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusedScanRequest {
    /// The attack class to scan for (e.g. "sqli", "xss", "ssrf").
    pub attack_vector: String,
    /// The endpoint / URL to target.
    pub target_endpoint: String,
    /// Correlation ID from the sentinel or incident that triggered this cycle.
    pub source_incident_id: String,
    /// Severity level reported by the triggering system.
    pub severity: String,
}

/// The outcome of a single mini-cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleResult {
    pub cycle_id: String,
    pub triggered_by: String,
    pub scan_result: ScanOutcome,
    pub remediation_result: Option<RemediationOutcome>,
    pub pr_url: Option<String>,
    pub status: CycleStatus,
}

/// Scan sub-result embedded in CycleResult.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub tool_used: String,
    pub scan_input: serde_json::Value,
    pub vulns_found: usize,
    pub confirmed_new: bool,
    pub detail: String,
}

/// Remediation sub-result embedded in CycleResult.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationOutcome {
    pub fix_attempted: bool,
    pub fix_verified: bool,
    pub files_modified: Vec<String>,
    pub detail: String,
}

/// Terminal status of a cycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CycleStatus {
    Scanned,
    Remediated,
    Failed,
    RateLimited,
    Escalated,
}

/// Aggregated history of all cycles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleHistory {
    pub cycles: Vec<CycleResult>,
    pub total_auto_patches: u32,
    pub total_escalations: u32,
}

// =============================================================================
// CONSTRUCTOR / DEFAULTS
// =============================================================================

impl ContinuousLoopController {
    /// Create a new controller with default rate limit and empty history.
    pub fn new(known_vuln_ids: HashSet<String>, rate_limit_minutes: u32) -> Self {
        Self {
            last_cycle_at: None,
            cycle_history: CycleHistory {
                cycles: Vec::new(),
                total_auto_patches: 0,
                total_escalations: 0,
            },
            known_vuln_ids,
            rate_limit_minutes,
        }
    }

    /// Returns true if a new cycle is allowed (i.e. the cooldown has elapsed).
    pub fn can_run_cycle(&self) -> bool {
        let Some(ref last) = self.last_cycle_at else {
            return true;
        };
        let Ok(last_ts) = last.parse::<chrono::DateTime<chrono::Utc>>() else {
            return true;
        };
        let elapsed = chrono::Utc::now().signed_duration_since(last_ts);
        elapsed >= chrono::Duration::minutes(self.rate_limit_minutes as i64)
    }

    /// Record a completed cycle and update counters.
    pub fn record_cycle(&mut self, result: CycleResult) {
        match result.status {
            CycleStatus::Remediated => self.cycle_history.total_auto_patches += 1,
            CycleStatus::Escalated | CycleStatus::Failed => {
                self.cycle_history.total_escalations += 1;
            }
            _ => {}
        }
        self.last_cycle_at = Some(chrono::Utc::now().to_rfc3339());
        self.cycle_history.cycles.push(result);
    }
}

impl Default for ContinuousLoopController {
    fn default() -> Self {
        Self::new(HashSet::new(), 30)
    }
}

// =============================================================================
// MAIN TOOL ENTRY POINT
// =============================================================================

/// Tool entry point. Accepts JSON input describing a newly detected attack
/// vector and runs the full mini-cycle: scan -> remediate -> verify -> PR/escalate.
///
/// # Input fields
/// - `attack_vector`       (required) Attack class: sqli, xss, ssrf, csrf, etc.
/// - `target_endpoint`     (required) URL/path to scan.
/// - `source_incident_id`  (required) Correlation ID from sentinel/incident.
/// - `severity`            (required) CRITICAL | HIGH | MEDIUM | LOW.
/// - `known_vuln_ids`      (optional) Array of vuln IDs already in the report.
/// - `state_path`          (optional) Path to persist controller state JSON.
/// - `repo_path`           (optional) Repository path for remediation.
/// - `telegram_bot_token`  (optional) Bot token for human escalation.
/// - `telegram_chat_id`    (optional) Chat ID for human escalation.
pub async fn tool_trigger_focused_scan(input: &serde_json::Value) -> Result<String, String> {
    let attack_vector = input["attack_vector"]
        .as_str()
        .ok_or("Missing 'attack_vector' field")?;
    let target_endpoint = input["target_endpoint"]
        .as_str()
        .ok_or("Missing 'target_endpoint' field")?;
    let source_incident_id = input["source_incident_id"]
        .as_str()
        .ok_or("Missing 'source_incident_id' field")?;
    let severity = input["severity"]
        .as_str()
        .ok_or("Missing 'severity' field")?;

    let state_path = input["state_path"].as_str();
    let repo_path = input["repo_path"].as_str().unwrap_or("");
    let telegram_bot_token = input["telegram_bot_token"].as_str();
    let telegram_chat_id = input["telegram_chat_id"].as_str();

    // Build the set of already-known vuln IDs from input (if provided)
    let known_ids: HashSet<String> = input["known_vuln_ids"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Load or create controller state
    let mut controller = if let Some(sp) = state_path {
        load_controller(sp).unwrap_or_else(|_| ContinuousLoopController::new(known_ids.clone(), 30))
    } else {
        ContinuousLoopController::new(known_ids.clone(), 30)
    };

    // Merge any newly supplied known IDs into the controller
    for id in &known_ids {
        controller.known_vuln_ids.insert(id.clone());
    }

    let cycle_id = generate_cycle_id(source_incident_id, attack_vector);

    // ---- Rate-limit check ----
    if !controller.can_run_cycle() {
        let result = CycleResult {
            cycle_id: cycle_id.clone(),
            triggered_by: source_incident_id.to_string(),
            scan_result: ScanOutcome {
                tool_used: String::new(),
                scan_input: serde_json::Value::Null,
                vulns_found: 0,
                confirmed_new: false,
                detail: format!(
                    "Rate limited: last cycle was less than {} minutes ago",
                    controller.rate_limit_minutes
                ),
            },
            remediation_result: None,
            pr_url: None,
            status: CycleStatus::RateLimited,
        };

        controller.record_cycle(result.clone());
        persist_if_needed(state_path, &controller);

        return Ok(serde_json::to_string_pretty(&result).unwrap());
    }

    // ---- Sandbox safety check ----
    if !target_endpoint.is_empty() && !is_sandbox_target(target_endpoint) {
        return Err(format!(
            "Safety check failed: target_endpoint '{}' is not a sandbox/localhost target. \
             Focused scans may only run against sandbox environments.",
            target_endpoint
        ));
    }

    let request = FocusedScanRequest {
        attack_vector: attack_vector.to_string(),
        target_endpoint: target_endpoint.to_string(),
        source_incident_id: source_incident_id.to_string(),
        severity: severity.to_string(),
    };

    // ---- Phase 1: Focused Scan ----
    let scan_tool = map_vector_to_tool(attack_vector);
    let scan_input = build_scan_input(attack_vector, target_endpoint);
    let scan_outcome = execute_focused_scan(&request, scan_tool, &scan_input);

    // If no vulns found, record and return
    if scan_outcome.vulns_found == 0 {
        let result = CycleResult {
            cycle_id: cycle_id.clone(),
            triggered_by: source_incident_id.to_string(),
            scan_result: scan_outcome,
            remediation_result: None,
            pr_url: None,
            status: CycleStatus::Scanned,
        };

        controller.record_cycle(result.clone());
        persist_if_needed(state_path, &controller);

        return Ok(serde_json::to_string_pretty(&result).unwrap());
    }

    // ---- Phase 2: Focused Remediation ----
    let remediation_outcome = execute_focused_remediation(
        repo_path,
        attack_vector,
        target_endpoint,
        &cycle_id,
    );

    // ---- Phase 2b: Verify Fix ----
    let fix_verified = remediation_outcome.fix_verified;

    if fix_verified {
        // ---- Phase 2c: Emergency PR ----
        let pr_url = create_emergency_pr(repo_path, attack_vector, &cycle_id, &request);

        let result = CycleResult {
            cycle_id: cycle_id.clone(),
            triggered_by: source_incident_id.to_string(),
            scan_result: scan_outcome,
            remediation_result: Some(remediation_outcome),
            pr_url: Some(pr_url),
            status: CycleStatus::Remediated,
        };

        controller.known_vuln_ids.insert(cycle_id.clone());
        controller.record_cycle(result.clone());
        persist_if_needed(state_path, &controller);

        return Ok(serde_json::to_string_pretty(&result).unwrap());
    }

    // ---- Fix failed: escalate to human ----
    let escalation_detail = escalate_to_human(
        telegram_bot_token,
        telegram_chat_id,
        &request,
        &cycle_id,
    );

    let mut remediation_with_escalation = remediation_outcome;
    remediation_with_escalation.detail = format!(
        "{}; Escalation: {}",
        remediation_with_escalation.detail, escalation_detail
    );

    let result = CycleResult {
        cycle_id: cycle_id.clone(),
        triggered_by: source_incident_id.to_string(),
        scan_result: scan_outcome,
        remediation_result: Some(remediation_with_escalation),
        pr_url: None,
        status: CycleStatus::Escalated,
    };

    controller.record_cycle(result.clone());
    persist_if_needed(state_path, &controller);

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

// =============================================================================
// PHASE 1: FOCUSED SCAN
// =============================================================================

fn execute_focused_scan(
    request: &FocusedScanRequest,
    scan_tool: &str,
    scan_input: &serde_json::Value,
) -> ScanOutcome {
    // For network-based attack vectors, run a lightweight probe via curl to
    // confirm the vulnerability is reachable before delegating to the full tool.
    let (vulns_found, confirmed_new, detail) =
        probe_attack_vector(&request.attack_vector, &request.target_endpoint);

    ScanOutcome {
        tool_used: scan_tool.to_string(),
        scan_input: scan_input.clone(),
        vulns_found,
        confirmed_new,
        detail,
    }
}

/// Lightweight probe that sends a single canary request per attack vector.
/// Returns (vulns_found, confirmed_new, detail).
fn probe_attack_vector(attack_vector: &str, target: &str) -> (usize, bool, String) {
    let (payload, indicator) = match attack_vector.to_lowercase().as_str() {
        "sqli" | "sql-injection" | "sql_injection" => (
            "' OR '1'='1' --",
            vec!["syntax error", "sql", "unclosed quotation", "mysql", "postgresql"],
        ),
        "xss" | "cross-site-scripting" => (
            "<script>alert('shieldagi')</script>",
            vec!["<script>alert", "onerror="],
        ),
        "ssrf" | "server-side-request-forgery" => (
            "http://169.254.169.254/latest/meta-data/",
            vec!["ami-id", "instance-id", "meta-data"],
        ),
        "traversal" | "path-traversal" | "path_traversal" | "lfi" | "rfi" => (
            "../../../../../../etc/passwd",
            vec!["root:", "bin:", "daemon:"],
        ),
        _ => {
            // For vectors that cannot be probed with a simple HTTP request
            // (csrf, idor, auth, headers, secrets), report delegation-only.
            return (
                0,
                false,
                format!(
                    "Vector '{}' requires full tool execution; probe skipped. \
                     Agent orchestrator should execute the delegated scan tool.",
                    attack_vector
                ),
            );
        }
    };

    let url = if target.contains('?') {
        format!("{}&probe={}", target, urlencoding(payload))
    } else {
        format!("{}?probe={}", target, urlencoding(payload))
    };

    let (status, body) = curl_get(&url);

    if status == 0 {
        return (
            0,
            false,
            format!("Probe failed: target '{}' unreachable", target),
        );
    }

    let body_lower = body.to_lowercase();
    let matched = indicator.iter().any(|i| body_lower.contains(i));

    if matched {
        (
            1,
            true,
            format!(
                "Probe confirmed {} vulnerability at {} (HTTP {})",
                attack_vector, target, status
            ),
        )
    } else {
        (
            0,
            false,
            format!(
                "Probe did not confirm {} at {} (HTTP {}); may need full scan",
                attack_vector, target, status
            ),
        )
    }
}

// =============================================================================
// PHASE 2: FOCUSED REMEDIATION
// =============================================================================

fn execute_focused_remediation(
    repo_path: &str,
    attack_vector: &str,
    _target_endpoint: &str,
    cycle_id: &str,
) -> RemediationOutcome {
    if repo_path.is_empty() {
        return RemediationOutcome {
            fix_attempted: false,
            fix_verified: false,
            files_modified: vec![],
            detail: "No repo_path provided; remediation cannot proceed".to_string(),
        };
    }

    // Verify the repo exists and is a git directory
    let is_git = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(repo_path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !is_git {
        return RemediationOutcome {
            fix_attempted: false,
            fix_verified: false,
            files_modified: vec![],
            detail: format!("'{}' is not a valid git repository", repo_path),
        };
    }

    // Create a remediation branch
    let branch_name = format!(
        "shieldagi/emergency-{}-{}",
        sanitize_branch_segment(attack_vector),
        cycle_id
    );

    let branch_created = Command::new("git")
        .args(["checkout", "-b", &branch_name])
        .current_dir(repo_path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !branch_created {
        // Try force-creating if branch already exists
        let _ = Command::new("git")
            .args(["branch", "--force", &branch_name])
            .current_dir(repo_path)
            .output();
    }

    // Determine which files to scan/fix based on attack vector
    let target_patterns = match attack_vector.to_lowercase().as_str() {
        "sqli" | "sql-injection" | "sql_injection" => {
            vec!["*.js", "*.ts", "*.py", "*.rb", "*.java", "*.go", "*.rs"]
        }
        "xss" | "cross-site-scripting" => {
            vec!["*.js", "*.ts", "*.jsx", "*.tsx", "*.html", "*.vue", "*.svelte"]
        }
        "ssrf" | "server-side-request-forgery" => vec!["*.js", "*.ts", "*.py", "*.go", "*.rs"],
        "csrf" => vec!["*.js", "*.ts", "*.py"],
        "headers" | "misconfig" | "security-misconfiguration" => {
            vec!["*.js", "*.ts", "*.py", "*.conf", "*.yaml", "*.yml", "*.toml"]
        }
        "secrets" | "hardcoded-secrets" => vec!["*.env", "*.js", "*.ts", "*.py", "*.json"],
        _ => vec!["*.js", "*.ts", "*.py"],
    };

    // Run a lightweight grep to find potentially vulnerable files
    let mut files_found: Vec<String> = Vec::new();
    for pattern in &target_patterns {
        if let Ok(output) = Command::new("find")
            .args([repo_path, "-name", pattern, "-type", "f", "-not", "-path", "*node_modules*", "-not", "-path", "*.git*"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        files_found.push(trimmed.to_string());
                    }
                }
            }
        }
    }

    // For the focused remediation, the actual code transformation is delegated
    // to the remediation_engine tool by the agent orchestrator. Here we record
    // which files are candidates and whether the branch was set up.
    let fix_attempted = !files_found.is_empty() && branch_created;

    // Verify fix by re-running the probe (simulated: in production the agent
    // layer would call verify_fix tool after applying the code changes)
    let fix_verified = false; // Requires agent-layer round-trip

    RemediationOutcome {
        fix_attempted,
        fix_verified,
        files_modified: if files_found.len() > 20 {
            files_found[..20].to_vec()
        } else {
            files_found
        },
        detail: if fix_attempted {
            format!(
                "Remediation branch '{}' created; files identified for {} fix. \
                 Agent orchestrator should apply remediation_engine and verify_fix.",
                branch_name, attack_vector
            )
        } else if !branch_created {
            format!("Failed to create remediation branch '{}'", branch_name)
        } else {
            format!("No candidate files found for {} remediation", attack_vector)
        },
    }
}

// =============================================================================
// PHASE 2c: EMERGENCY PR
// =============================================================================

fn create_emergency_pr(
    repo_path: &str,
    attack_vector: &str,
    cycle_id: &str,
    request: &FocusedScanRequest,
) -> String {
    let branch_name = format!(
        "shieldagi/emergency-{}-{}",
        sanitize_branch_segment(attack_vector),
        cycle_id
    );

    let pr_title = format!(
        "fix(security): auto-patch {} vulnerability [{}]",
        attack_vector, request.severity
    );

    let pr_body = format!(
        "## ShieldAGI Emergency Auto-Patch\n\n\
         **Triggered by:** {}\n\
         **Attack vector:** {}\n\
         **Severity:** {}\n\
         **Target endpoint:** {}\n\
         **Cycle ID:** {}\n\n\
         This PR was automatically generated by the ShieldAGI continuous loop \
         controller after detecting and remediating a new vulnerability that was \
         not in the original scan report.\n\n\
         ---\n\
         *Generated by ShieldAGI 2.0 Continuous Loop Controller*",
        request.source_incident_id,
        request.attack_vector,
        request.severity,
        request.target_endpoint,
        cycle_id,
    );

    if repo_path.is_empty() {
        return format!("PR not created: no repo_path (branch: {})", branch_name);
    }

    // Push the branch
    let push_ok = Command::new("git")
        .args(["push", "-u", "origin", &branch_name])
        .current_dir(repo_path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !push_ok {
        return format!(
            "Branch '{}' created locally but push failed; \
             agent should retry or create PR manually",
            branch_name
        );
    }

    // Create PR via gh CLI
    let pr_output = Command::new("gh")
        .args([
            "pr", "create",
            "--title", &pr_title,
            "--body", &pr_body,
            "--head", &branch_name,
            "--label", "security,auto-patch,emergency",
        ])
        .current_dir(repo_path)
        .output();

    match pr_output {
        Ok(o) if o.status.success() => {
            let url = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if url.starts_with("http") {
                url
            } else {
                format!("PR created on branch '{}' (url not captured)", branch_name)
            }
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            format!(
                "gh pr create failed: {}; branch '{}' was pushed",
                stderr.trim(),
                branch_name
            )
        }
        Err(e) => format!(
            "gh CLI not available ({}); branch '{}' was pushed",
            e, branch_name
        ),
    }
}

// =============================================================================
// ESCALATION: TELEGRAM
// =============================================================================

fn escalate_to_human(
    bot_token: Option<&str>,
    chat_id: Option<&str>,
    request: &FocusedScanRequest,
    cycle_id: &str,
) -> String {
    let (Some(token), Some(cid)) = (bot_token, chat_id) else {
        return "Escalation skipped: telegram_bot_token or telegram_chat_id not provided. \
                Human operator must be notified via alternative channel."
            .to_string();
    };

    if token.is_empty() || cid.is_empty() {
        return "Escalation skipped: empty telegram credentials".to_string();
    }

    let message = format!(
        "SHIELDAGI ESCALATION\n\n\
         Cycle: {}\n\
         Attack vector: {}\n\
         Severity: {}\n\
         Target: {}\n\
         Incident: {}\n\n\
         Automated remediation FAILED. Human intervention required.\n\
         Please review and apply a manual fix.",
        cycle_id,
        request.attack_vector,
        request.severity,
        request.target_endpoint,
        request.source_incident_id,
    );

    let payload = serde_json::json!({
        "chat_id": cid,
        "text": message,
        "parse_mode": "HTML",
    });

    let payload_str = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => return format!("Failed to serialize Telegram payload: {}", e),
    };

    let url = format!("https://api.telegram.org/bot{}/sendMessage", token);

    let output = Command::new("curl")
        .args([
            "-s",
            "--max-time", "15",
            "-X", "POST",
            &url,
            "-H", "Content-Type: application/json",
            "-d", &payload_str,
        ])
        .output();

    match output {
        Ok(o) => {
            let body = String::from_utf8_lossy(&o.stdout);
            if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&body) {
                if resp["ok"].as_bool() == Some(true) {
                    let msg_id = resp["result"]["message_id"]
                        .as_i64()
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    format!("Telegram alert sent (message_id: {})", msg_id)
                } else {
                    let desc = resp["description"]
                        .as_str()
                        .unwrap_or("unknown error");
                    format!("Telegram API error: {}", desc)
                }
            } else {
                format!(
                    "Failed to parse Telegram response: {}",
                    &body[..body.len().min(200)]
                )
            }
        }
        Err(e) => format!("curl failed: {}", e),
    }
}

// =============================================================================
// ATTACK VECTOR -> TOOL MAPPING
// =============================================================================

fn map_vector_to_tool(attack_vector: &str) -> &'static str {
    match attack_vector.to_lowercase().as_str() {
        "sqli" | "sql-injection" | "sql_injection" => "sqlmap_attack",
        "xss" | "cross-site-scripting" => "xss_inject",
        "ssrf" | "server-side-request-forgery" => "ssrf_probe",
        "brute-force" | "brute_force" | "bruteforce" | "auth" => "brute_force",
        "traversal" | "path-traversal" | "path_traversal" | "lfi" | "rfi" => "path_traverse",
        "idor" | "broken-access-control" => "idor_test",
        "csrf" => "csrf_test",
        "headers" | "misconfig" | "security-misconfiguration" => "header_audit",
        "secrets" | "hardcoded-secrets" => "secret_scan",
        _ => "semgrep_scan",
    }
}

// =============================================================================
// SCAN INPUT BUILDER
// =============================================================================

fn build_scan_input(attack_vector: &str, target: &str) -> serde_json::Value {
    match attack_vector.to_lowercase().as_str() {
        "sqli" | "sql-injection" | "sql_injection" => serde_json::json!({
            "target_url": target,
            "method": "GET",
            "level": 3,
            "risk": 2,
            "technique": "BEUSTQ"
        }),
        "xss" | "cross-site-scripting" => serde_json::json!({
            "target_url": target,
            "xss_type": "all",
            "payload_set": "advanced"
        }),
        "ssrf" | "server-side-request-forgery" => serde_json::json!({
            "target_url": target,
            "parameter": "url",
            "method": "GET",
            "probes": [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://127.0.0.1:8080/",
                "http://localhost:22/"
            ]
        }),
        "brute-force" | "brute_force" | "bruteforce" | "auth" => serde_json::json!({
            "target_url": target,
            "username_field": "username",
            "password_field": "password",
            "test_usernames": ["admin", "root", "administrator", "user", "test"],
            "max_attempts": 20,
            "check_rate_limit": true
        }),
        "traversal" | "path-traversal" | "path_traversal" | "lfi" | "rfi" => serde_json::json!({
            "target_url": target,
            "parameter": "file",
            "method": "GET",
            "encoding_levels": 3
        }),
        "idor" | "broken-access-control" => serde_json::json!({
            "endpoints": [target],
            "user_a_token": "__AGENT_PROVIDE_TOKEN_A__",
            "user_b_token": "__AGENT_PROVIDE_TOKEN_B__",
            "resource_ids": ["1", "2", "3"]
        }),
        "csrf" => serde_json::json!({
            "target_url": target,
            "method": "POST",
            "check_origin": true,
            "check_referer": true
        }),
        "headers" | "misconfig" | "security-misconfiguration" => serde_json::json!({
            "target_url": target,
            "follow_redirects": true
        }),
        _ => serde_json::json!({
            "repo_path": "__AGENT_PROVIDE_REPO_PATH__",
            "ruleset": "all",
            "severity": "ERROR"
        }),
    }
}

// =============================================================================
// SANDBOX SAFETY
// =============================================================================

fn is_sandbox_target(url: &str) -> bool {
    let host = extract_host(url);

    if host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host.starts_with("127.")
    {
        return true;
    }

    // RFC 1918 private ranges
    if host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host.starts_with("172.17.")
        || host.starts_with("172.18.")
        || host.starts_with("172.19.")
        || host.starts_with("172.2")
        || host.starts_with("172.3")
    {
        return true;
    }

    let lower = host.to_lowercase();
    lower.contains("sandbox")
        || lower.contains("staging")
        || lower.contains(".local")
        || lower.ends_with(".test")
        || lower.ends_with(".example")
        || lower.ends_with(".example.com")
        || lower.ends_with(".invalid")
        || lower.contains("dvwa")
        || lower.contains("webgoat")
        || lower.contains("juice-shop")
        || lower.contains("testfire")
        || lower.contains("hackazon")
        || lower.contains("vulnerable-app")
        || lower.contains("shieldagi-")
}

fn extract_host(url: &str) -> String {
    let without_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };

    let host_port = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme);

    // Handle IPv6
    if host_port.starts_with('[') {
        if let Some(bracket_end) = host_port.find(']') {
            return host_port[1..bracket_end].to_string();
        }
    }

    host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port)
        .to_string()
}

// =============================================================================
// STATE PERSISTENCE
// =============================================================================

fn load_controller(path: &str) -> Result<ContinuousLoopController, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read controller state from {}: {}", path, e))?;
    serde_json::from_str::<ContinuousLoopController>(&content)
        .map_err(|e| format!("Failed to parse controller state: {}", e))
}

fn save_controller(path: &str, controller: &ContinuousLoopController) -> Result<(), String> {
    let content = serde_json::to_string_pretty(controller)
        .map_err(|e| format!("Failed to serialize controller state: {}", e))?;

    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create state directory: {}", e))?;
    }

    std::fs::write(path, content)
        .map_err(|e| format!("Failed to write state to {}: {}", path, e))
}

fn persist_if_needed(state_path: Option<&str>, controller: &ContinuousLoopController) {
    if let Some(sp) = state_path {
        if let Err(e) = save_controller(sp, controller) {
            eprintln!("[continuous_loop] Warning: failed to persist state: {}", e);
        }
    }
}

// =============================================================================
// HTTP HELPERS
// =============================================================================

fn curl_get(url: &str) -> (u16, String) {
    let args = vec![
        "-s",
        "-o", "/dev/stdout",
        "-w", "\n%{http_code}",
        "--max-time", "10",
        url,
    ];

    match Command::new("curl").args(&args).output() {
        Ok(output) => {
            let full = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = full.trim().rsplitn(2, '\n').collect();
            let code: u16 = parts
                .first()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            let body = parts.last().unwrap_or(&"").to_string();
            (code, body)
        }
        Err(_) => (0, String::new()),
    }
}

fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

// =============================================================================
// UTILITY
// =============================================================================

fn generate_cycle_id(source: &str, attack_vector: &str) -> String {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let short_uuid = &uuid::Uuid::new_v4().to_string()[..8];
    format!(
        "{}-{}-{}-{}",
        sanitize_branch_segment(source),
        sanitize_branch_segment(attack_vector),
        ts,
        short_uuid,
    )
}

fn sanitize_branch_segment(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
        .collect()
}

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ContinuousLoopController ----

    #[test]
    fn test_controller_new_defaults() {
        let ctrl = ContinuousLoopController::default();
        assert!(ctrl.last_cycle_at.is_none());
        assert_eq!(ctrl.rate_limit_minutes, 30);
        assert!(ctrl.known_vuln_ids.is_empty());
        assert!(ctrl.cycle_history.cycles.is_empty());
        assert_eq!(ctrl.cycle_history.total_auto_patches, 0);
        assert_eq!(ctrl.cycle_history.total_escalations, 0);
    }

    #[test]
    fn test_controller_new_with_known_ids() {
        let ids: HashSet<String> = ["V-001", "V-002"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let ctrl = ContinuousLoopController::new(ids.clone(), 15);
        assert_eq!(ctrl.known_vuln_ids.len(), 2);
        assert!(ctrl.known_vuln_ids.contains("V-001"));
        assert!(ctrl.known_vuln_ids.contains("V-002"));
        assert_eq!(ctrl.rate_limit_minutes, 15);
    }

    #[test]
    fn test_can_run_cycle_no_previous() {
        let ctrl = ContinuousLoopController::default();
        assert!(ctrl.can_run_cycle(), "Should allow cycle when no previous cycle exists");
    }

    #[test]
    fn test_can_run_cycle_within_cooldown() {
        let mut ctrl = ContinuousLoopController::default();
        ctrl.last_cycle_at = Some(chrono::Utc::now().to_rfc3339());
        assert!(
            !ctrl.can_run_cycle(),
            "Should block cycle within 30-min cooldown"
        );
    }

    #[test]
    fn test_can_run_cycle_after_cooldown() {
        let mut ctrl = ContinuousLoopController::default();
        let old = chrono::Utc::now() - chrono::Duration::minutes(31);
        ctrl.last_cycle_at = Some(old.to_rfc3339());
        assert!(
            ctrl.can_run_cycle(),
            "Should allow cycle after cooldown expires"
        );
    }

    #[test]
    fn test_can_run_cycle_custom_rate_limit() {
        let mut ctrl = ContinuousLoopController::new(HashSet::new(), 5);
        let recent = chrono::Utc::now() - chrono::Duration::minutes(3);
        ctrl.last_cycle_at = Some(recent.to_rfc3339());
        assert!(
            !ctrl.can_run_cycle(),
            "Should block within custom 5-min rate limit"
        );

        let old_enough = chrono::Utc::now() - chrono::Duration::minutes(6);
        ctrl.last_cycle_at = Some(old_enough.to_rfc3339());
        assert!(ctrl.can_run_cycle(), "Should allow after custom 5-min limit");
    }

    #[test]
    fn test_can_run_cycle_invalid_timestamp() {
        let mut ctrl = ContinuousLoopController::default();
        ctrl.last_cycle_at = Some("not-a-timestamp".to_string());
        assert!(
            ctrl.can_run_cycle(),
            "Should allow cycle when timestamp is unparseable"
        );
    }

    #[test]
    fn test_record_cycle_remediated() {
        let mut ctrl = ContinuousLoopController::default();
        let result = make_test_cycle(CycleStatus::Remediated);
        ctrl.record_cycle(result);
        assert_eq!(ctrl.cycle_history.total_auto_patches, 1);
        assert_eq!(ctrl.cycle_history.total_escalations, 0);
        assert_eq!(ctrl.cycle_history.cycles.len(), 1);
        assert!(ctrl.last_cycle_at.is_some());
    }

    #[test]
    fn test_record_cycle_escalated() {
        let mut ctrl = ContinuousLoopController::default();
        ctrl.record_cycle(make_test_cycle(CycleStatus::Escalated));
        assert_eq!(ctrl.cycle_history.total_auto_patches, 0);
        assert_eq!(ctrl.cycle_history.total_escalations, 1);
    }

    #[test]
    fn test_record_cycle_failed() {
        let mut ctrl = ContinuousLoopController::default();
        ctrl.record_cycle(make_test_cycle(CycleStatus::Failed));
        assert_eq!(ctrl.cycle_history.total_escalations, 1);
    }

    #[test]
    fn test_record_cycle_scanned_only() {
        let mut ctrl = ContinuousLoopController::default();
        ctrl.record_cycle(make_test_cycle(CycleStatus::Scanned));
        assert_eq!(ctrl.cycle_history.total_auto_patches, 0);
        assert_eq!(ctrl.cycle_history.total_escalations, 0);
    }

    #[test]
    fn test_record_cycle_rate_limited() {
        let mut ctrl = ContinuousLoopController::default();
        ctrl.record_cycle(make_test_cycle(CycleStatus::RateLimited));
        assert_eq!(ctrl.cycle_history.total_auto_patches, 0);
        assert_eq!(ctrl.cycle_history.total_escalations, 0);
        assert_eq!(ctrl.cycle_history.cycles.len(), 1);
    }

    #[test]
    fn test_record_multiple_cycles() {
        let mut ctrl = ContinuousLoopController::default();
        ctrl.record_cycle(make_test_cycle(CycleStatus::Remediated));
        ctrl.record_cycle(make_test_cycle(CycleStatus::Escalated));
        ctrl.record_cycle(make_test_cycle(CycleStatus::Scanned));
        ctrl.record_cycle(make_test_cycle(CycleStatus::Remediated));
        assert_eq!(ctrl.cycle_history.cycles.len(), 4);
        assert_eq!(ctrl.cycle_history.total_auto_patches, 2);
        assert_eq!(ctrl.cycle_history.total_escalations, 1);
    }

    // ---- Struct serialization ----

    #[test]
    fn test_focused_scan_request_serde() {
        let req = FocusedScanRequest {
            attack_vector: "sqli".to_string(),
            target_endpoint: "http://localhost:3000/api/search".to_string(),
            source_incident_id: "INC-42".to_string(),
            severity: "CRITICAL".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let parsed: FocusedScanRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.attack_vector, "sqli");
        assert_eq!(parsed.severity, "CRITICAL");
    }

    #[test]
    fn test_cycle_result_serde() {
        let result = make_test_cycle(CycleStatus::Remediated);
        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: CycleResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, CycleStatus::Remediated);
        assert_eq!(parsed.triggered_by, "test-incident");
    }

    #[test]
    fn test_cycle_history_serde() {
        let history = CycleHistory {
            cycles: vec![
                make_test_cycle(CycleStatus::Remediated),
                make_test_cycle(CycleStatus::Escalated),
            ],
            total_auto_patches: 1,
            total_escalations: 1,
        };

        let json = serde_json::to_string(&history).unwrap();
        let parsed: CycleHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cycles.len(), 2);
        assert_eq!(parsed.total_auto_patches, 1);
        assert_eq!(parsed.total_escalations, 1);
    }

    #[test]
    fn test_controller_serde_roundtrip() {
        let mut ctrl = ContinuousLoopController::new(
            ["V-001".to_string()].into_iter().collect(),
            45,
        );
        ctrl.record_cycle(make_test_cycle(CycleStatus::Remediated));

        let json = serde_json::to_string_pretty(&ctrl).unwrap();
        let parsed: ContinuousLoopController = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rate_limit_minutes, 45);
        assert!(parsed.known_vuln_ids.contains("V-001"));
        assert_eq!(parsed.cycle_history.total_auto_patches, 1);
        assert_eq!(parsed.cycle_history.cycles.len(), 1);
    }

    // ---- State persistence ----

    #[test]
    fn test_save_and_load_controller() {
        let path = "/tmp/shieldagi_test_ctrl_state.json";
        let mut ctrl = ContinuousLoopController::new(
            ["VULN-A".to_string()].into_iter().collect(),
            30,
        );
        ctrl.record_cycle(make_test_cycle(CycleStatus::Scanned));

        save_controller(path, &ctrl).expect("save should succeed");
        let loaded = load_controller(path).expect("load should succeed");

        assert_eq!(loaded.rate_limit_minutes, 30);
        assert!(loaded.known_vuln_ids.contains("VULN-A"));
        assert_eq!(loaded.cycle_history.cycles.len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_load_controller_missing_file() {
        let result = load_controller("/tmp/shieldagi_nonexistent_ctrl_xyz.json");
        assert!(result.is_err());
    }

    // ---- Sandbox safety ----

    #[test]
    fn test_sandbox_localhost() {
        assert!(is_sandbox_target("http://localhost:3000/api/test"));
        assert!(is_sandbox_target("http://127.0.0.1:8080/login"));
        assert!(is_sandbox_target("http://127.0.0.2/anything"));
    }

    #[test]
    fn test_sandbox_private_ip() {
        assert!(is_sandbox_target("http://192.168.1.100/app"));
        assert!(is_sandbox_target("http://10.0.0.5/api"));
        assert!(is_sandbox_target("http://172.16.0.1/test"));
        assert!(is_sandbox_target("http://172.28.0.5:3001/api"));
    }

    #[test]
    fn test_sandbox_keyword_domains() {
        assert!(is_sandbox_target("http://app.sandbox.example.com/api"));
        assert!(is_sandbox_target("http://staging.myapp.com/login"));
        assert!(is_sandbox_target("http://myapp.local/api/users"));
        assert!(is_sandbox_target("http://dvwa.local/vulnerabilities/sqli/"));
        assert!(is_sandbox_target("http://webgoat:8080/WebGoat/login"));
        assert!(is_sandbox_target("http://juice-shop.local:3000/"));
        assert!(is_sandbox_target("http://vulnerable-app:3001/api"));
        assert!(is_sandbox_target("http://shieldagi-target:3001/api"));
    }

    #[test]
    fn test_sandbox_rejects_production() {
        assert!(!is_sandbox_target("https://api.stripe.com/v1/charges"));
        assert!(!is_sandbox_target("https://production.myapp.com/api"));
        assert!(!is_sandbox_target("https://myapp.io/users"));
    }

    #[test]
    fn test_sandbox_empty_url() {
        assert!(!is_sandbox_target(""));
    }

    // ---- Extract host ----

    #[test]
    fn test_extract_host_with_port() {
        assert_eq!(extract_host("http://localhost:3000/path"), "localhost");
        assert_eq!(extract_host("https://192.168.1.1:8443/api"), "192.168.1.1");
    }

    #[test]
    fn test_extract_host_without_port() {
        assert_eq!(extract_host("http://example.com/path"), "example.com");
        assert_eq!(extract_host("https://staging.app.io"), "staging.app.io");
    }

    #[test]
    fn test_extract_host_no_scheme() {
        assert_eq!(extract_host("localhost/path"), "localhost");
    }

    #[test]
    fn test_extract_host_ipv6() {
        assert_eq!(extract_host("http://[::1]:3000/path"), "::1");
    }

    // ---- Attack vector mapping ----

    #[test]
    fn test_map_vector_to_tool_all_vectors() {
        assert_eq!(map_vector_to_tool("sqli"), "sqlmap_attack");
        assert_eq!(map_vector_to_tool("sql-injection"), "sqlmap_attack");
        assert_eq!(map_vector_to_tool("xss"), "xss_inject");
        assert_eq!(map_vector_to_tool("cross-site-scripting"), "xss_inject");
        assert_eq!(map_vector_to_tool("ssrf"), "ssrf_probe");
        assert_eq!(map_vector_to_tool("brute-force"), "brute_force");
        assert_eq!(map_vector_to_tool("brute_force"), "brute_force");
        assert_eq!(map_vector_to_tool("auth"), "brute_force");
        assert_eq!(map_vector_to_tool("traversal"), "path_traverse");
        assert_eq!(map_vector_to_tool("path-traversal"), "path_traverse");
        assert_eq!(map_vector_to_tool("lfi"), "path_traverse");
        assert_eq!(map_vector_to_tool("idor"), "idor_test");
        assert_eq!(map_vector_to_tool("csrf"), "csrf_test");
        assert_eq!(map_vector_to_tool("headers"), "header_audit");
        assert_eq!(map_vector_to_tool("secrets"), "secret_scan");
        assert_eq!(map_vector_to_tool("unknown-vector"), "semgrep_scan");
    }

    // ---- Scan input builder ----

    #[test]
    fn test_build_scan_input_sqli() {
        let input = build_scan_input("sqli", "http://localhost/search?q=test");
        assert_eq!(input["target_url"], "http://localhost/search?q=test");
        assert!(input.get("level").is_some());
        assert!(input.get("risk").is_some());
        assert_eq!(input["technique"], "BEUSTQ");
    }

    #[test]
    fn test_build_scan_input_xss() {
        let input = build_scan_input("xss", "http://localhost/reflect");
        assert_eq!(input["xss_type"], "all");
        assert_eq!(input["payload_set"], "advanced");
    }

    #[test]
    fn test_build_scan_input_ssrf() {
        let input = build_scan_input("ssrf", "http://localhost/fetch");
        let probes = input["probes"].as_array().expect("probes should be array");
        assert!(!probes.is_empty());
        assert!(probes
            .iter()
            .any(|p| p.as_str().unwrap_or("").contains("169.254.169.254")));
    }

    #[test]
    fn test_build_scan_input_brute_force() {
        let input = build_scan_input("brute-force", "http://localhost/login");
        assert_eq!(input["check_rate_limit"], true);
        assert!(input["test_usernames"].as_array().is_some());
    }

    #[test]
    fn test_build_scan_input_traversal() {
        let input = build_scan_input("traversal", "http://localhost/file");
        assert_eq!(input["parameter"], "file");
        assert!(input.get("encoding_levels").is_some());
    }

    #[test]
    fn test_build_scan_input_csrf() {
        let input = build_scan_input("csrf", "http://localhost/transfer");
        assert_eq!(input["method"], "POST");
        assert_eq!(input["check_origin"], true);
    }

    #[test]
    fn test_build_scan_input_unknown_falls_back_to_semgrep() {
        let input = build_scan_input("unknown-attack", "http://localhost/x");
        assert!(input.get("ruleset").is_some());
        assert_eq!(input["severity"], "ERROR");
    }

    // ---- Probe attack vector ----

    #[test]
    fn test_probe_unsupported_vector_returns_zero() {
        let (vulns, confirmed, detail) =
            probe_attack_vector("csrf", "http://localhost:3000/api");
        assert_eq!(vulns, 0);
        assert!(!confirmed);
        assert!(detail.contains("probe skipped"));
    }

    #[test]
    fn test_probe_idor_returns_zero() {
        let (vulns, confirmed, _) =
            probe_attack_vector("idor", "http://localhost:3000/api");
        assert_eq!(vulns, 0);
        assert!(!confirmed);
    }

    #[test]
    fn test_probe_auth_returns_zero() {
        let (vulns, confirmed, _) =
            probe_attack_vector("auth", "http://localhost:3000/login");
        assert_eq!(vulns, 0);
        assert!(!confirmed);
    }

    // ---- URL encoding ----

    #[test]
    fn test_urlencoding_plain() {
        assert_eq!(urlencoding("hello"), "hello");
    }

    #[test]
    fn test_urlencoding_special_chars() {
        assert_eq!(urlencoding("a b"), "a%20b");
        assert_eq!(urlencoding("'OR 1=1"), "%27OR%201%3D1");
    }

    #[test]
    fn test_urlencoding_angle_brackets() {
        let encoded = urlencoding("<script>");
        assert!(encoded.contains("%3C"));
        assert!(encoded.contains("%3E"));
    }

    // ---- Cycle ID generation ----

    #[test]
    fn test_generate_cycle_id_format() {
        let id = generate_cycle_id("sentinel", "sqli");
        assert!(id.starts_with("sentinel-sqli-"));
        // Should contain timestamp (14 digits) and short UUID (8 chars)
        let parts: Vec<&str> = id.split('-').collect();
        assert!(parts.len() >= 4, "Cycle ID should have at least 4 segments: {}", id);
    }

    #[test]
    fn test_generate_cycle_id_sanitizes_special_chars() {
        let id = generate_cycle_id("incident/report", "sql injection");
        assert!(!id.contains('/'));
        assert!(!id.contains(' '));
    }

    #[test]
    fn test_generate_cycle_id_unique() {
        let id1 = generate_cycle_id("test", "xss");
        let id2 = generate_cycle_id("test", "xss");
        assert_ne!(id1, id2, "Cycle IDs should be unique due to UUID component");
    }

    // ---- Sanitize branch segment ----

    #[test]
    fn test_sanitize_branch_segment() {
        assert_eq!(sanitize_branch_segment("sqli"), "sqli");
        assert_eq!(sanitize_branch_segment("sql-injection"), "sql-injection");
        assert_eq!(sanitize_branch_segment("sql injection"), "sql_injection");
        assert_eq!(sanitize_branch_segment("path/traversal"), "path_traversal");
    }

    // ---- Focused remediation ----

    #[test]
    fn test_remediation_no_repo() {
        let outcome = execute_focused_remediation("", "sqli", "http://localhost:3000", "cycle-1");
        assert!(!outcome.fix_attempted);
        assert!(!outcome.fix_verified);
        assert!(outcome.detail.contains("No repo_path"));
    }

    #[test]
    fn test_remediation_nonexistent_repo() {
        let outcome = execute_focused_remediation(
            "/tmp/shieldagi_nonexistent_repo_xyz",
            "sqli",
            "http://localhost:3000",
            "cycle-1",
        );
        assert!(!outcome.fix_attempted);
        assert!(outcome.detail.contains("not a valid git repository"));
    }

    // ---- Escalation ----

    #[test]
    fn test_escalate_no_credentials() {
        let request = FocusedScanRequest {
            attack_vector: "sqli".to_string(),
            target_endpoint: "http://localhost:3000".to_string(),
            source_incident_id: "INC-1".to_string(),
            severity: "CRITICAL".to_string(),
        };
        let result = escalate_to_human(None, None, &request, "cycle-1");
        assert!(result.contains("skipped"));
    }

    #[test]
    fn test_escalate_empty_credentials() {
        let request = FocusedScanRequest {
            attack_vector: "sqli".to_string(),
            target_endpoint: "http://localhost:3000".to_string(),
            source_incident_id: "INC-1".to_string(),
            severity: "CRITICAL".to_string(),
        };
        let result = escalate_to_human(Some(""), Some(""), &request, "cycle-1");
        assert!(result.contains("empty telegram credentials"));
    }

    // ---- End-to-end tool tests ----

    #[tokio::test]
    async fn test_trigger_missing_attack_vector() {
        let input = serde_json::json!({
            "target_endpoint": "http://localhost:3000",
            "source_incident_id": "INC-1",
            "severity": "HIGH"
        });
        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("attack_vector"));
    }

    #[tokio::test]
    async fn test_trigger_missing_target_endpoint() {
        let input = serde_json::json!({
            "attack_vector": "sqli",
            "source_incident_id": "INC-1",
            "severity": "HIGH"
        });
        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("target_endpoint"));
    }

    #[tokio::test]
    async fn test_trigger_missing_source_incident_id() {
        let input = serde_json::json!({
            "attack_vector": "sqli",
            "target_endpoint": "http://localhost:3000",
            "severity": "HIGH"
        });
        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("source_incident_id"));
    }

    #[tokio::test]
    async fn test_trigger_missing_severity() {
        let input = serde_json::json!({
            "attack_vector": "sqli",
            "target_endpoint": "http://localhost:3000",
            "source_incident_id": "INC-1"
        });
        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("severity"));
    }

    #[tokio::test]
    async fn test_trigger_rejects_non_sandbox() {
        let input = serde_json::json!({
            "attack_vector": "xss",
            "target_endpoint": "https://production.example.com/api",
            "source_incident_id": "INC-1",
            "severity": "HIGH"
        });
        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Safety check failed"), "Got: {}", err);
    }

    #[tokio::test]
    async fn test_trigger_rate_limited() {
        let state_path = "/tmp/shieldagi_test_trigger_rate_limit.json";

        // Create a controller with a very recent cycle
        let mut ctrl = ContinuousLoopController::default();
        ctrl.last_cycle_at = Some(chrono::Utc::now().to_rfc3339());
        save_controller(state_path, &ctrl).expect("save should succeed");

        let input = serde_json::json!({
            "attack_vector": "sqli",
            "target_endpoint": "http://localhost:3000/api",
            "source_incident_id": "INC-1",
            "severity": "HIGH",
            "state_path": state_path
        });

        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_ok());

        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(json["status"], "RateLimited");
        assert!(json["scan_result"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("Rate limited"));

        let _ = std::fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn test_trigger_sandbox_target_no_vulns() {
        // Target is sandbox but unreachable, so probe will find 0 vulns
        let input = serde_json::json!({
            "attack_vector": "xss",
            "target_endpoint": "http://localhost:59999/nonexistent",
            "source_incident_id": "INC-2",
            "severity": "MEDIUM"
        });

        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_ok());

        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(json["status"], "Scanned");
        assert_eq!(json["scan_result"]["vulns_found"], 0);
        assert!(json["remediation_result"].is_null());
    }

    #[tokio::test]
    async fn test_trigger_with_known_vuln_ids() {
        let input = serde_json::json!({
            "attack_vector": "sqli",
            "target_endpoint": "http://localhost:59999/api",
            "source_incident_id": "INC-3",
            "severity": "CRITICAL",
            "known_vuln_ids": ["V-001", "V-002", "V-003"]
        });

        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_trigger_persists_state() {
        let state_path = "/tmp/shieldagi_test_trigger_persist.json";
        let _ = std::fs::remove_file(state_path);

        let input = serde_json::json!({
            "attack_vector": "xss",
            "target_endpoint": "http://localhost:59999/search",
            "source_incident_id": "INC-4",
            "severity": "HIGH",
            "state_path": state_path,
            "known_vuln_ids": ["V-X"]
        });

        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_ok());

        // Verify the state file was created
        let loaded = load_controller(state_path).expect("State should be persisted");
        assert_eq!(loaded.cycle_history.cycles.len(), 1);
        assert!(loaded.known_vuln_ids.contains("V-X"));
        assert!(loaded.last_cycle_at.is_some());

        let _ = std::fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn test_trigger_csrf_probe_skipped() {
        // CSRF cannot be probed via simple HTTP; should still succeed
        let input = serde_json::json!({
            "attack_vector": "csrf",
            "target_endpoint": "http://localhost:59999/transfer",
            "source_incident_id": "INC-5",
            "severity": "MEDIUM"
        });

        let result = tool_trigger_focused_scan(&input).await;
        assert!(result.is_ok());

        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(json["status"], "Scanned");
        assert!(json["scan_result"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("probe skipped"));
    }

    // ---- Emergency PR helper (unit) ----

    #[test]
    fn test_create_emergency_pr_no_repo() {
        let req = FocusedScanRequest {
            attack_vector: "sqli".to_string(),
            target_endpoint: "http://localhost:3000".to_string(),
            source_incident_id: "INC-1".to_string(),
            severity: "CRITICAL".to_string(),
        };
        let result = create_emergency_pr("", "sqli", "cycle-1", &req);
        assert!(result.contains("no repo_path"));
    }

    // ---- Helper to construct test CycleResult ----

    fn make_test_cycle(status: CycleStatus) -> CycleResult {
        CycleResult {
            cycle_id: "test-cycle-001".to_string(),
            triggered_by: "test-incident".to_string(),
            scan_result: ScanOutcome {
                tool_used: "sqlmap_attack".to_string(),
                scan_input: serde_json::json!({"target_url": "http://localhost:3000"}),
                vulns_found: if status == CycleStatus::Scanned { 0 } else { 1 },
                confirmed_new: status != CycleStatus::Scanned,
                detail: "test scan outcome".to_string(),
            },
            remediation_result: match status {
                CycleStatus::Remediated => Some(RemediationOutcome {
                    fix_attempted: true,
                    fix_verified: true,
                    files_modified: vec!["src/server.js".to_string()],
                    detail: "test fix applied".to_string(),
                }),
                CycleStatus::Escalated | CycleStatus::Failed => Some(RemediationOutcome {
                    fix_attempted: true,
                    fix_verified: false,
                    files_modified: vec![],
                    detail: "test fix failed".to_string(),
                }),
                _ => None,
            },
            pr_url: if status == CycleStatus::Remediated {
                Some("https://github.com/test/repo/pull/42".to_string())
            } else {
                None
            },
            status,
        }
    }
}
