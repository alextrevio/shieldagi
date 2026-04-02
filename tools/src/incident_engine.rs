/// ShieldAGI Tool: incident_engine
///
/// Automated incident response engine. Receives a single threat event, verifies
/// it is not a false positive, classifies the attack type, executes containment
/// actions, generates a forensic snapshot, checks for novel vulnerabilities, and
/// produces an IncidentReport suitable for Telegram alerting.
/// Part of ShieldAGI Phase D (24/7 Monitoring).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

// ═══════════════════════════════════════════════
// CORE TYPES
// ═══════════════════════════════════════════════

/// A single threat event received from the Sentinel runtime or log analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub threat_type: String,
    pub source_ip: String,
    pub target_endpoint: String,
    pub severity: String,
    pub matched_pattern: String,
    pub raw_log_entry: String,
    pub correlation_id: Option<String>,
    pub report_context: Option<ReportContext>,
}

/// Optional context from a prior vulnerability report, used to detect novel vulns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportContext {
    pub known_vulnerability_ids: Vec<String>,
}

/// Result of the incident response pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentResponse {
    pub incident_id: String,
    pub severity: String,
    /// "contained" | "mitigated" | "resolved"
    pub status: String,
    pub attack_type: String,
    pub actions_taken: Vec<String>,
    pub forensic_data: ForensicData,
    pub requires_human: bool,
    pub novel_vulnerability_detected: bool,
    pub mini_rescan_triggered: bool,
    pub telegram_message: String,
    pub scan_duration_ms: u64,
}

/// Forensic snapshot collected during incident response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicData {
    pub attacker_ip: String,
    pub all_logs_from_ip: Vec<String>,
    pub queries_executed: Vec<String>,
    pub response_times: Vec<f64>,
    pub timeline: Vec<TimelineEntry>,
    pub ip_history: IpHistory,
    pub correlated_events: Vec<String>,
}

/// Timeline entry for forensic record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub event: String,
}

/// Historical data about an IP address for false-positive verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpHistory {
    pub ip: String,
    pub previous_incidents: usize,
    pub first_seen: String,
    pub last_seen: String,
    pub total_requests: usize,
    pub threat_score: f64,
}

/// Containment action applied during incident response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentAction {
    pub action_type: String,
    pub target: String,
    pub executed: bool,
    pub result: String,
}

// ═══════════════════════════════════════════════
// INCIDENT ENGINE
// ═══════════════════════════════════════════════

/// The core incident response engine. Maintains state across invocations:
/// active incidents, containment actions taken, and forensic logs.
pub struct IncidentEngine {
    pub active_incidents: Mutex<HashMap<String, IncidentResponse>>,
    pub containment_actions: Mutex<Vec<ContainmentAction>>,
    pub forensic_logs: Mutex<Vec<String>>,
    ip_history_cache: Mutex<HashMap<String, IpHistory>>,
}

impl IncidentEngine {
    /// Create a new IncidentEngine with empty state.
    pub fn new() -> Self {
        Self {
            active_incidents: Mutex::new(HashMap::new()),
            containment_actions: Mutex::new(Vec::new()),
            forensic_logs: Mutex::new(Vec::new()),
            ip_history_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Primary entry point: respond to a single threat event.
    pub fn respond_to_threat(&self, threat: ThreatEvent) -> IncidentResponse {
        let start = std::time::Instant::now();
        let incident_id = generate_incident_id();
        let now = chrono::Utc::now().to_rfc3339();

        let mut timeline = vec![TimelineEntry {
            timestamp: now.clone(),
            event: format!("Incident {} created for threat from {}", incident_id, threat.source_ip),
        }];

        // ── 1. Verify not a false positive ───────────────────────────────────
        let ip_history = self.get_or_create_ip_history(&threat.source_ip);
        let is_false_positive = self.check_false_positive(&threat, &ip_history);

        timeline.push(TimelineEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event: if is_false_positive {
                format!("False positive check: LIKELY FALSE POSITIVE (threat_score={:.2})", ip_history.threat_score)
            } else {
                format!("False positive check: CONFIRMED THREAT (threat_score={:.2})", ip_history.threat_score)
            },
        });

        if is_false_positive {
            let forensic_data = ForensicData {
                attacker_ip: threat.source_ip.clone(),
                all_logs_from_ip: vec![threat.raw_log_entry.clone()],
                queries_executed: Vec::new(),
                response_times: Vec::new(),
                timeline: timeline.clone(),
                ip_history: ip_history.clone(),
                correlated_events: Vec::new(),
            };

            let response = IncidentResponse {
                incident_id: incident_id.clone(),
                severity: "LOW".to_string(),
                status: "resolved".to_string(),
                attack_type: threat.threat_type.clone(),
                actions_taken: vec!["Verified as false positive — no containment needed".to_string()],
                forensic_data,
                requires_human: false,
                novel_vulnerability_detected: false,
                mini_rescan_triggered: false,
                telegram_message: format_telegram_message_fp(&incident_id, &threat),
                scan_duration_ms: start.elapsed().as_millis() as u64,
            };

            if let Ok(mut incidents) = self.active_incidents.lock() {
                incidents.insert(incident_id.clone(), response.clone());
            }
            return response;
        }

        // ── 2. Classify attack type ──────────────────────────────────────────
        let attack_type = classify_attack_type(&threat.threat_type);

        timeline.push(TimelineEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event: format!("Attack classified as: {}", attack_type),
        });

        // ── 3. Execute containment by type ───────────────────────────────────
        let (containment_actions, actions_taken) =
            self.execute_containment(&attack_type, &threat.source_ip, &threat.target_endpoint);

        for action in &containment_actions {
            timeline.push(TimelineEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                event: format!(
                    "Containment '{}' on '{}': {}",
                    action.action_type, action.target, action.result
                ),
            });
        }

        // Store containment actions
        if let Ok(mut stored_actions) = self.containment_actions.lock() {
            stored_actions.extend(containment_actions.iter().cloned());
        }

        // ── 4. Generate forensic snapshot ────────────────────────────────────
        let forensic_data = self.build_forensic_snapshot(&threat, &ip_history, &timeline);

        // Store forensic log
        if let Ok(mut logs) = self.forensic_logs.lock() {
            logs.push(format!(
                "[{}] Incident {} — {} from {} against {}",
                now, incident_id, attack_type, threat.source_ip, threat.target_endpoint
            ));
        }

        // ── 5. Check for novel vulnerability ─────────────────────────────────
        let novel_vulnerability_detected =
            check_novel_vulnerability(&threat, &attack_type);
        let mini_rescan_triggered = novel_vulnerability_detected;

        if novel_vulnerability_detected {
            timeline.push(TimelineEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                event: "Novel vulnerability detected — triggering mini Phase 1->2 rescan".to_string(),
            });
        }

        // ── 6. Determine severity and status ─────────────────────────────────
        let severity = determine_severity(&threat.severity, &attack_type, novel_vulnerability_detected);
        let requires_human = determine_requires_human(&severity, &attack_type, novel_vulnerability_detected);
        let status = determine_status(&containment_actions, requires_human);

        timeline.push(TimelineEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event: format!("Incident status: {} | severity: {} | requires_human: {}", status, severity, requires_human),
        });

        // ── 7. Generate Telegram message ─────────────────────────────────────
        let telegram_message = format_telegram_message(
            &incident_id,
            &severity,
            &attack_type,
            &threat,
            &actions_taken,
            requires_human,
            novel_vulnerability_detected,
        );

        let scan_duration_ms = start.elapsed().as_millis() as u64;

        let response = IncidentResponse {
            incident_id: incident_id.clone(),
            severity,
            status,
            attack_type,
            actions_taken,
            forensic_data,
            requires_human,
            novel_vulnerability_detected,
            mini_rescan_triggered,
            telegram_message,
            scan_duration_ms,
        };

        // Store in active incidents
        if let Ok(mut incidents) = self.active_incidents.lock() {
            incidents.insert(incident_id.clone(), response.clone());
        }

        // Update IP history with new incident
        self.record_incident_for_ip(&threat.source_ip);

        response
    }

    /// Check IP history and correlate with other events to detect false positives.
    fn check_false_positive(&self, threat: &ThreatEvent, ip_history: &IpHistory) -> bool {
        // If the IP has been seen in previous incidents, it is not a false positive
        if ip_history.previous_incidents > 0 {
            return false;
        }

        // High or critical severity threats are never considered false positives
        let sev = threat.severity.to_uppercase();
        if sev == "CRITICAL" || sev == "HIGH" {
            return false;
        }

        // Very low threat score with no history: could be false positive
        if ip_history.threat_score < 0.2 && ip_history.total_requests < 3 {
            return true;
        }

        // Known scanner patterns are never false positives
        let pattern_lower = threat.matched_pattern.to_lowercase();
        let definite_attack_patterns = [
            "union select", "or 1=1", "<script", "onerror=", "javascript:",
            "../../../", "169.254.169.254", "/etc/passwd", "cmd=", "exec(",
        ];
        for p in &definite_attack_patterns {
            if pattern_lower.contains(p) {
                return false;
            }
        }

        // Single low-severity event with short matched pattern: possibly false positive
        if sev == "LOW" && threat.matched_pattern.len() < 10 {
            return true;
        }

        false
    }

    /// Get or create IP history for false-positive checking.
    fn get_or_create_ip_history(&self, ip: &str) -> IpHistory {
        let mut cache = self.ip_history_cache.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(history) = cache.get(ip) {
            return history.clone();
        }

        let now = chrono::Utc::now().to_rfc3339();
        let history = IpHistory {
            ip: ip.to_string(),
            previous_incidents: 0,
            first_seen: now.clone(),
            last_seen: now,
            total_requests: 1,
            threat_score: 0.5,
        };
        cache.insert(ip.to_string(), history.clone());
        history
    }

    /// Record that an incident was confirmed for this IP, raising its threat score.
    fn record_incident_for_ip(&self, ip: &str) {
        let mut cache = self.ip_history_cache.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(history) = cache.get_mut(ip) {
            history.previous_incidents += 1;
            history.total_requests += 1;
            history.last_seen = chrono::Utc::now().to_rfc3339();
            history.threat_score = (history.threat_score + 0.3).min(1.0);
        }
    }

    /// Execute containment actions based on attack type.
    fn execute_containment(
        &self,
        attack_type: &str,
        source_ip: &str,
        target_endpoint: &str,
    ) -> (Vec<ContainmentAction>, Vec<String>) {
        let mut actions: Vec<ContainmentAction> = Vec::new();
        let mut descriptions: Vec<String> = Vec::new();

        match attack_type {
            "sqli" | "xss" | "ssrf" => {
                // Block IP via iptables or WAF rule
                let (executed, result) = execute_iptables_block(source_ip);
                actions.push(ContainmentAction {
                    action_type: "block-ip".to_string(),
                    target: source_ip.to_string(),
                    executed,
                    result: result.clone(),
                });
                descriptions.push(format!("Block IP {} via iptables: {}", source_ip, result));

                // Add WAF rule
                let waf_rule = format!(
                    "Add WAF rule to block {} payloads from {} targeting {}",
                    attack_type, source_ip, target_endpoint
                );
                actions.push(ContainmentAction {
                    action_type: "waf-rule".to_string(),
                    target: target_endpoint.to_string(),
                    executed: false,
                    result: format!("Recommended: {}", waf_rule),
                });
                descriptions.push(waf_rule);
            }
            "brute-force" => {
                // Block /24 subnet
                let subnet = ip_to_slash24(source_ip);
                let (executed, result) = execute_iptables_block(&subnet);
                actions.push(ContainmentAction {
                    action_type: "block-subnet".to_string(),
                    target: subnet.clone(),
                    executed,
                    result: result.clone(),
                });
                descriptions.push(format!("Block subnet {} via iptables: {}", subnet, result));

                // Lock targeted accounts
                actions.push(ContainmentAction {
                    action_type: "account-lockout".to_string(),
                    target: format!("Accounts targeted via {}", target_endpoint),
                    executed: false,
                    result: "Recommended: Lock targeted accounts and force password reset".to_string(),
                });
                descriptions.push(format!(
                    "Recommended: Lock accounts targeted via {} and force password reset",
                    target_endpoint
                ));

                // Rate limit auth endpoints
                actions.push(ContainmentAction {
                    action_type: "rate-limit".to_string(),
                    target: target_endpoint.to_string(),
                    executed: false,
                    result: "Recommended: Enforce 5 req/min rate limit on authentication endpoints".to_string(),
                });
                descriptions.push("Recommended: Enforce 5 req/min rate limit on auth endpoints".to_string());
            }
            "ddos" => {
                // Activate aggressive rate limiting
                actions.push(ContainmentAction {
                    action_type: "aggressive-rate-limit".to_string(),
                    target: "All ingress traffic".to_string(),
                    executed: false,
                    result: "Recommended: Enable DDoS mitigation — nginx limit_req 10r/s, activate CDN shield mode".to_string(),
                });
                descriptions.push("Activate aggressive rate limiting: nginx 10r/s, CDN shield mode".to_string());

                // Notify upstream provider
                actions.push(ContainmentAction {
                    action_type: "notify-upstream".to_string(),
                    target: "CDN / DDoS protection provider".to_string(),
                    executed: false,
                    result: "Recommended: Contact CDN provider to enable volumetric DDoS scrubbing".to_string(),
                });
                descriptions.push("Recommended: Contact CDN provider for DDoS scrubbing".to_string());

                // Also block the known source IP
                let (executed, result) = execute_iptables_block(source_ip);
                actions.push(ContainmentAction {
                    action_type: "block-ip".to_string(),
                    target: source_ip.to_string(),
                    executed,
                    result: result.clone(),
                });
                descriptions.push(format!("Block IP {}: {}", source_ip, result));
            }
            "scanning" => {
                // Rate limit the IP
                let rate_limit_cmd = format!(
                    "iptables -I INPUT -s {} -m limit --limit 5/min -j ACCEPT && iptables -I INPUT -s {} -j DROP",
                    source_ip, source_ip
                );
                actions.push(ContainmentAction {
                    action_type: "rate-limit-ip".to_string(),
                    target: source_ip.to_string(),
                    executed: false,
                    result: format!("Recommended: {}", rate_limit_cmd),
                });
                descriptions.push(format!("Rate limit IP {} to 5 req/min", source_ip));

                // Log everything from this IP
                actions.push(ContainmentAction {
                    action_type: "enhanced-logging".to_string(),
                    target: source_ip.to_string(),
                    executed: false,
                    result: format!(
                        "Recommended: Enable verbose logging for all requests from {}",
                        source_ip
                    ),
                });
                descriptions.push(format!("Enable verbose logging for all requests from {}", source_ip));

                // Honeypot
                actions.push(ContainmentAction {
                    action_type: "honeypot-enable".to_string(),
                    target: "Common scanner paths".to_string(),
                    executed: false,
                    result: "Recommended: Enable honeypot endpoints (/.git, /admin, /wp-admin) to fingerprint scanners".to_string(),
                });
                descriptions.push("Enable honeypot endpoints to fingerprint and auto-block scanners".to_string());
            }
            _ => {
                // Unknown attack type — conservative: block IP and escalate
                let (executed, result) = execute_iptables_block(source_ip);
                actions.push(ContainmentAction {
                    action_type: "block-ip".to_string(),
                    target: source_ip.to_string(),
                    executed,
                    result: result.clone(),
                });
                descriptions.push(format!("Block IP {} (unknown attack type): {}", source_ip, result));
                descriptions.push("Escalating to human review — unknown attack type".to_string());
            }
        }

        (actions, descriptions)
    }

    /// Build a forensic snapshot for the incident.
    fn build_forensic_snapshot(
        &self,
        threat: &ThreatEvent,
        ip_history: &IpHistory,
        timeline: &[TimelineEntry],
    ) -> ForensicData {
        // Collect all logs from the attacker IP (from forensic_logs store)
        let all_logs_from_ip = if let Ok(logs) = self.forensic_logs.lock() {
            logs.iter()
                .filter(|log| log.contains(&threat.source_ip))
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

        // Include the current raw log entry
        let mut logs = all_logs_from_ip;
        logs.push(threat.raw_log_entry.clone());

        // Extract any SQL-like queries from the raw log
        let queries_executed = extract_queries(&threat.raw_log_entry, &threat.matched_pattern);

        // Estimate response times (from log entry if parseable)
        let response_times = extract_response_times(&threat.raw_log_entry);

        // Build correlated events
        let mut correlated_events = Vec::new();
        if let Some(ref corr_id) = threat.correlation_id {
            correlated_events.push(format!("Correlated via ID: {}", corr_id));
        }
        if ip_history.previous_incidents > 0 {
            correlated_events.push(format!(
                "IP {} has {} previous incidents (first seen: {})",
                threat.source_ip, ip_history.previous_incidents, ip_history.first_seen
            ));
        }

        ForensicData {
            attacker_ip: threat.source_ip.clone(),
            all_logs_from_ip: logs,
            queries_executed,
            response_times,
            timeline: timeline.to_vec(),
            ip_history: ip_history.clone(),
            correlated_events,
        }
    }
}

// ═══════════════════════════════════════════════
// TOOL ENTRY POINT
// ═══════════════════════════════════════════════

/// Respond to a threat event with automated incident handling.
///
/// # Input fields
/// - `threat_type`      — Attack type string (e.g. "sqli", "xss", "brute-force")
/// - `source_ip`        — Attacker IP address
/// - `target_endpoint`  — Targeted URL / path
/// - `severity`         — CRITICAL | HIGH | MEDIUM | LOW
/// - `matched_pattern`  — The pattern that triggered detection
/// - `raw_log_entry`    — Full raw log line
/// - `correlation_id`   — (optional) Correlation ID for event tracking
/// - `report_context`   — (optional) Object with `known_vulnerability_ids` array
pub async fn tool_respond_to_incident(input: &serde_json::Value) -> Result<String, String> {
    let threat_type = input["threat_type"]
        .as_str()
        .ok_or("Missing 'threat_type' field")?
        .to_string();
    let source_ip = input["source_ip"]
        .as_str()
        .ok_or("Missing 'source_ip' field")?
        .to_string();
    let target_endpoint = input["target_endpoint"]
        .as_str()
        .ok_or("Missing 'target_endpoint' field")?
        .to_string();
    let severity = input["severity"]
        .as_str()
        .ok_or("Missing 'severity' field")?
        .to_string();
    let matched_pattern = input["matched_pattern"]
        .as_str()
        .ok_or("Missing 'matched_pattern' field")?
        .to_string();
    let raw_log_entry = input["raw_log_entry"]
        .as_str()
        .ok_or("Missing 'raw_log_entry' field")?
        .to_string();
    let correlation_id = input["correlation_id"].as_str().map(String::from);

    let report_context = if input["report_context"].is_object() {
        let known_ids: Vec<String> = input["report_context"]["known_vulnerability_ids"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Some(ReportContext {
            known_vulnerability_ids: known_ids,
        })
    } else {
        None
    };

    let threat = ThreatEvent {
        threat_type,
        source_ip,
        target_endpoint,
        severity,
        matched_pattern,
        raw_log_entry,
        correlation_id,
        report_context,
    };

    let engine = IncidentEngine::new();
    let response = engine.respond_to_threat(threat);

    serde_json::to_string_pretty(&response).map_err(|e| format!("Serialization error: {}", e))
}

// ═══════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════

/// Generate a unique incident ID: SHIELD-INC-{timestamp}-{short_uuid}.
fn generate_incident_id() -> String {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
    let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let short_hash = format!("{:08x}", (nanos ^ 0xCAFE_BABE_DEAD_BEEFu64 as i64) as u64);
    format!("SHIELD-INC-{}-{}", ts, &short_hash[..8])
}

/// Classify the raw threat_type string into a canonical attack category.
fn classify_attack_type(raw: &str) -> String {
    let raw_lower = raw.to_lowercase();

    if raw_lower.contains("sqli") || raw_lower.contains("sql-injection") || raw_lower.contains("sql_injection") {
        return "sqli".to_string();
    }
    if raw_lower.contains("xss") || raw_lower.contains("cross-site-scripting") {
        return "xss".to_string();
    }
    if raw_lower.contains("ssrf") || raw_lower.contains("server-side-request") {
        return "ssrf".to_string();
    }
    if raw_lower.contains("brute") || raw_lower.contains("auth-fail") || raw_lower.contains("credential-stuff") {
        return "brute-force".to_string();
    }
    if raw_lower.contains("ddos") || raw_lower.contains("traffic-spike") || raw_lower.contains("flood") {
        return "ddos".to_string();
    }
    if raw_lower.contains("scan") || raw_lower.contains("recon") || raw_lower.contains("404-enum") {
        return "scanning".to_string();
    }
    if raw_lower.contains("path-traversal") || raw_lower.contains("lfi") || raw_lower.contains("directory-traversal") {
        return "path-traversal".to_string();
    }
    if raw_lower.contains("cmd") || raw_lower.contains("command-injection") || raw_lower.contains("rce") {
        return "cmd-injection".to_string();
    }

    raw.to_string()
}

/// Execute an iptables DROP rule. Returns (executed, result_message).
fn execute_iptables_block(target: &str) -> (bool, String) {
    if target == "unknown" || target == "multiple" || target.is_empty() {
        return (
            false,
            format!("Skipped: invalid target '{}'", target),
        );
    }

    let output = std::process::Command::new("iptables")
        .args(["-I", "INPUT", "-s", target, "-j", "DROP"])
        .output();

    match output {
        Ok(o) if o.status.success() => (
            true,
            format!("iptables rule added: DROP traffic from {}", target),
        ),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            (
                false,
                format!(
                    "iptables failed (may require root): {} — manual: iptables -I INPUT -s {} -j DROP",
                    err.trim(),
                    target
                ),
            )
        }
        Err(e) => (
            false,
            format!(
                "iptables not available ({}): manual: iptables -I INPUT -s {} -j DROP",
                e, target
            ),
        ),
    }
}

/// Convert an IP address to its /24 subnet (e.g. "10.0.0.42" -> "10.0.0.0/24").
fn ip_to_slash24(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        format!("{}/24", ip)
    }
}

/// Determine the incident severity, potentially escalating based on attack type
/// and whether a novel vulnerability was found.
fn determine_severity(
    event_severity: &str,
    attack_type: &str,
    novel_vuln: bool,
) -> String {
    let base = event_severity.to_uppercase();

    // Novel vulnerabilities always escalate to at least HIGH
    if novel_vuln && (base == "LOW" || base == "MEDIUM") {
        return "HIGH".to_string();
    }

    // Certain attack types are always at least HIGH
    match attack_type {
        "sqli" | "ssrf" | "cmd-injection" => {
            if base == "LOW" || base == "MEDIUM" {
                return "HIGH".to_string();
            }
        }
        _ => {}
    }

    if base.is_empty() {
        return "MEDIUM".to_string();
    }

    base
}

/// Determine if human escalation is needed.
fn determine_requires_human(severity: &str, attack_type: &str, novel_vuln: bool) -> bool {
    if severity == "CRITICAL" {
        return true;
    }
    if novel_vuln {
        return true;
    }
    // SQLi, SSRF, and command injection can lead to data exfiltration
    if matches!(attack_type, "sqli" | "ssrf" | "cmd-injection") {
        return true;
    }
    false
}

/// Determine incident status based on containment outcome.
fn determine_status(actions: &[ContainmentAction], requires_human: bool) -> String {
    if requires_human {
        // Even if some containment was applied, human review is needed
        let any_executed = actions.iter().any(|a| a.executed);
        if any_executed {
            return "contained".to_string();
        }
        return "mitigated".to_string();
    }

    let any_executed = actions.iter().any(|a| a.executed);
    if any_executed {
        return "contained".to_string();
    }

    let has_recommendations = !actions.is_empty();
    if has_recommendations {
        return "mitigated".to_string();
    }

    "resolved".to_string()
}

/// Check if the attack exploited a vulnerability not in the prior report.
fn check_novel_vulnerability(threat: &ThreatEvent, attack_type: &str) -> bool {
    let report_context = match &threat.report_context {
        Some(ctx) => ctx,
        None => {
            // No prior report context — any confirmed attack is novel
            // Only flag as novel for serious attack types
            return matches!(
                attack_type,
                "sqli" | "xss" | "ssrf" | "cmd-injection" | "path-traversal"
            );
        }
    };

    if report_context.known_vulnerability_ids.is_empty() {
        // Empty known list — same as no context
        return matches!(
            attack_type,
            "sqli" | "xss" | "ssrf" | "cmd-injection" | "path-traversal"
        );
    }

    // Check if any known vulnerability ID matches the attack type
    // If none of the known IDs cover this attack type, it is novel
    let type_lower = attack_type.to_lowercase();
    let covered = report_context.known_vulnerability_ids.iter().any(|id| {
        let id_lower = id.to_lowercase();
        id_lower.contains(&type_lower)
            || (type_lower == "sqli" && id_lower.contains("sql"))
            || (type_lower == "xss" && id_lower.contains("xss"))
            || (type_lower == "ssrf" && id_lower.contains("ssrf"))
            || (type_lower == "cmd-injection" && (id_lower.contains("cmd") || id_lower.contains("rce")))
            || (type_lower == "path-traversal" && (id_lower.contains("traversal") || id_lower.contains("lfi")))
            || (type_lower == "brute-force" && id_lower.contains("brute"))
    });

    !covered
}

/// Extract SQL-like queries from a raw log entry and matched pattern.
fn extract_queries(raw_log: &str, matched_pattern: &str) -> Vec<String> {
    let mut queries = Vec::new();

    // Look for common SQL keywords in the log entry
    let sql_re = regex::Regex::new(
        r"(?i)((?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION|CREATE)\s+.{5,80})"
    );
    if let Ok(re) = sql_re {
        for cap in re.captures_iter(raw_log) {
            if let Some(m) = cap.get(1) {
                let query = m.as_str().to_string();
                if query.len() > 200 {
                    queries.push(format!("{}...", &query[..200]));
                } else {
                    queries.push(query);
                }
            }
        }
    }

    // Also check the matched pattern for query fragments
    if let Ok(re) = regex::Regex::new(r"(?i)((?:SELECT|UNION|INSERT|DELETE|DROP)\s+\S+)") {
        for cap in re.captures_iter(matched_pattern) {
            if let Some(m) = cap.get(1) {
                let frag = m.as_str().to_string();
                if !queries.contains(&frag) {
                    queries.push(frag);
                }
            }
        }
    }

    queries
}

/// Extract response times from a raw log entry.
fn extract_response_times(raw_log: &str) -> Vec<f64> {
    let mut times = Vec::new();

    // Match patterns like "response_time_ms":123.4 or duration=45.6ms
    let patterns = [
        regex::Regex::new(r#""?response_time(?:_ms)?"?\s*[:=]\s*(\d+(?:\.\d+)?)"#),
        regex::Regex::new(r#"duration[:=]\s*(\d+(?:\.\d+)?)\s*(?:ms)?"#),
        regex::Regex::new(r#"time[:=]\s*(\d+(?:\.\d+)?)\s*ms"#),
    ];

    for pattern_result in &patterns {
        if let Ok(re) = pattern_result {
            for cap in re.captures_iter(raw_log) {
                if let Some(m) = cap.get(1) {
                    if let Ok(t) = m.as_str().parse::<f64>() {
                        times.push(t);
                    }
                }
            }
        }
    }

    times
}

/// Format a Telegram alert message for a confirmed incident.
fn format_telegram_message(
    incident_id: &str,
    severity: &str,
    attack_type: &str,
    threat: &ThreatEvent,
    actions_taken: &[String],
    requires_human: bool,
    novel_vuln: bool,
) -> String {
    let emoji = match severity {
        "CRITICAL" => "\xf0\x9f\x94\xb4",  // red circle
        "HIGH" => "\xf0\x9f\x9f\xa0",       // orange circle
        "MEDIUM" => "\xf0\x9f\x9f\xa1",     // yellow circle
        _ => "\xf0\x9f\x94\xb5",            // blue circle
    };

    let human_tag = if requires_human {
        "\n\nACTION REQUIRED: Human review needed"
    } else {
        ""
    };

    let novel_tag = if novel_vuln {
        "\nNOVEL VULNERABILITY: Mini Phase 1->2 rescan triggered"
    } else {
        ""
    };

    let actions_text = if actions_taken.is_empty() {
        "None".to_string()
    } else {
        actions_taken
            .iter()
            .enumerate()
            .map(|(i, a)| format!("{}. {}", i + 1, a))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "{emoji} {severity} INCIDENT — {attack_type}\n\
        \n\
        ID: {incident_id}\n\
        Source: {source_ip}\n\
        Target: {target_endpoint}\n\
        Pattern: {matched_pattern}\n\
        \n\
        Actions taken:\n\
        {actions_text}\
        {human_tag}\
        {novel_tag}",
        emoji = emoji,
        severity = severity,
        attack_type = attack_type.to_uppercase(),
        incident_id = incident_id,
        source_ip = threat.source_ip,
        target_endpoint = threat.target_endpoint,
        matched_pattern = threat.matched_pattern,
        actions_text = actions_text,
        human_tag = human_tag,
        novel_tag = novel_tag,
    )
}

/// Format a Telegram message for a false-positive event (informational only).
fn format_telegram_message_fp(incident_id: &str, threat: &ThreatEvent) -> String {
    format!(
        "\xf0\x9f\x94\xb5 FALSE POSITIVE RESOLVED\n\
        \n\
        ID: {}\n\
        Source: {}\n\
        Target: {}\n\
        Pattern: {}\n\
        \n\
        Verified as false positive — no action taken.",
        incident_id,
        threat.source_ip,
        threat.target_endpoint,
        threat.matched_pattern,
    )
}

// ═══════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_threat(
        threat_type: &str,
        severity: &str,
        source_ip: &str,
        endpoint: &str,
        pattern: &str,
    ) -> ThreatEvent {
        ThreatEvent {
            threat_type: threat_type.to_string(),
            source_ip: source_ip.to_string(),
            target_endpoint: endpoint.to_string(),
            severity: severity.to_string(),
            matched_pattern: pattern.to_string(),
            raw_log_entry: format!(
                "GET {} HTTP/1.1 from {} — pattern: {}",
                endpoint, source_ip, pattern
            ),
            correlation_id: Some("corr-test-001".to_string()),
            report_context: None,
        }
    }

    // ── IncidentEngine basic tests ───────────────────────────────────────────

    #[test]
    fn test_engine_creation() {
        let engine = IncidentEngine::new();
        let incidents = engine.active_incidents.lock().unwrap();
        assert!(incidents.is_empty());
        let actions = engine.containment_actions.lock().unwrap();
        assert!(actions.is_empty());
        let logs = engine.forensic_logs.lock().unwrap();
        assert!(logs.is_empty());
    }

    #[test]
    fn test_respond_to_sqli_threat() {
        let engine = IncidentEngine::new();
        let threat = make_threat(
            "sqli",
            "HIGH",
            "10.0.0.99",
            "/api/search",
            "UNION SELECT username,password FROM users",
        );

        let response = engine.respond_to_threat(threat);

        assert!(response.incident_id.starts_with("SHIELD-INC-"));
        assert_eq!(response.attack_type, "sqli");
        assert_eq!(response.severity, "HIGH");
        assert!(response.requires_human, "SQLi should require human review");
        assert!(!response.actions_taken.is_empty(), "Should have containment actions");
        assert!(!response.forensic_data.all_logs_from_ip.is_empty());
        assert!(!response.telegram_message.is_empty());
    }

    #[test]
    fn test_respond_to_xss_threat() {
        let engine = IncidentEngine::new();
        let threat = make_threat(
            "xss",
            "HIGH",
            "192.168.1.50",
            "/api/comments",
            "<script>alert(document.cookie)</script>",
        );

        let response = engine.respond_to_threat(threat);

        assert_eq!(response.attack_type, "xss");
        assert!(!response.actions_taken.is_empty());
        // XSS containment should include block-ip
        let has_block = response.actions_taken.iter().any(|a| a.contains("Block IP"));
        assert!(has_block, "XSS should include IP block action");
    }

    #[test]
    fn test_respond_to_brute_force_threat() {
        let engine = IncidentEngine::new();
        let threat = make_threat(
            "brute-force",
            "HIGH",
            "203.0.113.42",
            "/auth/login",
            "50 auth failures from same IP",
        );

        let response = engine.respond_to_threat(threat);

        assert_eq!(response.attack_type, "brute-force");
        // Should block /24 subnet
        let has_subnet = response.actions_taken.iter().any(|a| a.contains("203.0.113.0/24"));
        assert!(has_subnet, "Brute force should block /24 subnet");
        // Should recommend account lockout
        let has_lockout = response.actions_taken.iter().any(|a| a.contains("Lock"));
        assert!(has_lockout, "Brute force should recommend account lockout");
    }

    #[test]
    fn test_respond_to_ddos_threat() {
        let engine = IncidentEngine::new();
        let threat = make_threat(
            "ddos",
            "CRITICAL",
            "10.0.0.1",
            "/",
            "traffic-spike 500x baseline",
        );

        let response = engine.respond_to_threat(threat);

        assert_eq!(response.attack_type, "ddos");
        assert_eq!(response.severity, "CRITICAL");
        assert!(response.requires_human, "CRITICAL events require human");
        let has_rate_limit = response.actions_taken.iter().any(|a| a.contains("rate limiting"));
        assert!(has_rate_limit, "DDoS should activate aggressive rate limiting");
    }

    #[test]
    fn test_respond_to_scanning_threat() {
        let engine = IncidentEngine::new();
        let threat = make_threat(
            "scanning",
            "MEDIUM",
            "198.51.100.5",
            "/admin",
            "25 sequential 404 responses",
        );

        let response = engine.respond_to_threat(threat);

        assert_eq!(response.attack_type, "scanning");
        let has_rate_limit = response.actions_taken.iter().any(|a| a.contains("Rate limit"));
        assert!(has_rate_limit, "Scanning should rate-limit the IP");
        let has_logging = response.actions_taken.iter().any(|a| a.contains("logging"));
        assert!(has_logging, "Scanning should enable verbose logging");
    }

    #[test]
    fn test_respond_to_ssrf_threat() {
        let engine = IncidentEngine::new();
        let threat = make_threat(
            "ssrf",
            "CRITICAL",
            "10.0.0.50",
            "/api/fetch",
            "169.254.169.254 metadata access",
        );

        let response = engine.respond_to_threat(threat);

        assert_eq!(response.attack_type, "ssrf");
        assert_eq!(response.severity, "CRITICAL");
        assert!(response.requires_human);
    }

    // ── False positive detection ─────────────────────────────────────────────

    #[test]
    fn test_false_positive_low_severity_no_history() {
        let engine = IncidentEngine::new();
        let threat = ThreatEvent {
            threat_type: "anomaly".to_string(),
            source_ip: "172.16.0.1".to_string(),
            target_endpoint: "/health".to_string(),
            severity: "LOW".to_string(),
            matched_pattern: "blip".to_string(),
            raw_log_entry: "GET /health HTTP/1.1".to_string(),
            correlation_id: None,
            report_context: None,
        };

        let response = engine.respond_to_threat(threat);
        assert_eq!(response.status, "resolved");
        assert!(response.actions_taken.iter().any(|a| a.contains("false positive")));
    }

    #[test]
    fn test_not_false_positive_with_attack_pattern() {
        let engine = IncidentEngine::new();
        let threat = make_threat(
            "sqli",
            "HIGH",
            "10.0.0.1",
            "/api/search",
            "UNION SELECT 1,2,3",
        );

        let response = engine.respond_to_threat(threat);
        assert_ne!(response.status, "resolved");
        assert!(!response.actions_taken.iter().any(|a| a.contains("false positive")));
    }

    #[test]
    fn test_repeat_offender_not_false_positive() {
        let engine = IncidentEngine::new();

        // First incident from this IP
        let threat1 = make_threat(
            "sqli",
            "HIGH",
            "10.0.0.77",
            "/api/users",
            "OR 1=1",
        );
        let _ = engine.respond_to_threat(threat1);

        // Second incident from same IP — even if low severity, not FP
        let threat2 = ThreatEvent {
            threat_type: "scanning".to_string(),
            source_ip: "10.0.0.77".to_string(),
            target_endpoint: "/admin".to_string(),
            severity: "LOW".to_string(),
            matched_pattern: "enum".to_string(),
            raw_log_entry: "GET /admin HTTP/1.1".to_string(),
            correlation_id: None,
            report_context: None,
        };
        let response2 = engine.respond_to_threat(threat2);
        // Should not be resolved as false positive due to prior history
        assert!(!response2.actions_taken.iter().any(|a| a.contains("false positive")));
    }

    // ── Attack type classification ───────────────────────────────────────────

    #[test]
    fn test_classify_attack_type_sqli_variants() {
        assert_eq!(classify_attack_type("sqli"), "sqli");
        assert_eq!(classify_attack_type("sql-injection"), "sqli");
        assert_eq!(classify_attack_type("sql_injection"), "sqli");
        assert_eq!(classify_attack_type("SQLI-time-based"), "sqli");
    }

    #[test]
    fn test_classify_attack_type_xss() {
        assert_eq!(classify_attack_type("xss"), "xss");
        assert_eq!(classify_attack_type("cross-site-scripting"), "xss");
        assert_eq!(classify_attack_type("XSS-reflected"), "xss");
    }

    #[test]
    fn test_classify_attack_type_brute_force() {
        assert_eq!(classify_attack_type("brute-force"), "brute-force");
        assert_eq!(classify_attack_type("auth-failure"), "brute-force");
        assert_eq!(classify_attack_type("credential-stuffing"), "brute-force");
    }

    #[test]
    fn test_classify_attack_type_ddos() {
        assert_eq!(classify_attack_type("ddos"), "ddos");
        assert_eq!(classify_attack_type("traffic-spike"), "ddos");
        assert_eq!(classify_attack_type("syn-flood"), "ddos");
    }

    #[test]
    fn test_classify_attack_type_scanning() {
        assert_eq!(classify_attack_type("scanning"), "scanning");
        assert_eq!(classify_attack_type("recon"), "scanning");
        assert_eq!(classify_attack_type("404-enum"), "scanning");
    }

    #[test]
    fn test_classify_attack_type_unknown() {
        assert_eq!(classify_attack_type("something-new"), "something-new");
    }

    // ── Severity and status determination ────────────────────────────────────

    #[test]
    fn test_determine_severity_escalation_sqli() {
        assert_eq!(determine_severity("LOW", "sqli", false), "HIGH");
        assert_eq!(determine_severity("MEDIUM", "sqli", false), "HIGH");
        assert_eq!(determine_severity("HIGH", "sqli", false), "HIGH");
        assert_eq!(determine_severity("CRITICAL", "sqli", false), "CRITICAL");
    }

    #[test]
    fn test_determine_severity_novel_vuln_escalation() {
        assert_eq!(determine_severity("LOW", "xss", true), "HIGH");
        assert_eq!(determine_severity("MEDIUM", "scanning", true), "HIGH");
        assert_eq!(determine_severity("HIGH", "xss", true), "HIGH");
    }

    #[test]
    fn test_determine_severity_no_escalation_needed() {
        assert_eq!(determine_severity("CRITICAL", "ddos", false), "CRITICAL");
        assert_eq!(determine_severity("HIGH", "brute-force", false), "HIGH");
    }

    #[test]
    fn test_determine_requires_human() {
        assert!(determine_requires_human("CRITICAL", "ddos", false));
        assert!(determine_requires_human("HIGH", "sqli", false));
        assert!(determine_requires_human("HIGH", "ssrf", false));
        assert!(determine_requires_human("HIGH", "cmd-injection", false));
        assert!(determine_requires_human("LOW", "scanning", true)); // novel vuln
        assert!(!determine_requires_human("HIGH", "brute-force", false));
        assert!(!determine_requires_human("MEDIUM", "scanning", false));
    }

    #[test]
    fn test_determine_status_contained() {
        let actions = vec![ContainmentAction {
            action_type: "block-ip".to_string(),
            target: "10.0.0.1".to_string(),
            executed: true,
            result: "blocked".to_string(),
        }];
        assert_eq!(determine_status(&actions, false), "contained");
    }

    #[test]
    fn test_determine_status_mitigated() {
        let actions = vec![ContainmentAction {
            action_type: "rate-limit".to_string(),
            target: "10.0.0.1".to_string(),
            executed: false,
            result: "recommended".to_string(),
        }];
        assert_eq!(determine_status(&actions, false), "mitigated");
    }

    #[test]
    fn test_determine_status_requires_human_with_execution() {
        let actions = vec![ContainmentAction {
            action_type: "block-ip".to_string(),
            target: "10.0.0.1".to_string(),
            executed: true,
            result: "blocked".to_string(),
        }];
        assert_eq!(determine_status(&actions, true), "contained");
    }

    #[test]
    fn test_determine_status_requires_human_no_execution() {
        let actions = vec![ContainmentAction {
            action_type: "waf-rule".to_string(),
            target: "10.0.0.1".to_string(),
            executed: false,
            result: "recommended".to_string(),
        }];
        assert_eq!(determine_status(&actions, true), "mitigated");
    }

    // ── Novel vulnerability detection ────────────────────────────────────────

    #[test]
    fn test_novel_vuln_no_context() {
        let threat = make_threat("sqli", "HIGH", "10.0.0.1", "/api", "UNION SELECT");
        assert!(check_novel_vulnerability(&threat, "sqli"));
    }

    #[test]
    fn test_novel_vuln_empty_known_ids() {
        let mut threat = make_threat("xss", "HIGH", "10.0.0.1", "/api", "<script>");
        threat.report_context = Some(ReportContext {
            known_vulnerability_ids: Vec::new(),
        });
        assert!(check_novel_vulnerability(&threat, "xss"));
    }

    #[test]
    fn test_not_novel_vuln_covered_by_report() {
        let mut threat = make_threat("sqli", "HIGH", "10.0.0.1", "/api", "UNION SELECT");
        threat.report_context = Some(ReportContext {
            known_vulnerability_ids: vec!["VULN-001-sqli".to_string()],
        });
        assert!(!check_novel_vulnerability(&threat, "sqli"));
    }

    #[test]
    fn test_novel_vuln_different_type_than_known() {
        let mut threat = make_threat("ssrf", "HIGH", "10.0.0.1", "/api/fetch", "169.254.169.254");
        threat.report_context = Some(ReportContext {
            known_vulnerability_ids: vec!["VULN-001-sqli".to_string(), "VULN-002-xss".to_string()],
        });
        assert!(check_novel_vulnerability(&threat, "ssrf"));
    }

    #[test]
    fn test_not_novel_brute_force_with_context() {
        let mut threat = make_threat("brute-force", "HIGH", "10.0.0.1", "/login", "auth failures");
        threat.report_context = Some(ReportContext {
            known_vulnerability_ids: vec!["VULN-003-brute-force".to_string()],
        });
        assert!(!check_novel_vulnerability(&threat, "brute-force"));
    }

    // ── IP helper ────────────────────────────────────────────────────────────

    #[test]
    fn test_ip_to_slash24() {
        assert_eq!(ip_to_slash24("203.0.113.42"), "203.0.113.0/24");
        assert_eq!(ip_to_slash24("10.0.0.1"), "10.0.0.0/24");
        assert_eq!(ip_to_slash24("192.168.1.100"), "192.168.1.0/24");
    }

    // ── Incident ID format ───────────────────────────────────────────────────

    #[test]
    fn test_generate_incident_id_format() {
        let id = generate_incident_id();
        assert!(id.starts_with("SHIELD-INC-"), "ID should start with SHIELD-INC-");
        assert!(id.len() > 20, "ID should include timestamp and hash");
    }

    #[test]
    fn test_generate_incident_id_unique() {
        let id1 = generate_incident_id();
        // tiny sleep to ensure different nanos
        std::thread::sleep(std::time::Duration::from_millis(1));
        let id2 = generate_incident_id();
        assert_ne!(id1, id2, "Two IDs generated at different times should differ");
    }

    // ── Query extraction ─────────────────────────────────────────────────────

    #[test]
    fn test_extract_queries_from_log() {
        let log = "GET /api/search?q=' UNION SELECT username,password FROM users-- HTTP/1.1";
        let pattern = "UNION SELECT";
        let queries = extract_queries(log, pattern);
        assert!(!queries.is_empty(), "Should extract SQL query");
        assert!(queries.iter().any(|q| q.contains("SELECT")));
    }

    #[test]
    fn test_extract_queries_no_sql() {
        let log = "GET /health HTTP/1.1 200 OK";
        let pattern = "health-check";
        let queries = extract_queries(log, pattern);
        assert!(queries.is_empty(), "Should not find queries in normal log");
    }

    // ── Response time extraction ─────────────────────────────────────────────

    #[test]
    fn test_extract_response_times() {
        let log = r#"{"path":"/api","response_time_ms":42.5,"status":200}"#;
        let times = extract_response_times(log);
        assert!(!times.is_empty());
        assert!((times[0] - 42.5).abs() < 0.001);
    }

    #[test]
    fn test_extract_response_times_duration_format() {
        let log = "request completed duration=125ms status=200";
        let times = extract_response_times(log);
        assert!(!times.is_empty());
        assert!((times[0] - 125.0).abs() < 0.001);
    }

    #[test]
    fn test_extract_response_times_none() {
        let log = "GET /api HTTP/1.1 200 OK";
        let times = extract_response_times(log);
        assert!(times.is_empty());
    }

    // ── Telegram message formatting ──────────────────────────────────────────

    #[test]
    fn test_telegram_message_contains_key_fields() {
        let threat = make_threat("sqli", "HIGH", "10.0.0.99", "/api/search", "UNION SELECT");
        let msg = format_telegram_message(
            "SHIELD-INC-TEST",
            "HIGH",
            "sqli",
            &threat,
            &["Block IP 10.0.0.99".to_string()],
            true,
            false,
        );

        assert!(msg.contains("HIGH"), "Should contain severity");
        assert!(msg.contains("SQLI"), "Should contain attack type");
        assert!(msg.contains("SHIELD-INC-TEST"), "Should contain incident ID");
        assert!(msg.contains("10.0.0.99"), "Should contain source IP");
        assert!(msg.contains("/api/search"), "Should contain target endpoint");
        assert!(msg.contains("UNION SELECT"), "Should contain pattern");
        assert!(msg.contains("Block IP"), "Should contain action");
        assert!(msg.contains("Human review"), "Should indicate human review needed");
    }

    #[test]
    fn test_telegram_message_novel_vuln_tag() {
        let threat = make_threat("ssrf", "HIGH", "10.0.0.1", "/fetch", "169.254.169.254");
        let msg = format_telegram_message(
            "SHIELD-INC-TEST",
            "HIGH",
            "ssrf",
            &threat,
            &["Block IP".to_string()],
            true,
            true,
        );
        assert!(msg.contains("NOVEL VULNERABILITY"), "Should tag novel vuln");
        assert!(msg.contains("Phase 1->2"), "Should mention rescan");
    }

    #[test]
    fn test_telegram_message_false_positive() {
        let threat = make_threat("anomaly", "LOW", "10.0.0.1", "/health", "blip");
        let msg = format_telegram_message_fp("SHIELD-INC-FP", &threat);
        assert!(msg.contains("FALSE POSITIVE"), "Should indicate false positive");
        assert!(msg.contains("no action taken"), "Should say no action");
    }

    // ── Tool entry point tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_tool_respond_to_incident_sqli() {
        let input = serde_json::json!({
            "threat_type": "sqli",
            "source_ip": "10.0.0.99",
            "target_endpoint": "/api/search",
            "severity": "HIGH",
            "matched_pattern": "UNION SELECT username,password FROM users",
            "raw_log_entry": "GET /api/search?q=' UNION SELECT username,password FROM users-- HTTP/1.1 from 10.0.0.99"
        });

        let result = tool_respond_to_incident(&input).await;
        assert!(result.is_ok(), "Tool should succeed: {:?}", result.err());

        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(parsed["attack_type"], "sqli");
        assert_eq!(parsed["severity"], "HIGH");
        assert!(parsed["incident_id"].as_str().unwrap().starts_with("SHIELD-INC-"));
        assert!(parsed["requires_human"].as_bool().unwrap(), "SQLi should require human");
        assert!(!parsed["actions_taken"].as_array().unwrap().is_empty());
        assert!(!parsed["telegram_message"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_tool_respond_to_incident_with_correlation_id() {
        let input = serde_json::json!({
            "threat_type": "xss",
            "source_ip": "192.168.1.50",
            "target_endpoint": "/api/comments",
            "severity": "HIGH",
            "matched_pattern": "<script>alert(1)</script>",
            "raw_log_entry": "POST /api/comments HTTP/1.1",
            "correlation_id": "corr-abc-123"
        });

        let result = tool_respond_to_incident(&input).await;
        assert!(result.is_ok());

        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let correlated = &parsed["forensic_data"]["correlated_events"];
        let has_corr = correlated.as_array().unwrap().iter().any(|e| {
            e.as_str().unwrap_or("").contains("corr-abc-123")
        });
        assert!(has_corr, "Should include correlation ID in forensic data");
    }

    #[tokio::test]
    async fn test_tool_respond_to_incident_with_report_context() {
        let input = serde_json::json!({
            "threat_type": "ssrf",
            "source_ip": "10.0.0.50",
            "target_endpoint": "/api/fetch",
            "severity": "CRITICAL",
            "matched_pattern": "169.254.169.254",
            "raw_log_entry": "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
            "report_context": {
                "known_vulnerability_ids": ["VULN-001-sqli", "VULN-002-xss"]
            }
        });

        let result = tool_respond_to_incident(&input).await;
        assert!(result.is_ok());

        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(
            parsed["novel_vulnerability_detected"].as_bool().unwrap(),
            "SSRF should be novel when only sqli/xss are known"
        );
        assert!(
            parsed["mini_rescan_triggered"].as_bool().unwrap(),
            "Should trigger mini rescan for novel vuln"
        );
    }

    #[tokio::test]
    async fn test_tool_respond_to_incident_known_vuln() {
        let input = serde_json::json!({
            "threat_type": "sqli",
            "source_ip": "10.0.0.99",
            "target_endpoint": "/api/search",
            "severity": "HIGH",
            "matched_pattern": "UNION SELECT",
            "raw_log_entry": "GET /api/search?q=test HTTP/1.1",
            "report_context": {
                "known_vulnerability_ids": ["VULN-001-sqli-search"]
            }
        });

        let result = tool_respond_to_incident(&input).await;
        assert!(result.is_ok());

        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(
            !parsed["novel_vulnerability_detected"].as_bool().unwrap(),
            "SQLi should NOT be novel when sqli is known"
        );
        assert!(
            !parsed["mini_rescan_triggered"].as_bool().unwrap(),
            "Should NOT trigger rescan for known vuln"
        );
    }

    #[tokio::test]
    async fn test_tool_respond_to_incident_missing_fields() {
        let input = serde_json::json!({
            "threat_type": "sqli"
        });
        let result = tool_respond_to_incident(&input).await;
        assert!(result.is_err(), "Should error when required fields are missing");
    }

    #[tokio::test]
    async fn test_tool_respond_to_incident_brute_force() {
        let input = serde_json::json!({
            "threat_type": "brute-force",
            "source_ip": "185.220.101.5",
            "target_endpoint": "/auth/login",
            "severity": "HIGH",
            "matched_pattern": "50 auth failures from same IP in 2 minutes",
            "raw_log_entry": "IP 185.220.101.5 generated 50 401 responses on /auth/login"
        });

        let result = tool_respond_to_incident(&input).await;
        assert!(result.is_ok());

        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(parsed["attack_type"], "brute-force");

        // Should block /24 subnet
        let actions = parsed["actions_taken"].as_array().unwrap();
        let has_subnet = actions.iter().any(|a| {
            a.as_str().unwrap_or("").contains("185.220.101.0/24")
        });
        assert!(has_subnet, "Brute force should block /24 subnet");
    }

    #[tokio::test]
    async fn test_tool_respond_to_incident_ddos() {
        let input = serde_json::json!({
            "threat_type": "ddos",
            "source_ip": "10.0.0.1",
            "target_endpoint": "/",
            "severity": "CRITICAL",
            "matched_pattern": "traffic-spike 500x baseline",
            "raw_log_entry": "Traffic spike detected: 50000 req/s from 10.0.0.1"
        });

        let result = tool_respond_to_incident(&input).await;
        assert!(result.is_ok());

        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(parsed["attack_type"], "ddos");
        assert_eq!(parsed["severity"], "CRITICAL");
        assert!(parsed["requires_human"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_tool_respond_to_incident_scanning() {
        let input = serde_json::json!({
            "threat_type": "scanning",
            "source_ip": "198.51.100.5",
            "target_endpoint": "/admin",
            "severity": "MEDIUM",
            "matched_pattern": "25 sequential 404 responses",
            "raw_log_entry": "IP 198.51.100.5 generated 25 404 responses scanning paths"
        });

        let result = tool_respond_to_incident(&input).await;
        assert!(result.is_ok());

        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(parsed["attack_type"], "scanning");
        let actions = parsed["actions_taken"].as_array().unwrap();
        let has_rate_limit = actions.iter().any(|a| {
            a.as_str().unwrap_or("").contains("Rate limit")
        });
        assert!(has_rate_limit, "Scanning should rate-limit the IP");
    }

    // ── Forensic data tests ──────────────────────────────────────────────────

    #[test]
    fn test_forensic_data_includes_timeline() {
        let engine = IncidentEngine::new();
        let threat = make_threat("sqli", "HIGH", "10.0.0.1", "/api", "UNION SELECT");
        let response = engine.respond_to_threat(threat);

        assert!(!response.forensic_data.timeline.is_empty(), "Should have timeline entries");
        // First entry should be incident creation
        assert!(
            response.forensic_data.timeline[0].event.contains("Incident"),
            "First timeline entry should be incident creation"
        );
    }

    #[test]
    fn test_forensic_data_includes_ip_history() {
        let engine = IncidentEngine::new();
        let threat = make_threat("xss", "HIGH", "10.0.0.42", "/comments", "<script>alert(1)</script>");
        let response = engine.respond_to_threat(threat);

        assert_eq!(response.forensic_data.ip_history.ip, "10.0.0.42");
        assert!(response.forensic_data.ip_history.threat_score > 0.0);
    }

    #[test]
    fn test_forensic_data_query_extraction() {
        let engine = IncidentEngine::new();
        let threat = ThreatEvent {
            threat_type: "sqli".to_string(),
            source_ip: "10.0.0.1".to_string(),
            target_endpoint: "/api/search".to_string(),
            severity: "HIGH".to_string(),
            matched_pattern: "UNION SELECT".to_string(),
            raw_log_entry: "GET /api/search?q=' UNION SELECT username,password FROM users-- HTTP/1.1".to_string(),
            correlation_id: None,
            report_context: None,
        };
        let response = engine.respond_to_threat(threat);

        assert!(
            !response.forensic_data.queries_executed.is_empty(),
            "Should extract SQL queries from SQLi log entry"
        );
    }

    // ── Engine state persistence across calls ────────────────────────────────

    #[test]
    fn test_engine_tracks_active_incidents() {
        let engine = IncidentEngine::new();

        let threat1 = make_threat("sqli", "HIGH", "10.0.0.1", "/api", "UNION SELECT");
        let response1 = engine.respond_to_threat(threat1);

        let threat2 = make_threat("xss", "HIGH", "10.0.0.2", "/comments", "<script>");
        let response2 = engine.respond_to_threat(threat2);

        let incidents = engine.active_incidents.lock().unwrap();
        assert_eq!(incidents.len(), 2, "Should track both incidents");
        assert!(incidents.contains_key(&response1.incident_id));
        assert!(incidents.contains_key(&response2.incident_id));
    }

    #[test]
    fn test_engine_accumulates_containment_actions() {
        let engine = IncidentEngine::new();

        let threat1 = make_threat("sqli", "HIGH", "10.0.0.1", "/api", "OR 1=1");
        let _ = engine.respond_to_threat(threat1);

        let threat2 = make_threat("brute-force", "HIGH", "10.0.0.2", "/login", "50 failures");
        let _ = engine.respond_to_threat(threat2);

        let actions = engine.containment_actions.lock().unwrap();
        assert!(actions.len() >= 2, "Should accumulate containment actions from both incidents");
    }

    #[test]
    fn test_engine_accumulates_forensic_logs() {
        let engine = IncidentEngine::new();

        let threat1 = make_threat("sqli", "HIGH", "10.0.0.1", "/api", "UNION SELECT");
        let _ = engine.respond_to_threat(threat1);

        let threat2 = make_threat("xss", "HIGH", "10.0.0.2", "/page", "<script>");
        let _ = engine.respond_to_threat(threat2);

        let logs = engine.forensic_logs.lock().unwrap();
        assert_eq!(logs.len(), 2, "Should have forensic log for each incident");
    }
}
