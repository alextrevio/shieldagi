/// ShieldAGI Tool: sentinel_runtime
///
/// The Sentinel engine runs every 5 minutes to detect threats by parsing logs,
/// matching attack signatures, and comparing metrics against a baseline.
/// Part of ShieldAGI Phase D (24/7 Monitoring).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SentinelCycleResult {
    pub cycle_id: String,
    pub timestamp: String,
    pub events_analyzed: usize,
    pub threats: Vec<ThreatEvent>,
    pub baseline_updated: bool,
    pub alert_actions: Vec<String>,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatEvent {
    pub timestamp: String,
    pub source_ip: String,
    pub threat_type: String,
    /// CRITICAL / HIGH / MEDIUM / LOW
    pub severity: String,
    pub matched_pattern: String,
    pub raw_log_entry: String,
    pub correlation_id: String,
    pub affected_endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BaselineMetrics {
    pub requests_per_minute_avg: f64,
    pub requests_per_minute_stddev: f64,
    pub error_rate_avg: f64,
    pub p95_response_time_ms: f64,
    pub auth_failures_per_hour: f64,
    pub unique_ips_per_hour: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub user_agent: String,
    pub response_time_ms: f64,
    pub body_size: u64,
}

// ─── Attack signature patterns ────────────────────────────────────────────────
// (regex_pattern, threat_type, severity)
const ATTACK_PATTERNS: &[(&str, &str, &str)] = &[
    // SQL injection
    (r"(?i)union\s+(all\s+)?select", "sqli", "HIGH"),
    (r"(?i)'\s*or\s+'?\d+'?\s*=\s*'?\d+", "sqli", "HIGH"),
    (r"(?i)\bor\s+1\s*=\s*1\b", "sqli", "HIGH"),
    (r"(?i);\s*(drop|delete|truncate|alter)\s+table", "sqli", "CRITICAL"),
    (r"(?i)sleep\s*\(\s*\d+\s*\)|benchmark\s*\(", "sqli-time-based", "HIGH"),
    (r"(?i)information_schema|pg_tables|sysobjects", "sqli-enumeration", "HIGH"),
    // XSS
    (r"(?i)<\s*script[\s>]", "xss", "HIGH"),
    (r"(?i)onerror\s*=|onload\s*=|onclick\s*=", "xss", "HIGH"),
    (r"(?i)javascript\s*:", "xss", "HIGH"),
    (r"(?i)alert\s*\(|document\.cookie|document\.location", "xss-execution", "HIGH"),
    // Path traversal
    (r"(\.\./){2,}|(%2e%2e/){2,}|(%252e%252e)", "path-traversal", "HIGH"),
    (r"(?i)/etc/passwd|/etc/shadow|/proc/self/environ", "path-traversal-lfi", "CRITICAL"),
    // SSRF
    (r"169\.254\.169\.254", "ssrf-metadata-aws", "CRITICAL"),
    (r"(?i)metadata\.google\.internal", "ssrf-metadata-gcp", "CRITICAL"),
    (r"(?i)(file|gopher|dict)://", "ssrf-protocol", "HIGH"),
    // Scanner user agents
    (r"(?i)sqlmap|nikto|nuclei|gobuster|dirbuster|masscan|nmap|hydra|burpsuite|wfuzz|ffuf|dirb\b", "scanner-ua", "MEDIUM"),
    // Command injection
    (r"(?i)(;|\||&&|`)\s*(ls|cat|id|whoami|uname|wget|curl|bash|sh|python)", "cmd-injection", "CRITICAL"),
    (r"(?i)(cmd|exec|system|passthru|shell_exec|popen)\s*\(", "cmd-injection-func", "CRITICAL"),
];

/// Run one Sentinel monitoring cycle.
pub async fn tool_run_sentinel_cycle(input: &serde_json::Value) -> Result<String, String> {
    let log_source = input["log_source"]
        .as_str()
        .ok_or("Missing 'log_source' field")?;
    let baseline_path = input["baseline_path"].as_str();
    let time_range_minutes = input["time_range_minutes"].as_u64().unwrap_or(5) as i64;

    let start = std::time::Instant::now();
    let cycle_id = generate_cycle_id();
    let cycle_timestamp = chrono::Utc::now().to_rfc3339();

    // ── 1. Read log file ──────────────────────────────────────────────────────
    let log_content = std::fs::read_to_string(log_source)
        .map_err(|e| format!("Failed to read log file '{}': {}", log_source, e))?;

    // ── 2. Parse log entries ──────────────────────────────────────────────────
    let cutoff = chrono::Utc::now() - chrono::Duration::minutes(time_range_minutes);
    let all_entries: Vec<LogEntry> = log_content
        .lines()
        .filter_map(parse_log_line)
        .filter(|e| {
            // Keep entries within the time window (best-effort; keep all if ts unparseable)
            chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                .map(|dt| dt.with_timezone(&chrono::Utc) >= cutoff)
                .unwrap_or(true)
        })
        .collect();

    let events_analyzed = all_entries.len();

    // ── 3. Load optional baseline ─────────────────────────────────────────────
    let saved_baseline: Option<BaselineMetrics> = baseline_path.and_then(|p| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    });

    // ── 4. Pattern-match threats ──────────────────────────────────────────────
    let compiled: Vec<(regex::Regex, &str, &str)> = ATTACK_PATTERNS
        .iter()
        .filter_map(|(pat, ttype, sev)| {
            regex::Regex::new(pat).ok().map(|r| (r, *ttype, *sev))
        })
        .collect();

    let ip_regex = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").ok();

    // Track 404 counts per IP for scanning detection
    let mut ip_404_counts: HashMap<String, usize> = HashMap::new();
    // Track auth failure counts per IP for brute-force detection
    let mut ip_auth_fail_counts: HashMap<String, usize> = HashMap::new();

    for entry in &all_entries {
        if entry.status_code == 404 {
            *ip_404_counts.entry(entry.ip.clone()).or_insert(0) += 1;
        }
        if entry.status_code == 401 || entry.status_code == 403 {
            *ip_auth_fail_counts.entry(entry.ip.clone()).or_insert(0) += 1;
        }
    }

    let mut threats: Vec<ThreatEvent> = Vec::new();

    // Pattern matching against raw log lines
    for line in log_content.lines() {
        for (re, threat_type, severity) in &compiled {
            if re.is_match(line) {
                let source_ip = ip_regex
                    .as_ref()
                    .and_then(|r| r.find(line).map(|m| m.as_str().to_string()))
                    .unwrap_or_else(|| "unknown".to_string());

                let affected_endpoint = extract_endpoint(line);
                let ts = extract_log_timestamp(line)
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

                threats.push(ThreatEvent {
                    timestamp: ts,
                    source_ip,
                    threat_type: threat_type.to_string(),
                    severity: severity.to_string(),
                    matched_pattern: re.as_str().to_string(),
                    raw_log_entry: if line.len() > 512 {
                        format!("{}...", &line[..512])
                    } else {
                        line.to_string()
                    },
                    correlation_id: generate_correlation_id(),
                    affected_endpoint,
                });
                // Only report first matching pattern per line to avoid duplicates
                break;
            }
        }
    }

    // ── Brute force: >10 auth failures from same IP ──────────────────────────
    for (ip, count) in &ip_auth_fail_counts {
        if *count > 10 {
            threats.push(ThreatEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                source_ip: ip.clone(),
                threat_type: "brute-force".to_string(),
                severity: if *count > 50 { "CRITICAL" } else { "HIGH" }.to_string(),
                matched_pattern: format!("{} auth failures from same IP", count),
                raw_log_entry: format!("IP {} generated {} 401/403 responses", ip, count),
                correlation_id: generate_correlation_id(),
                affected_endpoint: "/auth".to_string(),
            });
        }
    }

    // ── Scanning: sequential 404s from same IP (>20) ─────────────────────────
    for (ip, count) in &ip_404_counts {
        if *count > 20 {
            threats.push(ThreatEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                source_ip: ip.clone(),
                threat_type: "scanning-404".to_string(),
                severity: "MEDIUM".to_string(),
                matched_pattern: format!("{} sequential 404 responses", count),
                raw_log_entry: format!("IP {} generated {} 404 responses", ip, count),
                correlation_id: generate_correlation_id(),
                affected_endpoint: "multiple".to_string(),
            });
        }
    }

    // ── 5. Anomaly detection against baseline ─────────────────────────────────
    let current_baseline = calculate_baseline(&all_entries);
    let mut anomaly_threats: Vec<ThreatEvent> = if let Some(ref saved) = saved_baseline {
        detect_anomalies(&current_baseline, saved)
    } else {
        Vec::new()
    };
    threats.append(&mut anomaly_threats);

    // ── 6. Build alert actions ────────────────────────────────────────────────
    let mut alert_actions: Vec<String> = Vec::new();

    let critical_count = threats.iter().filter(|t| t.severity == "CRITICAL").count();
    let high_count = threats.iter().filter(|t| t.severity == "HIGH").count();

    if critical_count > 0 {
        alert_actions.push(format!(
            "URGENT: {} CRITICAL threat(s) detected — send immediate Telegram alert",
            critical_count
        ));
        alert_actions.push("Trigger incident_engine for CRITICAL events".to_string());
    }
    if high_count > 0 {
        alert_actions.push(format!(
            "{} HIGH threat(s) detected — notify on-call channel",
            high_count
        ));
    }
    // Collect unique attacker IPs for blocking recommendation
    let attacker_ips: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        threats
            .iter()
            .filter(|t| t.severity == "CRITICAL" || t.severity == "HIGH")
            .map(|t| t.source_ip.clone())
            .filter(|ip| seen.insert(ip.clone()))
            .collect()
    };
    for ip in &attacker_ips {
        alert_actions.push(format!("Recommend blocking IP: {}", ip));
    }

    // Save current baseline if no prior exists (first run)
    let baseline_updated = if saved_baseline.is_none() {
        if let Some(bp) = baseline_path {
            if let Ok(json) = serde_json::to_string_pretty(&current_baseline) {
                std::fs::write(bp, json).is_ok()
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    let scan_duration_ms = start.elapsed().as_millis() as u64;

    let result = SentinelCycleResult {
        cycle_id,
        timestamp: cycle_timestamp,
        events_analyzed,
        threats,
        baseline_updated,
        alert_actions,
        scan_duration_ms,
    };

    serde_json::to_string_pretty(&result).map_err(|e| format!("Serialization error: {}", e))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Parse a single log line into a LogEntry.
/// Supports:
///   - Combined/Common Log Format:
///     127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "..." "..."
///   - JSON log lines: {"timestamp":...,"ip":...}
pub fn parse_log_line(line: &str) -> Option<LogEntry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Try JSON first
    if line.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let timestamp = v["timestamp"]
                .as_str()
                .or_else(|| v["time"].as_str())
                .or_else(|| v["@timestamp"].as_str())
                .unwrap_or("")
                .to_string();
            let ip = v["ip"]
                .as_str()
                .or_else(|| v["remote_addr"].as_str())
                .or_else(|| v["client_ip"].as_str())
                .unwrap_or("unknown")
                .to_string();
            let method = v["method"]
                .as_str()
                .or_else(|| v["request_method"].as_str())
                .unwrap_or("GET")
                .to_string();
            let path = v["path"]
                .as_str()
                .or_else(|| v["uri"].as_str())
                .or_else(|| v["request_uri"].as_str())
                .unwrap_or("/")
                .to_string();
            let status_code = v["status"]
                .as_u64()
                .or_else(|| v["status_code"].as_u64())
                .unwrap_or(200) as u16;
            let user_agent = v["user_agent"]
                .as_str()
                .or_else(|| v["http_user_agent"].as_str())
                .unwrap_or("")
                .to_string();
            let response_time_ms = v["response_time_ms"]
                .as_f64()
                .or_else(|| v["duration"].as_f64())
                .unwrap_or(0.0);
            let body_size = v["body_size"]
                .as_u64()
                .or_else(|| v["bytes_sent"].as_u64())
                .unwrap_or(0);

            return Some(LogEntry {
                timestamp,
                ip,
                method,
                path,
                status_code,
                user_agent,
                response_time_ms,
                body_size,
            });
        }
    }

    // Common/Combined Log Format regex
    // 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache HTTP/1.0" 200 2326
    let clf_re = regex::Regex::new(
        r#"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+|-)\s*(?:"[^"]*")?\s*(?:"([^"]*)")?"#,
    )
    .ok()?;

    if let Some(caps) = clf_re.captures(line) {
        let ip = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown").to_string();
        let raw_ts = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
        // Normalize CLF timestamp to RFC3339 (best-effort)
        let timestamp = parse_clf_timestamp(&raw_ts).unwrap_or(raw_ts);
        let method = caps.get(3).map(|m| m.as_str()).unwrap_or("GET").to_string();
        let path = caps.get(4).map(|m| m.as_str()).unwrap_or("/").to_string();
        let status_code: u16 = caps
            .get(5)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(200);
        let body_size: u64 = caps
            .get(6)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let user_agent = caps
            .get(7)
            .map(|m| m.as_str())
            .unwrap_or("")
            .to_string();

        return Some(LogEntry {
            timestamp,
            ip,
            method,
            path,
            status_code,
            user_agent,
            response_time_ms: 0.0,
            body_size,
        });
    }

    // Minimal fallback: extract IP and status if format is unknown
    let ip_re = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").ok()?;
    let status_re = regex::Regex::new(r"\b([1-5]\d{2})\b").ok()?;
    let ip = ip_re
        .find(line)
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let status_code: u16 = status_re
        .find(line)
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(200);

    Some(LogEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        ip,
        method: "UNKNOWN".to_string(),
        path: "UNKNOWN".to_string(),
        status_code,
        user_agent: String::new(),
        response_time_ms: 0.0,
        body_size: 0,
    })
}

/// Calculate baseline metrics from a slice of log entries.
pub fn calculate_baseline(entries: &[LogEntry]) -> BaselineMetrics {
    if entries.is_empty() {
        return BaselineMetrics {
            requests_per_minute_avg: 0.0,
            requests_per_minute_stddev: 0.0,
            error_rate_avg: 0.0,
            p95_response_time_ms: 0.0,
            auth_failures_per_hour: 0.0,
            unique_ips_per_hour: 0.0,
        };
    }

    let total = entries.len() as f64;

    // Requests per minute: group by minute bucket
    let mut minute_counts: HashMap<String, usize> = HashMap::new();
    for e in entries {
        // Use first 16 chars of ISO timestamp as minute key (YYYY-MM-DDTHH:MM)
        let minute_key = if e.timestamp.len() >= 16 {
            e.timestamp[..16].to_string()
        } else {
            e.timestamp.clone()
        };
        *minute_counts.entry(minute_key).or_insert(0) += 1;
    }

    let rpm_values: Vec<f64> = minute_counts.values().map(|&c| c as f64).collect();
    let rpm_avg = if rpm_values.is_empty() {
        0.0
    } else {
        rpm_values.iter().sum::<f64>() / rpm_values.len() as f64
    };
    let rpm_stddev = if rpm_values.len() < 2 {
        0.0
    } else {
        let variance = rpm_values
            .iter()
            .map(|v| (v - rpm_avg).powi(2))
            .sum::<f64>()
            / (rpm_values.len() - 1) as f64;
        variance.sqrt()
    };

    // Error rate (4xx/5xx)
    let errors = entries
        .iter()
        .filter(|e| e.status_code >= 400)
        .count() as f64;
    let error_rate_avg = errors / total;

    // P95 response time
    let mut rtimes: Vec<f64> = entries.iter().map(|e| e.response_time_ms).collect();
    rtimes.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p95_idx = ((rtimes.len() as f64) * 0.95) as usize;
    let p95_response_time_ms = rtimes
        .get(p95_idx.min(rtimes.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0.0);

    // Auth failures per hour
    let auth_failures = entries
        .iter()
        .filter(|e| e.status_code == 401 || e.status_code == 403)
        .count() as f64;
    // Estimate span in hours
    let span_hours = (minute_counts.len() as f64 / 60.0).max(1.0 / 60.0);
    let auth_failures_per_hour = auth_failures / span_hours;

    // Unique IPs per hour
    let unique_ips = entries
        .iter()
        .map(|e| e.ip.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len() as f64;
    let unique_ips_per_hour = unique_ips / span_hours;

    BaselineMetrics {
        requests_per_minute_avg: rpm_avg,
        requests_per_minute_stddev: rpm_stddev,
        error_rate_avg,
        p95_response_time_ms,
        auth_failures_per_hour,
        unique_ips_per_hour,
    }
}

/// Detect anomalies by comparing current metrics to saved baseline (±3 stddev rule).
pub fn detect_anomalies(
    current: &BaselineMetrics,
    baseline: &BaselineMetrics,
) -> Vec<ThreatEvent> {
    let mut events = Vec::new();
    let now = chrono::Utc::now().to_rfc3339();

    // RPM spike: current avg exceeds baseline avg + 3*stddev
    let rpm_threshold = baseline.requests_per_minute_avg + 3.0 * baseline.requests_per_minute_stddev;
    if baseline.requests_per_minute_stddev > 0.0
        && current.requests_per_minute_avg > rpm_threshold
    {
        events.push(ThreatEvent {
            timestamp: now.clone(),
            source_ip: "multiple".to_string(),
            threat_type: "traffic-spike-anomaly".to_string(),
            severity: if current.requests_per_minute_avg > rpm_threshold * 2.0 {
                "CRITICAL"
            } else {
                "HIGH"
            }
            .to_string(),
            matched_pattern: format!(
                "RPM {:.1} exceeds baseline threshold {:.1} (avg={:.1}, stddev={:.1})",
                current.requests_per_minute_avg,
                rpm_threshold,
                baseline.requests_per_minute_avg,
                baseline.requests_per_minute_stddev
            ),
            raw_log_entry: "Anomaly detected via baseline comparison".to_string(),
            correlation_id: generate_correlation_id(),
            affected_endpoint: "all".to_string(),
        });
    }

    // Error rate spike
    let error_threshold = baseline.error_rate_avg + 3.0 * (baseline.error_rate_avg * 0.3 + 0.01);
    if current.error_rate_avg > error_threshold && current.error_rate_avg > 0.1 {
        events.push(ThreatEvent {
            timestamp: now.clone(),
            source_ip: "multiple".to_string(),
            threat_type: "error-rate-anomaly".to_string(),
            severity: "HIGH".to_string(),
            matched_pattern: format!(
                "Error rate {:.2}% exceeds baseline {:.2}% by >3 sigma",
                current.error_rate_avg * 100.0,
                baseline.error_rate_avg * 100.0
            ),
            raw_log_entry: "Anomaly detected via baseline comparison".to_string(),
            correlation_id: generate_correlation_id(),
            affected_endpoint: "all".to_string(),
        });
    }

    // Auth failure spike
    let auth_threshold =
        baseline.auth_failures_per_hour + 3.0 * (baseline.auth_failures_per_hour * 0.5 + 1.0);
    if current.auth_failures_per_hour > auth_threshold {
        events.push(ThreatEvent {
            timestamp: now.clone(),
            source_ip: "multiple".to_string(),
            threat_type: "auth-failure-anomaly".to_string(),
            severity: "HIGH".to_string(),
            matched_pattern: format!(
                "Auth failures {:.0}/hr exceeds baseline {:.0}/hr by >3 sigma",
                current.auth_failures_per_hour, baseline.auth_failures_per_hour
            ),
            raw_log_entry: "Anomaly detected via baseline comparison".to_string(),
            correlation_id: generate_correlation_id(),
            affected_endpoint: "/auth".to_string(),
        });
    }

    // P95 latency degradation (could indicate slowloris/resource exhaustion)
    let p95_threshold = baseline.p95_response_time_ms * 4.0 + 500.0;
    if baseline.p95_response_time_ms > 0.0 && current.p95_response_time_ms > p95_threshold {
        events.push(ThreatEvent {
            timestamp: now.clone(),
            source_ip: "multiple".to_string(),
            threat_type: "latency-anomaly".to_string(),
            severity: "MEDIUM".to_string(),
            matched_pattern: format!(
                "P95 latency {:.0}ms exceeds 4x baseline {:.0}ms",
                current.p95_response_time_ms, baseline.p95_response_time_ms
            ),
            raw_log_entry: "Anomaly detected via baseline comparison".to_string(),
            correlation_id: generate_correlation_id(),
            affected_endpoint: "all".to_string(),
        });
    }

    events
}

// ─── Private utilities ────────────────────────────────────────────────────────

fn generate_cycle_id() -> String {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    format!("SENTINEL-{}", ts)
}

fn generate_correlation_id() -> String {
    // Use a simple UUID-like hex string built from timestamp + pseudo-random nibbles
    let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    format!("corr-{:x}", ts ^ 0xDEAD_BEEF_CAFE_1234u64)
}

fn extract_endpoint(line: &str) -> String {
    // Try to pull the first HTTP path-like token
    let re = regex::Regex::new(r#"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)"#).ok();
    if let Some(r) = re {
        if let Some(caps) = r.captures(line) {
            return caps.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
        }
    }
    // Fallback: look for first /path token
    let path_re = regex::Regex::new(r"(/[^\s?#]{1,200})").ok();
    if let Some(r) = path_re {
        if let Some(m) = r.find(line) {
            return m.as_str().to_string();
        }
    }
    "unknown".to_string()
}

fn extract_log_timestamp(line: &str) -> Option<String> {
    let iso_re = regex::Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})").ok()?;
    if let Some(m) = iso_re.find(line) {
        return Some(m.as_str().to_string());
    }
    // CLF: [15/Jan/2024:14:30:00 +0000]
    let clf_re = regex::Regex::new(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[^\]]*)\]").ok()?;
    if let Some(caps) = clf_re.captures(line) {
        let raw = caps.get(1)?.as_str();
        return Some(parse_clf_timestamp(raw).unwrap_or_else(|| raw.to_string()));
    }
    None
}

/// Convert CLF timestamp "15/Jan/2024:14:30:00 +0000" → RFC3339 (best-effort).
fn parse_clf_timestamp(s: &str) -> Option<String> {
    // Strip potential surrounding brackets
    let s = s.trim_matches(|c| c == '[' || c == ']');
    // Format: 15/Jan/2024:14:30:00 +0000
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() < 2 {
        return None;
    }
    let date_part = parts[0]; // "15/Jan/2024"
    let rest = parts[1]; // "14:30:00 +0000"
    let date_segs: Vec<&str> = date_part.split('/').collect();
    if date_segs.len() != 3 {
        return None;
    }
    let day: u32 = date_segs[0].parse().ok()?;
    let month_idx = months.iter().position(|&m| m == date_segs[1])? + 1;
    let year: i32 = date_segs[2].parse().ok()?;
    let time_tz: Vec<&str> = rest.splitn(2, ' ').collect();
    let time_str = time_tz[0]; // "14:30:00"
    let tz_str = time_tz.get(1).copied().unwrap_or("+0000");
    let tz_str = if tz_str.len() == 5 {
        // +0000 → +00:00
        format!("{}:{}", &tz_str[..3], &tz_str[3..])
    } else {
        tz_str.to_string()
    };
    Some(format!(
        "{:04}-{:02}-{:02}T{}{}", year, month_idx, day, time_str, tz_str
    ))
}

// ─── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clf_log_line() {
        let line = r#"192.168.1.100 - frank [10/Oct/2023:13:55:36 +0000] "GET /apache_pb.gif HTTP/1.0" 200 2326 "-" "Mozilla/5.0""#;
        let entry = parse_log_line(line).expect("Should parse CLF line");
        assert_eq!(entry.ip, "192.168.1.100");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/apache_pb.gif");
        assert_eq!(entry.status_code, 200);
        assert_eq!(entry.body_size, 2326);
    }

    #[test]
    fn test_parse_json_log_line() {
        let line = r#"{"timestamp":"2024-01-15T14:30:00Z","ip":"10.0.0.1","method":"POST","path":"/login","status":401,"user_agent":"curl/7.68","response_time_ms":12.5,"bytes_sent":45}"#;
        let entry = parse_log_line(line).expect("Should parse JSON line");
        assert_eq!(entry.ip, "10.0.0.1");
        assert_eq!(entry.status_code, 401);
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/login");
    }

    #[test]
    fn test_parse_empty_line() {
        assert!(parse_log_line("").is_none());
        assert!(parse_log_line("   ").is_none());
    }

    #[test]
    fn test_calculate_baseline_empty() {
        let baseline = calculate_baseline(&[]);
        assert_eq!(baseline.requests_per_minute_avg, 0.0);
        assert_eq!(baseline.error_rate_avg, 0.0);
    }

    #[test]
    fn test_calculate_baseline_non_empty() {
        let entries: Vec<LogEntry> = (0..60)
            .map(|i| LogEntry {
                timestamp: format!("2024-01-15T14:{:02}:00Z", i % 60),
                ip: format!("10.0.0.{}", i % 10 + 1),
                method: "GET".to_string(),
                path: "/api".to_string(),
                status_code: if i % 10 == 0 { 500 } else { 200 },
                user_agent: "test".to_string(),
                response_time_ms: 50.0 + i as f64,
                body_size: 100,
            })
            .collect();
        let baseline = calculate_baseline(&entries);
        assert!(baseline.error_rate_avg > 0.0);
        assert!(baseline.p95_response_time_ms > 0.0);
        assert!(baseline.unique_ips_per_hour > 0.0);
    }

    #[test]
    fn test_sqli_pattern_matching() {
        let patterns: Vec<(regex::Regex, &str, &str)> = ATTACK_PATTERNS
            .iter()
            .filter_map(|(pat, ttype, sev)| {
                regex::Regex::new(pat).ok().map(|r| (r, *ttype, *sev))
            })
            .collect();

        let sqli_lines = [
            r#"GET /search?q=' UNION SELECT username,password FROM users-- HTTP/1.1"#,
            r#"GET /item?id=1 OR 1=1-- HTTP/1.1"#,
            r#"POST /admin?cmd='; DROP TABLE users;-- HTTP/1.1"#,
        ];

        for line in &sqli_lines {
            let matched = patterns.iter().any(|(re, ttype, _)| {
                re.is_match(line) && ttype.contains("sqli")
            });
            assert!(matched, "SQLi not detected in: {}", line);
        }
    }

    #[test]
    fn test_xss_pattern_matching() {
        let patterns: Vec<(regex::Regex, &str, &str)> = ATTACK_PATTERNS
            .iter()
            .filter_map(|(pat, ttype, sev)| {
                regex::Regex::new(pat).ok().map(|r| (r, *ttype, *sev))
            })
            .collect();

        let xss_lines = [
            r#"GET /search?q=<script>alert(1)</script> HTTP/1.1"#,
            r#"GET /img?src=x+onerror=document.cookie HTTP/1.1"#,
            r#"GET /link?url=javascript:alert(1) HTTP/1.1"#,
        ];

        for line in &xss_lines {
            let matched = patterns.iter().any(|(re, ttype, _)| {
                re.is_match(line) && ttype.contains("xss")
            });
            assert!(matched, "XSS not detected in: {}", line);
        }
    }

    #[test]
    fn test_ssrf_pattern_matching() {
        let patterns: Vec<(regex::Regex, &str, &str)> = ATTACK_PATTERNS
            .iter()
            .filter_map(|(pat, ttype, sev)| {
                regex::Regex::new(pat).ok().map(|r| (r, *ttype, *sev))
            })
            .collect();

        let ssrf_line = r#"GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1"#;
        let matched = patterns.iter().any(|(re, _, _)| re.is_match(ssrf_line));
        assert!(matched, "SSRF not detected");
    }

    #[test]
    fn test_path_traversal_pattern_matching() {
        let patterns: Vec<(regex::Regex, &str, &str)> = ATTACK_PATTERNS
            .iter()
            .filter_map(|(pat, ttype, sev)| {
                regex::Regex::new(pat).ok().map(|r| (r, *ttype, *sev))
            })
            .collect();

        let traversal_lines = [
            r#"GET /download?file=../../../etc/passwd HTTP/1.1"#,
            r#"GET /file?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1"#,
        ];

        for line in &traversal_lines {
            let matched = patterns
                .iter()
                .any(|(re, ttype, _)| re.is_match(line) && ttype.contains("traversal") || ttype.contains("path"));
            assert!(matched, "Path traversal not detected in: {}", line);
        }
    }

    #[test]
    fn test_detect_anomalies_rpm_spike() {
        let baseline = BaselineMetrics {
            requests_per_minute_avg: 100.0,
            requests_per_minute_stddev: 10.0,
            error_rate_avg: 0.01,
            p95_response_time_ms: 200.0,
            auth_failures_per_hour: 5.0,
            unique_ips_per_hour: 20.0,
        };
        let current = BaselineMetrics {
            requests_per_minute_avg: 500.0, // massive spike
            requests_per_minute_stddev: 20.0,
            error_rate_avg: 0.01,
            p95_response_time_ms: 200.0,
            auth_failures_per_hour: 5.0,
            unique_ips_per_hour: 20.0,
        };
        let anomalies = detect_anomalies(&current, &baseline);
        assert!(
            anomalies.iter().any(|e| e.threat_type == "traffic-spike-anomaly"),
            "RPM spike should be flagged"
        );
    }

    #[test]
    fn test_clf_timestamp_parse() {
        let ts = parse_clf_timestamp("15/Jan/2024:14:30:00 +0000");
        assert!(ts.is_some());
        let ts_str = ts.unwrap();
        assert!(ts_str.contains("2024-01-15"));
    }
}
