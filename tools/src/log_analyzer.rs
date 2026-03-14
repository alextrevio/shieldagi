/// ShieldAGI Tool: log_analyzer
///
/// Analyzes application and server logs for attack patterns, anomalies,
/// and suspicious activity using pattern matching against known attack signatures.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct LogAnalyzerResult {
    pub log_source: String,
    pub time_range_minutes: u64,
    pub total_lines_analyzed: usize,
    pub total_alerts: usize,
    pub alerts: Vec<LogAlert>,
    pub summary: LogSummary,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogAlert {
    pub pattern_name: String,
    pub category: String,
    pub severity: String,
    pub matched_line: String,
    pub line_number: usize,
    pub timestamp: Option<String>,
    pub source_ip: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogSummary {
    pub sqli_attempts: usize,
    pub xss_attempts: usize,
    pub path_traversal_attempts: usize,
    pub brute_force_indicators: usize,
    pub error_spikes: usize,
    pub unique_source_ips: usize,
    pub top_offending_ips: Vec<(String, usize)>,
}

/// Attack signature patterns
const ATTACK_PATTERNS: &[(&str, &str, &str, &str)] = &[
    // (regex_pattern, name, category, severity)
    (r"(?i)(union\s+select|union\s+all\s+select)", "sqli-union", "sql-injection", "HIGH"),
    (r"(?i)(or\s+1\s*=\s*1|'\s*or\s*')", "sqli-tautology", "sql-injection", "HIGH"),
    (r"(?i)(;|\-\-|\#).*(?:drop|delete|update|insert|alter)", "sqli-destructive", "sql-injection", "CRITICAL"),
    (r"(?i)sleep\s*\(\d+\)|benchmark\s*\(", "sqli-time-based", "sql-injection", "HIGH"),
    (r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)", "xss-payload", "xss", "HIGH"),
    (r"(?i)(alert\s*\(|document\.cookie|document\.location)", "xss-execution", "xss", "HIGH"),
    (r"(?i)(\.\./|\.\.\\|%2e%2e|%252e%252e)", "path-traversal", "traversal", "HIGH"),
    (r"(?i)(/etc/passwd|/etc/shadow|/proc/self)", "path-traversal-target", "traversal", "CRITICAL"),
    (r"(?i)(cmd=|exec=|system\(|eval\(|passthru\()", "command-injection", "injection", "CRITICAL"),
    (r"(?i)(admin|root|administrator).*(?:login|auth).*(?:fail|error|invalid)", "brute-force-admin", "brute-force", "MEDIUM"),
    (r"HTTP/\d\.\d\"\s+(?:401|403)\s+", "auth-failure", "brute-force", "LOW"),
    (r"HTTP/\d\.\d\"\s+(?:500|502|503)\s+", "server-error", "availability", "MEDIUM"),
    (r"(?i)(169\.254\.169\.254|metadata\.google\.internal)", "ssrf-metadata", "ssrf", "CRITICAL"),
    (r"(?i)(file://|gopher://|dict://)", "ssrf-protocol", "ssrf", "HIGH"),
];

pub async fn tool_log_analyzer(input: &serde_json::Value) -> Result<String, String> {
    let log_source = input["log_source"]
        .as_str()
        .ok_or("Missing 'log_source' field")?;

    let time_range_minutes = input["time_range_minutes"].as_u64().unwrap_or(5);
    let baseline_path = input["baseline_path"].as_str();
    let custom_patterns: Vec<String> = input["patterns"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let start = std::time::Instant::now();

    // Read log content — supports file path or command output
    let log_content = if log_source.starts_with('/') || log_source.starts_with('.') {
        // File path
        std::fs::read_to_string(log_source)
            .map_err(|e| format!("Failed to read log file: {}", e))?
    } else if log_source.starts_with("http") {
        // HTTP endpoint (e.g., log API)
        let output = Command::new("curl")
            .args(["-s", "--max-time", "15", log_source])
            .output()
            .map_err(|e| format!("Failed to fetch logs from endpoint: {}", e))?;
        String::from_utf8_lossy(&output.stdout).to_string()
    } else if log_source.starts_with("docker:") {
        // Docker container logs
        let container = log_source.strip_prefix("docker:").unwrap_or("");
        let minutes_str = format!("{}m", time_range_minutes);
        let output = Command::new("docker")
            .args(["logs", "--since", &minutes_str, container])
            .output()
            .map_err(|e| format!("Failed to get docker logs: {}", e))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("{}\n{}", stdout, stderr)
    } else {
        return Err(format!("Unsupported log source format: {}", log_source));
    };

    let lines: Vec<&str> = log_content.lines().collect();
    let total_lines = lines.len();
    let mut alerts = Vec::new();
    let mut sqli_count = 0usize;
    let mut xss_count = 0usize;
    let mut traversal_count = 0usize;
    let mut brute_force_count = 0usize;
    let mut error_count = 0usize;
    let mut ip_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // Compile regex patterns
    let compiled_patterns: Vec<(regex::Regex, &str, &str, &str)> = ATTACK_PATTERNS
        .iter()
        .filter_map(|(pattern, name, cat, sev)| {
            regex::Regex::new(pattern).ok().map(|r| (r, *name, *cat, *sev))
        })
        .collect();

    // Compile custom patterns
    let compiled_custom: Vec<(regex::Regex, String)> = custom_patterns
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok().map(|r| (r, p.clone())))
        .collect();

    // IP extraction regex
    let ip_regex = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").ok();

    for (line_num, line) in lines.iter().enumerate() {
        // Extract source IP if present
        let source_ip = ip_regex
            .as_ref()
            .and_then(|r| r.find(line).map(|m| m.as_str().to_string()));

        if let Some(ref ip) = source_ip {
            *ip_counts.entry(ip.clone()).or_insert(0) += 1;
        }

        // Match against attack patterns
        for (regex, name, category, severity) in &compiled_patterns {
            if regex.is_match(line) {
                match *category {
                    "sql-injection" => sqli_count += 1,
                    "xss" => xss_count += 1,
                    "traversal" => traversal_count += 1,
                    "brute-force" => brute_force_count += 1,
                    "availability" => error_count += 1,
                    _ => {}
                }

                // Extract timestamp (common formats)
                let timestamp = extract_timestamp(line);

                alerts.push(LogAlert {
                    pattern_name: name.to_string(),
                    category: category.to_string(),
                    severity: severity.to_string(),
                    matched_line: if line.len() > 500 {
                        format!("{}...", &line[..500])
                    } else {
                        line.to_string()
                    },
                    line_number: line_num + 1,
                    timestamp,
                    source_ip: source_ip.clone(),
                });
            }
        }

        // Match custom patterns
        for (regex, pattern_str) in &compiled_custom {
            if regex.is_match(line) {
                alerts.push(LogAlert {
                    pattern_name: format!("custom:{}", pattern_str),
                    category: "custom".to_string(),
                    severity: "MEDIUM".to_string(),
                    matched_line: if line.len() > 500 {
                        format!("{}...", &line[..500])
                    } else {
                        line.to_string()
                    },
                    line_number: line_num + 1,
                    timestamp: extract_timestamp(line),
                    source_ip: source_ip.clone(),
                });
            }
        }
    }

    // Build top offending IPs
    let mut ip_vec: Vec<(String, usize)> = ip_counts.into_iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let unique_ips = ip_vec.len();
    let top_ips: Vec<(String, usize)> = ip_vec.into_iter().take(10).collect();

    let duration = start.elapsed().as_millis() as u64;

    let result = LogAnalyzerResult {
        log_source: log_source.to_string(),
        time_range_minutes,
        total_lines_analyzed: total_lines,
        total_alerts: alerts.len(),
        alerts,
        summary: LogSummary {
            sqli_attempts: sqli_count,
            xss_attempts: xss_count,
            path_traversal_attempts: traversal_count,
            brute_force_indicators: brute_force_count,
            error_spikes: error_count,
            unique_source_ips: unique_ips,
            top_offending_ips: top_ips,
        },
        scan_duration_ms: duration,
        error: None,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

fn extract_timestamp(line: &str) -> Option<String> {
    // Try common timestamp formats
    let ts_patterns = [
        // ISO 8601: 2024-01-15T14:30:00
        regex::Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
        // Common log format: [15/Jan/2024:14:30:00 +0000]
        regex::Regex::new(r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*\]"),
        // Syslog: Jan 15 14:30:00
        regex::Regex::new(r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
    ];

    for pattern in &ts_patterns {
        if let Ok(re) = pattern {
            if let Some(m) = re.find(line) {
                return Some(m.as_str().to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_timestamp() {
        assert!(extract_timestamp("2024-01-15T14:30:00 GET /api/test").is_some());
        assert!(extract_timestamp("[15/Jan/2024:14:30:00 +0000] GET /").is_some());
        assert!(extract_timestamp("no timestamp here").is_none());
    }
}
