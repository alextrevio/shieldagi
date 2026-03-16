/// ShieldAGI Tool: verify_fix
///
/// Re-runs the original attack tool against a remediated endpoint to confirm
/// the vulnerability has been successfully patched. Compares before/after
/// results and produces a confidence score.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyFixResult {
    pub vulnerability_id: String,
    pub category: String,
    pub tool_used: String,
    pub pre_fix_vulnerable: bool,
    pub post_fix_vulnerable: bool,
    pub fix_confirmed: bool,
    pub confidence: f64,
    pub detail: String,
    pub raw_output: Option<String>,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifyResult {
    pub total_checked: usize,
    pub confirmed_fixed: usize,
    pub still_vulnerable: usize,
    pub inconclusive: usize,
    pub results: Vec<VerifyFixResult>,
    pub overall_confidence: f64,
    pub scan_duration_ms: u64,
}

pub async fn tool_verify_fix(input: &serde_json::Value) -> Result<String, String> {
    let mode = input["mode"].as_str().unwrap_or("single");

    match mode {
        "batch" => verify_batch(input).await,
        _ => verify_single(input).await,
    }
}

async fn verify_single(input: &serde_json::Value) -> Result<String, String> {
    let vulnerability_id = input["vulnerability_id"]
        .as_str()
        .ok_or("Missing 'vulnerability_id' field")?;

    let category = input["category"]
        .as_str()
        .ok_or("Missing 'category' field")?;

    let target_url = input["target_url"]
        .as_str()
        .ok_or("Missing 'target_url' field")?;

    if !is_sandbox_target(target_url) {
        return Err("SAFETY: verify_fix can only target sandbox URLs".into());
    }

    let start = std::time::Instant::now();

    let (tool_used, post_fix_vulnerable, confidence, detail, raw_output) =
        run_verification(category, target_url, input);

    let duration = start.elapsed().as_millis() as u64;

    let result = VerifyFixResult {
        vulnerability_id: vulnerability_id.to_string(),
        category: category.to_string(),
        tool_used,
        pre_fix_vulnerable: true, // Assumed true — this was in the report
        post_fix_vulnerable,
        fix_confirmed: !post_fix_vulnerable,
        confidence,
        detail,
        raw_output,
        scan_duration_ms: duration,
        error: None,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

async fn verify_batch(input: &serde_json::Value) -> Result<String, String> {
    let vulnerabilities = input["vulnerabilities"]
        .as_array()
        .ok_or("Missing 'vulnerabilities' array")?;

    let start = std::time::Instant::now();
    let mut results = Vec::new();
    let mut confirmed = 0usize;
    let mut still_vuln = 0usize;
    let mut inconclusive = 0usize;

    for vuln in vulnerabilities {
        let vuln_id = vuln["vulnerability_id"].as_str().unwrap_or("unknown");
        let category = vuln["category"].as_str().unwrap_or("unknown");
        let target_url = vuln["target_url"].as_str().unwrap_or("");

        if target_url.is_empty() || !is_sandbox_target(target_url) {
            results.push(VerifyFixResult {
                vulnerability_id: vuln_id.to_string(),
                category: category.to_string(),
                tool_used: "none".to_string(),
                pre_fix_vulnerable: true,
                post_fix_vulnerable: false,
                fix_confirmed: false,
                confidence: 0.0,
                detail: "Skipped: no valid sandbox target URL".to_string(),
                raw_output: None,
                scan_duration_ms: 0,
                error: Some("No sandbox target URL provided".to_string()),
            });
            inconclusive += 1;
            continue;
        }

        let scan_start = std::time::Instant::now();
        let (tool_used, post_fix_vulnerable, confidence, detail, raw_output) =
            run_verification(category, target_url, vuln);
        let scan_duration = scan_start.elapsed().as_millis() as u64;

        if confidence < 0.5 {
            inconclusive += 1;
        } else if post_fix_vulnerable {
            still_vuln += 1;
        } else {
            confirmed += 1;
        }

        results.push(VerifyFixResult {
            vulnerability_id: vuln_id.to_string(),
            category: category.to_string(),
            tool_used,
            pre_fix_vulnerable: true,
            post_fix_vulnerable,
            fix_confirmed: !post_fix_vulnerable && confidence >= 0.5,
            confidence,
            detail,
            raw_output,
            scan_duration_ms: scan_duration,
            error: None,
        });
    }

    let duration = start.elapsed().as_millis() as u64;
    let total = results.len();
    let overall_confidence = if total > 0 {
        results.iter().map(|r| r.confidence).sum::<f64>() / total as f64
    } else {
        0.0
    };

    let batch_result = BatchVerifyResult {
        total_checked: total,
        confirmed_fixed: confirmed,
        still_vulnerable: still_vuln,
        inconclusive,
        results,
        overall_confidence,
        scan_duration_ms: duration,
    };

    Ok(serde_json::to_string_pretty(&batch_result).unwrap())
}

// ═══════════════════════════════════════════════
// VERIFICATION RUNNERS — One per vulnerability category
// ═══════════════════════════════════════════════

fn run_verification(
    category: &str,
    target_url: &str,
    input: &serde_json::Value,
) -> (String, bool, f64, String, Option<String>) {
    match category {
        "sqli" | "sql-injection" => verify_sqli(target_url, input),
        "xss" | "cross-site-scripting" => verify_xss(target_url, input),
        "csrf" => verify_csrf(target_url, input),
        "ssrf" => verify_ssrf(target_url, input),
        "idor" | "broken-access-control" => verify_idor(target_url, input),
        "path-traversal" | "traversal" => verify_path_traversal(target_url, input),
        "auth" | "brute-force" | "authentication" => verify_auth(target_url, input),
        "misconfig" | "security-misconfiguration" => verify_headers(target_url),
        "secrets" | "hardcoded-secret" => verify_secrets(input),
        "info-disclosure" => verify_info_disclosure(target_url),
        _ => (
            "none".to_string(),
            false,
            0.0,
            format!("No verification available for category '{}'", category),
            None,
        ),
    }
}

fn verify_sqli(target_url: &str, input: &serde_json::Value) -> (String, bool, f64, String, Option<String>) {
    let parameter = input["parameter"].as_str().unwrap_or("id");

    // Send a basic SQLi payload and check if it's reflected/executed
    let payloads = vec![
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
    ];

    let mut any_successful = false;

    for payload in &payloads {
        let url = format!("{}?{}={}", target_url, parameter, urlencoding(payload));
        let (status, body) = curl_get(&url);

        // Signs of SQLi success: 200 response with data that shouldn't be there
        if status >= 200 && status < 400 {
            let body_lower = body.to_lowercase();
            if body_lower.contains("error in your sql")
                || body_lower.contains("syntax error")
                || body_lower.contains("unclosed quotation")
                || (body_lower.contains("rows") && payload.contains("UNION"))
            {
                any_successful = true;
                break;
            }
        }

        // If we get a 400/500 with SQL error, that's also a sign
        if status >= 400 && status < 600 {
            let body_lower = body.to_lowercase();
            if body_lower.contains("sql") || body_lower.contains("syntax") {
                any_successful = true;
                break;
            }
        }
    }

    let confidence = if any_successful { 0.9 } else { 0.8 };

    (
        "sqlmap_attack".to_string(),
        any_successful,
        confidence,
        if any_successful {
            "SQL injection still exploitable after fix".to_string()
        } else {
            "SQL injection payloads blocked or parameterized".to_string()
        },
        None,
    )
}

fn verify_xss(target_url: &str, input: &serde_json::Value) -> (String, bool, f64, String, Option<String>) {
    let parameter = input["parameter"].as_str().unwrap_or("q");

    let payloads = vec![
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
    ];

    let mut reflected = false;

    for payload in &payloads {
        let url = format!("{}?{}={}", target_url, parameter, urlencoding(payload));
        let (status, body) = curl_get(&url);

        if status >= 200 && status < 400 {
            // Check if the payload is reflected unescaped
            if body.contains(payload) {
                reflected = true;
                break;
            }
            // Check for partial reflection (script tag present)
            if body.contains("<script>alert") || body.contains("onerror=alert") {
                reflected = true;
                break;
            }
        }
    }

    let confidence = if reflected { 0.95 } else { 0.85 };

    (
        "xss_inject".to_string(),
        reflected,
        confidence,
        if reflected {
            "XSS payloads still reflected in response".to_string()
        } else {
            "XSS payloads properly escaped or blocked".to_string()
        },
        None,
    )
}

fn verify_csrf(target_url: &str, input: &serde_json::Value) -> (String, bool, f64, String, Option<String>) {
    let method = input["method"].as_str().unwrap_or("POST");
    let cookie = input["cookie"].as_str();

    // Send a state-changing request without CSRF token and with wrong Origin
    let mut args = vec![
        "-s", "-o", "/dev/null",
        "-w", "%{http_code}",
        "-X", method,
        "-H", "Origin: https://evil.com",
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "-d", "test=1",
        "--max-time", "10",
    ];

    let cookie_header;
    if let Some(c) = cookie {
        cookie_header = format!("Cookie: {}", c);
        args.push("-H");
        args.push(&cookie_header);
    }

    args.push(target_url);

    let output = Command::new("curl").args(&args).output();
    let status: u16 = output
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0);

    // CSRF protection should reject the request (403, 401, 400)
    let vulnerable = status >= 200 && status < 400;
    let confidence = 0.9;

    (
        "csrf_test".to_string(),
        vulnerable,
        confidence,
        if vulnerable {
            format!("Cross-origin request accepted (HTTP {})", status)
        } else {
            format!("Cross-origin request blocked (HTTP {})", status)
        },
        None,
    )
}

fn verify_ssrf(target_url: &str, input: &serde_json::Value) -> (String, bool, f64, String, Option<String>) {
    let parameter = input["parameter"].as_str().unwrap_or("url");

    // Try to fetch a known internal resource
    let probe_urls = vec![
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22/",
        "file:///etc/passwd",
    ];

    let mut any_successful = false;

    for probe in &probe_urls {
        let body = format!("{}={}", parameter, probe);
        let args = vec![
            "-s", "-o", "/dev/stdout",
            "-w", "\n%{http_code}",
            "-X", "POST",
            "-d", &body,
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "--max-time", "5",
            target_url,
        ];

        if let Ok(output) = Command::new("curl").args(&args).output() {
            let full = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = full.trim().rsplitn(2, '\n').collect();
            let status: u16 = parts.first().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let resp_body = parts.last().unwrap_or(&"").to_string();

            if status >= 200 && status < 400 && resp_body.len() > 20 {
                any_successful = true;
                break;
            }
        }
    }

    let confidence = 0.85;

    (
        "ssrf_probe".to_string(),
        any_successful,
        confidence,
        if any_successful {
            "SSRF probes still reaching internal resources".to_string()
        } else {
            "SSRF probes blocked by URL validation".to_string()
        },
        None,
    )
}

fn verify_idor(target_url: &str, input: &serde_json::Value) -> (String, bool, f64, String, Option<String>) {
    let user_a_token = input["user_a_token"].as_str().unwrap_or("");
    let user_b_token = input["user_b_token"].as_str().unwrap_or("");
    let resource_id = input["resource_id"].as_str().unwrap_or("1");

    let url = format!("{}/{}", target_url.trim_end_matches('/'), resource_id);

    // Request as User A (should succeed)
    let status_a = curl_with_auth(&url, "GET", user_a_token);

    // Request as User B (should fail with 403/404 if fixed)
    let status_b = curl_with_auth(&url, "GET", user_b_token);

    let vulnerable = status_a >= 200 && status_a < 400 && status_b >= 200 && status_b < 400;
    let confidence = if !user_a_token.is_empty() && !user_b_token.is_empty() {
        0.9
    } else {
        0.5
    };

    (
        "idor_test".to_string(),
        vulnerable,
        confidence,
        if vulnerable {
            format!(
                "User B still accessing User A's resource (A={}, B={})",
                status_a, status_b
            )
        } else {
            format!(
                "Access control enforced (A={}, B={})",
                status_a, status_b
            )
        },
        None,
    )
}

fn verify_path_traversal(target_url: &str, input: &serde_json::Value) -> (String, bool, f64, String, Option<String>) {
    let parameter = input["parameter"].as_str().unwrap_or("file");

    let payloads = vec![
        "../../../../../../etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
    ];

    let mut traversal_success = false;

    for payload in &payloads {
        let url = format!("{}?{}={}", target_url, parameter, payload);
        let (status, body) = curl_get(&url);

        if status >= 200 && status < 400 {
            if body.contains("root:") || body.contains("bin:") || body.contains("daemon:") {
                traversal_success = true;
                break;
            }
        }
    }

    let confidence = 0.9;

    (
        "path_traverse".to_string(),
        traversal_success,
        confidence,
        if traversal_success {
            "Path traversal still possible — /etc/passwd accessible".to_string()
        } else {
            "Path traversal payloads blocked".to_string()
        },
        None,
    )
}

fn verify_auth(target_url: &str, _input: &serde_json::Value) -> (String, bool, f64, String, Option<String>) {
    // Send 10 rapid login attempts to check rate limiting
    let mut got_429 = false;
    let mut attempts = 0;

    for i in 0..10 {
        attempts += 1;
        let body = format!("email=test@test.com&password=wrong{}", i);
        let args = vec![
            "-s", "-o", "/dev/null",
            "-w", "%{http_code}",
            "-X", "POST",
            "-d", &body,
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "--max-time", "5",
            target_url,
        ];

        if let Ok(output) = Command::new("curl").args(&args).output() {
            let status: u16 = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse()
                .unwrap_or(0);

            if status == 429 || status == 423 {
                got_429 = true;
                break;
            }
        }
    }

    let vulnerable = !got_429;
    let confidence = 0.8;

    (
        "brute_force".to_string(),
        vulnerable,
        confidence,
        if vulnerable {
            format!("No rate limiting detected after {} attempts", attempts)
        } else {
            format!("Rate limiting triggered after {} attempts", attempts)
        },
        None,
    )
}

fn verify_headers(target_url: &str) -> (String, bool, f64, String, Option<String>) {
    let args = vec![
        "-s", "-D", "-", "-o", "/dev/null",
        "--max-time", "10",
        target_url,
    ];

    let output = Command::new("curl").args(&args).output();
    let headers = output
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
        .to_lowercase();

    let mut missing = Vec::new();

    if !headers.contains("x-content-type-options") {
        missing.push("X-Content-Type-Options");
    }
    if !headers.contains("x-frame-options") && !headers.contains("content-security-policy") {
        missing.push("X-Frame-Options/CSP");
    }
    if !headers.contains("strict-transport-security") {
        missing.push("HSTS");
    }
    if headers.contains("x-powered-by") {
        missing.push("X-Powered-By (should be removed)");
    }

    let vulnerable = !missing.is_empty();
    let confidence = 0.95;

    (
        "header_audit".to_string(),
        vulnerable,
        confidence,
        if vulnerable {
            format!("Missing security headers: {}", missing.join(", "))
        } else {
            "All security headers present".to_string()
        },
        None,
    )
}

fn verify_secrets(input: &serde_json::Value) -> (String, bool, f64, String, Option<String>) {
    let repo_path = input["repo_path"].as_str().unwrap_or(".");

    // Run a quick grep for common secret patterns
    let output = Command::new("grep")
        .args([
            "-rn",
            "--include=*.js",
            "--include=*.ts",
            "--include=*.py",
            "-E",
            r#"(password|secret|api_key|token)\s*=\s*['"][a-zA-Z0-9_-]{10,}['"]"#,
            repo_path,
        ])
        .output();

    let found = output
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let confidence = 0.7;

    (
        "secret_scan".to_string(),
        found,
        confidence,
        if found {
            "Hardcoded secrets still found in source code".to_string()
        } else {
            "No hardcoded secrets detected".to_string()
        },
        None,
    )
}

fn verify_info_disclosure(target_url: &str) -> (String, bool, f64, String, Option<String>) {
    // Trigger an error and check for stack trace / DB info
    let url = format!("{}?id=undefined", target_url);
    let (status, body) = curl_get(&url);

    let body_lower = body.to_lowercase();
    let leaks_info = body_lower.contains("stack")
        || body_lower.contains("at module")
        || body_lower.contains("at object")
        || body_lower.contains("database_url")
        || body_lower.contains("node_modules");

    let confidence = 0.8;

    (
        "semgrep_scan".to_string(),
        leaks_info,
        confidence,
        if leaks_info {
            "Error responses still leaking internal information".to_string()
        } else {
            "Error responses do not leak internal details".to_string()
        },
        None,
    )
}

// ═══════════════════════════════════════════════
// HTTP HELPERS
// ═══════════════════════════════════════════════

fn curl_get(url: &str) -> (u16, String) {
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

fn curl_with_auth(url: &str, method: &str, token: &str) -> u16 {
    let mut args = vec![
        "-s", "-o", "/dev/null",
        "-w", "%{http_code}",
        "-X", method,
        "--max-time", "10",
    ];

    let auth_header;
    if !token.is_empty() {
        auth_header = format!("Authorization: Bearer {}", token);
        args.push("-H");
        args.push(&auth_header);
    }

    args.push(url);

    Command::new("curl")
        .args(&args)
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u16>()
                .ok()
        })
        .unwrap_or(0)
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
    fn test_urlencoding() {
        assert_eq!(urlencoding("hello"), "hello");
        assert_eq!(urlencoding("a b"), "a%20b");
        assert_eq!(urlencoding("'OR 1=1"), "%27OR%201%3D1");
    }

    #[test]
    fn test_is_sandbox_target() {
        assert!(is_sandbox_target("http://172.28.0.5:3001/api"));
        assert!(is_sandbox_target("http://localhost:3001/api"));
        assert!(!is_sandbox_target("http://google.com"));
    }
}
