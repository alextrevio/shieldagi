/// ShieldAGI Tool: csrf_test
///
/// Tests endpoints for CSRF vulnerabilities by crafting cross-origin requests.
/// Checks for CSRF token validation, Origin header enforcement, and SameSite cookies.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct CsrfResult {
    pub target_url: String,
    pub method: String,
    pub vulnerable: bool,
    pub checks: Vec<CsrfCheck>,
    pub severity: String,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CsrfCheck {
    pub check_name: String,
    pub passed: bool,
    pub detail: String,
}

pub async fn tool_csrf_test(input: &serde_json::Value) -> Result<String, String> {
    let target_url = input["target_url"]
        .as_str()
        .ok_or("Missing 'target_url' field")?;

    if !is_sandbox_target(target_url) {
        return Err("SAFETY: csrf_test can only target sandbox URLs".into());
    }

    let method = input["method"].as_str().unwrap_or("POST");
    let auth_cookie = input["auth_cookie"].as_str();
    let check_origin = input["check_origin"].as_bool().unwrap_or(true);
    let check_referer = input["check_referer"].as_bool().unwrap_or(true);

    let data = input["data"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| format!("{}={}", k, v.as_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("&")
        })
        .unwrap_or_default();

    let start = std::time::Instant::now();
    let mut checks = Vec::new();
    let mut vulnerable = false;

    // --- Check 1: Request without CSRF token ---
    {
        let mut args = vec![
            "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-X", method,
            "--max-time", "10",
        ];

        if !data.is_empty() {
            args.extend(&["-d", &data]);
            args.extend(&["-H", "Content-Type: application/x-www-form-urlencoded"]);
        }

        if let Some(cookie) = auth_cookie {
            args.extend(&["-b", cookie]);
        }

        args.push(target_url);

        if let Ok(output) = Command::new("curl").args(&args).output() {
            let status = String::from_utf8_lossy(&output.stdout);
            let status_code: u16 = status.trim().parse().unwrap_or(0);
            let no_token_accepted = status_code >= 200 && status_code < 400;

            checks.push(CsrfCheck {
                check_name: "csrf_token_required".to_string(),
                passed: !no_token_accepted,
                detail: if no_token_accepted {
                    format!("Request accepted without CSRF token (HTTP {})", status_code)
                } else {
                    format!("Request rejected without CSRF token (HTTP {})", status_code)
                },
            });

            if no_token_accepted {
                vulnerable = true;
            }
        }
    }

    // --- Check 2: Request with wrong Origin header ---
    if check_origin {
        let mut args = vec![
            "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-X", method,
            "-H", "Origin: https://evil-attacker.com",
            "--max-time", "10",
        ];

        if !data.is_empty() {
            args.extend(&["-d", &data]);
            args.extend(&["-H", "Content-Type: application/x-www-form-urlencoded"]);
        }

        if let Some(cookie) = auth_cookie {
            args.extend(&["-b", cookie]);
        }

        args.push(target_url);

        if let Ok(output) = Command::new("curl").args(&args).output() {
            let status = String::from_utf8_lossy(&output.stdout);
            let status_code: u16 = status.trim().parse().unwrap_or(0);
            let cross_origin_accepted = status_code >= 200 && status_code < 400;

            checks.push(CsrfCheck {
                check_name: "origin_header_validated".to_string(),
                passed: !cross_origin_accepted,
                detail: if cross_origin_accepted {
                    format!("Cross-origin request accepted (HTTP {})", status_code)
                } else {
                    format!("Cross-origin request rejected (HTTP {})", status_code)
                },
            });

            if cross_origin_accepted {
                vulnerable = true;
            }
        }
    }

    // --- Check 3: Request with wrong Referer header ---
    if check_referer {
        let mut args = vec![
            "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-X", method,
            "-H", "Referer: https://evil-attacker.com/csrf-page",
            "--max-time", "10",
        ];

        if !data.is_empty() {
            args.extend(&["-d", &data]);
            args.extend(&["-H", "Content-Type: application/x-www-form-urlencoded"]);
        }

        if let Some(cookie) = auth_cookie {
            args.extend(&["-b", cookie]);
        }

        args.push(target_url);

        if let Ok(output) = Command::new("curl").args(&args).output() {
            let status = String::from_utf8_lossy(&output.stdout);
            let status_code: u16 = status.trim().parse().unwrap_or(0);
            let wrong_referer_accepted = status_code >= 200 && status_code < 400;

            checks.push(CsrfCheck {
                check_name: "referer_header_validated".to_string(),
                passed: !wrong_referer_accepted,
                detail: if wrong_referer_accepted {
                    format!("Request with malicious Referer accepted (HTTP {})", status_code)
                } else {
                    format!("Request with malicious Referer rejected (HTTP {})", status_code)
                },
            });

            if wrong_referer_accepted {
                vulnerable = true;
            }
        }
    }

    // --- Check 4: Cookie SameSite attribute ---
    {
        let mut args = vec![
            "-s", "-D", "-",
            "-o", "/dev/null",
            "-X", "GET",
            "--max-time", "10",
        ];
        args.push(target_url);

        if let Ok(output) = Command::new("curl").args(&args).output() {
            let headers = String::from_utf8_lossy(&output.stdout);
            let has_samesite = headers.to_lowercase().contains("samesite=strict")
                || headers.to_lowercase().contains("samesite=lax");

            checks.push(CsrfCheck {
                check_name: "samesite_cookie".to_string(),
                passed: has_samesite,
                detail: if has_samesite {
                    "Session cookies have SameSite attribute".to_string()
                } else {
                    "Session cookies missing SameSite attribute".to_string()
                },
            });

            if !has_samesite {
                vulnerable = true;
            }
        }
    }

    let duration = start.elapsed().as_millis() as u64;
    let failed_checks = checks.iter().filter(|c| !c.passed).count();

    let severity = if failed_checks >= 3 {
        "CRITICAL"
    } else if failed_checks >= 2 {
        "HIGH"
    } else if failed_checks >= 1 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let result = CsrfResult {
        target_url: target_url.to_string(),
        method: method.to_string(),
        vulnerable,
        checks,
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
