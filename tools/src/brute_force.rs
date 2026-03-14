/// ShieldAGI Tool: brute_force
///
/// Tests authentication endpoints for rate limiting effectiveness and
/// weak credential detection. SANDBOX ONLY.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct BruteForceResult {
    pub target_url: String,
    pub rate_limit_detected: bool,
    pub rate_limit_threshold: Option<u32>,
    pub weak_credentials_found: Vec<WeakCredential>,
    pub lockout_detected: bool,
    pub lockout_after: Option<u32>,
    pub response_time_anomaly: bool,
    pub total_attempts: u32,
    pub severity: String,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WeakCredential {
    pub username: String,
    pub password: String,
    pub status_code: u16,
}

/// Common weak passwords to test
const COMMON_PASSWORDS: &[&str] = &[
    "password", "123456", "admin", "password123", "admin123",
    "letmein", "welcome", "monkey", "dragon", "master",
    "login", "abc123", "qwerty", "trustno1", "iloveyou",
    "test", "demo", "guest", "root", "changeme",
];

pub async fn tool_brute_force(input: &serde_json::Value) -> Result<String, String> {
    let target_url = input["target_url"]
        .as_str()
        .ok_or("Missing 'target_url' field")?;

    if !is_sandbox_target(target_url) {
        return Err("SAFETY: brute_force can only target sandbox URLs".into());
    }

    let username_field = input["username_field"].as_str().unwrap_or("email");
    let password_field = input["password_field"].as_str().unwrap_or("password");
    let max_attempts = input["max_attempts"].as_u64().unwrap_or(20) as u32;
    let check_rate_limit = input["check_rate_limit"].as_bool().unwrap_or(true);

    let test_usernames: Vec<String> = input["test_usernames"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["admin".to_string(), "test@test.com".to_string()]);

    let start = std::time::Instant::now();
    let mut weak_credentials = Vec::new();
    let mut rate_limit_detected = false;
    let mut rate_limit_threshold = None;
    let mut lockout_detected = false;
    let mut lockout_after = None;
    let mut response_time_anomaly = false;
    let mut total_attempts = 0u32;

    // --- Phase 1: Test for rate limiting ---
    if check_rate_limit {
        let mut consecutive_429s = 0u32;
        let mut prev_time: Option<f64> = None;

        for i in 0..max_attempts {
            total_attempts += 1;
            let body = format!(
                "{}={}&{}=wrong_password_{}",
                username_field, "ratelimit-test@test.com", password_field, i
            );

            let args = vec![
                "-s", "-o", "/dev/null",
                "-w", "%{http_code} %{time_total}",
                "-X", "POST",
                "-d", &body,
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "--max-time", "10",
                target_url,
            ];

            if let Ok(output) = Command::new("curl").args(&args).output() {
                let out = String::from_utf8_lossy(&output.stdout);
                let parts: Vec<&str> = out.trim().split_whitespace().collect();

                let status: u16 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                let time: f64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);

                if status == 429 {
                    consecutive_429s += 1;
                    if !rate_limit_detected {
                        rate_limit_detected = true;
                        rate_limit_threshold = Some(i + 1);
                    }
                }

                if status == 423 || status == 403 {
                    lockout_detected = true;
                    lockout_after = Some(i + 1);
                    break;
                }

                // Detect artificial delay (response time > 2x previous)
                if let Some(prev) = prev_time {
                    if time > prev * 3.0 && time > 2.0 {
                        response_time_anomaly = true;
                    }
                }
                prev_time = Some(time);
            }
        }
    }

    // --- Phase 2: Test common weak credentials ---
    for username in &test_usernames {
        let passwords_to_test: Vec<&str> = COMMON_PASSWORDS
            .iter()
            .take(max_attempts as usize)
            .copied()
            .collect();

        for password in passwords_to_test {
            total_attempts += 1;
            let body = format!(
                "{}={}&{}={}",
                username_field, username, password_field, password
            );

            let args = vec![
                "-s", "-o", "/dev/null",
                "-w", "%{http_code}",
                "-X", "POST",
                "-d", &body,
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "--max-time", "10",
                target_url,
            ];

            if let Ok(output) = Command::new("curl").args(&args).output() {
                let status_str = String::from_utf8_lossy(&output.stdout);
                let status: u16 = status_str.trim().parse().unwrap_or(0);

                // 200 on login typically means success
                if status == 200 {
                    weak_credentials.push(WeakCredential {
                        username: username.clone(),
                        password: password.to_string(),
                        status_code: status,
                    });
                }

                // Stop if rate limited
                if status == 429 {
                    break;
                }
            }
        }
    }

    let duration = start.elapsed().as_millis() as u64;

    let severity = if !weak_credentials.is_empty() && !rate_limit_detected {
        "CRITICAL"
    } else if !weak_credentials.is_empty() {
        "HIGH"
    } else if !rate_limit_detected && !lockout_detected {
        "HIGH"
    } else if !rate_limit_detected || !lockout_detected {
        "MEDIUM"
    } else {
        "LOW"
    };

    let result = BruteForceResult {
        target_url: target_url.to_string(),
        rate_limit_detected,
        rate_limit_threshold,
        weak_credentials_found: weak_credentials,
        lockout_detected,
        lockout_after,
        response_time_anomaly,
        total_attempts,
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
