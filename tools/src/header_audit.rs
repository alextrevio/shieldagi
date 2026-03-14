/// ShieldAGI Tool: header_audit
///
/// Audits HTTP security headers on a target URL.
/// Checks for all required headers from the Security Misconfiguration playbook.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct HeaderAuditResult {
    pub target_url: String,
    pub headers_present: Vec<HeaderCheck>,
    pub headers_missing: Vec<HeaderCheck>,
    pub score: f32, // 0.0 - 100.0
    pub grade: String, // A, B, C, D, F
    pub cookies: Vec<CookieCheck>,
    pub server_info_leak: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeaderCheck {
    pub name: String,
    pub expected: String,
    pub actual: Option<String>,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CookieCheck {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub issues: Vec<String>,
}

const REQUIRED_HEADERS: &[(&str, &str, &str, &str)] = &[
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains", "HIGH", "Enforces HTTPS connections"),
    ("X-Frame-Options", "DENY", "HIGH", "Prevents clickjacking attacks"),
    ("X-Content-Type-Options", "nosniff", "MEDIUM", "Prevents MIME type sniffing"),
    ("Content-Security-Policy", "default-src 'self'", "HIGH", "Controls resource loading to prevent XSS"),
    ("Referrer-Policy", "strict-origin-when-cross-origin", "MEDIUM", "Controls referrer information leaks"),
    ("Permissions-Policy", "camera=(), microphone=()", "LOW", "Restricts browser API access"),
    ("Cross-Origin-Opener-Policy", "same-origin", "MEDIUM", "Isolates browsing context"),
    ("Cross-Origin-Resource-Policy", "same-origin", "MEDIUM", "Prevents cross-origin resource reading"),
];

const LEAK_HEADERS: &[&str] = &[
    "X-Powered-By",
    "Server",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
];

pub async fn tool_header_audit(input: &serde_json::Value) -> Result<String, String> {
    let target_url = input["target_url"]
        .as_str()
        .ok_or("Missing 'target_url' field")?;

    let follow_redirects = input["follow_redirects"].as_bool().unwrap_or(true);

    let client = reqwest::Client::builder()
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let response = client
        .get(target_url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    let headers = response.headers();
    let mut present = Vec::new();
    let mut missing = Vec::new();
    let mut score: f32 = 100.0;

    // Check required headers
    for (name, expected, severity, description) in REQUIRED_HEADERS {
        let check = HeaderCheck {
            name: name.to_string(),
            expected: expected.to_string(),
            actual: headers.get(*name).map(|v| v.to_str().unwrap_or("").to_string()),
            severity: severity.to_string(),
            description: description.to_string(),
        };

        if check.actual.is_some() {
            present.push(check);
        } else {
            let penalty = match *severity {
                "HIGH" => 15.0,
                "MEDIUM" => 10.0,
                "LOW" => 5.0,
                _ => 5.0,
            };
            score -= penalty;
            missing.push(check);
        }
    }

    // Check for info leak headers
    let mut server_info_leak = None;
    for leak_header in LEAK_HEADERS {
        if let Some(value) = headers.get(*leak_header) {
            server_info_leak = Some(format!("{}: {}", leak_header, value.to_str().unwrap_or("")));
            score -= 5.0;
            break;
        }
    }

    // Check cookies
    let mut cookies = Vec::new();
    for cookie_header in headers.get_all("set-cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            let name = cookie_str.split('=').next().unwrap_or("unknown").to_string();
            let lower = cookie_str.to_lowercase();
            let mut issues = Vec::new();

            let secure = lower.contains("secure");
            let http_only = lower.contains("httponly");
            let same_site = if lower.contains("samesite=strict") {
                Some("Strict".to_string())
            } else if lower.contains("samesite=lax") {
                Some("Lax".to_string())
            } else if lower.contains("samesite=none") {
                Some("None".to_string())
            } else {
                None
            };

            if !secure { issues.push("Missing Secure flag".into()); score -= 5.0; }
            if !http_only { issues.push("Missing HttpOnly flag".into()); score -= 5.0; }
            if same_site.is_none() { issues.push("Missing SameSite attribute".into()); score -= 3.0; }

            cookies.push(CookieCheck { name, secure, http_only, same_site, issues });
        }
    }

    let grade = match score as i32 {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }.to_string();

    let result = HeaderAuditResult {
        target_url: target_url.to_string(),
        headers_present: present,
        headers_missing: missing,
        score: score.max(0.0),
        grade,
        cookies,
        server_info_leak,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}
