/// ShieldAGI Tool: idor_test
///
/// Tests API endpoints for Insecure Direct Object Reference (IDOR) vulnerabilities.
/// Uses multi-user context to verify access controls on resource endpoints.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct IdorResult {
    pub endpoints_tested: usize,
    pub vulnerable_endpoints: Vec<IdorVulnerability>,
    pub total_vulnerabilities: usize,
    pub severity: String,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdorVulnerability {
    pub endpoint: String,
    pub method: String,
    pub resource_id: String,
    pub detail: String,
    pub status_code_user_a: u16,
    pub status_code_user_b: u16,
    pub data_leaked: bool,
}

pub async fn tool_idor_test(input: &serde_json::Value) -> Result<String, String> {
    let endpoints: Vec<String> = input["endpoints"]
        .as_array()
        .ok_or("Missing 'endpoints' array")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let user_a_token = input["user_a_token"]
        .as_str()
        .ok_or("Missing 'user_a_token'")?;

    let user_b_token = input["user_b_token"]
        .as_str()
        .ok_or("Missing 'user_b_token'")?;

    let resource_ids: Vec<String> = input["resource_ids"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["1".to_string(), "2".to_string(), "3".to_string()]);

    // Validate all endpoints are sandbox targets
    for endpoint in &endpoints {
        if !is_sandbox_target(endpoint) {
            return Err(format!(
                "SAFETY: idor_test can only target sandbox URLs. '{}' is not allowed.",
                endpoint
            ));
        }
    }

    let start = std::time::Instant::now();
    let mut vulnerabilities = Vec::new();

    for endpoint in &endpoints {
        for resource_id in &resource_ids {
            // Replace :id, {id}, or trailing segment with resource_id
            let url = resolve_endpoint_url(endpoint, resource_id);

            // Test with GET and DELETE methods
            for method in &["GET", "DELETE"] {
                // Step 1: Request as User A (resource owner) — should succeed
                let status_a = make_request(&url, method, user_a_token);

                // Step 2: Request as User B (non-owner) — should fail with 403/404
                let status_b = make_request(&url, method, user_b_token);

                // Step 3: Request without auth — should fail with 401
                let status_noauth = make_request(&url, method, "");

                let a_code = status_a.unwrap_or(0);
                let b_code = status_b.unwrap_or(0);
                let noauth_code = status_noauth.unwrap_or(0);

                // IDOR detected if User B gets same success response as User A
                let idor_detected = a_code >= 200
                    && a_code < 400
                    && b_code >= 200
                    && b_code < 400;

                let missing_auth = noauth_code >= 200 && noauth_code < 400;

                if idor_detected || missing_auth {
                    vulnerabilities.push(IdorVulnerability {
                        endpoint: endpoint.clone(),
                        method: method.to_string(),
                        resource_id: resource_id.clone(),
                        detail: if missing_auth {
                            format!(
                                "Endpoint accessible without authentication (HTTP {})",
                                noauth_code
                            )
                        } else {
                            format!(
                                "User B accessed User A's resource (A={}, B={})",
                                a_code, b_code
                            )
                        },
                        status_code_user_a: a_code,
                        status_code_user_b: b_code,
                        data_leaked: idor_detected,
                    });
                }
            }
        }
    }

    let duration = start.elapsed().as_millis() as u64;

    let severity = if vulnerabilities.iter().any(|v| v.method == "DELETE" && v.data_leaked) {
        "CRITICAL"
    } else if !vulnerabilities.is_empty() {
        "HIGH"
    } else {
        "LOW"
    };

    let result = IdorResult {
        endpoints_tested: endpoints.len(),
        vulnerable_endpoints: vulnerabilities.clone(),
        total_vulnerabilities: vulnerabilities.len(),
        severity: severity.to_string(),
        scan_duration_ms: duration,
        error: None,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

fn resolve_endpoint_url(endpoint: &str, resource_id: &str) -> String {
    // Replace common URL patterns: :id, {id}, :resourceId
    let url = endpoint
        .replace(":id", resource_id)
        .replace("{id}", resource_id)
        .replace(":resourceId", resource_id);

    // If no pattern was replaced, append the ID
    if url == endpoint {
        if endpoint.ends_with('/') {
            format!("{}{}", endpoint, resource_id)
        } else {
            format!("{}/{}", endpoint, resource_id)
        }
    } else {
        url
    }
}

fn make_request(url: &str, method: &str, token: &str) -> Option<u16> {
    let mut args = vec![
        "-s".to_string(),
        "-o".to_string(),
        "/dev/null".to_string(),
        "-w".to_string(),
        "%{http_code}".to_string(),
        "-X".to_string(),
        method.to_string(),
        "--max-time".to_string(),
        "10".to_string(),
    ];

    if !token.is_empty() {
        args.push("-H".to_string());
        args.push(format!("Authorization: Bearer {}", token));
    }

    args.push(url.to_string());

    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    Command::new("curl")
        .args(&args_refs)
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u16>()
                .ok()
        })
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
    fn test_resolve_endpoint_url() {
        assert_eq!(
            resolve_endpoint_url("http://localhost:3001/api/documents/:id", "42"),
            "http://localhost:3001/api/documents/42"
        );
        assert_eq!(
            resolve_endpoint_url("http://localhost:3001/api/documents/{id}", "42"),
            "http://localhost:3001/api/documents/42"
        );
        assert_eq!(
            resolve_endpoint_url("http://localhost:3001/api/documents", "42"),
            "http://localhost:3001/api/documents/42"
        );
    }
}
