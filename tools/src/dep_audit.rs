/// ShieldAGI Tool: dep_audit
///
/// Audits project dependencies for known CVEs using npm audit, pip-audit,
/// and cargo-audit. Auto-detects package manager or uses specified one.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct DepAuditResult {
    pub repo_path: String,
    pub package_manager: String,
    pub total_vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub vulnerabilities: Vec<DepVulnerability>,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepVulnerability {
    pub package_name: String,
    pub installed_version: String,
    pub patched_version: Option<String>,
    pub severity: String,
    pub cve_id: Option<String>,
    pub title: String,
    pub url: Option<String>,
    pub recommendation: String,
}

pub async fn tool_dep_audit(input: &serde_json::Value) -> Result<String, String> {
    let repo_path = input["repo_path"]
        .as_str()
        .ok_or("Missing 'repo_path' field")?;

    let pkg_manager = input["package_manager"].as_str().unwrap_or("auto");

    let start = std::time::Instant::now();

    // Auto-detect package manager
    let detected = if pkg_manager == "auto" {
        detect_package_manager(repo_path)
    } else {
        pkg_manager.to_string()
    };

    let result = match detected.as_str() {
        "npm" => audit_npm(repo_path).await,
        "pip" => audit_pip(repo_path).await,
        "cargo" => audit_cargo(repo_path).await,
        other => Err(format!("Unsupported package manager: {}", other)),
    };

    let duration = start.elapsed().as_millis() as u64;

    match result {
        Ok(mut audit_result) => {
            audit_result.scan_duration_ms = duration;
            Ok(serde_json::to_string_pretty(&audit_result).unwrap())
        }
        Err(e) => {
            let result = DepAuditResult {
                repo_path: repo_path.to_string(),
                package_manager: detected,
                total_vulnerabilities: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                vulnerabilities: vec![],
                scan_duration_ms: duration,
                error: Some(e),
            };
            Ok(serde_json::to_string_pretty(&result).unwrap())
        }
    }
}

fn detect_package_manager(repo_path: &str) -> String {
    let path = std::path::Path::new(repo_path);
    if path.join("package.json").exists() || path.join("package-lock.json").exists() {
        "npm".to_string()
    } else if path.join("requirements.txt").exists()
        || path.join("setup.py").exists()
        || path.join("pyproject.toml").exists()
    {
        "pip".to_string()
    } else if path.join("Cargo.toml").exists() || path.join("Cargo.lock").exists() {
        "cargo".to_string()
    } else {
        "npm".to_string() // Default fallback
    }
}

async fn audit_npm(repo_path: &str) -> Result<DepAuditResult, String> {
    let output = Command::new("npm")
        .args(["audit", "--json"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run npm audit: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse npm audit JSON: {}", e))?;

    let mut vulns = Vec::new();
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;

    // npm audit v2+ format: { vulnerabilities: { pkg_name: { ... } } }
    if let Some(vulnerabilities) = json["vulnerabilities"].as_object() {
        for (pkg_name, vuln_data) in vulnerabilities {
            let severity = vuln_data["severity"].as_str().unwrap_or("info").to_string();
            match severity.as_str() {
                "critical" => critical += 1,
                "high" => high += 1,
                "moderate" | "medium" => medium += 1,
                "low" => low += 1,
                _ => {}
            }

            let fix_available = vuln_data["fixAvailable"].as_bool().unwrap_or(false);
            let range = vuln_data["range"].as_str().unwrap_or("").to_string();

            // Parse via entries for CVE info
            let mut cve_id = None;
            let mut title = vuln_data["name"].as_str().unwrap_or(pkg_name).to_string();
            let mut url = None;

            if let Some(via) = vuln_data["via"].as_array() {
                for v in via {
                    if let Some(t) = v["title"].as_str() {
                        title = t.to_string();
                    }
                    if let Some(u) = v["url"].as_str() {
                        url = Some(u.to_string());
                        // Extract CVE from URL if present
                        if u.contains("CVE-") {
                            if let Some(cve_start) = u.find("CVE-") {
                                let cve = &u[cve_start..];
                                if let Some(end) = cve.find(|c: char| !c.is_alphanumeric() && c != '-') {
                                    cve_id = Some(cve[..end].to_string());
                                } else {
                                    cve_id = Some(cve.to_string());
                                }
                            }
                        }
                    }
                }
            }

            vulns.push(DepVulnerability {
                package_name: pkg_name.clone(),
                installed_version: range,
                patched_version: if fix_available {
                    Some("Fix available via npm audit fix".to_string())
                } else {
                    None
                },
                severity: normalize_severity(&severity),
                cve_id,
                title,
                url,
                recommendation: if fix_available {
                    "Run `npm audit fix` or update manually".to_string()
                } else {
                    "No fix available — consider replacing package".to_string()
                },
            });
        }
    }

    Ok(DepAuditResult {
        repo_path: repo_path.to_string(),
        package_manager: "npm".to_string(),
        total_vulnerabilities: vulns.len(),
        critical,
        high,
        medium,
        low,
        vulnerabilities: vulns,
        scan_duration_ms: 0,
        error: None,
    })
}

async fn audit_pip(repo_path: &str) -> Result<DepAuditResult, String> {
    let output = Command::new("pip-audit")
        .args(["--format", "json", "--desc"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run pip-audit: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse pip-audit JSON: {}", e))?;

    let mut vulns = Vec::new();
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;

    if let Some(dependencies) = json["dependencies"].as_array() {
        for dep in dependencies {
            if let Some(dep_vulns) = dep["vulns"].as_array() {
                for v in dep_vulns {
                    let severity = v["fix_versions"]
                        .as_array()
                        .map(|_| "HIGH")
                        .unwrap_or("MEDIUM")
                        .to_string();

                    match severity.as_str() {
                        "CRITICAL" => critical += 1,
                        "HIGH" => high += 1,
                        "MEDIUM" => medium += 1,
                        "LOW" => low += 1,
                        _ => {}
                    }

                    let fix_versions: Vec<String> = v["fix_versions"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|fv| fv.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    vulns.push(DepVulnerability {
                        package_name: dep["name"].as_str().unwrap_or("").to_string(),
                        installed_version: dep["version"].as_str().unwrap_or("").to_string(),
                        patched_version: fix_versions.first().cloned(),
                        severity,
                        cve_id: v["id"].as_str().map(String::from),
                        title: v["description"].as_str().unwrap_or("").to_string(),
                        url: v["id"]
                            .as_str()
                            .filter(|id| id.starts_with("CVE-") || id.starts_with("PYSEC-"))
                            .map(|id| {
                                if id.starts_with("CVE-") {
                                    format!("https://nvd.nist.gov/vuln/detail/{}", id)
                                } else {
                                    format!("https://osv.dev/vulnerability/{}", id)
                                }
                            }),
                        recommendation: if !fix_versions.is_empty() {
                            format!("Upgrade to {}", fix_versions.join(" or "))
                        } else {
                            "No fix available — consider replacing package".to_string()
                        },
                    });
                }
            }
        }
    }

    Ok(DepAuditResult {
        repo_path: repo_path.to_string(),
        package_manager: "pip".to_string(),
        total_vulnerabilities: vulns.len(),
        critical,
        high,
        medium,
        low,
        vulnerabilities: vulns,
        scan_duration_ms: 0,
        error: None,
    })
}

async fn audit_cargo(repo_path: &str) -> Result<DepAuditResult, String> {
    let output = Command::new("cargo")
        .args(["audit", "--json"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run cargo audit: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse cargo audit JSON: {}", e))?;

    let mut vulns = Vec::new();
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;

    if let Some(advisories) = json["vulnerabilities"]["list"].as_array() {
        for advisory in advisories {
            let adv = &advisory["advisory"];
            let severity = adv["cvss"]
                .as_str()
                .map(|cvss| {
                    // Parse CVSS base score for severity
                    if let Some(score_part) = cvss.split('/').next() {
                        if let Ok(score) = score_part.replace("CVSS:3.1/AV:", "").parse::<f64>() {
                            if score >= 9.0 { return "CRITICAL".to_string(); }
                            if score >= 7.0 { return "HIGH".to_string(); }
                            if score >= 4.0 { return "MEDIUM".to_string(); }
                        }
                    }
                    "MEDIUM".to_string()
                })
                .unwrap_or_else(|| "MEDIUM".to_string());

            match severity.as_str() {
                "CRITICAL" => critical += 1,
                "HIGH" => high += 1,
                "MEDIUM" => medium += 1,
                "LOW" => low += 1,
                _ => {}
            }

            let patched = advisory["versions"]["patched"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .map(String::from);

            vulns.push(DepVulnerability {
                package_name: advisory["package"]["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                installed_version: advisory["package"]["version"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                patched_version: patched.clone(),
                severity,
                cve_id: adv["id"].as_str().map(String::from),
                title: adv["title"].as_str().unwrap_or("").to_string(),
                url: adv["url"].as_str().map(String::from),
                recommendation: patched
                    .map(|p| format!("Upgrade to {}", p))
                    .unwrap_or_else(|| "No fix available — consider replacing crate".to_string()),
            });
        }
    }

    Ok(DepAuditResult {
        repo_path: repo_path.to_string(),
        package_manager: "cargo".to_string(),
        total_vulnerabilities: vulns.len(),
        critical,
        high,
        medium,
        low,
        vulnerabilities: vulns,
        scan_duration_ms: 0,
        error: None,
    })
}

fn normalize_severity(s: &str) -> String {
    match s.to_lowercase().as_str() {
        "critical" => "CRITICAL",
        "high" => "HIGH",
        "moderate" | "medium" => "MEDIUM",
        "low" => "LOW",
        "info" | "informational" => "INFO",
        _ => "MEDIUM",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_severity() {
        assert_eq!(normalize_severity("critical"), "CRITICAL");
        assert_eq!(normalize_severity("moderate"), "MEDIUM");
        assert_eq!(normalize_severity("HIGH"), "HIGH");
        assert_eq!(normalize_severity("info"), "INFO");
    }

    #[test]
    fn test_detect_package_manager() {
        // This test needs actual filesystem, so we just verify the function exists
        // and returns a valid default
        let result = detect_package_manager("/nonexistent/path");
        assert_eq!(result, "npm"); // Default fallback
    }
}
