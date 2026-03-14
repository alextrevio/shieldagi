/// ShieldAGI Tool: secret_scan
///
/// Scans a repository for hardcoded secrets, API keys, and credentials
/// using both trufflehog and gitleaks. Merges and deduplicates results.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretScanResult {
    pub repo_path: String,
    pub total_secrets: usize,
    pub secrets: Vec<SecretFinding>,
    pub scanners_used: Vec<String>,
    pub scan_history: bool,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretFinding {
    pub secret_type: String,
    pub file: String,
    pub line: Option<u64>,
    pub commit: Option<String>,
    pub author: Option<String>,
    pub redacted_value: String,
    pub severity: String,
    pub scanner: String,
}

pub async fn tool_secret_scan(input: &serde_json::Value) -> Result<String, String> {
    let repo_path = input["repo_path"]
        .as_str()
        .ok_or("Missing 'repo_path' field")?;

    let scan_history = input["scan_history"].as_bool().unwrap_or(true);
    let include_patterns: Vec<String> = input["include_patterns"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let start = std::time::Instant::now();
    let mut secrets = Vec::new();
    let mut scanners_used = Vec::new();
    let mut errors = Vec::new();

    // --- Run trufflehog ---
    let trufflehog_args = vec!["filesystem", "--json", repo_path];

    if let Ok(output) = Command::new("trufflehog").args(&trufflehog_args).output() {
        scanners_used.push("trufflehog".to_string());
        let stdout = String::from_utf8_lossy(&output.stdout);

        // trufflehog outputs one JSON object per line (NDJSON)
        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(finding) = serde_json::from_str::<serde_json::Value>(line) {
                let raw_secret = finding["Raw"].as_str().unwrap_or("");
                let redacted = redact_secret(raw_secret);

                secrets.push(SecretFinding {
                    secret_type: finding["DetectorName"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string(),
                    file: finding["SourceMetadata"]["Data"]["Filesystem"]["file"]
                        .as_str()
                        .or_else(|| finding["SourceMetadata"]["Data"]["Git"]["file"].as_str())
                        .unwrap_or("")
                        .to_string(),
                    line: finding["SourceMetadata"]["Data"]["Filesystem"]["line"].as_u64(),
                    commit: finding["SourceMetadata"]["Data"]["Git"]["commit"]
                        .as_str()
                        .map(String::from),
                    author: finding["SourceMetadata"]["Data"]["Git"]["email"]
                        .as_str()
                        .map(String::from),
                    redacted_value: redacted,
                    severity: if finding["Verified"].as_bool().unwrap_or(false) {
                        "CRITICAL".to_string()
                    } else {
                        "HIGH".to_string()
                    },
                    scanner: "trufflehog".to_string(),
                });
            }
        }
    } else {
        errors.push("trufflehog not found or failed to execute".to_string());
    }

    // --- Run gitleaks ---
    let gitleaks_report = format!("/tmp/gitleaks-{}.json", uuid::Uuid::new_v4());
    let mut gitleaks_args = vec![
        "detect",
        "--source",
        repo_path,
        "--report-format",
        "json",
        "--report-path",
        &gitleaks_report,
        "--exit-code",
        "0",
    ];

    if !scan_history {
        gitleaks_args.push("--no-git");
    }

    if let Ok(_output) = Command::new("gitleaks").args(&gitleaks_args).output() {
        scanners_used.push("gitleaks".to_string());

        if let Ok(report_content) = std::fs::read_to_string(&gitleaks_report) {
            if let Ok(findings) = serde_json::from_str::<Vec<serde_json::Value>>(&report_content) {
                for finding in findings {
                    let raw_secret = finding["Secret"].as_str().unwrap_or("");
                    let file = finding["File"].as_str().unwrap_or("").to_string();
                    let secret_type = finding["RuleID"].as_str().unwrap_or("unknown").to_string();

                    // Deduplicate against trufflehog findings
                    let already_found = secrets.iter().any(|s| {
                        s.file == file && s.secret_type.to_lowercase() == secret_type.to_lowercase()
                    });

                    if !already_found {
                        secrets.push(SecretFinding {
                            secret_type,
                            file,
                            line: finding["StartLine"].as_u64(),
                            commit: finding["Commit"].as_str().map(String::from),
                            author: finding["Author"].as_str().map(String::from),
                            redacted_value: redact_secret(raw_secret),
                            severity: "HIGH".to_string(),
                            scanner: "gitleaks".to_string(),
                        });
                    }
                }
            }
        }

        let _ = std::fs::remove_file(&gitleaks_report);
    } else {
        errors.push("gitleaks not found or failed to execute".to_string());
    }

    // --- Check for additional custom patterns via grep ---
    if !include_patterns.is_empty() {
        for pattern in &include_patterns {
            if let Ok(output) = Command::new("grep")
                .args([
                    "-rn", pattern, repo_path,
                    "--include=*.js", "--include=*.ts", "--include=*.py",
                    "--include=*.env", "--include=*.json", "--include=*.yaml",
                    "--include=*.yml", "--include=*.toml",
                ])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    // Format: file:line_num:matched_content
                    let parts: Vec<&str> = line.splitn(3, ':').collect();
                    if parts.len() >= 3 {
                        secrets.push(SecretFinding {
                            secret_type: format!("custom-pattern:{}", pattern),
                            file: parts[0].to_string(),
                            line: parts[1].parse::<u64>().ok(),
                            commit: None,
                            author: None,
                            redacted_value: redact_secret(parts[2].trim()),
                            severity: "MEDIUM".to_string(),
                            scanner: "grep-custom".to_string(),
                        });
                    }
                }
            }
        }
    }

    let duration = start.elapsed().as_millis() as u64;

    let result = SecretScanResult {
        repo_path: repo_path.to_string(),
        total_secrets: secrets.len(),
        secrets,
        scanners_used,
        scan_history,
        scan_duration_ms: duration,
        error: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        return "*".repeat(secret.len());
    }
    format!(
        "{}{}{}",
        &secret[..4],
        "*".repeat(secret.len() - 6),
        &secret[secret.len() - 2..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_secret() {
        assert_eq!(redact_secret("sk-1234567890abcdef"), "sk-1**********ef");
        assert_eq!(redact_secret("short"), "*****");
        assert_eq!(redact_secret("abcdefghij"), "abcd****ij");
    }
}
