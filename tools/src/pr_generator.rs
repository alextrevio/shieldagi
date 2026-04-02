/// ShieldAGI Tool: pr_generator
///
/// Generates detailed GitHub Pull Request descriptions from remediation results.
/// Produces markdown with summary tables, before/after code snippets, severity
/// breakdown, Chain Walls status, and verification results.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct PrGeneratorInput {
    pub remediation_result: serde_json::Value,
    pub repo_path: String,
    pub base_branch: Option<String>,
    pub title: Option<String>,
    pub auto_push: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrGeneratorResult {
    pub pr_title: String,
    pub pr_body: String,
    pub branch_name: String,
    pub base_branch: String,
    pub total_fixes: usize,
    pub severity_breakdown: SeverityBreakdown,
    pub pr_url: Option<String>,
    pub pushed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

pub async fn tool_pr_generator(input: &serde_json::Value) -> Result<String, String> {
    let repo_path = input["repo_path"]
        .as_str()
        .ok_or("Missing 'repo_path' field")?;

    let remediation = &input["remediation_result"];
    if remediation.is_null() {
        return Err("Missing 'remediation_result' field".into());
    }

    let base_branch = input["base_branch"]
        .as_str()
        .unwrap_or("main")
        .to_string();

    let auto_push = input["auto_push"].as_bool().unwrap_or(false);

    // Extract data from remediation result
    let report_id = remediation["report_id"].as_str().unwrap_or("unknown");
    let total_vulns = remediation["total_vulnerabilities"].as_u64().unwrap_or(0) as usize;
    let fixed = remediation["fixed"].as_u64().unwrap_or(0) as usize;
    let failed = remediation["failed"].as_u64().unwrap_or(0) as usize;
    let skipped = remediation["skipped"].as_u64().unwrap_or(0) as usize;
    let chain_walls = remediation["chain_walls_applied"].as_bool().unwrap_or(false);
    let tests_passed = remediation["tests_passed"].as_bool();
    let branch_name = remediation["branch_name"]
        .as_str()
        .unwrap_or("shieldagi/remediation")
        .to_string();

    let fixes = remediation["fixes"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let verifications = remediation["verification_results"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // Count severities from the original report (embedded in fixes)
    let severity_breakdown = count_severities(&fixes);

    // Generate PR title
    let pr_title = input["title"]
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| {
            format!(
                "fix(security): remediate {} vulnerabilities [{} critical, {} high]",
                fixed, severity_breakdown.critical, severity_breakdown.high
            )
        });

    // Generate PR body
    let pr_body = generate_pr_body(
        report_id,
        total_vulns,
        fixed,
        failed,
        skipped,
        chain_walls,
        tests_passed,
        &fixes,
        &verifications,
        &severity_breakdown,
        repo_path,
        &branch_name,
    );

    // Push if requested
    let mut pushed = false;
    let mut pr_url = None;

    if auto_push {
        // Push branch
        let push_result = Command::new("git")
            .args(["push", "-u", "origin", &branch_name])
            .current_dir(repo_path)
            .output();

        if let Ok(output) = push_result {
            if output.status.success() {
                pushed = true;

                // Create PR via gh CLI
                let pr_result = Command::new("gh")
                    .args([
                        "pr", "create",
                        "--title", &pr_title,
                        "--body", &pr_body,
                        "--base", &base_branch,
                        "--head", &branch_name,
                        "--label", "security",
                    ])
                    .current_dir(repo_path)
                    .output();

                if let Ok(pr_output) = pr_result {
                    let stdout = String::from_utf8_lossy(&pr_output.stdout);
                    let url = stdout.trim().to_string();
                    if url.starts_with("http") {
                        pr_url = Some(url);
                    }
                }
            }
        }
    }

    let result = PrGeneratorResult {
        pr_title,
        pr_body,
        branch_name,
        base_branch,
        total_fixes: fixed,
        severity_breakdown,
        pr_url,
        pushed,
        error: None,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

// ═══════════════════════════════════════════════
// PR BODY GENERATION
// ═══════════════════════════════════════════════

fn generate_pr_body(
    report_id: &str,
    total_vulns: usize,
    fixed: usize,
    failed: usize,
    skipped: usize,
    chain_walls: bool,
    tests_passed: Option<bool>,
    fixes: &[serde_json::Value],
    verifications: &[serde_json::Value],
    severity: &SeverityBreakdown,
    repo_path: &str,
    branch_name: &str,
) -> String {
    let mut body = String::new();

    // Header
    body.push_str("## ShieldAGI Security Remediation\n\n");
    body.push_str(&format!("> Automated security fixes generated by ShieldAGI 2.0\n"));
    body.push_str(&format!("> Report: `{}`\n\n", report_id));

    // Summary stats
    body.push_str("### Summary\n\n");
    body.push_str("| Metric | Value |\n");
    body.push_str("|--------|-------|\n");
    body.push_str(&format!("| Total Vulnerabilities | {} |\n", total_vulns));
    body.push_str(&format!("| Fixed | {} |\n", fixed));
    body.push_str(&format!("| Failed | {} |\n", failed));
    body.push_str(&format!("| Skipped | {} |\n", skipped));
    body.push_str(&format!(
        "| Chain Walls | {} |\n",
        if chain_walls { "Applied" } else { "Not needed" }
    ));
    body.push_str(&format!(
        "| Tests | {} |\n",
        match tests_passed {
            Some(true) => "Passing",
            Some(false) => "FAILING",
            None => "Not run",
        }
    ));
    body.push('\n');

    // Severity breakdown
    body.push_str("### Severity Breakdown\n\n");
    body.push_str(&format!(
        "| {} Critical | {} High | {} Medium | {} Low |\n",
        severity.critical, severity.high, severity.medium, severity.low
    ));
    body.push_str("|:---:|:---:|:---:|:---:|\n\n");

    // Individual fixes table
    body.push_str("### Fixes Applied\n\n");
    body.push_str("| # | Vulnerability | Status | Files Modified |\n");
    body.push_str("|---|--------------|--------|----------------|\n");

    for (i, fix) in fixes.iter().enumerate() {
        let vuln_id = fix["vulnerability_id"].as_str().unwrap_or("?");
        let status = fix["status"].as_str().unwrap_or("?");
        let files = fix["files_modified"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        let status_icon = match status {
            "fixed" => "FIXED",
            "failed" => "FAILED",
            "skipped" => "SKIPPED",
            _ => status,
        };

        body.push_str(&format!(
            "| {} | `{}` | {} | `{}` |\n",
            i + 1,
            vuln_id,
            status_icon,
            if files.is_empty() { "-" } else { &files }
        ));
    }
    body.push('\n');

    // Fix details — before/after snippets from git diff
    body.push_str("### Fix Details\n\n");
    for fix in fixes {
        if fix["status"].as_str() != Some("fixed") {
            continue;
        }
        let vuln_id = fix["vulnerability_id"].as_str().unwrap_or("?");
        let description = fix["fix_description"].as_str().unwrap_or("");
        let files = fix["files_modified"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        body.push_str(&format!("<details>\n<summary><strong>{}</strong>: {}</summary>\n\n", vuln_id, description));

        // Get diff for each modified file
        for file in &files {
            let diff = get_file_diff(repo_path, branch_name, file);
            if !diff.is_empty() {
                body.push_str(&format!("**`{}`**\n", file));
                body.push_str("```diff\n");
                // Limit diff output to avoid huge PRs
                let truncated: String = diff.lines().take(40).collect::<Vec<_>>().join("\n");
                body.push_str(&truncated);
                if diff.lines().count() > 40 {
                    body.push_str("\n... (truncated)");
                }
                body.push_str("\n```\n\n");
            }
        }

        body.push_str("</details>\n\n");
    }

    // Chain Walls section
    if chain_walls {
        body.push_str("### Chain Walls Middleware\n\n");
        body.push_str("7-layer security middleware has been added:\n\n");
        body.push_str("1. **Rate Limiter** — Prevents brute-force and DDoS\n");
        body.push_str("2. **Input Sanitizer** — Blocks SQLi/XSS payloads\n");
        body.push_str("3. **Auth Validator** — Enforces JWT authentication\n");
        body.push_str("4. **CSRF Guard** — Validates Origin/Referer headers\n");
        body.push_str("5. **RBAC Enforcer** — Role-based access control\n");
        body.push_str("6. **SSRF Shield** — Blocks internal IP/metadata requests\n");
        body.push_str("7. **Request Logger** — Audit trail for all requests\n\n");
    }

    // Verification results
    if !verifications.is_empty() {
        body.push_str("### Verification Results\n\n");
        body.push_str("| Vulnerability | Tool | Still Vulnerable? | Detail |\n");
        body.push_str("|--------------|------|-------------------|--------|\n");

        for v in verifications {
            let vuln_id = v["vulnerability_id"].as_str().unwrap_or("?");
            let tool = v["tool_used"].as_str().unwrap_or("?");
            let still_vuln = v["still_vulnerable"].as_bool().unwrap_or(false);
            let detail = v["detail"].as_str().unwrap_or("");

            body.push_str(&format!(
                "| `{}` | `{}` | {} | {} |\n",
                vuln_id,
                tool,
                if still_vuln { "YES" } else { "No" },
                detail
            ));
        }
        body.push('\n');
    }

    // Footer
    body.push_str("---\n\n");
    body.push_str("*Generated by [ShieldAGI 2.0](https://github.com/shieldagi) — Autonomous Cyber Defense Platform*\n");

    body
}

fn get_file_diff(repo_path: &str, branch_name: &str, file: &str) -> String {
    // Try to get diff between base and current branch
    let output = Command::new("git")
        .args(["diff", "HEAD~1", "--", file])
        .current_dir(repo_path)
        .output();

    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => String::new(),
    }
}

fn count_severities(fixes: &[serde_json::Value]) -> SeverityBreakdown {
    let mut breakdown = SeverityBreakdown {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    for fix in fixes {
        // Try to infer severity from vulnerability_id or fix_description
        let vuln_id = fix["vulnerability_id"].as_str().unwrap_or("").to_lowercase();
        let desc = fix["fix_description"].as_str().unwrap_or("").to_lowercase();

        if vuln_id.contains("critical") || desc.contains("critical") {
            breakdown.critical += 1;
        } else if vuln_id.contains("sqli")
            || vuln_id.contains("rce")
            || desc.contains("sql injection")
            || desc.contains("remote code")
        {
            breakdown.critical += 1;
        } else if vuln_id.contains("xss")
            || vuln_id.contains("ssrf")
            || vuln_id.contains("idor")
            || desc.contains("cross-site")
        {
            breakdown.high += 1;
        } else if vuln_id.contains("csrf")
            || vuln_id.contains("traversal")
            || desc.contains("csrf")
        {
            breakdown.medium += 1;
        } else {
            breakdown.low += 1;
        }
    }

    // If all zeros (no pattern matches), distribute based on fix status
    if breakdown.critical == 0
        && breakdown.high == 0
        && breakdown.medium == 0
        && breakdown.low == 0
    {
        let fixed_count = fixes
            .iter()
            .filter(|f| f["status"].as_str() == Some("fixed"))
            .count();
        breakdown.high = fixed_count;
    }

    breakdown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_severities() {
        let fixes = vec![
            serde_json::json!({
                "vulnerability_id": "VULN-SQLI-001",
                "status": "fixed",
                "fix_description": "Parameterized SQL injection",
                "files_modified": ["src/server.js"]
            }),
            serde_json::json!({
                "vulnerability_id": "VULN-XSS-001",
                "status": "fixed",
                "fix_description": "Escaped XSS output",
                "files_modified": ["src/server.js"]
            }),
            serde_json::json!({
                "vulnerability_id": "VULN-CSRF-001",
                "status": "fixed",
                "fix_description": "Added CSRF token validation",
                "files_modified": ["src/server.js"]
            }),
        ];

        let breakdown = count_severities(&fixes);
        assert_eq!(breakdown.critical, 1); // sqli
        assert_eq!(breakdown.high, 1); // xss
        assert_eq!(breakdown.medium, 1); // csrf
    }

    #[test]
    fn test_generate_pr_body_contains_sections() {
        let body = generate_pr_body(
            "RPT-001",
            3, 2, 1, 0,
            true,
            Some(true),
            &[serde_json::json!({
                "vulnerability_id": "V1",
                "status": "fixed",
                "fix_description": "Fixed SQLi",
                "files_modified": ["server.js"]
            })],
            &[],
            &SeverityBreakdown { critical: 1, high: 0, medium: 0, low: 0 },
            "/tmp",
            "shieldagi/remediation",
        );

        assert!(body.contains("## ShieldAGI Security Remediation"));
        assert!(body.contains("### Summary"));
        assert!(body.contains("### Fixes Applied"));
        assert!(body.contains("### Chain Walls Middleware"));
        assert!(body.contains("Rate Limiter"));
    }
}
