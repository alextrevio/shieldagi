/// ShieldAGI Tool: dep_monitor
///
/// Dependency monitoring engine for the dep-guardian Hand.
/// Extends dep_audit with diff-against-previous, auto-patching, and PR branch creation.
///
/// Pipeline: detect PM → audit → diff vs previous → optional auto-patch → return result

use serde::{Deserialize, Serialize};
use std::process::Command;

// ═══════════════════════════════════════════════
// OUTPUT SCHEMAS
// ═══════════════════════════════════════════════

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DepVuln {
    pub package: String,
    pub current_version: String,
    pub severity: String,
    pub cve_id: Option<String>,
    pub title: String,
    pub patched_version: Option<String>,
    pub breaking_change: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PatchAction {
    pub package: String,
    pub from_version: String,
    pub to_version: String,
    pub pr_branch: String,
    pub tests_passed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepCheckResult {
    pub repo_path: String,
    pub package_manager: String,
    pub total_deps: usize,
    pub new_vulns: Vec<DepVuln>,
    pub auto_patched: Vec<PatchAction>,
    pub needs_review: Vec<String>,
    pub scan_timestamp: String,
    pub previous_check: Option<String>,
    pub scan_duration_ms: u64,
}

// ═══════════════════════════════════════════════
// MAIN TOOL ENTRY POINT
// ═══════════════════════════════════════════════

pub async fn tool_check_dependencies(input: &serde_json::Value) -> Result<String, String> {
    let repo_path = input["repo_path"]
        .as_str()
        .ok_or("Missing 'repo_path' field")?;

    let previous_results_path = input["previous_results_path"].as_str();
    let auto_patch = input["auto_patch"].as_bool().unwrap_or(false);

    let start = std::time::Instant::now();
    let scan_timestamp = chrono::Utc::now().to_rfc3339();

    // Step 1: Detect package manager
    let package_manager = detect_package_manager(repo_path);

    // Step 2: Run audit command and parse vulns
    let all_vulns = run_audit(repo_path, &package_manager)?;
    let total_deps = count_total_deps(repo_path, &package_manager);

    // Step 3: If previous results provided, diff to find NEW vulns only
    let (new_vulns, previous_check) = if let Some(prev_path) = previous_results_path {
        let previous_check_ts = load_previous_timestamp(prev_path);
        let previous_vulns = load_previous_vulns(prev_path)?;
        let new_only = diff_results(&all_vulns, &previous_vulns);
        (new_only, previous_check_ts)
    } else {
        (all_vulns, None)
    };

    // Step 4 & 5: Auto-patch mode
    let mut auto_patched: Vec<PatchAction> = Vec::new();
    let mut needs_review: Vec<String> = Vec::new();

    if auto_patch {
        for vuln in &new_vulns {
            if vuln.breaking_change {
                needs_review.push(format!(
                    "{} {} → {} (breaking change, manual review required)",
                    vuln.package,
                    vuln.current_version,
                    vuln.patched_version
                        .as_deref()
                        .unwrap_or("no patch available")
                ));
                continue;
            }

            match &vuln.patched_version {
                None => {
                    needs_review.push(format!(
                        "{} {} — no patched version available ({})",
                        vuln.package, vuln.current_version, vuln.severity
                    ));
                }
                Some(patched) => {
                    let branch = format!(
                        "shieldagi/dep-update-{}-{}",
                        sanitize_branch_segment(&vuln.package),
                        sanitize_branch_segment(patched)
                    );

                    // Create branch
                    let branch_created = Command::new("git")
                        .args(["checkout", "-b", &branch])
                        .current_dir(repo_path)
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false);

                    if !branch_created {
                        needs_review.push(format!(
                            "{} — failed to create branch {}",
                            vuln.package, branch
                        ));
                        continue;
                    }

                    // Run update command
                    let update_ok = run_update_command(
                        repo_path,
                        &package_manager,
                        &vuln.package,
                        patched,
                    );

                    if !update_ok {
                        // Restore main branch
                        let _ = Command::new("git")
                            .args(["checkout", "-"])
                            .current_dir(repo_path)
                            .output();
                        needs_review.push(format!(
                            "{} — update command failed on branch {}",
                            vuln.package, branch
                        ));
                        continue;
                    }

                    // Run tests
                    let tests_passed = run_tests(repo_path, &package_manager);

                    if tests_passed {
                        // Commit the change
                        let commit_msg = format!(
                            "fix(deps): bump {} from {} to {} (security patch)",
                            vuln.package, vuln.current_version, patched
                        );
                        let _ = Command::new("git")
                            .args(["add", "-A"])
                            .current_dir(repo_path)
                            .output();
                        let _ = Command::new("git")
                            .args(["commit", "-m", &commit_msg])
                            .current_dir(repo_path)
                            .output();

                        auto_patched.push(PatchAction {
                            package: vuln.package.clone(),
                            from_version: vuln.current_version.clone(),
                            to_version: patched.clone(),
                            pr_branch: branch,
                            tests_passed: true,
                        });
                    } else {
                        // Tests failed — revert and flag for review
                        let _ = Command::new("git")
                            .args(["checkout", "-"])
                            .current_dir(repo_path)
                            .output();
                        auto_patched.push(PatchAction {
                            package: vuln.package.clone(),
                            from_version: vuln.current_version.clone(),
                            to_version: patched.clone(),
                            pr_branch: branch,
                            tests_passed: false,
                        });
                        needs_review.push(format!(
                            "{} — tests failed after patching to {}, needs manual verification",
                            vuln.package, patched
                        ));
                    }

                    // Return to default branch for next iteration
                    let _ = Command::new("git")
                        .args(["checkout", "-"])
                        .current_dir(repo_path)
                        .output();
                }
            }
        }
    } else {
        // Not auto-patching — collect everything with a patch as needs_review
        for vuln in &new_vulns {
            if vuln.breaking_change {
                needs_review.push(format!(
                    "{} {} — breaking change, manual upgrade to {} required",
                    vuln.package,
                    vuln.current_version,
                    vuln.patched_version.as_deref().unwrap_or("N/A")
                ));
            } else if vuln.patched_version.is_none() {
                needs_review.push(format!(
                    "{} {} — no fix available ({}), consider replacement",
                    vuln.package, vuln.current_version, vuln.severity
                ));
            }
        }
    }

    let duration = start.elapsed().as_millis() as u64;

    let result = DepCheckResult {
        repo_path: repo_path.to_string(),
        package_manager,
        total_deps,
        new_vulns,
        auto_patched,
        needs_review,
        scan_timestamp,
        previous_check,
        scan_duration_ms: duration,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

// ═══════════════════════════════════════════════
// PACKAGE MANAGER DETECTION
// ═══════════════════════════════════════════════

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

// ═══════════════════════════════════════════════
// AUDIT DISPATCH
// ═══════════════════════════════════════════════

fn run_audit(repo_path: &str, package_manager: &str) -> Result<Vec<DepVuln>, String> {
    match package_manager {
        "npm" => {
            let output = Command::new("npm")
                .args(["audit", "--json"])
                .current_dir(repo_path)
                .output()
                .map_err(|e| format!("Failed to run npm audit: {}", e))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(parse_npm_audit(&stdout))
        }
        "pip" => {
            let output = Command::new("pip-audit")
                .args(["--format", "json"])
                .current_dir(repo_path)
                .output()
                .map_err(|e| format!("Failed to run pip-audit: {}", e))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(parse_pip_audit(&stdout))
        }
        "cargo" => {
            let output = Command::new("cargo")
                .args(["audit", "--json"])
                .current_dir(repo_path)
                .output()
                .map_err(|e| format!("Failed to run cargo audit: {}", e))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(parse_cargo_audit(&stdout))
        }
        other => Err(format!("Unsupported package manager: {}", other)),
    }
}

fn count_total_deps(repo_path: &str, package_manager: &str) -> usize {
    match package_manager {
        "npm" => {
            // npm list --json gives full dependency tree
            let output = Command::new("npm")
                .args(["list", "--json", "--all"])
                .current_dir(repo_path)
                .output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(deps) = json["dependencies"].as_object() {
                        return deps.len();
                    }
                }
            }
            0
        }
        "pip" => {
            let output = Command::new("pip")
                .args(["list", "--format=json"])
                .current_dir(repo_path)
                .output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(arr) = json.as_array() {
                        return arr.len();
                    }
                }
            }
            0
        }
        "cargo" => {
            let output = Command::new("cargo")
                .args(["metadata", "--format-version", "1", "--no-deps"])
                .current_dir(repo_path)
                .output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(packages) = json["packages"].as_array() {
                        return packages.len();
                    }
                }
            }
            0
        }
        _ => 0,
    }
}

// ═══════════════════════════════════════════════
// NPM AUDIT PARSER
// npm audit --json v2+ format:
// { vulnerabilities: { pkg: { severity, via: [{title, url}], fixAvailable, range } } }
// ═══════════════════════════════════════════════

fn parse_npm_audit(output: &str) -> Vec<DepVuln> {
    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(j) => j,
        Err(_) => return vec![],
    };

    let mut vulns = Vec::new();

    let vulnerabilities = match json["vulnerabilities"].as_object() {
        Some(v) => v,
        None => return vulns,
    };

    for (pkg_name, vuln_data) in vulnerabilities {
        let severity = normalize_severity(vuln_data["severity"].as_str().unwrap_or("medium"));
        let range = vuln_data["range"].as_str().unwrap_or("unknown").to_string();

        // Determine if a specific patched version is available
        let fix_available = match &vuln_data["fixAvailable"] {
            v if v.is_boolean() => v.as_bool().unwrap_or(false),
            v if v.is_object() => true,
            _ => false,
        };

        let patched_version = if fix_available {
            // Try to extract the exact version from fixAvailable object
            vuln_data["fixAvailable"]["version"]
                .as_str()
                .map(String::from)
                .or_else(|| Some("latest".to_string()))
        } else {
            None
        };

        // Breaking change flag comes from fixAvailable.isSemVerMajor
        let breaking_change = vuln_data["fixAvailable"]["isSemVerMajor"]
            .as_bool()
            .unwrap_or(false);

        // Pull title and CVE from via array
        let mut title = pkg_name.clone();
        let mut cve_id: Option<String> = None;

        if let Some(via) = vuln_data["via"].as_array() {
            for v in via {
                if let Some(t) = v["title"].as_str() {
                    title = t.to_string();
                }
                // Extract CVE from URL
                if let Some(url) = v["url"].as_str() {
                    if let Some(pos) = url.find("CVE-") {
                        let cve_slice = &url[pos..];
                        let end = cve_slice
                            .find(|c: char| !c.is_alphanumeric() && c != '-')
                            .unwrap_or(cve_slice.len());
                        cve_id = Some(cve_slice[..end].to_string());
                    }
                }
            }
        }

        vulns.push(DepVuln {
            package: pkg_name.clone(),
            current_version: range,
            severity,
            cve_id,
            title,
            patched_version,
            breaking_change,
        });
    }

    vulns
}

// ═══════════════════════════════════════════════
// PIP-AUDIT PARSER
// pip-audit --format json output:
// { dependencies: [{ name, version, vulns: [{ id, fix_versions, description, aliases }] }] }
// ═══════════════════════════════════════════════

fn parse_pip_audit(output: &str) -> Vec<DepVuln> {
    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(j) => j,
        Err(_) => return vec![],
    };

    let mut vulns = Vec::new();

    let dependencies = match json["dependencies"].as_array() {
        Some(d) => d,
        None => return vulns,
    };

    for dep in dependencies {
        let pkg_name = dep["name"].as_str().unwrap_or("").to_string();
        let current_version = dep["version"].as_str().unwrap_or("unknown").to_string();

        let dep_vulns = match dep["vulns"].as_array() {
            Some(v) => v,
            None => continue,
        };

        for v in dep_vulns {
            let vuln_id = v["id"].as_str().unwrap_or("").to_string();
            let description = v["description"].as_str().unwrap_or("").to_string();

            // pip-audit doesn't always include severity; infer from CVSS aliases
            let severity = infer_pip_severity(v);

            // Fix versions
            let fix_versions: Vec<String> = v["fix_versions"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|fv| fv.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let patched_version = fix_versions.first().cloned();

            // CVE ID: prefer aliases that start with CVE-, fall back to id
            let cve_id = v["aliases"]
                .as_array()
                .and_then(|aliases| {
                    aliases
                        .iter()
                        .find_map(|a| a.as_str().filter(|s| s.starts_with("CVE-")).map(String::from))
                })
                .or_else(|| {
                    if vuln_id.starts_with("CVE-") {
                        Some(vuln_id.clone())
                    } else {
                        None
                    }
                });

            // pip-audit never reports breaking changes directly; flag if major version bump
            let breaking_change = patched_version
                .as_deref()
                .map(|pv| is_major_bump(&current_version, pv))
                .unwrap_or(false);

            vulns.push(DepVuln {
                package: pkg_name.clone(),
                current_version: current_version.clone(),
                severity,
                cve_id,
                title: if description.is_empty() {
                    vuln_id.clone()
                } else {
                    // Truncate long descriptions to a useful title
                    description.lines().next().unwrap_or(&vuln_id).to_string()
                },
                patched_version,
                breaking_change,
            });
        }
    }

    vulns
}

fn infer_pip_severity(vuln: &serde_json::Value) -> String {
    // pip-audit may expose a severity field in newer versions
    if let Some(s) = vuln["severity"].as_str() {
        return normalize_severity(s);
    }
    // Fall back to MEDIUM as a safe default for pip advisories
    "MEDIUM".to_string()
}

// ═══════════════════════════════════════════════
// CARGO AUDIT PARSER
// cargo audit --json output:
// { vulnerabilities: { list: [{ advisory: { id, title, url, cvss, versions: { patched } }, package: { name, version } }] } }
// ═══════════════════════════════════════════════

fn parse_cargo_audit(output: &str) -> Vec<DepVuln> {
    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(j) => j,
        Err(_) => return vec![],
    };

    let mut vulns = Vec::new();

    let list = match json["vulnerabilities"]["list"].as_array() {
        Some(l) => l,
        None => return vulns,
    };

    for entry in list {
        let adv = &entry["advisory"];
        let pkg = &entry["package"];

        let package = pkg["name"].as_str().unwrap_or("").to_string();
        let current_version = pkg["version"].as_str().unwrap_or("unknown").to_string();
        let title = adv["title"].as_str().unwrap_or("").to_string();

        // CVSS string from cargo-audit: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        let severity = adv["cvss"]
            .as_str()
            .map(|cvss| cvss_string_to_severity(cvss))
            .unwrap_or_else(|| "MEDIUM".to_string());

        // Advisory ID — may be RUSTSEC-YYYY-NNNN or CVE-YYYY-NNNN
        let advisory_id = adv["id"].as_str().unwrap_or("").to_string();

        // Extract CVE from aliases list or from id directly
        let cve_id = adv["aliases"]
            .as_array()
            .and_then(|aliases| {
                aliases
                    .iter()
                    .find_map(|a| a.as_str().filter(|s| s.starts_with("CVE-")).map(String::from))
            })
            .or_else(|| {
                if advisory_id.starts_with("CVE-") {
                    Some(advisory_id.clone())
                } else {
                    None
                }
            });

        // Patched versions list (requirement ranges like ">= 1.2.3")
        let patched_version = adv["versions"]["patched"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(String::from);

        // Cargo ecosystem rarely has breaking changes in security patches,
        // but flag if the patched constraint implies a major version boundary
        let breaking_change = patched_version
            .as_deref()
            .map(|pv| {
                // A patched constraint like ">= 2.0.0" when on 1.x is a major bump
                let clean_pv = pv
                    .trim_start_matches(|c: char| !c.is_numeric())
                    .split(' ')
                    .next()
                    .unwrap_or(pv);
                is_major_bump(&current_version, clean_pv)
            })
            .unwrap_or(false);

        vulns.push(DepVuln {
            package,
            current_version,
            severity,
            cve_id,
            title,
            patched_version,
            breaking_change,
        });
    }

    vulns
}

// ═══════════════════════════════════════════════
// DIFF: find vulns in current that are NOT in previous
// Match by (package, cve_id or title) to avoid duplicate alerts
// ═══════════════════════════════════════════════

fn diff_results(current: &[DepVuln], previous: &[DepVuln]) -> Vec<DepVuln> {
    current
        .iter()
        .filter(|curr| {
            !previous.iter().any(|prev| {
                // Two vulns are the same if they share the package and either CVE id or title
                if curr.package != prev.package {
                    return false;
                }
                match (&curr.cve_id, &prev.cve_id) {
                    (Some(a), Some(b)) => a == b,
                    _ => curr.title == prev.title,
                }
            })
        })
        .cloned()
        .collect()
}

// ═══════════════════════════════════════════════
// PREVIOUS RESULTS HELPERS
// ═══════════════════════════════════════════════

fn load_previous_vulns(path: &str) -> Result<Vec<DepVuln>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read previous results from {}: {}", path, e))?;

    let prev_result: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse previous results JSON: {}", e))?;

    // The previous file is itself a DepCheckResult; extract new_vulns
    serde_json::from_value(prev_result["new_vulns"].clone())
        .map_err(|e| format!("Failed to deserialize previous vulns: {}", e))
}

fn load_previous_timestamp(path: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json["scan_timestamp"].as_str().map(String::from)
}

// ═══════════════════════════════════════════════
// PATCH HELPERS
// ═══════════════════════════════════════════════

fn run_update_command(
    repo_path: &str,
    package_manager: &str,
    package: &str,
    version: &str,
) -> bool {
    let output = match package_manager {
        "npm" => Command::new("npm")
            .args(["install", &format!("{}@{}", package, version)])
            .current_dir(repo_path)
            .output(),
        "pip" => Command::new("pip")
            .args(["install", &format!("{}=={}", package, version)])
            .current_dir(repo_path)
            .output(),
        "cargo" => Command::new("cargo")
            .args(["update", "-p", package, "--precise", version])
            .current_dir(repo_path)
            .output(),
        _ => return false,
    };

    output.map(|o| o.status.success()).unwrap_or(false)
}

fn run_tests(repo_path: &str, package_manager: &str) -> bool {
    let output = match package_manager {
        "npm" => Command::new("npm")
            .args(["test", "--", "--passWithNoTests"])
            .current_dir(repo_path)
            .output(),
        "pip" => Command::new("python")
            .args(["-m", "pytest", "--tb=short", "-q"])
            .current_dir(repo_path)
            .output(),
        "cargo" => Command::new("cargo")
            .args(["test", "--quiet"])
            .current_dir(repo_path)
            .output(),
        _ => return false,
    };

    output.map(|o| o.status.success()).unwrap_or(false)
}

fn sanitize_branch_segment(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

// ═══════════════════════════════════════════════
// SEVERITY HELPERS
// ═══════════════════════════════════════════════

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

/// Convert a CVSS v3 vector string to a severity label using the base score bucket.
/// cargo-audit emits the raw CVSS vector; we extract the score from the metrics.
fn cvss_string_to_severity(cvss: &str) -> String {
    // Simplified: derive score from common AV/AC/PR/UI combits rather than
    // a full CVSS calculation, because cargo-audit gives us the vector not the score.
    // Use a heuristic: count high-impact components.
    let high_components = ["AV:N", "AC:L", "PR:N", "UI:N", "C:H", "I:H", "A:H"];
    let count = high_components
        .iter()
        .filter(|&&c| cvss.contains(c))
        .count();

    if count >= 6 {
        "CRITICAL".to_string()
    } else if count >= 4 {
        "HIGH".to_string()
    } else if count >= 2 {
        "MEDIUM".to_string()
    } else {
        "LOW".to_string()
    }
}

/// Returns true if upgrading from `current` to `target` is a major semver bump.
fn is_major_bump(current: &str, target: &str) -> bool {
    let current_major = current
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let target_major = target
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    target_major > current_major
}

// ═══════════════════════════════════════════════
// UNIT TESTS
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── npm audit parser ──────────────────────────────────────────────────

    #[test]
    fn test_parse_npm_audit_basic() {
        let json = serde_json::json!({
            "vulnerabilities": {
                "lodash": {
                    "severity": "high",
                    "via": [
                        {
                            "title": "Prototype Pollution in lodash",
                            "url": "https://github.com/advisories/GHSA-jf85-cpcp-j695"
                        }
                    ],
                    "range": "< 4.17.21",
                    "fixAvailable": {
                        "version": "4.17.21",
                        "isSemVerMajor": false
                    }
                }
            }
        });

        let result = parse_npm_audit(&json.to_string());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].package, "lodash");
        assert_eq!(result[0].severity, "HIGH");
        assert_eq!(result[0].patched_version, Some("4.17.21".to_string()));
        assert!(!result[0].breaking_change);
        assert_eq!(result[0].title, "Prototype Pollution in lodash");
    }

    #[test]
    fn test_parse_npm_audit_cve_extraction() {
        let json = serde_json::json!({
            "vulnerabilities": {
                "axios": {
                    "severity": "critical",
                    "via": [
                        {
                            "title": "SSRF in axios",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-45857"
                        }
                    ],
                    "range": "< 1.6.0",
                    "fixAvailable": true
                }
            }
        });

        let result = parse_npm_audit(&json.to_string());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].cve_id, Some("CVE-2023-45857".to_string()));
        assert_eq!(result[0].severity, "CRITICAL");
    }

    #[test]
    fn test_parse_npm_audit_breaking_change() {
        let json = serde_json::json!({
            "vulnerabilities": {
                "semver": {
                    "severity": "high",
                    "via": [{ "title": "ReDoS in semver" }],
                    "range": "< 7.5.2",
                    "fixAvailable": {
                        "version": "7.5.2",
                        "isSemVerMajor": true
                    }
                }
            }
        });

        let result = parse_npm_audit(&json.to_string());
        assert_eq!(result.len(), 1);
        assert!(result[0].breaking_change);
    }

    #[test]
    fn test_parse_npm_audit_no_fix() {
        let json = serde_json::json!({
            "vulnerabilities": {
                "old-pkg": {
                    "severity": "moderate",
                    "via": [{ "title": "Known vuln with no fix" }],
                    "range": "* ",
                    "fixAvailable": false
                }
            }
        });

        let result = parse_npm_audit(&json.to_string());
        assert_eq!(result.len(), 1);
        assert!(result[0].patched_version.is_none());
        assert_eq!(result[0].severity, "MEDIUM");
    }

    #[test]
    fn test_parse_npm_audit_empty() {
        let json = serde_json::json!({ "vulnerabilities": {} });
        let result = parse_npm_audit(&json.to_string());
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_npm_audit_malformed() {
        let result = parse_npm_audit("not json at all {{");
        assert!(result.is_empty());
    }

    // ── pip-audit parser ──────────────────────────────────────────────────

    #[test]
    fn test_parse_pip_audit_basic() {
        let json = serde_json::json!({
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.27.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-74",
                            "description": "Requests allows proxy credential exposure",
                            "fix_versions": ["2.31.0"],
                            "aliases": ["CVE-2023-32681"]
                        }
                    ]
                }
            ]
        });

        let result = parse_pip_audit(&json.to_string());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].package, "requests");
        assert_eq!(result[0].current_version, "2.27.0");
        assert_eq!(result[0].patched_version, Some("2.31.0".to_string()));
        assert_eq!(result[0].cve_id, Some("CVE-2023-32681".to_string()));
    }

    #[test]
    fn test_parse_pip_audit_no_fix() {
        let json = serde_json::json!({
            "dependencies": [
                {
                    "name": "insecure-lib",
                    "version": "1.0.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2024-01",
                            "description": "Critical issue with no fix",
                            "fix_versions": [],
                            "aliases": []
                        }
                    ]
                }
            ]
        });

        let result = parse_pip_audit(&json.to_string());
        assert_eq!(result.len(), 1);
        assert!(result[0].patched_version.is_none());
        assert!(result[0].cve_id.is_none());
    }

    #[test]
    fn test_parse_pip_audit_no_vulns() {
        let json = serde_json::json!({
            "dependencies": [
                { "name": "safe-lib", "version": "1.0.0", "vulns": [] }
            ]
        });
        let result = parse_pip_audit(&json.to_string());
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_pip_audit_multiple() {
        let json = serde_json::json!({
            "dependencies": [
                {
                    "name": "flask",
                    "version": "1.0.0",
                    "vulns": [
                        {
                            "id": "CVE-2018-1000656",
                            "description": "Flask DoS via large JSON",
                            "fix_versions": ["1.0.1"],
                            "aliases": ["CVE-2018-1000656"]
                        },
                        {
                            "id": "PYSEC-2023-100",
                            "description": "Another flask issue",
                            "fix_versions": ["2.3.0"],
                            "aliases": []
                        }
                    ]
                }
            ]
        });

        let result = parse_pip_audit(&json.to_string());
        assert_eq!(result.len(), 2);
    }

    // ── cargo audit parser ────────────────────────────────────────────────

    #[test]
    fn test_parse_cargo_audit_basic() {
        let json = serde_json::json!({
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2022-0090",
                            "title": "Integer overflow in time crate",
                            "url": "https://rustsec.org/advisories/RUSTSEC-2022-0090.html",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "versions": {
                                "patched": [">= 0.3.20"]
                            },
                            "aliases": ["CVE-2022-23174"]
                        },
                        "package": {
                            "name": "time",
                            "version": "0.3.1"
                        }
                    }
                ]
            }
        });

        let result = parse_cargo_audit(&json.to_string());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].package, "time");
        assert_eq!(result[0].current_version, "0.3.1");
        assert_eq!(result[0].cve_id, Some("CVE-2022-23174".to_string()));
        assert_eq!(result[0].severity, "CRITICAL");
        assert_eq!(
            result[0].patched_version,
            Some(">= 0.3.20".to_string())
        );
    }

    #[test]
    fn test_parse_cargo_audit_no_aliases() {
        let json = serde_json::json!({
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2023-0001",
                            "title": "Use-after-free in unsafe-crate",
                            "cvss": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
                            "versions": { "patched": [] },
                            "aliases": []
                        },
                        "package": { "name": "unsafe-crate", "version": "1.0.0" }
                    }
                ]
            }
        });

        let result = parse_cargo_audit(&json.to_string());
        assert_eq!(result.len(), 1);
        assert!(result[0].cve_id.is_none());
        assert!(result[0].patched_version.is_none());
        assert_eq!(result[0].severity, "LOW");
    }

    #[test]
    fn test_parse_cargo_audit_empty() {
        let json = serde_json::json!({ "vulnerabilities": { "list": [] } });
        let result = parse_cargo_audit(&json.to_string());
        assert!(result.is_empty());
    }

    // ── diff_results ─────────────────────────────────────────────────────

    #[test]
    fn test_diff_results_finds_new_vulns() {
        let previous = vec![DepVuln {
            package: "lodash".to_string(),
            current_version: "4.17.20".to_string(),
            severity: "HIGH".to_string(),
            cve_id: Some("CVE-2021-23337".to_string()),
            title: "Command Injection".to_string(),
            patched_version: Some("4.17.21".to_string()),
            breaking_change: false,
        }];

        let current = vec![
            previous[0].clone(),
            DepVuln {
                package: "axios".to_string(),
                current_version: "0.21.0".to_string(),
                severity: "CRITICAL".to_string(),
                cve_id: Some("CVE-2023-45857".to_string()),
                title: "SSRF".to_string(),
                patched_version: Some("1.6.0".to_string()),
                breaking_change: false,
            },
        ];

        let new_vulns = diff_results(&current, &previous);
        assert_eq!(new_vulns.len(), 1);
        assert_eq!(new_vulns[0].package, "axios");
    }

    #[test]
    fn test_diff_results_no_new_vulns() {
        let vuln = DepVuln {
            package: "requests".to_string(),
            current_version: "2.27.0".to_string(),
            severity: "MEDIUM".to_string(),
            cve_id: Some("CVE-2023-32681".to_string()),
            title: "Proxy credential exposure".to_string(),
            patched_version: Some("2.31.0".to_string()),
            breaking_change: false,
        };
        let current = vec![vuln.clone()];
        let previous = vec![vuln];

        let new_vulns = diff_results(&current, &previous);
        assert!(new_vulns.is_empty());
    }

    #[test]
    fn test_diff_results_matches_by_title_when_no_cve() {
        let previous = vec![DepVuln {
            package: "some-pkg".to_string(),
            current_version: "1.0.0".to_string(),
            severity: "MEDIUM".to_string(),
            cve_id: None,
            title: "Known ReDoS vulnerability".to_string(),
            patched_version: None,
            breaking_change: false,
        }];

        let current = vec![previous[0].clone()];
        let new_vulns = diff_results(&current, &previous);
        assert!(new_vulns.is_empty());
    }

    #[test]
    fn test_diff_results_empty_previous() {
        let current = vec![DepVuln {
            package: "new-pkg".to_string(),
            current_version: "0.1.0".to_string(),
            severity: "HIGH".to_string(),
            cve_id: Some("CVE-2024-0001".to_string()),
            title: "Brand new vuln".to_string(),
            patched_version: Some("0.2.0".to_string()),
            breaking_change: false,
        }];

        let new_vulns = diff_results(&current, &[]);
        assert_eq!(new_vulns.len(), 1);
    }

    // ── helpers ───────────────────────────────────────────────────────────

    #[test]
    fn test_normalize_severity() {
        assert_eq!(normalize_severity("critical"), "CRITICAL");
        assert_eq!(normalize_severity("CRITICAL"), "CRITICAL");
        assert_eq!(normalize_severity("high"), "HIGH");
        assert_eq!(normalize_severity("moderate"), "MEDIUM");
        assert_eq!(normalize_severity("medium"), "MEDIUM");
        assert_eq!(normalize_severity("low"), "LOW");
        assert_eq!(normalize_severity("info"), "INFO");
        assert_eq!(normalize_severity("unknown_xyz"), "MEDIUM");
    }

    #[test]
    fn test_detect_package_manager_nonexistent_path() {
        // Nonexistent path should return default "npm"
        let result = detect_package_manager("/nonexistent/path/xyz");
        assert_eq!(result, "npm");
    }

    #[test]
    fn test_is_major_bump() {
        assert!(is_major_bump("1.2.3", "2.0.0"));
        assert!(!is_major_bump("1.2.3", "1.9.9"));
        assert!(!is_major_bump("2.0.0", "2.5.1"));
        assert!(is_major_bump("0.9.9", "1.0.0"));
    }

    #[test]
    fn test_cvss_string_to_severity() {
        // All high-impact components → CRITICAL
        assert_eq!(
            cvss_string_to_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "CRITICAL"
        );
        // Fewer high-impact → lower severity
        assert_eq!(
            cvss_string_to_severity("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"),
            "LOW"
        );
    }

    #[test]
    fn test_sanitize_branch_segment() {
        assert_eq!(sanitize_branch_segment("lodash"), "lodash");
        assert_eq!(sanitize_branch_segment("@babel/core"), "_babel_core");
        assert_eq!(sanitize_branch_segment("1.2.3"), "1.2.3");
        assert_eq!(sanitize_branch_segment("pkg name"), "pkg_name");
    }
}
