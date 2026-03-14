/// ShieldAGI Tool: semgrep_scan
///
/// Runs semgrep static analysis against a repository with OWASP and custom
/// ShieldAGI rules. Parses JSON output into structured findings.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct SemgrepResult {
    pub repo_path: String,
    pub ruleset: String,
    pub total_findings: usize,
    pub findings: Vec<SemgrepFinding>,
    pub errors: Vec<String>,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SemgrepFinding {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line_start: u64,
    pub line_end: u64,
    pub code_snippet: String,
    pub category: String,
    pub cwe: Vec<String>,
    pub fix_suggestion: Option<String>,
}

/// Custom ShieldAGI semgrep rules targeting common web vulnerabilities
const SHIELDAGI_RULES_YAML: &str = r#"rules:
  - id: shieldagi.sqli-string-concat
    patterns:
      - pattern-either:
        - pattern: pool.query(`... ${...} ...`)
        - pattern: pool.query("..." + $VAR + "...")
        - pattern: $DB.execute(f"... {$VAR} ...")
        - pattern: cursor.execute("..." + $VAR + "...")
        - pattern: cursor.execute(f"... {$VAR} ...")
    message: "SQL query built with string concatenation — vulnerable to SQL injection"
    severity: ERROR
    languages: [javascript, typescript, python]
    metadata:
      category: security
      cwe: ["CWE-89"]

  - id: shieldagi.xss-raw-html
    patterns:
      - pattern-either:
        - pattern: res.send(`... ${$INPUT} ...`)
        - pattern: res.send("..." + $INPUT + "...")
        - pattern: "dangerouslySetInnerHTML={{__html: $VAR}}"
    message: "User input reflected in HTML without sanitization — XSS vulnerability"
    severity: ERROR
    languages: [javascript, typescript]
    metadata:
      category: security
      cwe: ["CWE-79"]

  - id: shieldagi.ssrf-unvalidated-url
    patterns:
      - pattern-either:
        - pattern: fetch($URL)
        - pattern: axios.get($URL)
        - pattern: requests.get($URL)
        - pattern: http.get($URL, ...)
    message: "Server-side request with unvalidated URL — potential SSRF"
    severity: WARNING
    languages: [javascript, typescript, python]
    metadata:
      category: security
      cwe: ["CWE-918"]

  - id: shieldagi.hardcoded-secret
    patterns:
      - pattern-either:
        - pattern: |
            const $KEY = '...'
        - pattern: |
            $KEY = "sk-..."
        - pattern: |
            $KEY = "api_key_..."
    message: "Hardcoded secret or API key detected"
    severity: ERROR
    languages: [javascript, typescript, python]
    metadata:
      category: security
      cwe: ["CWE-798"]

  - id: shieldagi.path-traversal
    patterns:
      - pattern-either:
        - pattern: path.join(..., $INPUT)
        - pattern: os.path.join(..., $INPUT)
        - pattern: fs.readFileSync($INPUT)
    message: "File path constructed from user input without sanitization — path traversal risk"
    severity: ERROR
    languages: [javascript, typescript, python]
    metadata:
      category: security
      cwe: ["CWE-22"]

  - id: shieldagi.weak-jwt
    patterns:
      - pattern-either:
        - pattern: jwt.sign($PAYLOAD, "...", ...)
        - pattern: jwt.sign($PAYLOAD, $SECRET, {expiresIn: '30d'})
    message: "JWT signed with potentially weak secret or overly long expiration"
    severity: WARNING
    languages: [javascript, typescript]
    metadata:
      category: security
      cwe: ["CWE-347"]

  - id: shieldagi.cookie-no-flags
    patterns:
      - pattern-either:
        - pattern: res.cookie($NAME, $VAL)
        - pattern: res.cookie($NAME, $VAL, {})
    message: "Cookie set without Secure, HttpOnly, or SameSite flags"
    severity: WARNING
    languages: [javascript, typescript]
    metadata:
      category: security
      cwe: ["CWE-614"]

  - id: shieldagi.stack-trace-leak
    patterns:
      - pattern-either:
        - pattern: "res.json({..., stack: $ERR.stack, ...})"
        - pattern: "res.send($ERR.stack)"
    message: "Stack trace exposed in error response — information disclosure"
    severity: WARNING
    languages: [javascript, typescript]
    metadata:
      category: security
      cwe: ["CWE-209"]
"#;

pub async fn tool_semgrep_scan(input: &serde_json::Value) -> Result<String, String> {
    let repo_path = input["repo_path"]
        .as_str()
        .ok_or("Missing 'repo_path' field")?;

    let ruleset = input["ruleset"].as_str().unwrap_or("all");
    let language = input["language"].as_str();
    let min_severity = input["severity"].as_str().unwrap_or("INFO");

    // Write custom ShieldAGI rules to temp file
    let rules_path = "/tmp/shieldagi-semgrep-rules.yaml";
    std::fs::write(rules_path, SHIELDAGI_RULES_YAML)
        .map_err(|e| format!("Failed to write custom rules: {}", e))?;

    let start = std::time::Instant::now();

    let mut args = vec![
        "scan".to_string(),
        "--json".to_string(),
        "--no-git-ignore".to_string(),
        "--timeout".to_string(),
        "60".to_string(),
    ];

    match ruleset {
        "owasp" => {
            args.push("--config".to_string());
            args.push("p/owasp-top-ten".to_string());
        }
        "shieldagi" => {
            args.push("--config".to_string());
            args.push(rules_path.to_string());
        }
        _ => {
            args.push("--config".to_string());
            args.push("p/owasp-top-ten".to_string());
            args.push("--config".to_string());
            args.push(rules_path.to_string());
        }
    }

    if let Some(lang) = language {
        args.push("--lang".to_string());
        args.push(lang.to_string());
    }

    args.push(repo_path.to_string());

    let output = Command::new("semgrep")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to execute semgrep: {}", e))?;

    let duration = start.elapsed().as_millis() as u64;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut findings = Vec::new();
    let mut errors = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(results) = json["results"].as_array() {
            for result in results {
                let severity = result["extra"]["severity"]
                    .as_str()
                    .unwrap_or("INFO")
                    .to_string();

                if !meets_severity_threshold(&severity, min_severity) {
                    continue;
                }

                let cwe = result["extra"]["metadata"]["cwe"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                findings.push(SemgrepFinding {
                    rule_id: result["check_id"].as_str().unwrap_or("").to_string(),
                    severity,
                    message: result["extra"]["message"].as_str().unwrap_or("").to_string(),
                    file: result["path"].as_str().unwrap_or("").to_string(),
                    line_start: result["start"]["line"].as_u64().unwrap_or(0),
                    line_end: result["end"]["line"].as_u64().unwrap_or(0),
                    code_snippet: result["extra"]["lines"].as_str().unwrap_or("").to_string(),
                    category: result["extra"]["metadata"]["category"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string(),
                    cwe,
                    fix_suggestion: result["extra"]["fix"].as_str().map(String::from),
                });
            }
        }

        if let Some(errs) = json["errors"].as_array() {
            for err in errs {
                if let Some(msg) = err["message"].as_str() {
                    errors.push(msg.to_string());
                }
            }
        }
    } else if !stdout.is_empty() {
        errors.push("Failed to parse semgrep JSON output".to_string());
    }

    let result = SemgrepResult {
        repo_path: repo_path.to_string(),
        ruleset: ruleset.to_string(),
        total_findings: findings.len(),
        findings,
        errors,
        scan_duration_ms: duration,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

fn meets_severity_threshold(severity: &str, threshold: &str) -> bool {
    let level = |s: &str| match s.to_uppercase().as_str() {
        "ERROR" => 3,
        "WARNING" => 2,
        "INFO" => 1,
        _ => 0,
    };
    level(severity) >= level(threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_threshold() {
        assert!(meets_severity_threshold("ERROR", "INFO"));
        assert!(meets_severity_threshold("ERROR", "WARNING"));
        assert!(meets_severity_threshold("ERROR", "ERROR"));
        assert!(meets_severity_threshold("WARNING", "INFO"));
        assert!(!meets_severity_threshold("INFO", "ERROR"));
        assert!(!meets_severity_threshold("WARNING", "ERROR"));
    }
}
