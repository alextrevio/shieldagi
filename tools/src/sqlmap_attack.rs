/// ShieldAGI Tool: sqlmap_attack
///
/// Wraps the sqlmap binary to test for SQL injection vulnerabilities.
/// Runs ONLY inside the Docker sandbox — never against production.
///
/// Output: Structured JSON with injectable parameters, injection types,
/// payloads, and DBMS identification.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct SqlmapResult {
    pub target_url: String,
    pub injectable: bool,
    pub injection_type: Vec<String>,
    pub dbms: Option<String>,
    pub parameters: Vec<InjectableParam>,
    pub tables_enumerated: Vec<String>,
    pub scan_duration_ms: u64,
    pub risk_level: u64,
    pub test_level: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InjectableParam {
    pub name: String,
    pub injection_type: String,
    pub payload: String,
    pub place: String, // GET, POST, COOKIE, HEADER
    pub dbms: Option<String>,
    pub title: String,
}

pub async fn tool_sqlmap_attack(input: &serde_json::Value) -> Result<String, String> {
    let target_url = input["target_url"]
        .as_str()
        .ok_or("Missing 'target_url' field")?;

    // Safety: verify target is in sandbox network
    if !is_sandbox_target(target_url) {
        return Err(
            "SAFETY: sqlmap_attack can only target sandbox URLs (172.28.x.x or shieldagi-*)"
                .into(),
        );
    }

    let method = input["method"].as_str().unwrap_or("GET");
    let level = input["level"].as_u64().unwrap_or(3);
    let risk = input["risk"].as_u64().unwrap_or(2);
    let technique = input["technique"].as_str().unwrap_or("BTUSE");

    // Use a unique output dir per scan to avoid conflicts
    let scan_id = uuid::Uuid::new_v4().to_string();
    let output_dir = format!("/results/sqlmap/{}", scan_id);

    let level_str = level.to_string();
    let risk_str = risk.to_string();

    let mut args: Vec<&str> = vec![
        "/tools/sqlmap/sqlmap.py",
        "-u",
        target_url,
        "--batch",             // Non-interactive
        "--output-dir",
        &output_dir,
        "--level",
        &level_str,
        "--risk",
        &risk_str,
        "--technique",
        technique,
        "--threads=4",
        "--timeout=30",
        "--retries=2",
        "--forms",             // Auto-detect forms
        "--smart",             // Smart heuristic
        "--tamper=space2comment,between", // Basic WAF bypass
    ];

    if method == "POST" {
        if let Some(data) = input["data"].as_str() {
            args.extend(&["--data", data]);
        }
    }

    if let Some(cookie) = input["cookie"].as_str() {
        args.extend(&["--cookie", cookie]);
    }

    // Add custom headers if provided
    if let Some(headers) = input["headers"].as_str() {
        args.extend(&["--headers", headers]);
    }

    let start = std::time::Instant::now();

    let output = Command::new("python3")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to execute sqlmap: {}", e))?;

    let duration = start.elapsed().as_millis() as u64;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Parse results from both stdout and the output directory
    let mut parameters = Vec::new();
    let mut injection_types = Vec::new();
    let mut dbms = None;
    let mut tables_enumerated = Vec::new();

    // --- Parse sqlmap stdout for injection indicators ---
    let injectable = stdout.contains("is vulnerable")
        || stdout.contains("injectable")
        || stdout.contains("sqlmap identified the following injection point");

    // Extract injection types
    if stdout.contains("boolean-based") {
        injection_types.push("boolean-based".into());
    }
    if stdout.contains("time-based") {
        injection_types.push("time-based".into());
    }
    if stdout.contains("UNION query") {
        injection_types.push("union-based".into());
    }
    if stdout.contains("error-based") {
        injection_types.push("error-based".into());
    }
    if stdout.contains("stacked queries") {
        injection_types.push("stacked-queries".into());
    }
    if stdout.contains("inline query") {
        injection_types.push("inline-query".into());
    }

    // Extract DBMS
    for db in &[
        "PostgreSQL",
        "MySQL",
        "SQLite",
        "Microsoft SQL Server",
        "Oracle",
        "MariaDB",
    ] {
        if stdout.contains(db) {
            dbms = Some(db.to_string());
            break;
        }
    }

    // --- Parse individual injectable parameters from stdout ---
    // sqlmap outputs blocks like:
    //   Parameter: name (GET)
    //     Type: boolean-based blind
    //     Title: AND boolean-based blind - WHERE or HAVING clause
    //     Payload: name=test%' AND 1=1 AND '%'='
    parse_injection_points(&stdout, &mut parameters);

    // --- Try to parse JSON log from output directory ---
    // sqlmap writes a log file at <output_dir>/<target_host>/log
    if let Ok(entries) = std::fs::read_dir(&output_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let log_path = entry.path().join("log");
                if let Ok(log_content) = std::fs::read_to_string(&log_path) {
                    parse_sqlmap_log(&log_content, &mut parameters, &mut dbms);
                }

                // Try to read target.txt for enumerated tables
                let target_path = entry.path().join("dump");
                if let Ok(dump_entries) = std::fs::read_dir(&target_path) {
                    for dump_entry in dump_entries.flatten() {
                        if dump_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            if let Some(db_name) = dump_entry.file_name().to_str() {
                                if let Ok(table_entries) = std::fs::read_dir(dump_entry.path()) {
                                    for table in table_entries.flatten() {
                                        if let Some(table_name) = table.file_name().to_str() {
                                            let name = table_name.trim_end_matches(".csv");
                                            tables_enumerated.push(format!(
                                                "{}.{}",
                                                db_name, name
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Deduplicate injection_types from parameters
    for param in &parameters {
        let ptype = &param.injection_type;
        if !injection_types.iter().any(|t| t == ptype) {
            injection_types.push(ptype.clone());
        }
    }

    let result = SqlmapResult {
        target_url: target_url.to_string(),
        injectable,
        injection_type: injection_types,
        dbms,
        parameters,
        tables_enumerated,
        scan_duration_ms: duration,
        risk_level: risk,
        test_level: level,
        error: if output.status.success() || injectable {
            None
        } else if !stderr.is_empty() {
            Some(stderr.to_string())
        } else {
            None
        },
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

/// Parse injection point blocks from sqlmap stdout.
///
/// sqlmap prints blocks like:
/// ```text
/// Parameter: name (GET)
///     Type: boolean-based blind
///     Title: AND boolean-based blind - WHERE or HAVING clause
///     Payload: name=test%' AND 1=1 AND '%'='
///
///     Type: time-based blind
///     Title: PostgreSQL > 8.1 AND time-based blind
///     Payload: name=test%' AND 9628=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||...
/// ```
fn parse_injection_points(stdout: &str, parameters: &mut Vec<InjectableParam>) {
    let lines: Vec<&str> = stdout.lines().collect();
    let mut current_param_name = String::new();
    let mut current_place = String::new();
    let mut current_type = String::new();
    let mut current_title = String::new();
    let mut current_payload = String::new();
    let mut current_dbms: Option<String> = None;

    for i in 0..lines.len() {
        let line = lines[i].trim();

        // Detect parameter block: "Parameter: name (GET)"
        if line.starts_with("Parameter:") {
            if let Some(rest) = line.strip_prefix("Parameter:") {
                let rest = rest.trim();
                // Parse "name (GET)" or "#1* (POST)"
                if let Some(paren_start) = rest.rfind('(') {
                    current_param_name = rest[..paren_start].trim().to_string();
                    current_place = rest[paren_start + 1..]
                        .trim_end_matches(')')
                        .trim()
                        .to_string();
                } else {
                    current_param_name = rest.to_string();
                    current_place = "GET".to_string();
                }
            }
        }

        // Detect Type line
        if line.starts_with("Type:") {
            // Flush previous entry if we have one
            if !current_type.is_empty() && !current_param_name.is_empty() {
                parameters.push(InjectableParam {
                    name: current_param_name.clone(),
                    injection_type: current_type.clone(),
                    payload: current_payload.clone(),
                    place: current_place.clone(),
                    dbms: current_dbms.clone(),
                    title: current_title.clone(),
                });
            }
            current_type = line.strip_prefix("Type:").unwrap_or("").trim().to_string();
            current_title.clear();
            current_payload.clear();
            current_dbms = None;
        }

        if line.starts_with("Title:") {
            current_title = line.strip_prefix("Title:").unwrap_or("").trim().to_string();
            // Try to extract DBMS from title (e.g., "PostgreSQL > 8.1 AND...")
            for db in &["PostgreSQL", "MySQL", "SQLite", "MSSQL", "Oracle", "MariaDB"] {
                if current_title.contains(db) {
                    current_dbms = Some(db.to_string());
                    break;
                }
            }
        }

        if line.starts_with("Payload:") {
            current_payload = line.strip_prefix("Payload:").unwrap_or("").trim().to_string();
        }
    }

    // Flush last entry
    if !current_type.is_empty() && !current_param_name.is_empty() {
        parameters.push(InjectableParam {
            name: current_param_name,
            injection_type: current_type,
            payload: current_payload,
            place: current_place,
            dbms: current_dbms,
            title: current_title,
        });
    }
}

/// Parse sqlmap's log file for additional injection details.
fn parse_sqlmap_log(
    log_content: &str,
    parameters: &mut Vec<InjectableParam>,
    dbms: &mut Option<String>,
) {
    for line in log_content.lines() {
        // sqlmap log lines like: "[INFO] the back-end DBMS is PostgreSQL"
        if line.contains("the back-end DBMS is") {
            if let Some(db_part) = line.split("the back-end DBMS is").nth(1) {
                let db = db_part.trim();
                if !db.is_empty() && dbms.is_none() {
                    *dbms = Some(db.to_string());
                }
            }
        }

        // Parse additional parameter findings from log
        // "[INFO] GET parameter 'name' is 'boolean-based blind' injectable"
        if line.contains("is '") && line.contains("' injectable") {
            if let (Some(param_start), Some(type_start)) = (
                line.find("parameter '"),
                line.find("is '"),
            ) {
                let param_name = &line[param_start + 11..];
                if let Some(end) = param_name.find('\'') {
                    let name = param_name[..end].to_string();
                    let type_str = &line[type_start + 4..];
                    if let Some(type_end) = type_str.find("' injectable") {
                        let inj_type = type_str[..type_end].to_string();

                        // Determine place from log line
                        let place = if line.contains("GET parameter") {
                            "GET"
                        } else if line.contains("POST parameter") {
                            "POST"
                        } else if line.contains("Cookie parameter") || line.contains("cookie") {
                            "COOKIE"
                        } else if line.contains("Header") {
                            "HEADER"
                        } else {
                            "UNKNOWN"
                        };

                        // Only add if not already present
                        let already_exists = parameters
                            .iter()
                            .any(|p| p.name == name && p.injection_type == inj_type);
                        if !already_exists {
                            parameters.push(InjectableParam {
                                name,
                                injection_type: inj_type,
                                payload: String::new(), // Log doesn't always include payload
                                place: place.to_string(),
                                dbms: None,
                                title: String::new(),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn is_sandbox_target(url: &str) -> bool {
    url.contains("172.28.")
        || url.contains("shieldagi-")
        || url.contains("localhost:3001") // Mapped sandbox port
        || url.contains("vulnerable-app") // Docker service name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_target_validation() {
        assert!(is_sandbox_target("http://172.28.0.3:3000/api/users/search?name=test"));
        assert!(is_sandbox_target("http://shieldagi-vulnapp:3000/api"));
        assert!(is_sandbox_target("http://localhost:3001/api"));
        assert!(is_sandbox_target("http://vulnerable-app:3000/api"));
        assert!(!is_sandbox_target("http://example.com/api"));
        assert!(!is_sandbox_target("http://192.168.1.1/api"));
    }

    #[test]
    fn test_parse_injection_points() {
        let stdout = r#"
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
Parameter: name (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=test%' AND 8371=8371 AND '%'='

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: name=test%' AND (SELECT 9628 FROM PG_SLEEP(5)) AND '%'='

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: name=test%' UNION ALL SELECT NULL,CONCAT(0x71,0x76),NULL-- -
"#;

        let mut params = Vec::new();
        parse_injection_points(stdout, &mut params);

        assert_eq!(params.len(), 3);
        assert_eq!(params[0].name, "name");
        assert_eq!(params[0].place, "GET");
        assert_eq!(params[0].injection_type, "boolean-based blind");
        assert_eq!(params[1].injection_type, "time-based blind");
        assert!(params[1].dbms.as_deref() == Some("PostgreSQL"));
        assert_eq!(params[2].injection_type, "UNION query");
    }

    #[test]
    fn test_parse_sqlmap_log() {
        let log = r#"
[12:00:00] [INFO] testing connection to the target URL
[12:00:01] [INFO] GET parameter 'name' is 'boolean-based blind' injectable
[12:00:02] [INFO] GET parameter 'name' is 'time-based blind' injectable
[12:00:03] [INFO] the back-end DBMS is PostgreSQL
"#;

        let mut params = Vec::new();
        let mut dbms = None;
        parse_sqlmap_log(log, &mut params, &mut dbms);

        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "name");
        assert_eq!(params[0].place, "GET");
        assert_eq!(dbms, Some("PostgreSQL".to_string()));
    }
}
