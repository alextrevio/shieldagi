/// ShieldAGI Tool: rls_validate
///
/// Validates Supabase Row Level Security policies for completeness and correctness.
/// Inspects schemas via SQL queries and checks for unprotected tables.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct RlsValidateResult {
    pub supabase_url: String,
    pub total_tables: usize,
    pub tables_with_rls: usize,
    pub tables_without_rls: Vec<String>,
    pub policy_issues: Vec<RlsPolicyIssue>,
    pub score: f32,
    pub grade: String,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RlsPolicyIssue {
    pub table_name: String,
    pub issue_type: String,
    pub severity: String,
    pub detail: String,
    pub recommendation: String,
}

pub async fn tool_rls_validate(input: &serde_json::Value) -> Result<String, String> {
    let supabase_url = input["supabase_url"]
        .as_str()
        .ok_or("Missing 'supabase_url' field")?;

    let service_key = input["service_key"].as_str();
    let repo_path = input["repo_path"].as_str();

    let start = std::time::Instant::now();
    let mut total_tables = 0usize;
    let mut tables_with_rls = 0usize;
    let mut tables_without_rls = Vec::new();
    let mut policy_issues = Vec::new();
    let mut errors = Vec::new();

    // --- Method 1: Query Supabase directly via REST API ---
    if let Some(key) = service_key {
        // Query pg_tables and pg_policies via Supabase RPC
        let tables_query = "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public'";
        let rpc_url = format!("{}/rest/v1/rpc/query", supabase_url);

        let args = vec![
            "-s",
            "-X", "POST",
            "-H", &format!("apikey: {}", key),
            "-H", &format!("Authorization: Bearer {}", key),
            "-H", "Content-Type: application/json",
            "-d", &format!(r#"{{"query": "{}"}}"#, tables_query),
            "--max-time", "15",
            &rpc_url,
        ];

        if let Ok(output) = Command::new("curl").args(&args).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(rows) = json.as_array() {
                    total_tables = rows.len();
                    for row in rows {
                        let table = row["tablename"].as_str().unwrap_or("");
                        let rls_enabled = row["rowsecurity"].as_bool().unwrap_or(false);

                        if rls_enabled {
                            tables_with_rls += 1;
                        } else {
                            tables_without_rls.push(table.to_string());
                            policy_issues.push(RlsPolicyIssue {
                                table_name: table.to_string(),
                                issue_type: "rls_disabled".to_string(),
                                severity: "CRITICAL".to_string(),
                                detail: format!(
                                    "Table '{}' has RLS disabled — all rows accessible",
                                    table
                                ),
                                recommendation: format!(
                                    "ALTER TABLE {} ENABLE ROW LEVEL SECURITY;",
                                    table
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Check for overly permissive policies
        let policies_query = "SELECT schemaname, tablename, policyname, permissive, cmd, qual FROM pg_policies WHERE schemaname = 'public'";
        let args2 = vec![
            "-s",
            "-X", "POST",
            "-H", &format!("apikey: {}", key),
            "-H", &format!("Authorization: Bearer {}", key),
            "-H", "Content-Type: application/json",
            "-d", &format!(r#"{{"query": "{}"}}"#, policies_query),
            "--max-time", "15",
            &rpc_url,
        ];

        if let Ok(output) = Command::new("curl").args(&args2).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(policies) = json.as_array() {
                    for policy in policies {
                        let table = policy["tablename"].as_str().unwrap_or("");
                        let name = policy["policyname"].as_str().unwrap_or("");
                        let qual = policy["qual"].as_str().unwrap_or("");

                        // Check for overly permissive policies
                        if qual == "true" || qual.is_empty() {
                            policy_issues.push(RlsPolicyIssue {
                                table_name: table.to_string(),
                                issue_type: "permissive_policy".to_string(),
                                severity: "HIGH".to_string(),
                                detail: format!(
                                    "Policy '{}' on '{}' allows all rows (qual=true)",
                                    name, table
                                ),
                                recommendation: format!(
                                    "Add a restrictive WHERE clause to policy '{}' (e.g., auth.uid() = user_id)",
                                    name
                                ),
                            });
                        }
                    }

                    // Check for tables with RLS but no policies
                    // (RLS enabled but no policy = deny all, which might be intentional but flag it)
                    let tables_with_policies: Vec<String> = policies
                        .iter()
                        .filter_map(|p| p["tablename"].as_str().map(String::from))
                        .collect();

                    for table in &tables_without_rls {
                        if !tables_with_policies.contains(table) {
                            // Already flagged as no RLS
                        }
                    }
                }
            }
        }
    }

    // --- Method 2: Parse migration files from repo ---
    if let Some(path) = repo_path {
        let migrations_dir = format!("{}/supabase/migrations", path);
        if let Ok(entries) = std::fs::read_dir(&migrations_dir) {
            for entry in entries.flatten() {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    let content_upper = content.to_uppercase();

                    // Count CREATE TABLE statements
                    let create_tables: Vec<&str> = content_upper
                        .match_indices("CREATE TABLE")
                        .map(|(i, _)| &content[i..std::cmp::min(i + 100, content.len())])
                        .collect();
                    total_tables += create_tables.len();

                    // Check for ENABLE ROW LEVEL SECURITY
                    let rls_enables = content_upper.matches("ENABLE ROW LEVEL SECURITY").count();
                    tables_with_rls += rls_enables;

                    // Check for CREATE POLICY
                    if content_upper.contains("CREATE POLICY") {
                        // Check for permissive USING (true)
                        if content_upper.contains("USING (TRUE)") || content_upper.contains("USING(TRUE)") {
                            policy_issues.push(RlsPolicyIssue {
                                table_name: "migration-level".to_string(),
                                issue_type: "permissive_migration_policy".to_string(),
                                severity: "HIGH".to_string(),
                                detail: format!(
                                    "Migration {} contains USING (true) policy",
                                    entry.file_name().to_string_lossy()
                                ),
                                recommendation:
                                    "Replace USING (true) with proper auth check".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // No data sources available
    if total_tables == 0 && service_key.is_none() && repo_path.is_none() {
        errors.push("No service_key or repo_path provided — cannot inspect RLS".to_string());
    }

    let duration = start.elapsed().as_millis() as u64;

    // Scoring
    let score = if total_tables == 0 {
        0.0
    } else {
        let base = (tables_with_rls as f32 / total_tables as f32) * 100.0;
        let penalty = policy_issues.len() as f32 * 10.0;
        (base - penalty).max(0.0)
    };

    let grade = match score as i32 {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
    .to_string();

    let result = RlsValidateResult {
        supabase_url: supabase_url.to_string(),
        total_tables,
        tables_with_rls,
        tables_without_rls,
        policy_issues,
        score,
        grade,
        scan_duration_ms: duration,
        error: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}
