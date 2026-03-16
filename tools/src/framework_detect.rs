/// ShieldAGI Tool: framework_detect
///
/// Auto-detects the web framework(s) used in a repository by inspecting
/// configuration files, manifest files, and source entry points. Returns
/// a structured DetectionResult that downstream tools use to make
/// framework-aware decisions (Chain Walls injection, remediation strategies,
/// dependency audits, etc.).
///
/// Detection order (highest confidence first):
///   1. supabase/config.toml  → Supabase
///   2. next.config.*         → Next.js
///   3. package.json deps     → Next.js / Express
///   4. requirements.txt      → Django
///   5. Cargo.toml            → Rust web (actix / rocket / axum)
///   6. manage.py             → Django (fallback)
///   7. vercel.json           → Next.js (hint only)

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;

// ═══════════════════════════════════════════════
// OUTPUT STRUCTS
// ═══════════════════════════════════════════════

/// Details about a single detected framework within the repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkInfo {
    /// Framework type slug: "nextjs" | "express" | "supabase" | "django" | "rust-web" | "unknown"
    pub framework_type: String,
    /// Version string extracted from config (empty string if not determinable).
    pub version: String,
    /// Config files that confirmed this framework's presence.
    pub config_paths: Vec<String>,
    /// Source entry points for this framework (e.g. "src/index.js", "manage.py").
    pub entry_points: Vec<String>,
    /// Package manager used: "npm" | "yarn" | "pnpm" | "pip" | "cargo" | "unknown"
    pub package_manager: String,
}

impl Default for FrameworkInfo {
    fn default() -> Self {
        Self {
            framework_type: "unknown".to_string(),
            version: String::new(),
            config_paths: Vec::new(),
            entry_points: Vec::new(),
            package_manager: "unknown".to_string(),
        }
    }
}

/// Top-level result returned by `tool_detect_framework`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Absolute or relative path to the scanned repository.
    pub repo_path: String,
    /// All frameworks detected, ordered by confidence (highest first).
    pub frameworks: Vec<FrameworkInfo>,
    /// The single most-likely primary framework slug.
    pub primary_framework: String,
    /// Wall-clock time spent on detection.
    pub scan_duration_ms: u64,
}

impl Default for DetectionResult {
    fn default() -> Self {
        Self {
            repo_path: String::new(),
            frameworks: Vec::new(),
            primary_framework: "unknown".to_string(),
            scan_duration_ms: 0,
        }
    }
}

// ═══════════════════════════════════════════════
// TOOL ENTRY POINT
// ═══════════════════════════════════════════════

/// Detect the framework(s) used in the repository at `input["repo_path"]`.
///
/// # Input
/// ```json
/// { "repo_path": "/path/to/repo" }
/// ```
///
/// # Output
/// Serialized `DetectionResult` JSON.
pub async fn tool_detect_framework(input: &serde_json::Value) -> Result<String, String> {
    let repo_path = input["repo_path"]
        .as_str()
        .ok_or("Missing required field 'repo_path'")?;

    let start = Instant::now();

    if !Path::new(repo_path).exists() {
        return Err(format!("Repository path does not exist: {}", repo_path));
    }

    let mut frameworks: Vec<FrameworkInfo> = Vec::new();

    // ── 1. Supabase (check before Next.js; many supabase projects also use Next.js)
    if let Some(info) = detect_supabase(repo_path) {
        frameworks.push(info);
    }

    // ── 2. Next.js / Express (via package.json)
    let npm_frameworks = detect_from_package_json(repo_path);
    for info in npm_frameworks {
        if !frameworks.iter().any(|f| f.framework_type == info.framework_type) {
            frameworks.push(info);
        }
    }

    // ── 3. Django (requirements.txt, Pipfile, manage.py)
    if let Some(info) = detect_django(repo_path) {
        if !frameworks.iter().any(|f| f.framework_type == "django") {
            frameworks.push(info);
        }
    }

    // ── 4. Rust web frameworks (Cargo.toml)
    if let Some(info) = detect_rust_web(repo_path) {
        if !frameworks.iter().any(|f| f.framework_type.starts_with("rust-web")) {
            frameworks.push(info);
        }
    }

    // ── 5. Vercel hint (implies Next.js if not already detected)
    if Path::new(&format!("{}/vercel.json", repo_path)).exists() {
        if !frameworks.iter().any(|f| f.framework_type == "nextjs") {
            let mut hint = FrameworkInfo {
                framework_type: "nextjs".to_string(),
                version: String::new(),
                config_paths: vec!["vercel.json".to_string()],
                entry_points: Vec::new(),
                package_manager: detect_package_manager(repo_path),
            };
            hint.entry_points = find_js_entry_points(repo_path, "nextjs");
            frameworks.push(hint);
        }
    }

    let primary_framework = frameworks
        .first()
        .map(|f| f.framework_type.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let scan_duration_ms = start.elapsed().as_millis() as u64;

    let result = DetectionResult {
        repo_path: repo_path.to_string(),
        frameworks,
        primary_framework,
        scan_duration_ms,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

// ═══════════════════════════════════════════════
// DETECTION HELPERS
// ═══════════════════════════════════════════════

/// Detect Supabase by checking for supabase/config.toml.
fn detect_supabase(repo_path: &str) -> Option<FrameworkInfo> {
    let config_path = format!("{}/supabase/config.toml", repo_path);
    if !Path::new(&config_path).exists() {
        return None;
    }

    let version = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find(|line| line.trim_start().starts_with("version"))
                .and_then(|line| line.splitn(2, '=').nth(1))
                .map(|v| v.trim().trim_matches('"').to_string())
        })
        .unwrap_or_default();

    let mut entry_points = Vec::new();

    // Supabase edge functions
    let functions_dir = format!("{}/supabase/functions", repo_path);
    if Path::new(&functions_dir).exists() {
        if let Ok(entries) = std::fs::read_dir(&functions_dir) {
            for entry in entries.flatten() {
                let index = entry.path().join("index.ts");
                if index.exists() {
                    entry_points.push(format!(
                        "supabase/functions/{}/index.ts",
                        entry.file_name().to_string_lossy()
                    ));
                }
            }
        }
    }

    // Migrations directory
    let migrations = format!("{}/supabase/migrations", repo_path);
    if Path::new(&migrations).exists() {
        entry_points.push("supabase/migrations".to_string());
    }

    Some(FrameworkInfo {
        framework_type: "supabase".to_string(),
        version,
        config_paths: vec!["supabase/config.toml".to_string()],
        entry_points,
        package_manager: detect_package_manager(repo_path),
    })
}

/// Detect Next.js or Express from package.json dependencies.
/// Returns a vec because a project may use both (e.g. Next.js + custom Express server).
fn detect_from_package_json(repo_path: &str) -> Vec<FrameworkInfo> {
    let pkg_path = format!("{}/package.json", repo_path);
    let content = match std::fs::read_to_string(&pkg_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let pkg: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();
    let pkg_mgr = detect_package_manager(repo_path);

    // Gather all dependency keys across all dependency sections
    let mut all_deps: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for section in &["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(obj) = pkg[section].as_object() {
            for (k, v) in obj {
                let ver = v.as_str().unwrap_or("").to_string();
                all_deps.insert(k.clone(), ver);
            }
        }
    }

    // ── Next.js detection
    let has_next = all_deps.contains_key("next");
    let next_config_exists = ["next.config.js", "next.config.mjs", "next.config.ts"]
        .iter()
        .any(|f| Path::new(&format!("{}/{}", repo_path, f)).exists());

    if has_next || next_config_exists {
        let version = all_deps.get("next").cloned().unwrap_or_default();
        let mut config_paths = vec!["package.json".to_string()];
        for cfg in &["next.config.js", "next.config.mjs", "next.config.ts"] {
            if Path::new(&format!("{}/{}", repo_path, cfg)).exists() {
                config_paths.push(cfg.to_string());
            }
        }
        let entry_points = find_js_entry_points(repo_path, "nextjs");
        results.push(FrameworkInfo {
            framework_type: "nextjs".to_string(),
            version: clean_version(&version),
            config_paths,
            entry_points,
            package_manager: pkg_mgr.clone(),
        });
    }

    // ── Express detection
    if all_deps.contains_key("express") {
        let version = all_deps.get("express").cloned().unwrap_or_default();
        let entry_points = find_js_entry_points(repo_path, "express");
        results.push(FrameworkInfo {
            framework_type: "express".to_string(),
            version: clean_version(&version),
            config_paths: vec!["package.json".to_string()],
            entry_points,
            package_manager: pkg_mgr.clone(),
        });
    }

    // ── React / Vue SPA (only if no server framework was found)
    if results.is_empty() && (all_deps.contains_key("react") || all_deps.contains_key("vue")) {
        let framework_type = if all_deps.contains_key("react") { "react" } else { "vue" };
        let version = all_deps.get(framework_type).cloned().unwrap_or_default();
        results.push(FrameworkInfo {
            framework_type: framework_type.to_string(),
            version: clean_version(&version),
            config_paths: vec!["package.json".to_string()],
            entry_points: find_js_entry_points(repo_path, framework_type),
            package_manager: pkg_mgr,
        });
    }

    results
}

/// Detect Django via requirements.txt, Pipfile, or manage.py.
fn detect_django(repo_path: &str) -> Option<FrameworkInfo> {
    let mut version = String::new();
    let mut config_paths = Vec::new();
    let mut found = false;

    // Check requirements.txt
    let req_path = format!("{}/requirements.txt", repo_path);
    if let Ok(content) = std::fs::read_to_string(&req_path) {
        if content.to_lowercase().contains("django") {
            found = true;
            config_paths.push("requirements.txt".to_string());
            version = content
                .lines()
                .find(|line| {
                    let lower = line.to_lowercase();
                    lower.starts_with("django==")
                        || lower.starts_with("django>=")
                        || lower.starts_with("django~=")
                        || lower.trim() == "django"
                })
                .map(|line| {
                    line.trim()
                        .trim_start_matches(|c: char| {
                            c.is_alphabetic() || c == '=' || c == '>' || c == '<' || c == '~'
                        })
                        .to_string()
                })
                .unwrap_or_default();
        }
    }

    // Check Pipfile
    let pipfile_path = format!("{}/Pipfile", repo_path);
    if let Ok(content) = std::fs::read_to_string(&pipfile_path) {
        if content.to_lowercase().contains("django") {
            found = true;
            if !config_paths.contains(&"Pipfile".to_string()) {
                config_paths.push("Pipfile".to_string());
            }
            if version.is_empty() {
                version = content
                    .lines()
                    .find(|line| {
                        let lower = line.to_lowercase();
                        lower.starts_with("django") && lower.contains('=')
                    })
                    .and_then(|line| line.splitn(2, '=').nth(1))
                    .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_string())
                    .unwrap_or_default();
            }
        }
    }

    // Fallback: manage.py is the canonical Django marker
    let manage_path = format!("{}/manage.py", repo_path);
    if Path::new(&manage_path).exists() {
        found = true;
        if !config_paths.contains(&"manage.py".to_string()) {
            config_paths.push("manage.py".to_string());
        }
    }

    if !found {
        return None;
    }

    // Entry points
    let mut entry_points = Vec::new();
    for candidate in &["manage.py", "wsgi.py", "asgi.py"] {
        if Path::new(&format!("{}/{}", repo_path, candidate)).exists() {
            entry_points.push(candidate.to_string());
        }
    }

    // Walk one level deep for settings.py
    if let Ok(entries) = std::fs::read_dir(repo_path) {
        for entry in entries.flatten() {
            let ep = entry.path();
            if ep.is_dir() {
                let settings = ep.join("settings.py");
                if settings.exists() {
                    let rel = settings
                        .strip_prefix(repo_path)
                        .ok()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if !rel.is_empty() && !entry_points.contains(&rel) {
                        entry_points.push(rel);
                    }
                }
            }
        }
    }

    Some(FrameworkInfo {
        framework_type: "django".to_string(),
        version,
        config_paths,
        entry_points,
        package_manager: "pip".to_string(),
    })
}

/// Detect Rust web frameworks (actix-web, rocket, axum, warp, tide) from Cargo.toml.
fn detect_rust_web(repo_path: &str) -> Option<FrameworkInfo> {
    let cargo_path = format!("{}/Cargo.toml", repo_path);
    let content = std::fs::read_to_string(&cargo_path).ok()?;

    let lower = content.to_lowercase();
    let is_web = lower.contains("actix-web")
        || lower.contains("rocket")
        || lower.contains("axum")
        || lower.contains("warp")
        || lower.contains("tide");

    if !is_web {
        return None;
    }

    let sub_frameworks = [
        "actix-web",
        "rocket",
        "axum",
        "warp",
        "tide",
    ];

    let mut detected_sub = String::new();
    let mut version = String::new();

    for dep_name in &sub_frameworks {
        if lower.contains(dep_name) {
            detected_sub = dep_name.to_string();
            let version_re = regex::Regex::new(&format!(
                r#"(?m){}\s*=\s*(?:"([^"]+)"|{{[^}}]*version\s*=\s*"([^"]+)")"#,
                regex::escape(dep_name)
            ))
            .ok();

            if let Some(re) = version_re {
                if let Some(caps) = re.captures(&content) {
                    version = caps
                        .get(1)
                        .or_else(|| caps.get(2))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default();
                }
            }
            break;
        }
    }

    let mut entry_points = Vec::new();
    for candidate in &["src/main.rs", "src/lib.rs", "src/server.rs", "src/app.rs"] {
        if Path::new(&format!("{}/{}", repo_path, candidate)).exists() {
            entry_points.push(candidate.to_string());
        }
    }

    let framework_label = if detected_sub.is_empty() {
        "rust-web".to_string()
    } else {
        format!("rust-web ({})", detected_sub)
    };

    Some(FrameworkInfo {
        framework_type: framework_label,
        version,
        config_paths: vec!["Cargo.toml".to_string()],
        entry_points,
        package_manager: "cargo".to_string(),
    })
}

// ═══════════════════════════════════════════════
// ENTRY POINT DISCOVERY
// ═══════════════════════════════════════════════

/// Find typical source entry points for a given JS/TS framework.
fn find_js_entry_points(repo_path: &str, framework: &str) -> Vec<String> {
    let mut found = Vec::new();

    let candidates: &[&str] = match framework {
        "nextjs" => &[
            "middleware.ts",
            "middleware.js",
            "src/middleware.ts",
            "src/middleware.js",
            "pages/_app.tsx",
            "pages/_app.jsx",
            "pages/_app.js",
            "src/pages/_app.tsx",
            "src/pages/_app.jsx",
            "app/layout.tsx",
            "app/layout.jsx",
            "src/app/layout.tsx",
            "src/app/layout.jsx",
            "next.config.js",
            "next.config.mjs",
            "next.config.ts",
        ],
        "express" => &[
            "app.js",
            "app.ts",
            "server.js",
            "server.ts",
            "index.js",
            "index.ts",
            "src/app.js",
            "src/app.ts",
            "src/server.js",
            "src/server.ts",
            "src/index.js",
            "src/index.ts",
        ],
        "react" | "vue" => &[
            "src/index.tsx",
            "src/index.jsx",
            "src/index.js",
            "src/main.tsx",
            "src/main.jsx",
            "src/main.js",
            "index.html",
            "public/index.html",
        ],
        _ => &[
            "index.js",
            "index.ts",
            "server.js",
            "server.ts",
            "app.js",
            "app.ts",
        ],
    };

    for candidate in candidates {
        if Path::new(&format!("{}/{}", repo_path, candidate)).exists() {
            found.push(candidate.to_string());
        }
    }

    found
}

// ═══════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════

/// Detect the package manager by checking for lockfiles in priority order.
fn detect_package_manager(repo_path: &str) -> String {
    if Path::new(&format!("{}/pnpm-lock.yaml", repo_path)).exists() {
        return "pnpm".to_string();
    }
    if Path::new(&format!("{}/yarn.lock", repo_path)).exists() {
        return "yarn".to_string();
    }
    if Path::new(&format!("{}/package-lock.json", repo_path)).exists() {
        return "npm".to_string();
    }
    if Path::new(&format!("{}/package.json", repo_path)).exists() {
        return "npm".to_string();
    }
    if Path::new(&format!("{}/Pipfile.lock", repo_path)).exists()
        || Path::new(&format!("{}/Pipfile", repo_path)).exists()
    {
        return "pipenv".to_string();
    }
    if Path::new(&format!("{}/requirements.txt", repo_path)).exists() {
        return "pip".to_string();
    }
    if Path::new(&format!("{}/Cargo.lock", repo_path)).exists()
        || Path::new(&format!("{}/Cargo.toml", repo_path)).exists()
    {
        return "cargo".to_string();
    }
    "unknown".to_string()
}

/// Strip leading semver range operators from a version string.
fn clean_version(version: &str) -> String {
    version
        .trim()
        .trim_start_matches(|c: char| {
            c == '^' || c == '~' || c == '>' || c == '<' || c == '=' || c == ' '
        })
        .to_string()
}

// ═══════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Global counter to make temp directories unique across test runs.
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Create a uniquely-named directory under std::env::temp_dir() and populate it
    /// with the given (relative_path, content) pairs. Returns the directory path as a
    /// String. The caller is responsible for cleanup; in tests we just leave them in
    /// /tmp and rely on OS cleanup.
    fn setup_repo(files: &[(&str, &str)]) -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir()
            .join(format!("shieldagi_test_{}_{}", pid, n));
        fs::create_dir_all(&dir).expect("failed to create test dir");
        for (rel_path, content) in files {
            let full = dir.join(rel_path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).expect("failed to create parent dir");
            }
            fs::write(&full, content).expect("failed to write test file");
        }
        dir.to_string_lossy().to_string()
    }

    // ── Unit tests for helpers ──────────────────

    #[test]
    fn test_clean_version_strips_operators() {
        assert_eq!(clean_version("^14.0.0"), "14.0.0");
        assert_eq!(clean_version("~3.2.1"), "3.2.1");
        assert_eq!(clean_version(">=4.0"), "4.0");
        assert_eq!(clean_version("4.2.0"), "4.2.0");
        assert_eq!(clean_version(""), "");
        assert_eq!(clean_version("*"), "*");
    }

    #[test]
    fn test_detect_package_manager_pnpm() {
        let dir = setup_repo(&[
            ("package.json", r#"{"name":"test"}"#),
            ("pnpm-lock.yaml", "lockfileVersion: 5.4"),
        ]);
        assert_eq!(detect_package_manager(&dir), "pnpm");
    }

    #[test]
    fn test_detect_package_manager_yarn() {
        let dir = setup_repo(&[
            ("package.json", r#"{"name":"test"}"#),
            ("yarn.lock", "# yarn lockfile v1"),
        ]);
        assert_eq!(detect_package_manager(&dir), "yarn");
    }

    #[test]
    fn test_detect_package_manager_npm() {
        let dir = setup_repo(&[
            ("package.json", r#"{"name":"test"}"#),
            ("package-lock.json", "{}"),
        ]);
        assert_eq!(detect_package_manager(&dir), "npm");
    }

    #[test]
    fn test_detect_package_manager_npm_no_lockfile() {
        let dir = setup_repo(&[("package.json", r#"{"name":"test"}"#)]);
        assert_eq!(detect_package_manager(&dir), "npm");
    }

    #[test]
    fn test_detect_package_manager_pip() {
        let dir = setup_repo(&[("requirements.txt", "Django==4.2\n")]);
        assert_eq!(detect_package_manager(&dir), "pip");
    }

    #[test]
    fn test_detect_package_manager_cargo() {
        let dir = setup_repo(&[
            ("Cargo.toml", "[package]\nname = \"myapp\""),
            ("Cargo.lock", ""),
        ]);
        assert_eq!(detect_package_manager(&dir), "cargo");
    }

    #[test]
    fn test_detect_package_manager_unknown() {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir()
            .join(format!("shieldagi_test_empty_{}_{}", pid, n));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(detect_package_manager(dir.to_str().unwrap()), "unknown");
    }

    // ── Next.js detection ───────────────────────

    #[test]
    fn test_detect_nextjs_from_package_json() {
        let pkg = r#"{
            "dependencies": {
                "next": "^14.0.0",
                "react": "^18.0.0",
                "react-dom": "^18.0.0"
            }
        }"#;
        let dir = setup_repo(&[
            ("package.json", pkg),
            ("package-lock.json", "{}"),
            ("middleware.ts", "// Next.js middleware"),
        ]);

        let results = detect_from_package_json(&dir);
        assert!(!results.is_empty());
        let nextjs = results.iter().find(|f| f.framework_type == "nextjs");
        assert!(nextjs.is_some(), "Expected nextjs to be detected");
        let nextjs = nextjs.unwrap();
        assert_eq!(nextjs.version, "14.0.0");
        assert_eq!(nextjs.package_manager, "npm");
        assert!(nextjs.entry_points.contains(&"middleware.ts".to_string()));
    }

    #[test]
    fn test_detect_nextjs_via_config_file_no_dep() {
        // next.config.js present but "next" not listed in dependencies
        let pkg = r#"{"dependencies":{"react":"18.0.0"}}"#;
        let dir = setup_repo(&[
            ("package.json", pkg),
            ("next.config.js", "module.exports = {};"),
        ]);

        let results = detect_from_package_json(&dir);
        let nextjs = results.iter().find(|f| f.framework_type == "nextjs");
        assert!(nextjs.is_some(), "next.config.js should trigger nextjs detection");
    }

    // ── Express detection ───────────────────────

    #[test]
    fn test_detect_express_from_package_json() {
        let pkg = r#"{
            "dependencies": {
                "express": "^4.18.0"
            }
        }"#;
        let dir = setup_repo(&[
            ("package.json", pkg),
            ("package-lock.json", "{}"),
            ("src/app.js", "const express = require('express');"),
        ]);

        let results = detect_from_package_json(&dir);
        let express = results.iter().find(|f| f.framework_type == "express");
        assert!(express.is_some(), "Expected express to be detected");
        let express = express.unwrap();
        assert_eq!(express.version, "4.18.0");
        assert!(express.entry_points.contains(&"src/app.js".to_string()));
    }

    #[test]
    fn test_detect_nextjs_and_express_coexist() {
        let pkg = r#"{
            "dependencies": {
                "next": "13.5.0",
                "express": "4.18.2"
            }
        }"#;
        let dir = setup_repo(&[("package.json", pkg)]);

        let results = detect_from_package_json(&dir);
        let types: Vec<&str> = results.iter().map(|f| f.framework_type.as_str()).collect();
        assert!(types.contains(&"nextjs"), "Expected nextjs");
        assert!(types.contains(&"express"), "Expected express");
    }

    // ── Django detection ────────────────────────

    #[test]
    fn test_detect_django_requirements_txt() {
        let dir = setup_repo(&[
            ("requirements.txt", "Django==4.2.1\npsycopg2-binary==2.9.6\n"),
            ("manage.py", "#!/usr/bin/env python\n"),
        ]);

        let result = detect_django(&dir);
        assert!(result.is_some(), "Expected Django to be detected");
        let info = result.unwrap();
        assert_eq!(info.framework_type, "django");
        assert_eq!(info.version, "4.2.1");
        assert_eq!(info.package_manager, "pip");
        assert!(info.config_paths.contains(&"requirements.txt".to_string()));
        assert!(info.entry_points.contains(&"manage.py".to_string()));
    }

    #[test]
    fn test_detect_django_manage_py_only() {
        let dir = setup_repo(&[("manage.py", "#!/usr/bin/env python\n")]);
        let result = detect_django(&dir);
        assert!(result.is_some(), "Expected Django via manage.py");
        let info = result.unwrap();
        assert_eq!(info.framework_type, "django");
        assert!(info.config_paths.contains(&"manage.py".to_string()));
    }

    #[test]
    fn test_detect_django_not_present() {
        let dir = setup_repo(&[("requirements.txt", "flask==2.3.0\n")]);
        let result = detect_django(&dir);
        assert!(result.is_none(), "Flask should not be detected as Django");
    }

    #[test]
    fn test_detect_django_finds_settings_in_subdir() {
        let dir = setup_repo(&[
            ("requirements.txt", "Django==4.2\n"),
            ("manage.py", ""),
            ("myapp/settings.py", "DEBUG = False\n"),
        ]);

        let result = detect_django(&dir);
        assert!(result.is_some());
        let info = result.unwrap();
        // settings.py found in subdir should appear in entry_points
        assert!(
            info.entry_points.iter().any(|ep| ep.contains("settings.py")),
            "settings.py not found in entry_points: {:?}",
            info.entry_points
        );
    }

    // ── Rust web detection ──────────────────────

    #[test]
    fn test_detect_rust_web_actix() {
        let cargo = "[package]\nname = \"myapi\"\nversion = \"0.1.0\"\n\n[dependencies]\nactix-web = \"4.4\"\n";
        let dir = setup_repo(&[
            ("Cargo.toml", cargo),
            ("src/main.rs", "use actix_web::*;"),
        ]);

        let result = detect_rust_web(&dir);
        assert!(result.is_some(), "Expected rust-web to be detected");
        let info = result.unwrap();
        assert!(info.framework_type.contains("rust-web"));
        assert!(info.framework_type.contains("actix-web"));
        assert_eq!(info.version, "4.4");
        assert_eq!(info.package_manager, "cargo");
        assert!(info.entry_points.contains(&"src/main.rs".to_string()));
    }

    #[test]
    fn test_detect_rust_web_axum_with_table_syntax() {
        let cargo = "[package]\nname = \"server\"\n\n[dependencies]\naxum = { version = \"0.7\", features = [\"macros\"] }\n";
        let dir = setup_repo(&[("Cargo.toml", cargo)]);
        let result = detect_rust_web(&dir);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.framework_type.contains("axum"));
        assert_eq!(info.version, "0.7");
    }

    #[test]
    fn test_detect_rust_web_not_present() {
        let cargo = "[package]\nname = \"cli-tool\"\n\n[dependencies]\nserde = \"1.0\"\n";
        let dir = setup_repo(&[("Cargo.toml", cargo)]);
        let result = detect_rust_web(&dir);
        assert!(result.is_none());
    }

    // ── Supabase detection ──────────────────────

    #[test]
    fn test_detect_supabase() {
        let config = "[api]\nversion = \"20231123\"\nport = 54321\n";
        let dir = setup_repo(&[
            ("supabase/config.toml", config),
            ("supabase/migrations/001_init.sql", "CREATE TABLE users ();"),
        ]);

        let result = detect_supabase(&dir);
        assert!(result.is_some(), "Expected supabase to be detected");
        let info = result.unwrap();
        assert_eq!(info.framework_type, "supabase");
        assert!(info.config_paths.contains(&"supabase/config.toml".to_string()));
        assert!(info.entry_points.contains(&"supabase/migrations".to_string()));
    }

    #[test]
    fn test_detect_supabase_with_edge_functions() {
        let config = "[api]\nport = 54321\n";
        let dir = setup_repo(&[
            ("supabase/config.toml", config),
            ("supabase/functions/hello/index.ts", "Deno.serve(() => {});"),
        ]);

        let result = detect_supabase(&dir);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(
            info.entry_points.iter().any(|ep| ep.contains("hello/index.ts")),
            "Edge function entry point not found: {:?}",
            info.entry_points
        );
    }

    #[test]
    fn test_detect_supabase_not_present() {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir()
            .join(format!("shieldagi_test_nosb_{}_{}", pid, n));
        fs::create_dir_all(&dir).unwrap();
        let result = detect_supabase(dir.to_str().unwrap());
        assert!(result.is_none());
    }

    // ── Default / struct tests ──────────────────

    #[test]
    fn test_framework_info_default() {
        let info = FrameworkInfo::default();
        assert_eq!(info.framework_type, "unknown");
        assert_eq!(info.package_manager, "unknown");
        assert!(info.config_paths.is_empty());
        assert!(info.entry_points.is_empty());
        assert!(info.version.is_empty());
    }

    #[test]
    fn test_detection_result_default() {
        let result = DetectionResult::default();
        assert_eq!(result.primary_framework, "unknown");
        assert!(result.frameworks.is_empty());
        assert_eq!(result.scan_duration_ms, 0);
        assert!(result.repo_path.is_empty());
    }

    // ── Integration tests (full tool) ───────────

    #[tokio::test]
    async fn test_tool_detect_framework_missing_param() {
        let input = serde_json::json!({});
        let result = tool_detect_framework(&input).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("repo_path"));
    }

    #[tokio::test]
    async fn test_tool_detect_framework_nonexistent_path() {
        let input = serde_json::json!({ "repo_path": "/absolutely/nonexistent/path/xyz" });
        let result = tool_detect_framework(&input).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[tokio::test]
    async fn test_tool_detect_framework_express_repo() {
        let pkg = r#"{
            "name": "my-api",
            "dependencies": {
                "express": "^4.18.0",
                "pg": "^8.0.0"
            }
        }"#;
        let dir = setup_repo(&[
            ("package.json", pkg),
            ("package-lock.json", "{}"),
            ("server.js", "const express = require('express');"),
        ]);

        let input = serde_json::json!({ "repo_path": dir });
        let result = tool_detect_framework(&input).await;
        assert!(result.is_ok(), "Tool should succeed: {:?}", result);

        let output: DetectionResult = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(output.primary_framework, "express");
        assert!(!output.frameworks.is_empty());
        assert!(output.scan_duration_ms < 5000, "Detection should be fast");

        let express_fw = output.frameworks.iter().find(|f| f.framework_type == "express");
        assert!(express_fw.is_some());
        assert!(express_fw.unwrap().entry_points.contains(&"server.js".to_string()));
    }

    #[tokio::test]
    async fn test_tool_detect_framework_nextjs_repo() {
        let pkg = r#"{
            "dependencies": {
                "next": "14.1.0",
                "react": "18.2.0",
                "react-dom": "18.2.0"
            }
        }"#;
        let dir = setup_repo(&[
            ("package.json", pkg),
            ("next.config.js", "module.exports = {};"),
            ("middleware.ts", "export function middleware() {}"),
            ("app/layout.tsx", "export default function Layout() {}"),
        ]);

        let input = serde_json::json!({ "repo_path": dir });
        let output: DetectionResult =
            serde_json::from_str(&tool_detect_framework(&input).await.unwrap()).unwrap();

        assert_eq!(output.primary_framework, "nextjs");
        let nextjs = output.frameworks.iter().find(|f| f.framework_type == "nextjs").unwrap();
        assert_eq!(nextjs.version, "14.1.0");
        assert!(nextjs.entry_points.contains(&"middleware.ts".to_string()));
        assert!(nextjs.config_paths.contains(&"next.config.js".to_string()));
    }

    #[tokio::test]
    async fn test_tool_detect_framework_django_repo() {
        let dir = setup_repo(&[
            ("requirements.txt", "Django==4.2.7\npsycopg2-binary==2.9.9\n"),
            ("manage.py", "#!/usr/bin/env python\nimport os\n"),
            ("myapp/settings.py", "DEBUG = False\n"),
        ]);

        let input = serde_json::json!({ "repo_path": dir });
        let output: DetectionResult =
            serde_json::from_str(&tool_detect_framework(&input).await.unwrap()).unwrap();

        assert_eq!(output.primary_framework, "django");
        let django = output.frameworks.iter().find(|f| f.framework_type == "django").unwrap();
        assert_eq!(django.version, "4.2.7");
        assert_eq!(django.package_manager, "pip");
    }

    #[tokio::test]
    async fn test_tool_detect_framework_supabase_priority_over_nextjs() {
        let pkg = r#"{"dependencies":{"next":"14.0.0"}}"#;
        let supabase_cfg = "[api]\nport = 54321\n";
        let dir = setup_repo(&[
            ("package.json", pkg),
            ("supabase/config.toml", supabase_cfg),
        ]);

        let input = serde_json::json!({ "repo_path": dir });
        let output: DetectionResult =
            serde_json::from_str(&tool_detect_framework(&input).await.unwrap()).unwrap();

        // Supabase detected first → primary framework
        assert_eq!(output.primary_framework, "supabase");
        let types: Vec<&str> = output.frameworks.iter().map(|f| f.framework_type.as_str()).collect();
        assert!(types.contains(&"supabase"));
        assert!(types.contains(&"nextjs"));
    }

    #[tokio::test]
    async fn test_tool_detect_framework_rust_repo() {
        let cargo = "[package]\nname = \"api-server\"\nversion = \"0.1.0\"\n\n[dependencies]\naxum = \"0.7\"\ntokio = { version = \"1\", features = [\"full\"] }\n";
        let dir = setup_repo(&[
            ("Cargo.toml", cargo),
            ("Cargo.lock", ""),
            ("src/main.rs", "use axum::*;"),
        ]);

        let input = serde_json::json!({ "repo_path": dir });
        let output: DetectionResult =
            serde_json::from_str(&tool_detect_framework(&input).await.unwrap()).unwrap();

        assert!(output.primary_framework.contains("rust-web"));
        assert!(!output.frameworks.is_empty());
    }

    #[tokio::test]
    async fn test_tool_detect_framework_empty_repo_returns_unknown() {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir()
            .join(format!("shieldagi_test_empty2_{}_{}", pid, n));
        fs::create_dir_all(&dir).unwrap();

        let input = serde_json::json!({ "repo_path": dir.to_str().unwrap() });
        let output: DetectionResult =
            serde_json::from_str(&tool_detect_framework(&input).await.unwrap()).unwrap();

        assert_eq!(output.primary_framework, "unknown");
        assert!(output.frameworks.is_empty());
    }

    #[tokio::test]
    async fn test_tool_detect_framework_vercel_json_hint() {
        // Only vercel.json present — should hint at nextjs
        let dir = setup_repo(&[("vercel.json", r#"{"framework":"nextjs"}"#)]);

        let input = serde_json::json!({ "repo_path": dir });
        let output: DetectionResult =
            serde_json::from_str(&tool_detect_framework(&input).await.unwrap()).unwrap();

        assert_eq!(output.primary_framework, "nextjs");
        let nextjs = output.frameworks.iter().find(|f| f.framework_type == "nextjs");
        assert!(nextjs.is_some());
        assert!(nextjs.unwrap().config_paths.contains(&"vercel.json".to_string()));
    }

    #[tokio::test]
    async fn test_tool_returns_valid_json() {
        let pkg = r#"{"dependencies":{"express":"4.18.0"}}"#;
        let dir = setup_repo(&[("package.json", pkg)]);
        let input = serde_json::json!({ "repo_path": dir });
        let result = tool_detect_framework(&input).await.unwrap();
        // Must parse as valid JSON
        let _: serde_json::Value = serde_json::from_str(&result).expect("result must be valid JSON");
    }
}
