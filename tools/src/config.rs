/// ShieldAGI Tool: config
///
/// Centralized configuration system for ShieldAGI. Loads settings from a TOML
/// file (`shieldagi.toml` by default) and a `.env` file for secrets. Environment
/// variables override both sources.
///
/// Priority (highest wins): environment variables > .env file > TOML file > struct defaults

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════
// ERROR TYPES
// ═══════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read file '{path}': {source}")]
    FileRead {
        path: String,
        source: std::io::Error,
    },

    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<ConfigError> for String {
    fn from(e: ConfigError) -> String {
        e.to_string()
    }
}

// ═══════════════════════════════════════════════
// CONFIGURATION STRUCTS
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    pub target: TargetConfig,
    pub supabase: Option<SupabaseConfig>,
    pub github: Option<GithubConfig>,
    pub notifications: NotificationConfig,
    pub scan: ScanConfig,
    pub rate_limit: RateLimitConfig,
    pub sentinel: SentinelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub repo_url: String,
    pub domain: Option<String>,
    pub ssh_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupabaseConfig {
    pub url: String,
    pub anon_key: String,
    pub service_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubConfig {
    pub token: String,
    pub owner: String,
    pub repo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub slack_webhook: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Maximum total scan duration in seconds (default: 3600)
    pub max_duration_seconds: u64,
    /// Per-target nmap timeout in seconds (default: 300)
    pub nmap_timeout: u64,
    /// sqlmap testing level 1-5 (default: 3)
    pub sqlmap_level: u8,
    /// sqlmap risk level 1-3 (default: 2)
    pub sqlmap_risk: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Max authentication attempts per window (default: 5)
    pub auth_max: u32,
    /// Authentication window in milliseconds (default: 60000)
    pub auth_window_ms: u64,
    /// Max general API calls per window (default: 100)
    pub api_max: u32,
    /// API rate-limit window in milliseconds (default: 60000)
    pub api_window_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// How often the sentinel runs its monitoring pass, in minutes (default: 5)
    pub interval_minutes: u32,
    /// How often the sentinel runs a full dependency check, in hours (default: 6)
    pub dep_check_hours: u32,
}

// ── Defaults ──────────────────────────────────

impl Default for ShieldConfig {
    fn default() -> Self {
        ShieldConfig {
            target: TargetConfig::default(),
            supabase: None,
            github: None,
            notifications: NotificationConfig::default(),
            scan: ScanConfig::default(),
            rate_limit: RateLimitConfig::default(),
            sentinel: SentinelConfig::default(),
        }
    }
}

impl Default for TargetConfig {
    fn default() -> Self {
        TargetConfig {
            repo_url: String::new(),
            domain: None,
            ssh_key_path: None,
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        NotificationConfig {
            telegram_bot_token: None,
            telegram_chat_id: None,
            slack_webhook: None,
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            max_duration_seconds: 3600,
            nmap_timeout: 300,
            sqlmap_level: 3,
            sqlmap_risk: 2,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            auth_max: 5,
            auth_window_ms: 60000,
            api_max: 100,
            api_window_ms: 60000,
        }
    }
}

impl Default for SentinelConfig {
    fn default() -> Self {
        SentinelConfig {
            interval_minutes: 5,
            dep_check_hours: 6,
        }
    }
}

// ═══════════════════════════════════════════════
// TOOL ENTRY POINT
// ═══════════════════════════════════════════════

/// Load, parse, and validate the ShieldAGI configuration.
///
/// Input JSON schema:
/// ```json
/// {
///   "config_path": "./shieldagi.toml",  // optional
///   "env_path": "./.env",               // optional
///   "validate": true                    // optional
/// }
/// ```
///
/// Returns a JSON object:
/// ```json
/// {
///   "config": { ... },
///   "sources": ["toml", "env_file", "env_vars"],
///   "validation_errors": [],
///   "valid": true
/// }
/// ```
pub async fn tool_load_config(input: &serde_json::Value) -> Result<String, String> {
    let config_path = input["config_path"]
        .as_str()
        .unwrap_or("./shieldagi.toml");
    let env_path = input["env_path"].as_str().unwrap_or("./.env");
    let should_validate = input["validate"].as_bool().unwrap_or(true);

    info!(config_path, env_path, should_validate, "Loading ShieldAGI configuration");

    let (config, sources) = load_config_from_sources(config_path, env_path)?;

    let (validation_errors, valid) = if should_validate {
        let errors = validate_config(&config);
        let is_valid = errors.is_empty();
        if !is_valid {
            warn!(error_count = errors.len(), "Configuration validation found issues");
            for err in &errors {
                warn!(error = %err, "Validation error");
            }
        } else {
            info!("Configuration validation passed");
        }
        (errors, is_valid)
    } else {
        debug!("Skipping validation as requested");
        (Vec::new(), true)
    };

    let output = serde_json::json!({
        "config": config,
        "sources": sources,
        "config_path": config_path,
        "env_path": env_path,
        "validation_errors": validation_errors,
        "valid": valid
    });

    serde_json::to_string_pretty(&output)
        .map_err(|e| ConfigError::Serialization(e.to_string()).to_string())
}

// ═══════════════════════════════════════════════
// PUBLIC LOAD FUNCTION
// ═══════════════════════════════════════════════

/// Load configuration from a TOML file and .env file, with environment variable
/// overrides. This is the primary entry point for non-tool callers.
///
/// Priority (highest wins): environment variables > .env file > TOML file > defaults
pub fn load_config(config_path: &str) -> Result<ShieldConfig, String> {
    let env_path = "./.env";
    let (config, _sources) = load_config_from_sources(config_path, env_path)?;
    let errors = validate_config(&config);
    if errors.is_empty() {
        Ok(config)
    } else {
        Err(format!("Configuration validation failed:\n  - {}", errors.join("\n  - ")))
    }
}

/// Internal: load config from both TOML and .env sources, then overlay env vars.
/// Returns the config and a list of sources that contributed.
fn load_config_from_sources(config_path: &str, env_path: &str) -> Result<(ShieldConfig, Vec<String>), String> {
    let mut sources: Vec<String> = Vec::new();
    let mut cfg = ShieldConfig::default();

    // Step 1: Parse TOML file if it exists
    if std::path::Path::new(config_path).exists() {
        let content = std::fs::read_to_string(config_path).map_err(|e| {
            ConfigError::FileRead {
                path: config_path.to_string(),
                source: e,
            }
            .to_string()
        })?;
        cfg = parse_toml_config(&content);
        sources.push("toml".to_string());
        info!(path = config_path, "Loaded TOML configuration");
    } else {
        debug!(path = config_path, "TOML config file not found, using defaults");
    }

    // Step 2: Parse .env file if it exists — secrets from .env override TOML values
    if std::path::Path::new(env_path).exists() {
        let env_content = std::fs::read_to_string(env_path).map_err(|e| {
            ConfigError::FileRead {
                path: env_path.to_string(),
                source: e,
            }
            .to_string()
        })?;
        let env_map = parse_env_file(&env_content);
        overlay_env_map(&mut cfg, &env_map);
        sources.push("env_file".to_string());
        info!(path = env_path, keys = env_map.len(), "Loaded .env file secrets");
    } else {
        debug!(path = env_path, ".env file not found, skipping");
    }

    // Step 3: Process environment variables override both TOML and .env
    overlay_process_env(&mut cfg);
    sources.push("env_vars".to_string());

    Ok((cfg, sources))
}

// ═══════════════════════════════════════════════
// .ENV FILE PARSER
// ═══════════════════════════════════════════════

/// Parse a `.env` file into a key-value map.
///
/// Supported syntax:
/// - `KEY=value`
/// - `KEY="quoted value"`
/// - `KEY='single quoted value'`
/// - `export KEY=value` (export prefix stripped)
/// - Lines starting with `#` are comments
/// - Blank lines are ignored
/// - Inline comments after unquoted values are stripped (e.g. `KEY=val # comment`)
pub fn parse_env_file(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();

        // Skip comments and blank lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip optional `export ` prefix
        let line = if let Some(rest) = line.strip_prefix("export ") {
            rest.trim()
        } else {
            line
        };

        // Find the first `=`
        let eq_pos = match line.find('=') {
            Some(p) => p,
            None => continue,
        };

        let key = line[..eq_pos].trim().to_string();
        if key.is_empty() {
            continue;
        }

        let raw_value = line[eq_pos + 1..].trim();

        // Handle quoted values
        let value = if (raw_value.starts_with('"') && raw_value.ends_with('"') && raw_value.len() >= 2)
            || (raw_value.starts_with('\'') && raw_value.ends_with('\'') && raw_value.len() >= 2)
        {
            // Strip quotes, handle basic escape sequences in double-quoted strings
            let inner = &raw_value[1..raw_value.len() - 1];
            if raw_value.starts_with('"') {
                inner.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\")
            } else {
                inner.to_string()
            }
        } else {
            // Unquoted: strip inline comments
            match raw_value.find(" #") {
                Some(comment_pos) => raw_value[..comment_pos].trim_end().to_string(),
                None => raw_value.to_string(),
            }
        };

        debug!(key = %key, "Parsed .env entry");
        map.insert(key, value);
    }

    map
}

// ═══════════════════════════════════════════════
// TOML PARSER
// ═══════════════════════════════════════════════

/// Parse a TOML-format config file using basic string splitting.
///
/// Supported syntax:
/// - `[section]` headers to track current section
/// - `key = "value"` string assignments
/// - `key = 42` integer assignments
/// - Lines starting with `#` are comments and ignored
/// - Inline table syntax is NOT supported -- use section headers
pub fn parse_toml_config(content: &str) -> ShieldConfig {
    let mut cfg = ShieldConfig::default();

    let mut section = String::new();
    let mut kv: HashMap<String, HashMap<String, String>> = HashMap::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();

        // Skip comments and blank lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Section header: [target], [supabase], etc.
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }

        // key = value
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let raw_value = line[eq_pos + 1..].trim();

            // Strip surrounding quotes if present
            let value = if (raw_value.starts_with('"') && raw_value.ends_with('"'))
                || (raw_value.starts_with('\'') && raw_value.ends_with('\''))
            {
                raw_value[1..raw_value.len() - 1].to_string()
            } else {
                // Strip inline comments for unquoted values
                match raw_value.find(" #") {
                    Some(pos) => raw_value[..pos].trim_end().to_string(),
                    None => raw_value.to_string(),
                }
            };

            kv.entry(section.clone())
                .or_default()
                .insert(key, value);
        }
    }

    // ── [target] ──
    if let Some(target_map) = kv.get("target") {
        if let Some(v) = target_map.get("repo_url") {
            cfg.target.repo_url = v.clone();
        }
        if let Some(v) = target_map.get("domain") {
            if !v.is_empty() {
                cfg.target.domain = Some(v.clone());
            }
        }
        if let Some(v) = target_map.get("ssh_key_path") {
            if !v.is_empty() {
                cfg.target.ssh_key_path = Some(v.clone());
            }
        }
    }

    // ── [supabase] ──
    if let Some(sb_map) = kv.get("supabase") {
        let url = sb_map.get("url").cloned().unwrap_or_default();
        let anon_key = sb_map.get("anon_key").cloned().unwrap_or_default();
        let service_key = sb_map.get("service_key").cloned().unwrap_or_default();
        if !url.is_empty() || !anon_key.is_empty() || !service_key.is_empty() {
            cfg.supabase = Some(SupabaseConfig {
                url,
                anon_key,
                service_key,
            });
        }
    }

    // ── [github] ──
    if let Some(gh_map) = kv.get("github") {
        let token = gh_map.get("token").cloned().unwrap_or_default();
        let owner = gh_map.get("owner").cloned().unwrap_or_default();
        let repo = gh_map.get("repo").cloned().unwrap_or_default();
        if !token.is_empty() || !owner.is_empty() || !repo.is_empty() {
            cfg.github = Some(GithubConfig { token, owner, repo });
        }
    }

    // ── [notifications] ──
    if let Some(notif_map) = kv.get("notifications") {
        cfg.notifications.telegram_bot_token = notif_map
            .get("telegram_bot_token")
            .filter(|v| !v.is_empty())
            .cloned();
        cfg.notifications.telegram_chat_id = notif_map
            .get("telegram_chat_id")
            .filter(|v| !v.is_empty())
            .cloned();
        cfg.notifications.slack_webhook = notif_map
            .get("slack_webhook")
            .filter(|v| !v.is_empty())
            .cloned();
    }

    // ── [scan] ──
    if let Some(scan_map) = kv.get("scan") {
        if let Some(v) = scan_map.get("max_duration_seconds").and_then(|s| s.parse().ok()) {
            cfg.scan.max_duration_seconds = v;
        }
        // Also accept the shorter alias "max_duration"
        if let Some(v) = scan_map.get("max_duration").and_then(|s| s.parse().ok()) {
            cfg.scan.max_duration_seconds = v;
        }
        if let Some(v) = scan_map.get("nmap_timeout").and_then(|s| s.parse().ok()) {
            cfg.scan.nmap_timeout = v;
        }
        if let Some(v) = scan_map.get("sqlmap_level").and_then(|s| s.parse().ok()) {
            cfg.scan.sqlmap_level = v;
        }
        if let Some(v) = scan_map.get("sqlmap_risk").and_then(|s| s.parse().ok()) {
            cfg.scan.sqlmap_risk = v;
        }
    }

    // ── [rate_limit] ──
    if let Some(rl_map) = kv.get("rate_limit") {
        if let Some(v) = rl_map.get("auth_max").and_then(|s| s.parse().ok()) {
            cfg.rate_limit.auth_max = v;
        }
        if let Some(v) = rl_map.get("auth_window_ms").and_then(|s| s.parse().ok()) {
            cfg.rate_limit.auth_window_ms = v;
        }
        // Also accept "auth_window" as alias
        if let Some(v) = rl_map.get("auth_window").and_then(|s| s.parse().ok()) {
            cfg.rate_limit.auth_window_ms = v;
        }
        if let Some(v) = rl_map.get("api_max").and_then(|s| s.parse().ok()) {
            cfg.rate_limit.api_max = v;
        }
        if let Some(v) = rl_map.get("api_window_ms").and_then(|s| s.parse().ok()) {
            cfg.rate_limit.api_window_ms = v;
        }
        if let Some(v) = rl_map.get("api_window").and_then(|s| s.parse().ok()) {
            cfg.rate_limit.api_window_ms = v;
        }
    }

    // ── [sentinel] ──
    if let Some(sent_map) = kv.get("sentinel") {
        if let Some(v) = sent_map.get("interval_minutes").and_then(|s| s.parse().ok()) {
            cfg.sentinel.interval_minutes = v;
        }
        if let Some(v) = sent_map.get("dep_check_hours").and_then(|s| s.parse().ok()) {
            cfg.sentinel.dep_check_hours = v;
        }
    }

    cfg
}

// ═══════════════════════════════════════════════
// ENVIRONMENT OVERLAY
// ═══════════════════════════════════════════════

/// Mapping from .env / environment variable names to config fields.
/// The canonical variable names are:
///
/// Target:
///   SHIELDAGI_REPO_URL, SHIELDAGI_DOMAIN, SHIELDAGI_SSH_KEY_PATH
///
/// Supabase:
///   SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_KEY
///
/// GitHub:
///   GITHUB_TOKEN (or SHIELDAGI_GITHUB_TOKEN), GITHUB_OWNER, GITHUB_REPO
///
/// Notifications:
///   TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, SLACK_WEBHOOK
///
/// Scan:
///   SHIELDAGI_SCAN_MAX_DURATION, SHIELDAGI_NMAP_TIMEOUT,
///   SHIELDAGI_SQLMAP_LEVEL, SHIELDAGI_SQLMAP_RISK
///
/// Rate Limit:
///   SHIELDAGI_AUTH_MAX, SHIELDAGI_AUTH_WINDOW_MS,
///   SHIELDAGI_API_MAX, SHIELDAGI_API_WINDOW_MS
///
/// Sentinel:
///   SHIELDAGI_SENTINEL_INTERVAL, SHIELDAGI_DEP_CHECK_HOURS

/// Overlay values from a parsed .env HashMap onto the config.
/// Values from the map always override what is already in the config.
fn overlay_env_map(cfg: &mut ShieldConfig, map: &HashMap<String, String>) {
    // Helper closure to get non-empty values from the map
    let get = |key: &str| -> Option<String> {
        map.get(key).filter(|v| !v.is_empty()).cloned()
    };
    let get_u64 = |key: &str| -> Option<u64> {
        map.get(key).and_then(|v| v.parse().ok())
    };
    let get_u32 = |key: &str| -> Option<u32> {
        map.get(key).and_then(|v| v.parse().ok())
    };
    let get_u8 = |key: &str| -> Option<u8> {
        map.get(key).and_then(|v| v.parse().ok())
    };

    // Target
    if let Some(v) = get("SHIELDAGI_REPO_URL") {
        cfg.target.repo_url = v;
    }
    if let Some(v) = get("SHIELDAGI_DOMAIN") {
        cfg.target.domain = Some(v);
    }
    if let Some(v) = get("SHIELDAGI_SSH_KEY_PATH") {
        cfg.target.ssh_key_path = Some(v);
    }

    // Supabase
    apply_supabase_from_lookup(cfg, &get);

    // GitHub -- support both GITHUB_TOKEN and SHIELDAGI_GITHUB_TOKEN
    apply_github_from_lookup(cfg, &get);

    // Notifications
    if let Some(v) = get("TELEGRAM_BOT_TOKEN") {
        cfg.notifications.telegram_bot_token = Some(v);
    }
    if let Some(v) = get("TELEGRAM_CHAT_ID") {
        cfg.notifications.telegram_chat_id = Some(v);
    }
    if let Some(v) = get("SLACK_WEBHOOK") {
        cfg.notifications.slack_webhook = Some(v);
    }

    // Scan
    if let Some(v) = get_u64("SHIELDAGI_SCAN_MAX_DURATION") {
        cfg.scan.max_duration_seconds = v;
    }
    if let Some(v) = get_u64("SHIELDAGI_NMAP_TIMEOUT") {
        cfg.scan.nmap_timeout = v;
    }
    if let Some(v) = get_u8("SHIELDAGI_SQLMAP_LEVEL") {
        cfg.scan.sqlmap_level = v;
    }
    if let Some(v) = get_u8("SHIELDAGI_SQLMAP_RISK") {
        cfg.scan.sqlmap_risk = v;
    }

    // Rate limit
    if let Some(v) = get_u32("SHIELDAGI_AUTH_MAX") {
        cfg.rate_limit.auth_max = v;
    }
    if let Some(v) = get_u64("SHIELDAGI_AUTH_WINDOW_MS") {
        cfg.rate_limit.auth_window_ms = v;
    }
    if let Some(v) = get_u32("SHIELDAGI_API_MAX") {
        cfg.rate_limit.api_max = v;
    }
    if let Some(v) = get_u64("SHIELDAGI_API_WINDOW_MS") {
        cfg.rate_limit.api_window_ms = v;
    }

    // Sentinel
    if let Some(v) = get_u32("SHIELDAGI_SENTINEL_INTERVAL") {
        cfg.sentinel.interval_minutes = v;
    }
    if let Some(v) = get_u32("SHIELDAGI_DEP_CHECK_HOURS") {
        cfg.sentinel.dep_check_hours = v;
    }
}

/// Apply Supabase config from a generic string-lookup function.
fn apply_supabase_from_lookup<F: Fn(&str) -> Option<String>>(cfg: &mut ShieldConfig, get: &F) {
    let url = get("SUPABASE_URL");
    let anon = get("SUPABASE_ANON_KEY");
    let svc = get("SUPABASE_SERVICE_KEY");

    if url.is_some() || anon.is_some() || svc.is_some() {
        let existing = cfg.supabase.take().unwrap_or(SupabaseConfig {
            url: String::new(),
            anon_key: String::new(),
            service_key: String::new(),
        });
        cfg.supabase = Some(SupabaseConfig {
            url: url.unwrap_or(existing.url),
            anon_key: anon.unwrap_or(existing.anon_key),
            service_key: svc.unwrap_or(existing.service_key),
        });
    }
}

/// Apply GitHub config from a generic string-lookup function.
fn apply_github_from_lookup<F: Fn(&str) -> Option<String>>(cfg: &mut ShieldConfig, get: &F) {
    let token = get("SHIELDAGI_GITHUB_TOKEN").or_else(|| get("GITHUB_TOKEN"));
    let owner = get("GITHUB_OWNER");
    let repo = get("GITHUB_REPO");

    if token.is_some() || owner.is_some() || repo.is_some() {
        let existing = cfg.github.take().unwrap_or(GithubConfig {
            token: String::new(),
            owner: String::new(),
            repo: String::new(),
        });
        cfg.github = Some(GithubConfig {
            token: token.unwrap_or(existing.token),
            owner: owner.unwrap_or(existing.owner),
            repo: repo.unwrap_or(existing.repo),
        });
    }
}

/// Overlay process environment variables (std::env::var) onto the config.
/// These always win over both TOML and .env values.
fn overlay_process_env(cfg: &mut ShieldConfig) {
    // Target
    if let Some(v) = env_str("SHIELDAGI_REPO_URL") {
        cfg.target.repo_url = v;
    }
    if let Some(v) = env_str("SHIELDAGI_DOMAIN") {
        cfg.target.domain = Some(v);
    }
    if let Some(v) = env_str("SHIELDAGI_SSH_KEY_PATH") {
        cfg.target.ssh_key_path = Some(v);
    }

    // Supabase
    apply_supabase_from_lookup(cfg, &env_str_fn);

    // GitHub
    apply_github_from_lookup(cfg, &env_str_fn);

    // Notifications
    if let Some(v) = env_str("TELEGRAM_BOT_TOKEN") {
        cfg.notifications.telegram_bot_token = Some(v);
    }
    if let Some(v) = env_str("TELEGRAM_CHAT_ID") {
        cfg.notifications.telegram_chat_id = Some(v);
    }
    if let Some(v) = env_str("SLACK_WEBHOOK") {
        cfg.notifications.slack_webhook = Some(v);
    }

    // Scan
    if let Some(v) = env_u64("SHIELDAGI_SCAN_MAX_DURATION") {
        cfg.scan.max_duration_seconds = v;
    }
    if let Some(v) = env_u64("SHIELDAGI_NMAP_TIMEOUT") {
        cfg.scan.nmap_timeout = v;
    }
    if let Some(v) = env_u8("SHIELDAGI_SQLMAP_LEVEL") {
        cfg.scan.sqlmap_level = v;
    }
    if let Some(v) = env_u8("SHIELDAGI_SQLMAP_RISK") {
        cfg.scan.sqlmap_risk = v;
    }

    // Rate limit
    if let Some(v) = env_u32("SHIELDAGI_AUTH_MAX") {
        cfg.rate_limit.auth_max = v;
    }
    if let Some(v) = env_u64("SHIELDAGI_AUTH_WINDOW_MS") {
        cfg.rate_limit.auth_window_ms = v;
    }
    if let Some(v) = env_u32("SHIELDAGI_API_MAX") {
        cfg.rate_limit.api_max = v;
    }
    if let Some(v) = env_u64("SHIELDAGI_API_WINDOW_MS") {
        cfg.rate_limit.api_window_ms = v;
    }

    // Sentinel
    if let Some(v) = env_u32("SHIELDAGI_SENTINEL_INTERVAL") {
        cfg.sentinel.interval_minutes = v;
    }
    if let Some(v) = env_u32("SHIELDAGI_DEP_CHECK_HOURS") {
        cfg.sentinel.dep_check_hours = v;
    }
}

/// Build a ShieldConfig entirely from process environment variables.
/// Convenience function for environments where no files are available.
pub fn load_from_env() -> ShieldConfig {
    let mut cfg = ShieldConfig::default();
    overlay_process_env(&mut cfg);
    cfg
}

// ═══════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════

/// Validate a loaded ShieldConfig and return a list of human-readable
/// error messages for any missing required fields.
///
/// Required fields:
/// - target.repo_url is always required
/// - If supabase section present: url, anon_key, service_key must all be non-empty
/// - If github section present: token, owner, repo must all be non-empty
/// - Scan numeric bounds are checked
/// - Rate limit and sentinel values must be > 0
pub fn validate_config(config: &ShieldConfig) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    // target.repo_url is always required
    if config.target.repo_url.is_empty() {
        errors.push("target.repo_url is required but not set".to_string());
    } else if !config.target.repo_url.starts_with("http")
        && !config.target.repo_url.starts_with("git@")
        && !config.target.repo_url.starts_with('/')
    {
        errors.push(format!(
            "target.repo_url '{}' does not look like a valid URL or path",
            config.target.repo_url
        ));
    }

    // Supabase section -- all three fields required if section is present
    if let Some(ref sb) = config.supabase {
        if sb.url.is_empty() {
            errors.push("supabase.url is required but not set".to_string());
        }
        if sb.anon_key.is_empty() {
            errors.push("supabase.anon_key is required but not set".to_string());
        }
        if sb.service_key.is_empty() {
            errors.push("supabase.service_key is required but not set".to_string());
        }
    }

    // GitHub section
    if let Some(ref gh) = config.github {
        if gh.token.is_empty() {
            errors.push("github.token is required but not set".to_string());
        }
        if gh.owner.is_empty() {
            errors.push("github.owner is required but not set".to_string());
        }
        if gh.repo.is_empty() {
            errors.push("github.repo is required but not set".to_string());
        }
    }

    // Notification consistency: telegram needs both bot_token and chat_id together
    let has_bot = config.notifications.telegram_bot_token.is_some();
    let has_chat = config.notifications.telegram_chat_id.is_some();
    if has_bot && !has_chat {
        errors.push("notifications.telegram_chat_id is required when telegram_bot_token is set".to_string());
    }
    if has_chat && !has_bot {
        errors.push("notifications.telegram_bot_token is required when telegram_chat_id is set".to_string());
    }

    // Scan bounds
    if config.scan.sqlmap_level < 1 || config.scan.sqlmap_level > 5 {
        errors.push(format!(
            "scan.sqlmap_level must be 1-5, got {}",
            config.scan.sqlmap_level
        ));
    }
    if config.scan.sqlmap_risk < 1 || config.scan.sqlmap_risk > 3 {
        errors.push(format!(
            "scan.sqlmap_risk must be 1-3, got {}",
            config.scan.sqlmap_risk
        ));
    }
    if config.scan.max_duration_seconds == 0 {
        errors.push("scan.max_duration_seconds must be greater than 0".to_string());
    }
    if config.scan.nmap_timeout == 0 {
        errors.push("scan.nmap_timeout must be greater than 0".to_string());
    }

    // Rate limit sanity
    if config.rate_limit.auth_max == 0 {
        errors.push("rate_limit.auth_max must be greater than 0".to_string());
    }
    if config.rate_limit.auth_window_ms == 0 {
        errors.push("rate_limit.auth_window_ms must be greater than 0".to_string());
    }
    if config.rate_limit.api_max == 0 {
        errors.push("rate_limit.api_max must be greater than 0".to_string());
    }
    if config.rate_limit.api_window_ms == 0 {
        errors.push("rate_limit.api_window_ms must be greater than 0".to_string());
    }

    // Sentinel sanity
    if config.sentinel.interval_minutes == 0 {
        errors.push("sentinel.interval_minutes must be greater than 0".to_string());
    }
    if config.sentinel.dep_check_hours == 0 {
        errors.push("sentinel.dep_check_hours must be greater than 0".to_string());
    }

    errors
}

// ═══════════════════════════════════════════════
// PRIVATE ENV HELPERS
// ═══════════════════════════════════════════════

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// Wrapper that matches the `Fn(&str) -> Option<String>` signature needed
/// by `apply_supabase_from_lookup` and `apply_github_from_lookup`.
fn env_str_fn(key: &str) -> Option<String> {
    env_str(key)
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok()?.parse().ok()
}

fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok()?.parse().ok()
}

fn env_u8(key: &str) -> Option<u8> {
    std::env::var(key).ok()?.parse().ok()
}

// ═══════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: clear all ShieldAGI-related env vars ──

    fn clear_env() {
        for key in &[
            "SHIELDAGI_REPO_URL",
            "SHIELDAGI_DOMAIN",
            "SHIELDAGI_SSH_KEY_PATH",
            "SUPABASE_URL",
            "SUPABASE_ANON_KEY",
            "SUPABASE_SERVICE_KEY",
            "GITHUB_TOKEN",
            "SHIELDAGI_GITHUB_TOKEN",
            "GITHUB_OWNER",
            "GITHUB_REPO",
            "TELEGRAM_BOT_TOKEN",
            "TELEGRAM_CHAT_ID",
            "SLACK_WEBHOOK",
            "SHIELDAGI_SCAN_MAX_DURATION",
            "SHIELDAGI_NMAP_TIMEOUT",
            "SHIELDAGI_SQLMAP_LEVEL",
            "SHIELDAGI_SQLMAP_RISK",
            "SHIELDAGI_AUTH_MAX",
            "SHIELDAGI_AUTH_WINDOW_MS",
            "SHIELDAGI_API_MAX",
            "SHIELDAGI_API_WINDOW_MS",
            "SHIELDAGI_SENTINEL_INTERVAL",
            "SHIELDAGI_DEP_CHECK_HOURS",
        ] {
            std::env::remove_var(key);
        }
    }

    // ── Default values ────────────────────────

    #[test]
    fn test_scan_defaults() {
        let s = ScanConfig::default();
        assert_eq!(s.max_duration_seconds, 3600);
        assert_eq!(s.nmap_timeout, 300);
        assert_eq!(s.sqlmap_level, 3);
        assert_eq!(s.sqlmap_risk, 2);
    }

    #[test]
    fn test_rate_limit_defaults() {
        let r = RateLimitConfig::default();
        assert_eq!(r.auth_max, 5);
        assert_eq!(r.auth_window_ms, 60000);
        assert_eq!(r.api_max, 100);
        assert_eq!(r.api_window_ms, 60000);
    }

    #[test]
    fn test_sentinel_defaults() {
        let s = SentinelConfig::default();
        assert_eq!(s.interval_minutes, 5);
        assert_eq!(s.dep_check_hours, 6);
    }

    #[test]
    fn test_shield_config_default() {
        let cfg = ShieldConfig::default();
        assert!(cfg.target.repo_url.is_empty());
        assert!(cfg.supabase.is_none());
        assert!(cfg.github.is_none());
        assert!(cfg.notifications.telegram_bot_token.is_none());
    }

    // ── .env file parser ──────────────────────

    #[test]
    fn test_parse_env_file_empty() {
        let map = parse_env_file("");
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_env_file_comments_and_blanks() {
        let content = "# comment\n\n  # another comment\n";
        let map = parse_env_file(content);
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_env_file_simple_values() {
        let content = "KEY1=value1\nKEY2=value2\n";
        let map = parse_env_file(content);
        assert_eq!(map.get("KEY1").unwrap(), "value1");
        assert_eq!(map.get("KEY2").unwrap(), "value2");
    }

    #[test]
    fn test_parse_env_file_quoted_values() {
        let content = r#"
DOUBLE="hello world"
SINGLE='single quoted'
"#;
        let map = parse_env_file(content);
        assert_eq!(map.get("DOUBLE").unwrap(), "hello world");
        assert_eq!(map.get("SINGLE").unwrap(), "single quoted");
    }

    #[test]
    fn test_parse_env_file_escape_sequences() {
        let content = r#"MSG="line1\nline2""#;
        let map = parse_env_file(content);
        assert_eq!(map.get("MSG").unwrap(), "line1\nline2");
    }

    #[test]
    fn test_parse_env_file_export_prefix() {
        let content = "export MY_VAR=exported_value\n";
        let map = parse_env_file(content);
        assert_eq!(map.get("MY_VAR").unwrap(), "exported_value");
    }

    #[test]
    fn test_parse_env_file_inline_comments() {
        let content = "HOST=localhost # the host\nPORT=8080 # the port\n";
        let map = parse_env_file(content);
        assert_eq!(map.get("HOST").unwrap(), "localhost");
        assert_eq!(map.get("PORT").unwrap(), "8080");
    }

    #[test]
    fn test_parse_env_file_no_inline_comment_in_quoted() {
        let content = r#"MSG="hello # world""#;
        let map = parse_env_file(content);
        assert_eq!(map.get("MSG").unwrap(), "hello # world");
    }

    #[test]
    fn test_parse_env_file_spaces_around_equals() {
        let content = "  KEY  =  value  \n";
        let map = parse_env_file(content);
        assert_eq!(map.get("KEY").unwrap(), "value");
    }

    #[test]
    fn test_parse_env_file_empty_value() {
        let content = "EMPTY=\n";
        let map = parse_env_file(content);
        assert_eq!(map.get("EMPTY").unwrap(), "");
    }

    #[test]
    fn test_parse_env_file_realistic() {
        let content = r#"
# ShieldAGI secrets
SUPABASE_URL=https://abc.supabase.co
SUPABASE_ANON_KEY=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.anon
SUPABASE_SERVICE_KEY=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.service

export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_OWNER=acme
GITHUB_REPO=webapp

TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ
TELEGRAM_CHAT_ID=-1001234567890
"#;
        let map = parse_env_file(content);
        assert_eq!(map.len(), 8);
        assert_eq!(map.get("SUPABASE_URL").unwrap(), "https://abc.supabase.co");
        assert!(map.get("GITHUB_TOKEN").unwrap().starts_with("ghp_"));
        assert_eq!(map.get("TELEGRAM_CHAT_ID").unwrap(), "-1001234567890");
    }

    // ── load_from_env ─────────────────────────

    #[test]
    fn test_load_from_env_empty_env() {
        clear_env();
        let cfg = load_from_env();
        assert!(cfg.target.repo_url.is_empty());
        assert!(cfg.supabase.is_none());
        assert!(cfg.github.is_none());
    }

    #[test]
    fn test_load_from_env_repo_url() {
        clear_env();
        std::env::set_var("SHIELDAGI_REPO_URL", "https://github.com/example/app");
        let cfg = load_from_env();
        assert_eq!(cfg.target.repo_url, "https://github.com/example/app");
        clear_env();
    }

    #[test]
    fn test_load_from_env_full_supabase() {
        clear_env();
        std::env::set_var("SUPABASE_URL", "https://abc.supabase.co");
        std::env::set_var("SUPABASE_ANON_KEY", "anon-key-value");
        std::env::set_var("SUPABASE_SERVICE_KEY", "service-key-value");

        let cfg = load_from_env();
        assert!(cfg.supabase.is_some());
        let sb = cfg.supabase.unwrap();
        assert_eq!(sb.url, "https://abc.supabase.co");
        assert_eq!(sb.anon_key, "anon-key-value");
        assert_eq!(sb.service_key, "service-key-value");
        clear_env();
    }

    #[test]
    fn test_load_from_env_partial_supabase_still_creates_section() {
        clear_env();
        std::env::set_var("SUPABASE_URL", "https://abc.supabase.co");
        // anon_key and service_key not set -- section is still created with empty fields
        let cfg = load_from_env();
        assert!(cfg.supabase.is_some());
        let sb = cfg.supabase.unwrap();
        assert_eq!(sb.url, "https://abc.supabase.co");
        assert!(sb.anon_key.is_empty());
        clear_env();
    }

    #[test]
    fn test_load_from_env_github() {
        clear_env();
        std::env::set_var("GITHUB_TOKEN", "ghp_token123");
        std::env::set_var("GITHUB_OWNER", "acme");
        std::env::set_var("GITHUB_REPO", "web-app");

        let cfg = load_from_env();
        assert!(cfg.github.is_some());
        let gh = cfg.github.unwrap();
        assert_eq!(gh.token, "ghp_token123");
        assert_eq!(gh.owner, "acme");
        assert_eq!(gh.repo, "web-app");
        clear_env();
    }

    #[test]
    fn test_load_from_env_shieldagi_github_token_prefix() {
        clear_env();
        std::env::set_var("SHIELDAGI_GITHUB_TOKEN", "ghp_prefixed");
        std::env::set_var("GITHUB_OWNER", "org");
        std::env::set_var("GITHUB_REPO", "repo");

        let cfg = load_from_env();
        assert!(cfg.github.is_some());
        assert_eq!(cfg.github.unwrap().token, "ghp_prefixed");
        clear_env();
    }

    #[test]
    fn test_load_from_env_notifications() {
        clear_env();
        std::env::set_var("TELEGRAM_BOT_TOKEN", "bot-token");
        std::env::set_var("TELEGRAM_CHAT_ID", "-1001234567");
        std::env::set_var("SLACK_WEBHOOK", "https://hooks.slack.com/test");

        let cfg = load_from_env();
        assert_eq!(cfg.notifications.telegram_bot_token.as_deref(), Some("bot-token"));
        assert_eq!(cfg.notifications.telegram_chat_id.as_deref(), Some("-1001234567"));
        assert_eq!(
            cfg.notifications.slack_webhook.as_deref(),
            Some("https://hooks.slack.com/test")
        );
        clear_env();
    }

    #[test]
    fn test_load_from_env_scan_overrides() {
        clear_env();
        std::env::set_var("SHIELDAGI_SCAN_MAX_DURATION", "7200");
        std::env::set_var("SHIELDAGI_NMAP_TIMEOUT", "600");
        std::env::set_var("SHIELDAGI_SQLMAP_LEVEL", "5");
        std::env::set_var("SHIELDAGI_SQLMAP_RISK", "3");

        let cfg = load_from_env();
        assert_eq!(cfg.scan.max_duration_seconds, 7200);
        assert_eq!(cfg.scan.nmap_timeout, 600);
        assert_eq!(cfg.scan.sqlmap_level, 5);
        assert_eq!(cfg.scan.sqlmap_risk, 3);
        clear_env();
    }

    #[test]
    fn test_load_from_env_rate_limit_overrides() {
        clear_env();
        std::env::set_var("SHIELDAGI_AUTH_MAX", "10");
        std::env::set_var("SHIELDAGI_AUTH_WINDOW_MS", "30000");
        std::env::set_var("SHIELDAGI_API_MAX", "200");
        std::env::set_var("SHIELDAGI_API_WINDOW_MS", "120000");

        let cfg = load_from_env();
        assert_eq!(cfg.rate_limit.auth_max, 10);
        assert_eq!(cfg.rate_limit.auth_window_ms, 30000);
        assert_eq!(cfg.rate_limit.api_max, 200);
        assert_eq!(cfg.rate_limit.api_window_ms, 120000);
        clear_env();
    }

    #[test]
    fn test_load_from_env_sentinel_overrides() {
        clear_env();
        std::env::set_var("SHIELDAGI_SENTINEL_INTERVAL", "15");
        std::env::set_var("SHIELDAGI_DEP_CHECK_HOURS", "12");

        let cfg = load_from_env();
        assert_eq!(cfg.sentinel.interval_minutes, 15);
        assert_eq!(cfg.sentinel.dep_check_hours, 12);
        clear_env();
    }

    // ── parse_toml_config ─────────────────────

    #[test]
    fn test_parse_toml_empty_string() {
        let cfg = parse_toml_config("");
        assert!(cfg.target.repo_url.is_empty());
        assert!(cfg.supabase.is_none());
    }

    #[test]
    fn test_parse_toml_comments_ignored() {
        let toml = "# this is a comment\n# another comment\n";
        let cfg = parse_toml_config(toml);
        assert!(cfg.target.repo_url.is_empty());
    }

    #[test]
    fn test_parse_toml_target_section() {
        let toml = r#"
[target]
repo_url = "https://github.com/acme/app"
domain = "app.example.com"
ssh_key_path = "/home/user/.ssh/id_rsa"
"#;
        let cfg = parse_toml_config(toml);
        assert_eq!(cfg.target.repo_url, "https://github.com/acme/app");
        assert_eq!(cfg.target.domain.as_deref(), Some("app.example.com"));
        assert_eq!(cfg.target.ssh_key_path.as_deref(), Some("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn test_parse_toml_supabase_section() {
        let toml = r#"
[supabase]
url = "https://xyz.supabase.co"
anon_key = "anon123"
service_key = "service123"
"#;
        let cfg = parse_toml_config(toml);
        assert!(cfg.supabase.is_some());
        let sb = cfg.supabase.unwrap();
        assert_eq!(sb.url, "https://xyz.supabase.co");
        assert_eq!(sb.anon_key, "anon123");
        assert_eq!(sb.service_key, "service123");
    }

    #[test]
    fn test_parse_toml_github_section() {
        let toml = r#"
[github]
token = "ghp_abc"
owner = "acme"
repo = "web"
"#;
        let cfg = parse_toml_config(toml);
        assert!(cfg.github.is_some());
        let gh = cfg.github.unwrap();
        assert_eq!(gh.token, "ghp_abc");
        assert_eq!(gh.owner, "acme");
        assert_eq!(gh.repo, "web");
    }

    #[test]
    fn test_parse_toml_scan_section() {
        let toml = r#"
[scan]
max_duration_seconds = 1800
nmap_timeout = 120
sqlmap_level = 2
sqlmap_risk = 1
"#;
        let cfg = parse_toml_config(toml);
        assert_eq!(cfg.scan.max_duration_seconds, 1800);
        assert_eq!(cfg.scan.nmap_timeout, 120);
        assert_eq!(cfg.scan.sqlmap_level, 2);
        assert_eq!(cfg.scan.sqlmap_risk, 1);
    }

    #[test]
    fn test_parse_toml_rate_limit_section() {
        let toml = r#"
[rate_limit]
auth_max = 3
auth_window_ms = 30000
api_max = 50
api_window_ms = 30000
"#;
        let cfg = parse_toml_config(toml);
        assert_eq!(cfg.rate_limit.auth_max, 3);
        assert_eq!(cfg.rate_limit.auth_window_ms, 30000);
        assert_eq!(cfg.rate_limit.api_max, 50);
        assert_eq!(cfg.rate_limit.api_window_ms, 30000);
    }

    #[test]
    fn test_parse_toml_sentinel_section() {
        let toml = r#"
[sentinel]
interval_minutes = 10
dep_check_hours = 24
"#;
        let cfg = parse_toml_config(toml);
        assert_eq!(cfg.sentinel.interval_minutes, 10);
        assert_eq!(cfg.sentinel.dep_check_hours, 24);
    }

    #[test]
    fn test_parse_toml_notifications_section() {
        let toml = r#"
[notifications]
telegram_bot_token = "bot:TOKEN"
telegram_chat_id = "-1001234567890"
slack_webhook = "https://hooks.slack.com/services/T00/B00/xxx"
"#;
        let cfg = parse_toml_config(toml);
        assert_eq!(
            cfg.notifications.telegram_bot_token.as_deref(),
            Some("bot:TOKEN")
        );
        assert_eq!(
            cfg.notifications.telegram_chat_id.as_deref(),
            Some("-1001234567890")
        );
        assert_eq!(
            cfg.notifications.slack_webhook.as_deref(),
            Some("https://hooks.slack.com/services/T00/B00/xxx")
        );
    }

    #[test]
    fn test_parse_toml_full_config() {
        let toml = r#"
# ShieldAGI configuration

[target]
repo_url = "https://github.com/example/myapp"
domain = "myapp.io"

[supabase]
url = "https://abc123.supabase.co"
anon_key = "eyJhbGciOiJIUzI1NiJ9.anon"
service_key = "eyJhbGciOiJIUzI1NiJ9.service"

[github]
token = "ghp_real_token"
owner = "example"
repo = "myapp"

[notifications]
telegram_bot_token = "1234567890:ABC-DEF"
telegram_chat_id = "-100987654321"

[scan]
max_duration_seconds = 3600
nmap_timeout = 300
sqlmap_level = 3
sqlmap_risk = 2

[rate_limit]
auth_max = 5
auth_window_ms = 60000
api_max = 100
api_window_ms = 60000

[sentinel]
interval_minutes = 5
dep_check_hours = 6
"#;
        let cfg = parse_toml_config(toml);
        assert_eq!(cfg.target.repo_url, "https://github.com/example/myapp");
        assert!(cfg.supabase.is_some());
        assert!(cfg.github.is_some());
        assert!(cfg.notifications.telegram_bot_token.is_some());
        assert_eq!(cfg.scan.sqlmap_level, 3);
        assert_eq!(cfg.rate_limit.auth_max, 5);
        assert_eq!(cfg.sentinel.interval_minutes, 5);
    }

    #[test]
    fn test_parse_toml_inline_comment_stripping() {
        let toml = r#"
[scan]
max_duration_seconds = 1800 # half hour
nmap_timeout = 120 # two minutes
"#;
        let cfg = parse_toml_config(toml);
        assert_eq!(cfg.scan.max_duration_seconds, 1800);
        assert_eq!(cfg.scan.nmap_timeout, 120);
    }

    #[test]
    fn test_parse_toml_max_duration_alias() {
        let toml = r#"
[scan]
max_duration = 900
"#;
        let cfg = parse_toml_config(toml);
        assert_eq!(cfg.scan.max_duration_seconds, 900);
    }

    // ── overlay_env_map ───────────────────────

    #[test]
    fn test_overlay_env_map_overrides_toml() {
        let toml = r#"
[target]
repo_url = "https://github.com/toml/repo"
"#;
        let mut cfg = parse_toml_config(toml);
        assert_eq!(cfg.target.repo_url, "https://github.com/toml/repo");

        let mut env_map = HashMap::new();
        env_map.insert("SHIELDAGI_REPO_URL".to_string(), "https://github.com/env/repo".to_string());
        overlay_env_map(&mut cfg, &env_map);

        assert_eq!(cfg.target.repo_url, "https://github.com/env/repo");
    }

    #[test]
    fn test_overlay_env_map_adds_supabase() {
        let mut cfg = ShieldConfig::default();
        assert!(cfg.supabase.is_none());

        let mut env_map = HashMap::new();
        env_map.insert("SUPABASE_URL".to_string(), "https://x.supabase.co".to_string());
        env_map.insert("SUPABASE_ANON_KEY".to_string(), "anon".to_string());
        env_map.insert("SUPABASE_SERVICE_KEY".to_string(), "svc".to_string());
        overlay_env_map(&mut cfg, &env_map);

        assert!(cfg.supabase.is_some());
        let sb = cfg.supabase.unwrap();
        assert_eq!(sb.url, "https://x.supabase.co");
        assert_eq!(sb.anon_key, "anon");
        assert_eq!(sb.service_key, "svc");
    }

    #[test]
    fn test_overlay_env_map_merges_partial_supabase() {
        let toml = r#"
[supabase]
url = "https://existing.supabase.co"
anon_key = "existing_anon"
service_key = "existing_svc"
"#;
        let mut cfg = parse_toml_config(toml);
        let mut env_map = HashMap::new();
        env_map.insert("SUPABASE_SERVICE_KEY".to_string(), "new_svc".to_string());
        overlay_env_map(&mut cfg, &env_map);

        let sb = cfg.supabase.unwrap();
        assert_eq!(sb.url, "https://existing.supabase.co"); // preserved
        assert_eq!(sb.anon_key, "existing_anon");            // preserved
        assert_eq!(sb.service_key, "new_svc");               // overridden
    }

    #[test]
    fn test_overlay_env_map_github_token_prefix() {
        let mut cfg = ShieldConfig::default();
        let mut env_map = HashMap::new();
        env_map.insert("SHIELDAGI_GITHUB_TOKEN".to_string(), "ghp_prefixed".to_string());
        env_map.insert("GITHUB_OWNER".to_string(), "org".to_string());
        env_map.insert("GITHUB_REPO".to_string(), "repo".to_string());
        overlay_env_map(&mut cfg, &env_map);

        assert!(cfg.github.is_some());
        assert_eq!(cfg.github.unwrap().token, "ghp_prefixed");
    }

    #[test]
    fn test_overlay_env_map_scan_values() {
        let mut cfg = ShieldConfig::default();
        let mut env_map = HashMap::new();
        env_map.insert("SHIELDAGI_SCAN_MAX_DURATION".to_string(), "9999".to_string());
        env_map.insert("SHIELDAGI_SQLMAP_LEVEL".to_string(), "4".to_string());
        overlay_env_map(&mut cfg, &env_map);

        assert_eq!(cfg.scan.max_duration_seconds, 9999);
        assert_eq!(cfg.scan.sqlmap_level, 4);
    }

    // ── Merge priority: TOML < .env < process env ──

    #[test]
    fn test_merge_priority_env_file_overrides_toml() {
        clear_env();
        let toml_path = "/tmp/__shieldagi_priority_toml__.toml";
        let env_path = "/tmp/__shieldagi_priority_env__";
        std::fs::write(toml_path, r#"
[target]
repo_url = "https://toml-source.com/repo"
[scan]
nmap_timeout = 100
"#).unwrap();
        std::fs::write(env_path, "SHIELDAGI_REPO_URL=https://env-file-source.com/repo\n").unwrap();

        let (cfg, sources) = load_config_from_sources(toml_path, env_path).unwrap();
        assert!(sources.contains(&"toml".to_string()));
        assert!(sources.contains(&"env_file".to_string()));
        // .env overrides TOML for repo_url
        assert_eq!(cfg.target.repo_url, "https://env-file-source.com/repo");
        // TOML value preserved for nmap_timeout (not in .env)
        assert_eq!(cfg.scan.nmap_timeout, 100);

        let _ = std::fs::remove_file(toml_path);
        let _ = std::fs::remove_file(env_path);
        clear_env();
    }

    #[test]
    fn test_merge_priority_process_env_overrides_all() {
        clear_env();
        let toml_path = "/tmp/__shieldagi_priority2_toml__.toml";
        let env_path = "/tmp/__shieldagi_priority2_env__";
        std::fs::write(toml_path, r#"
[target]
repo_url = "https://toml.com/repo"
"#).unwrap();
        std::fs::write(env_path, "SHIELDAGI_REPO_URL=https://env-file.com/repo\n").unwrap();

        // Process env overrides both
        std::env::set_var("SHIELDAGI_REPO_URL", "https://process-env.com/repo");

        let (cfg, _) = load_config_from_sources(toml_path, env_path).unwrap();
        assert_eq!(cfg.target.repo_url, "https://process-env.com/repo");

        let _ = std::fs::remove_file(toml_path);
        let _ = std::fs::remove_file(env_path);
        clear_env();
    }

    // ── validate_config ───────────────────────

    #[test]
    fn test_validate_missing_repo_url() {
        let cfg = ShieldConfig::default();
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("repo_url")));
    }

    #[test]
    fn test_validate_valid_minimal_config() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        let errors = validate_config(&cfg);
        assert!(errors.is_empty(), "Unexpected errors: {:?}", errors);
    }

    #[test]
    fn test_validate_valid_git_ssh_url() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "git@github.com:example/app.git".to_string();
        let errors = validate_config(&cfg);
        assert!(errors.is_empty(), "Unexpected errors: {:?}", errors);
    }

    #[test]
    fn test_validate_valid_absolute_path() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "/home/user/repos/myapp".to_string();
        let errors = validate_config(&cfg);
        assert!(errors.is_empty(), "Unexpected errors: {:?}", errors);
    }

    #[test]
    fn test_validate_invalid_repo_url() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "not-a-url".to_string();
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("does not look like")));
    }

    #[test]
    fn test_validate_supabase_missing_fields() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.supabase = Some(SupabaseConfig {
            url: String::new(),
            anon_key: String::new(),
            service_key: "svc".to_string(),
        });
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("supabase.url")));
        assert!(errors.iter().any(|e| e.contains("supabase.anon_key")));
    }

    #[test]
    fn test_validate_github_missing_fields() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.github = Some(GithubConfig {
            token: String::new(),
            owner: "acme".to_string(),
            repo: String::new(),
        });
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("github.token")));
        assert!(errors.iter().any(|e| e.contains("github.repo")));
    }

    #[test]
    fn test_validate_telegram_requires_both() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.notifications.telegram_bot_token = Some("bot:token".to_string());
        // chat_id missing
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("telegram_chat_id")));
    }

    #[test]
    fn test_validate_telegram_chat_without_bot() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.notifications.telegram_chat_id = Some("-100123".to_string());
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("telegram_bot_token")));
    }

    #[test]
    fn test_validate_sqlmap_level_out_of_range() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.scan.sqlmap_level = 6;
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("sqlmap_level")));
    }

    #[test]
    fn test_validate_sqlmap_risk_out_of_range() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.scan.sqlmap_risk = 0;
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("sqlmap_risk")));
    }

    #[test]
    fn test_validate_zero_max_duration() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.scan.max_duration_seconds = 0;
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("max_duration_seconds")));
    }

    #[test]
    fn test_validate_zero_nmap_timeout() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.scan.nmap_timeout = 0;
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("nmap_timeout")));
    }

    #[test]
    fn test_validate_zero_rate_limit_auth_max() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.rate_limit.auth_max = 0;
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("auth_max")));
    }

    #[test]
    fn test_validate_zero_rate_limit_windows() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.rate_limit.auth_window_ms = 0;
        cfg.rate_limit.api_window_ms = 0;
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("auth_window_ms")));
        assert!(errors.iter().any(|e| e.contains("api_window_ms")));
    }

    #[test]
    fn test_validate_zero_sentinel_interval() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.sentinel.interval_minutes = 0;
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("interval_minutes")));
    }

    #[test]
    fn test_validate_zero_dep_check_hours() {
        let mut cfg = ShieldConfig::default();
        cfg.target.repo_url = "https://github.com/example/app".to_string();
        cfg.sentinel.dep_check_hours = 0;
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.contains("dep_check_hours")));
    }

    #[test]
    fn test_validate_complete_valid_config() {
        let cfg = ShieldConfig {
            target: TargetConfig {
                repo_url: "https://github.com/acme/app".to_string(),
                domain: Some("app.acme.io".to_string()),
                ssh_key_path: None,
            },
            supabase: Some(SupabaseConfig {
                url: "https://x.supabase.co".to_string(),
                anon_key: "anon".to_string(),
                service_key: "svc".to_string(),
            }),
            github: Some(GithubConfig {
                token: "ghp_test".to_string(),
                owner: "acme".to_string(),
                repo: "app".to_string(),
            }),
            notifications: NotificationConfig {
                telegram_bot_token: Some("bot:tok".to_string()),
                telegram_chat_id: Some("-100123".to_string()),
                slack_webhook: Some("https://hooks.slack.com/x".to_string()),
            },
            scan: ScanConfig::default(),
            rate_limit: RateLimitConfig::default(),
            sentinel: SentinelConfig::default(),
        };
        let errors = validate_config(&cfg);
        assert!(errors.is_empty(), "Unexpected errors: {:?}", errors);
    }

    // ── load_config ───────────────────────────

    #[test]
    fn test_load_config_returns_error_on_invalid() {
        clear_env();
        let result = load_config("/tmp/__nonexistent_path_12345__.toml");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("repo_url"));
        clear_env();
    }

    #[test]
    fn test_load_config_succeeds_with_valid_toml() {
        clear_env();
        let path = "/tmp/__shieldagi_load_config_test__.toml";
        std::fs::write(path, r#"
[target]
repo_url = "https://github.com/acme/app"
"#).unwrap();
        let result = load_config(path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().target.repo_url, "https://github.com/acme/app");
        let _ = std::fs::remove_file(path);
        clear_env();
    }

    // ── tool_load_config (async) ───────────────

    #[tokio::test]
    async fn test_tool_load_config_missing_file_falls_back_to_defaults() {
        clear_env();
        std::env::set_var("SHIELDAGI_REPO_URL", "https://github.com/test/repo");
        let input = serde_json::json!({
            "config_path": "/tmp/__nonexistent_shieldagi__.toml",
            "env_path": "/tmp/__nonexistent_env__"
        });
        let result = tool_load_config(&input).await;
        assert!(result.is_ok());
        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(parsed["sources"].as_array().unwrap().contains(&serde_json::json!("env_vars")));
        assert_eq!(parsed["config"]["target"]["repo_url"], "https://github.com/test/repo");
        clear_env();
    }

    #[tokio::test]
    async fn test_tool_load_config_default_paths() {
        clear_env();
        let input = serde_json::json!({});
        let result = tool_load_config(&input).await;
        assert!(result.is_ok());
        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(parsed["config"].is_object());
        assert!(parsed["validation_errors"].is_array());
        assert!(parsed["valid"].is_boolean());
        assert_eq!(parsed["config_path"], "./shieldagi.toml");
        assert_eq!(parsed["env_path"], "./.env");
        clear_env();
    }

    #[tokio::test]
    async fn test_tool_load_config_skip_validation() {
        clear_env();
        let input = serde_json::json!({
            "config_path": "/tmp/__nonexistent__.toml",
            "env_path": "/tmp/__nonexistent__",
            "validate": false
        });
        let result = tool_load_config(&input).await;
        assert!(result.is_ok());
        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        // Even though repo_url is empty, valid should be true because validation was skipped
        assert!(parsed["valid"].as_bool().unwrap());
        assert!(parsed["validation_errors"].as_array().unwrap().is_empty());
        clear_env();
    }

    #[tokio::test]
    async fn test_tool_load_config_from_written_toml_and_env() {
        clear_env();
        let toml_path = "/tmp/__shieldagi_tool_test__.toml";
        let env_path = "/tmp/__shieldagi_tool_test_env__";
        std::fs::write(toml_path, r#"
[target]
repo_url = "https://github.com/acme/secure-app"
domain = "secure.acme.io"

[scan]
max_duration_seconds = 1800
nmap_timeout = 60
sqlmap_level = 2
sqlmap_risk = 1

[rate_limit]
auth_max = 5
auth_window_ms = 60000
api_max = 100
api_window_ms = 60000

[sentinel]
interval_minutes = 5
dep_check_hours = 6
"#).unwrap();
        std::fs::write(env_path, r#"
# Secrets
GITHUB_TOKEN=ghp_test_token_123
GITHUB_OWNER=acme
GITHUB_REPO=secure-app
"#).unwrap();

        let input = serde_json::json!({
            "config_path": toml_path,
            "env_path": env_path
        });
        let result = tool_load_config(&input).await;
        assert!(result.is_ok());

        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let sources = parsed["sources"].as_array().unwrap();
        assert!(sources.contains(&serde_json::json!("toml")));
        assert!(sources.contains(&serde_json::json!("env_file")));

        assert!(parsed["valid"].as_bool().unwrap());
        assert_eq!(
            parsed["config"]["target"]["repo_url"],
            "https://github.com/acme/secure-app"
        );
        assert_eq!(parsed["config"]["github"]["token"], "ghp_test_token_123");
        assert_eq!(parsed["config"]["github"]["owner"], "acme");

        let _ = std::fs::remove_file(toml_path);
        let _ = std::fs::remove_file(env_path);
        clear_env();
    }

    #[tokio::test]
    async fn test_tool_load_config_env_file_overrides_toml_secrets() {
        clear_env();
        let toml_path = "/tmp/__shieldagi_override_test__.toml";
        let env_path = "/tmp/__shieldagi_override_test_env__";
        std::fs::write(toml_path, r#"
[target]
repo_url = "https://github.com/acme/app"

[github]
token = "toml_token"
owner = "toml_owner"
repo = "toml_repo"
"#).unwrap();
        std::fs::write(env_path, "GITHUB_TOKEN=env_file_token\n").unwrap();

        let input = serde_json::json!({
            "config_path": toml_path,
            "env_path": env_path
        });
        let result = tool_load_config(&input).await;
        assert!(result.is_ok());

        let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        // .env token should override TOML token
        assert_eq!(parsed["config"]["github"]["token"], "env_file_token");
        // owner/repo from TOML preserved
        assert_eq!(parsed["config"]["github"]["owner"], "toml_owner");
        assert_eq!(parsed["config"]["github"]["repo"], "toml_repo");

        let _ = std::fs::remove_file(toml_path);
        let _ = std::fs::remove_file(env_path);
        clear_env();
    }

    // ── ConfigError ───────────────────────────

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::Validation("test error".to_string());
        assert_eq!(err.to_string(), "Validation failed: test error");
    }

    #[test]
    fn test_config_error_into_string() {
        let err = ConfigError::Serialization("json error".to_string());
        let s: String = err.into();
        assert!(s.contains("json error"));
    }

    // ── Serialization roundtrip ───────────────

    #[test]
    fn test_shield_config_serialize_deserialize() {
        let cfg = ShieldConfig {
            target: TargetConfig {
                repo_url: "https://github.com/test/app".to_string(),
                domain: Some("test.io".to_string()),
                ssh_key_path: None,
            },
            supabase: None,
            github: Some(GithubConfig {
                token: "ghp_xxx".to_string(),
                owner: "test".to_string(),
                repo: "app".to_string(),
            }),
            notifications: NotificationConfig::default(),
            scan: ScanConfig::default(),
            rate_limit: RateLimitConfig::default(),
            sentinel: SentinelConfig::default(),
        };

        let json_str = serde_json::to_string(&cfg).unwrap();
        let deserialized: ShieldConfig = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.target.repo_url, "https://github.com/test/app");
        assert_eq!(deserialized.target.domain.as_deref(), Some("test.io"));
        assert!(deserialized.github.is_some());
        assert_eq!(deserialized.github.unwrap().token, "ghp_xxx");
        assert!(deserialized.supabase.is_none());
    }
}
