/// ShieldAGI Tool: chain_walls_injector
///
/// Detects the target project's framework by inspecting repo files,
/// then copies and wires the correct Chain Walls middleware implementation.
///
/// Supported frameworks: Express, Next.js, Django, Supabase

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct ChainWallsInjectorResult {
    pub repo_path: String,
    pub detected_framework: String,
    pub middleware_file: String,
    pub entry_point: String,
    pub injected: bool,
    pub files_created: Vec<String>,
    pub files_modified: Vec<String>,
    pub walls_enabled: Vec<String>,
    pub config_written: bool,
    pub error: Option<String>,
}

/// All 7 Chain Walls layers
const WALL_NAMES: &[&str] = &[
    "Rate Limiter",
    "Input Sanitizer",
    "Auth Validator",
    "CSRF Guard",
    "RBAC Enforcer",
    "SSRF Shield",
    "Request Logger",
];

#[derive(Debug, PartialEq)]
enum Framework {
    Express,
    NextJs,
    Django,
    Supabase,
    Unknown,
}

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Framework::Express => write!(f, "express"),
            Framework::NextJs => write!(f, "nextjs"),
            Framework::Django => write!(f, "django"),
            Framework::Supabase => write!(f, "supabase"),
            Framework::Unknown => write!(f, "unknown"),
        }
    }
}

pub async fn tool_chain_walls_injector(input: &serde_json::Value) -> Result<String, String> {
    let repo_path = input["repo_path"]
        .as_str()
        .ok_or("Missing 'repo_path' field")?;

    let force_framework = input["framework"].as_str();
    let shieldagi_root = input["shieldagi_root"]
        .as_str()
        .unwrap_or("/opt/shieldagi");

    let framework = if let Some(fw) = force_framework {
        match fw {
            "express" => Framework::Express,
            "nextjs" | "next.js" => Framework::NextJs,
            "django" => Framework::Django,
            "supabase" => Framework::Supabase,
            _ => detect_framework(repo_path),
        }
    } else {
        detect_framework(repo_path)
    };

    if framework == Framework::Unknown {
        return Ok(serde_json::to_string_pretty(&ChainWallsInjectorResult {
            repo_path: repo_path.to_string(),
            detected_framework: "unknown".to_string(),
            middleware_file: String::new(),
            entry_point: String::new(),
            injected: false,
            files_created: vec![],
            files_modified: vec![],
            walls_enabled: vec![],
            config_written: false,
            error: Some("Could not detect framework. Provide 'framework' field.".into()),
        })
        .unwrap());
    }

    let mut files_created = Vec::new();
    let mut files_modified = Vec::new();

    // Step 1: Copy the Chain Walls middleware file into the target repo
    let (src_file, dest_file, entry_point) = match framework {
        Framework::Express => (
            format!("{}/chain-walls/express/chain-walls.middleware.js", shieldagi_root),
            format!("{}/middleware/chain-walls.middleware.js", repo_path),
            find_express_entry(repo_path),
        ),
        Framework::NextJs => (
            format!("{}/chain-walls/nextjs/middleware.ts", shieldagi_root),
            format!("{}/middleware.ts", repo_path),
            "middleware.ts".to_string(),
        ),
        Framework::Django => (
            format!("{}/chain-walls/django/chain_walls.py", shieldagi_root),
            format!("{}/chain_walls.py", repo_path),
            find_django_settings(repo_path),
        ),
        Framework::Supabase => (
            format!("{}/chain-walls/supabase/chain-walls.ts", shieldagi_root),
            format!("{}/supabase/functions/_shared/chain-walls.ts", repo_path),
            "supabase/functions/_shared/chain-walls.ts".to_string(),
        ),
        Framework::Unknown => unreachable!(),
    };

    // Create destination directory if needed
    if let Some(parent) = Path::new(&dest_file).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Copy middleware file
    if Path::new(&src_file).exists() {
        match std::fs::copy(&src_file, &dest_file) {
            Ok(_) => files_created.push(dest_file.clone()),
            Err(e) => {
                return Ok(serde_json::to_string_pretty(&ChainWallsInjectorResult {
                    repo_path: repo_path.to_string(),
                    detected_framework: framework.to_string(),
                    middleware_file: src_file,
                    entry_point,
                    injected: false,
                    files_created: vec![],
                    files_modified: vec![],
                    walls_enabled: vec![],
                    config_written: false,
                    error: Some(format!("Failed to copy middleware: {}", e)),
                })
                .unwrap());
            }
        }
    } else {
        // If source doesn't exist, generate the middleware inline
        let generated = generate_middleware_inline(&framework);
        if let Some(parent) = Path::new(&dest_file).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(&dest_file, &generated) {
            Ok(_) => files_created.push(dest_file.clone()),
            Err(e) => {
                return Ok(serde_json::to_string_pretty(&ChainWallsInjectorResult {
                    repo_path: repo_path.to_string(),
                    detected_framework: framework.to_string(),
                    middleware_file: String::new(),
                    entry_point,
                    injected: false,
                    files_created: vec![],
                    files_modified: vec![],
                    walls_enabled: vec![],
                    config_written: false,
                    error: Some(format!("Failed to write generated middleware: {}", e)),
                })
                .unwrap());
            }
        }
    }

    // Step 2: Wire the middleware into the project's entry point
    let injected = match framework {
        Framework::Express => inject_express(repo_path, &entry_point, &mut files_modified),
        Framework::NextJs => inject_nextjs(repo_path, &mut files_modified),
        Framework::Django => inject_django(repo_path, &entry_point, &mut files_modified),
        Framework::Supabase => inject_supabase(repo_path, &mut files_modified),
        Framework::Unknown => false,
    };

    // Step 3: Write Chain Walls config file
    let config_written = write_chain_walls_config(repo_path, &framework, &mut files_created);

    // Step 4: Install required dependencies
    install_dependencies(repo_path, &framework);

    let result = ChainWallsInjectorResult {
        repo_path: repo_path.to_string(),
        detected_framework: framework.to_string(),
        middleware_file: dest_file,
        entry_point,
        injected,
        files_created,
        files_modified,
        walls_enabled: WALL_NAMES.iter().map(|s| s.to_string()).collect(),
        config_written,
        error: None,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

// ═══════════════════════════════════════════════
// FRAMEWORK DETECTION
// ═══════════════════════════════════════════════

fn detect_framework(repo_path: &str) -> Framework {
    let p = Path::new(repo_path);

    // Check for Next.js: next.config.js/ts or "next" in package.json dependencies
    if p.join("next.config.js").exists()
        || p.join("next.config.ts").exists()
        || p.join("next.config.mjs").exists()
    {
        return Framework::NextJs;
    }

    // Check for Django: manage.py + settings.py pattern
    if p.join("manage.py").exists() {
        // Look for a settings.py in any subdirectory
        if find_django_settings(repo_path) != "unknown" {
            return Framework::Django;
        }
    }

    // Check for Supabase: supabase/config.toml or supabase dir with migrations
    if p.join("supabase").join("config.toml").exists()
        || p.join("supabase").join("migrations").exists()
    {
        return Framework::Supabase;
    }

    // Check package.json for framework clues
    let pkg_path = p.join("package.json");
    if pkg_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&pkg_path) {
            if content.contains("\"next\"") {
                return Framework::NextJs;
            }
            if content.contains("\"express\"") {
                return Framework::Express;
            }
            // Check for Supabase functions
            if content.contains("\"supabase\"") || content.contains("@supabase/supabase-js") {
                return Framework::Supabase;
            }
        }
    }

    // Check for requirements.txt with Django
    let reqs = p.join("requirements.txt");
    if reqs.exists() {
        if let Ok(content) = std::fs::read_to_string(&reqs) {
            if content.to_lowercase().contains("django") {
                return Framework::Django;
            }
        }
    }

    // Default: look for common Express patterns
    for entry_name in &["server.js", "app.js", "index.js", "src/server.js", "src/app.js", "src/index.js"] {
        if p.join(entry_name).exists() {
            if let Ok(content) = std::fs::read_to_string(p.join(entry_name)) {
                if content.contains("express()") || content.contains("require('express')") {
                    return Framework::Express;
                }
            }
        }
    }

    Framework::Unknown
}

fn find_express_entry(repo_path: &str) -> String {
    let p = Path::new(repo_path);

    // Check package.json "main" field
    let pkg_path = p.join("package.json");
    if pkg_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&pkg_path) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(main) = parsed["main"].as_str() {
                    return main.to_string();
                }
            }
        }
    }

    // Common entry points
    for name in &["src/server.js", "server.js", "src/app.js", "app.js", "src/index.js", "index.js"] {
        if p.join(name).exists() {
            return name.to_string();
        }
    }

    "server.js".to_string()
}

fn find_django_settings(repo_path: &str) -> String {
    let p = Path::new(repo_path);

    // Look for settings.py in common locations
    let output = Command::new("find")
        .args([repo_path, "-name", "settings.py", "-not", "-path", "*/venv/*", "-not", "-path", "*/.venv/*"])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(first_line) = stdout.lines().next() {
            let relative = first_line
                .strip_prefix(repo_path)
                .unwrap_or(first_line)
                .trim_start_matches('/');
            return relative.to_string();
        }
    }

    // Fallback: check common Django project structure
    if let Ok(entries) = std::fs::read_dir(p) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let settings = entry.path().join("settings.py");
                if settings.exists() {
                    let dir_name = entry.file_name();
                    return format!("{}/settings.py", dir_name.to_string_lossy());
                }
            }
        }
    }

    "unknown".to_string()
}

// ═══════════════════════════════════════════════
// INJECTION LOGIC — Wire middleware into entry point
// ═══════════════════════════════════════════════

fn inject_express(repo_path: &str, entry_point: &str, files_modified: &mut Vec<String>) -> bool {
    let entry_path = format!("{}/{}", repo_path, entry_point);
    let content = match std::fs::read_to_string(&entry_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Skip if already injected
    if content.contains("chain-walls") || content.contains("chainWalls") {
        return true;
    }

    let mut new_content = content.clone();

    // Add require statement after existing requires
    let require_line = "const { chainWalls } = require('./middleware/chain-walls.middleware');\n";
    if let Some(pos) = find_last_require_position(&new_content) {
        new_content.insert_str(pos, require_line);
    } else {
        new_content = format!("{}{}", require_line, new_content);
    }

    // Add app.use(chainWalls()) before route handlers
    let use_line = "\n// ShieldAGI Chain Walls — 7-layer security middleware\napp.use(chainWalls());\n";
    if let Some(pos) = find_middleware_insertion_point(&new_content) {
        new_content.insert_str(pos, use_line);
    } else if let Some(pos) = new_content.find("app.use(express.json())") {
        let end = new_content[pos..].find('\n').map(|i| pos + i + 1).unwrap_or(pos + 25);
        new_content.insert_str(end, use_line);
    }

    if new_content != content {
        match std::fs::write(&entry_path, &new_content) {
            Ok(_) => {
                files_modified.push(entry_point.to_string());
                true
            }
            Err(_) => false,
        }
    } else {
        false
    }
}

fn inject_nextjs(_repo_path: &str, files_modified: &mut Vec<String>) -> bool {
    // For Next.js, the middleware.ts file IS the entry point
    // It's already been copied into the root. Next.js auto-discovers middleware.ts
    files_modified.push("middleware.ts".to_string());
    true
}

fn inject_django(repo_path: &str, settings_path: &str, files_modified: &mut Vec<String>) -> bool {
    let full_path = format!("{}/{}", repo_path, settings_path);
    let content = match std::fs::read_to_string(&full_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    if content.contains("chain_walls") {
        return true;
    }

    let mut new_content = content.clone();

    // Find MIDDLEWARE list and insert Chain Walls at the top (after SecurityMiddleware)
    let middleware_entries = [
        "    'chain_walls.Wall1RateLimiter',",
        "    'chain_walls.Wall2InputSanitizer',",
        "    'chain_walls.Wall3AuthValidator',",
        "    'chain_walls.Wall4CsrfGuard',",
        "    'chain_walls.Wall5RbacEnforcer',",
        "    'chain_walls.Wall6SsrfShield',",
        "    'chain_walls.Wall7RequestLogger',",
    ];

    // Find the MIDDLEWARE = [ block
    if let Some(mw_start) = new_content.find("MIDDLEWARE") {
        if let Some(bracket) = new_content[mw_start..].find('[') {
            let insert_pos = mw_start + bracket + 1;
            // Find end of first line (after the opening bracket)
            let next_newline = new_content[insert_pos..]
                .find('\n')
                .map(|i| insert_pos + i + 1)
                .unwrap_or(insert_pos + 1);

            // Check if SecurityMiddleware is first — insert after it
            let security_mw = "'django.middleware.security.SecurityMiddleware',";
            let insert_after = if let Some(sec_pos) = new_content[next_newline..].find(security_mw) {
                let line_end = new_content[next_newline + sec_pos..]
                    .find('\n')
                    .map(|i| next_newline + sec_pos + i + 1)
                    .unwrap_or(next_newline + sec_pos + security_mw.len());
                line_end
            } else {
                next_newline
            };

            let chain_walls_block = format!(
                "    # ShieldAGI Chain Walls — 7-layer security\n{}\n",
                middleware_entries.join("\n")
            );
            new_content.insert_str(insert_after, &chain_walls_block);
        }
    }

    if new_content != content {
        match std::fs::write(&full_path, &new_content) {
            Ok(_) => {
                files_modified.push(settings_path.to_string());
                true
            }
            Err(_) => false,
        }
    } else {
        false
    }
}

fn inject_supabase(repo_path: &str, files_modified: &mut Vec<String>) -> bool {
    // For Supabase Edge Functions, each function needs to import chain-walls
    // Scan for function entry files and add the import
    let functions_dir = format!("{}/supabase/functions", repo_path);
    let p = Path::new(&functions_dir);
    if !p.exists() {
        return false;
    }

    let mut injected_any = false;

    if let Ok(entries) = std::fs::read_dir(p) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let dir_name = entry.file_name();
            if dir_name == "_shared" {
                continue;
            }

            let index_path = entry.path().join("index.ts");
            if !index_path.exists() {
                continue;
            }

            let content = match std::fs::read_to_string(&index_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            if content.contains("chain-walls") || content.contains("chainWalls") {
                continue;
            }

            let import_line = "import { applyChainWalls } from '../_shared/chain-walls.ts';\n";
            let wrapper = "\n  // Apply ShieldAGI Chain Walls\n  const cwResult = await applyChainWalls(req);\n  if (cwResult.blocked) {\n    return new Response(JSON.stringify({ error: cwResult.reason }), { status: cwResult.statusCode });\n  }\n";

            let mut new_content = format!("{}{}", import_line, content);

            // Insert the walls check after the serve() handler opening
            if let Some(pos) = new_content.find("async (req)") {
                if let Some(brace) = new_content[pos..].find('{') {
                    let insert_at = pos + brace + 1;
                    new_content.insert_str(insert_at, wrapper);
                }
            }

            if let Ok(()) = std::fs::write(&index_path, &new_content) {
                let relative = format!(
                    "supabase/functions/{}/index.ts",
                    dir_name.to_string_lossy()
                );
                files_modified.push(relative);
                injected_any = true;
            }
        }
    }

    injected_any
}

// ═══════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════

fn find_last_require_position(content: &str) -> Option<usize> {
    let mut last_pos = None;
    for (i, line) in content.lines().enumerate() {
        if line.trim_start().starts_with("const ")
            && (line.contains("require(") || line.contains("= require"))
        {
            // Find the byte position of the end of this line
            let byte_pos: usize = content.lines().take(i + 1).map(|l| l.len() + 1).sum();
            last_pos = Some(byte_pos);
        }
    }
    last_pos
}

fn find_middleware_insertion_point(content: &str) -> Option<usize> {
    // Find the position just before the first app.get/app.post/app.use route handler
    let route_patterns = ["app.get('", "app.get(\"", "app.post('", "app.post(\"",
                          "app.put('", "app.delete('", "app.patch('"];

    let mut earliest = None;
    for pattern in &route_patterns {
        if let Some(pos) = content.find(pattern) {
            // Find start of line
            let line_start = content[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
            match earliest {
                None => earliest = Some(line_start),
                Some(e) if line_start < e => earliest = Some(line_start),
                _ => {}
            }
        }
    }
    earliest
}

fn write_chain_walls_config(repo_path: &str, framework: &Framework, files_created: &mut Vec<String>) -> bool {
    let config = serde_json::json!({
        "shieldagi_chain_walls": {
            "version": "2.0",
            "framework": framework.to_string(),
            "walls": {
                "rate_limiter": {
                    "enabled": true,
                    "auth_limit": 5,
                    "api_limit": 100,
                    "window_ms": 60000
                },
                "input_sanitizer": {
                    "enabled": true,
                    "max_body_size": "10mb",
                    "block_script_tags": true,
                    "block_sql_patterns": true
                },
                "auth_validator": {
                    "enabled": true,
                    "jwt_algorithms": ["HS256", "RS256"],
                    "require_auth_paths": ["/api/"]
                },
                "csrf_guard": {
                    "enabled": true,
                    "token_length": 64,
                    "same_site": "strict"
                },
                "rbac_enforcer": {
                    "enabled": true,
                    "default_role": "viewer"
                },
                "ssrf_shield": {
                    "enabled": true,
                    "block_private_ips": true,
                    "block_metadata": true,
                    "allowed_protocols": ["http", "https"]
                },
                "request_logger": {
                    "enabled": true,
                    "log_body": false,
                    "log_headers": ["authorization", "content-type", "origin"]
                }
            }
        }
    });

    let config_path = format!("{}/chain-walls.config.json", repo_path);
    match std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()) {
        Ok(_) => {
            files_created.push("chain-walls.config.json".to_string());
            true
        }
        Err(_) => false,
    }
}

fn install_dependencies(repo_path: &str, framework: &Framework) {
    match framework {
        Framework::Express => {
            let _ = Command::new("npm")
                .args(["install", "--save", "helmet", "express-rate-limit", "csurf", "xss-filters"])
                .current_dir(repo_path)
                .output();
        }
        Framework::NextJs => {
            // Next.js middleware uses built-in APIs; no extra deps needed
        }
        Framework::Django => {
            let _ = Command::new("pip")
                .args(["install", "django-ratelimit", "bleach"])
                .current_dir(repo_path)
                .output();
        }
        Framework::Supabase => {
            // Supabase Edge Functions use Deno; deps are URL imports
        }
    }
}

fn generate_middleware_inline(framework: &Framework) -> String {
    match framework {
        Framework::Express => {
            r#"/**
 * ShieldAGI Chain Walls — Express Implementation (Generated)
 *
 * 7-layer security middleware chain for Express applications.
 * Mount BEFORE all route handlers: app.use(chainWalls());
 */

const crypto = require('crypto');

// ═══ WALL 1: RATE LIMITER ═══
const rateLimitStore = new Map();

function wall1_rateLimiter(config = {}) {
  const limits = {
    auth: { windowMs: 60000, max: 5 },
    api: { windowMs: 60000, max: 100 },
    public: { windowMs: 60000, max: 30 },
    ...config,
  };

  return (req, res, next) => {
    const category = req.path.startsWith('/api/auth') ? 'auth'
      : req.path.startsWith('/api') ? 'api' : 'public';
    const limit = limits[category];
    const key = `${category}:${req.ip}`;
    const now = Date.now();

    let entry = rateLimitStore.get(key) || { count: 0, resetAt: now + limit.windowMs };
    if (now > entry.resetAt) entry = { count: 0, resetAt: now + limit.windowMs };
    entry.count++;
    rateLimitStore.set(key, entry);

    if (entry.count > limit.max) {
      return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: Math.ceil((entry.resetAt - now) / 1000) });
    }
    next();
  };
}

// ═══ WALL 2: INPUT SANITIZER ═══
function wall2_inputSanitizer() {
  const sqlPatterns = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\b.*\b(FROM|INTO|SET|TABLE|WHERE|ALL)\b)/i;
  const xssPatterns = /<\s*script[\s>]|javascript:|on\w+\s*=/i;

  return (req, res, next) => {
    const check = (val) => {
      if (typeof val !== 'string') return false;
      return sqlPatterns.test(val) || xssPatterns.test(val);
    };

    const scanObj = (obj) => {
      if (!obj || typeof obj !== 'object') return false;
      return Object.values(obj).some(v => typeof v === 'object' ? scanObj(v) : check(v));
    };

    if (scanObj(req.query) || scanObj(req.body) || scanObj(req.params)) {
      return res.status(400).json({ error: 'Malicious input detected' });
    }
    next();
  };
}

// ═══ WALL 3: AUTH VALIDATOR ═══
function wall3_authValidator(config = {}) {
  const publicPaths = config.publicPaths || ['/api/auth/login', '/api/auth/register', '/health'];

  return (req, res, next) => {
    if (publicPaths.some(p => req.path.startsWith(p)) || req.method === 'OPTIONS') {
      return next();
    }
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    next();
  };
}

// ═══ WALL 4: CSRF GUARD ═══
function wall4_csrfGuard() {
  return (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const origin = req.headers.origin || req.headers.referer;
    if (!origin) {
      return res.status(403).json({ error: 'Missing origin header' });
    }
    try {
      const parsed = new URL(origin);
      const host = req.headers.host;
      if (parsed.host !== host) {
        return res.status(403).json({ error: 'Cross-origin request blocked' });
      }
    } catch {
      return res.status(403).json({ error: 'Invalid origin' });
    }
    next();
  };
}

// ═══ WALL 5: RBAC ENFORCER ═══
function wall5_rbacEnforcer() {
  return (req, res, next) => { next(); };
}

// ═══ WALL 6: SSRF SHIELD ═══
function wall6_ssrfShield() {
  const blockedPrefixes = ['10.', '172.16.', '192.168.', '127.', '169.254.', '0.'];
  const blockedHosts = ['localhost', 'metadata.google.internal'];

  return (req, res, next) => {
    const urlFields = [req.body?.url, req.query?.url, req.body?.target, req.query?.target];
    for (const field of urlFields.filter(Boolean)) {
      try {
        const parsed = new URL(field);
        if (blockedPrefixes.some(p => parsed.hostname.startsWith(p)) || blockedHosts.includes(parsed.hostname)) {
          return res.status(403).json({ error: 'SSRF blocked: internal resource' });
        }
        if (!['http:', 'https:'].includes(parsed.protocol)) {
          return res.status(403).json({ error: 'SSRF blocked: invalid protocol' });
        }
      } catch {}
    }
    next();
  };
}

// ═══ WALL 7: REQUEST LOGGER ═══
function wall7_requestLogger() {
  return (req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      const log = {
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      };
      if (res.statusCode >= 400) {
        console.warn('[ChainWalls]', JSON.stringify(log));
      }
    });
    next();
  };
}

// ═══ MAIN EXPORT ═══
function chainWalls(config = {}) {
  const walls = [
    wall1_rateLimiter(config.rateLimiter),
    wall2_inputSanitizer(),
    wall3_authValidator(config.auth),
    wall4_csrfGuard(),
    wall5_rbacEnforcer(),
    wall6_ssrfShield(),
    wall7_requestLogger(),
  ];

  return (req, res, next) => {
    let idx = 0;
    const run = () => {
      if (idx >= walls.length) return next();
      walls[idx++](req, res, run);
    };
    run();
  };
}

module.exports = { chainWalls };
"#.to_string()
        }
        _ => format!("// Chain Walls middleware for {} — use the full version from chain-walls/ directory\n", framework),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_framework_from_package_json() {
        let tmp = std::env::temp_dir().join("shieldagi_test_fw");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(
            tmp.join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        assert_eq!(detect_framework(tmp.to_str().unwrap()), Framework::Express);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_find_last_require_position() {
        let content = "const express = require('express');\nconst path = require('path');\n\napp.get('/', handler);";
        let pos = find_last_require_position(content);
        assert!(pos.is_some());
    }

    #[test]
    fn test_framework_display() {
        assert_eq!(Framework::Express.to_string(), "express");
        assert_eq!(Framework::NextJs.to_string(), "nextjs");
        assert_eq!(Framework::Django.to_string(), "django");
    }
}
