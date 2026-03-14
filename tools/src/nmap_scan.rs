/// ShieldAGI Tool: nmap_scan
///
/// Wraps the nmap binary to perform network reconnaissance.
/// Parses nmap XML output into structured JSON for agent consumption.
///
/// Integration point: Register in openfang-runtime/src/tool_runner.rs as:
/// ```rust
/// ToolDefinition {
///     name: "nmap_scan".to_string(),
///     description: "Scan target for open ports, services, and OS detection".to_string(),
///     input_schema: serde_json::json!({
///         "type": "object",
///         "properties": {
///             "target": { "type": "string", "description": "IP address or hostname to scan" },
///             "ports": { "type": "string", "description": "Port range (e.g., '1-1000', '80,443,8080', '-' for all)" },
///             "scan_type": { "type": "string", "enum": ["quick", "service", "full", "vuln"], "description": "Scan intensity level" },
///             "timeout": { "type": "integer", "description": "Max scan duration in seconds (default: 300)" }
///         },
///         "required": ["target"]
///     }),
/// }
/// ```

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct NmapResult {
    pub target: String,
    pub scan_type: String,
    pub ports: Vec<PortInfo>,
    pub os_detection: Option<String>,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub version: Option<String>,
    pub extra_info: Option<String>,
}

pub async fn tool_nmap_scan(input: &serde_json::Value) -> Result<String, String> {
    let target = input["target"]
        .as_str()
        .ok_or("Missing 'target' field")?;

    // Validate target — prevent SSRF through tool abuse
    validate_target(target)?;

    let ports = input["ports"].as_str().unwrap_or("1-10000");
    let scan_type = input["scan_type"].as_str().unwrap_or("service");
    let timeout = input["timeout"].as_u64().unwrap_or(300);

    let mut args = vec![
        "-oX", "-",           // XML output to stdout
        "--noninteractive",   // No runtime interaction
        "-T4",                // Aggressive timing
    ];

    match scan_type {
        "quick" => {
            args.extend(&["-F", target]); // Fast scan (top 100 ports)
        }
        "service" => {
            args.extend(&["-sV", "-p", ports, target]); // Service version detection
        }
        "full" => {
            args.extend(&["-sV", "-sC", "-O", "-p", ports, target]); // Full scan with scripts + OS
        }
        "vuln" => {
            args.extend(&["--script", "vuln", "-p", ports, target]); // Vulnerability scripts
        }
        _ => {
            args.extend(&["-sV", "-p", ports, target]);
        }
    }

    let start = std::time::Instant::now();

    let output = Command::new("nmap")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to execute nmap: {}. Is nmap installed in the sandbox?", e))?;

    let duration = start.elapsed().as_millis() as u64;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(serde_json::to_string_pretty(&NmapResult {
            target: target.to_string(),
            scan_type: scan_type.to_string(),
            ports: vec![],
            os_detection: None,
            scan_duration_ms: duration,
            error: Some(format!("nmap exited with error: {}", stderr)),
        }).unwrap());
    }

    let xml_output = String::from_utf8_lossy(&output.stdout);
    let result = parse_nmap_xml(&xml_output, target, scan_type, duration);

    Ok(serde_json::to_string_pretty(&result).unwrap())
}

fn parse_nmap_xml(xml: &str, target: &str, scan_type: &str, duration: u64) -> NmapResult {
    let mut ports = Vec::new();
    let mut os_detection = None;

    // Simple XML parsing — in production, use a proper XML parser crate
    // This extracts port/service/version from nmap XML output
    for line in xml.lines() {
        let line = line.trim();

        // Parse port entries: <port protocol="tcp" portid="80">
        if line.starts_with("<port ") {
            if let Some(port_info) = parse_port_line(line, xml) {
                ports.push(port_info);
            }
        }

        // Parse OS detection: <osmatch name="Linux 5.x" accuracy="96">
        if line.starts_with("<osmatch ") {
            if let Some(name) = extract_attr(line, "name") {
                os_detection = Some(name);
            }
        }
    }

    NmapResult {
        target: target.to_string(),
        scan_type: scan_type.to_string(),
        ports,
        os_detection,
        scan_duration_ms: duration,
        error: None,
    }
}

fn parse_port_line(line: &str, full_xml: &str) -> Option<PortInfo> {
    let port: u16 = extract_attr(line, "portid")?.parse().ok()?;
    let protocol = extract_attr(line, "protocol").unwrap_or_else(|| "tcp".to_string());

    // Look for state and service in nearby lines
    let state = "open".to_string(); // Default; refine with full XML context
    let service = extract_service_from_context(full_xml, port).unwrap_or_else(|| "unknown".to_string());
    let version = extract_version_from_context(full_xml, port);

    Some(PortInfo {
        port,
        protocol,
        state,
        service,
        version,
        extra_info: None,
    })
}

fn extract_attr(line: &str, attr: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr);
    let start = line.find(&pattern)? + pattern.len();
    let end = line[start..].find('"')? + start;
    Some(line[start..end].to_string())
}

fn extract_service_from_context(xml: &str, port: u16) -> Option<String> {
    let port_str = format!("portid=\"{}\"", port);
    let idx = xml.find(&port_str)?;
    let context = &xml[idx..std::cmp::min(idx + 500, xml.len())];
    if let Some(service) = extract_attr(context, "name") {
        return Some(service);
    }
    None
}

fn extract_version_from_context(xml: &str, port: u16) -> Option<String> {
    let port_str = format!("portid=\"{}\"", port);
    let idx = xml.find(&port_str)?;
    let context = &xml[idx..std::cmp::min(idx + 500, xml.len())];
    let product = extract_attr(context, "product").unwrap_or_default();
    let version = extract_attr(context, "version").unwrap_or_default();
    if product.is_empty() && version.is_empty() {
        return None;
    }
    Some(format!("{} {}", product, version).trim().to_string())
}

fn validate_target(target: &str) -> Result<(), String> {
    // Prevent scanning internal infrastructure
    let blocked_patterns = [
        "127.", "0.0.0.0", "localhost",
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.", "169.254.",
        "::1", "fe80:", "fc00:", "fd00:",
    ];

    let target_lower = target.to_lowercase();
    for pattern in &blocked_patterns {
        if target_lower.starts_with(pattern) {
            return Err(format!(
                "Target '{}' is a private/internal address. Scanning internal infrastructure is blocked for safety.",
                target
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_target_blocks_private() {
        assert!(validate_target("192.168.1.1").is_err());
        assert!(validate_target("10.0.0.1").is_err());
        assert!(validate_target("127.0.0.1").is_err());
        assert!(validate_target("localhost").is_err());
    }

    #[test]
    fn test_validate_target_allows_public() {
        assert!(validate_target("93.184.216.34").is_ok());
        assert!(validate_target("example.com").is_ok());
    }

    #[test]
    fn test_extract_attr() {
        let line = r#"<port protocol="tcp" portid="443">"#;
        assert_eq!(extract_attr(line, "protocol"), Some("tcp".to_string()));
        assert_eq!(extract_attr(line, "portid"), Some("443".to_string()));
    }
}
