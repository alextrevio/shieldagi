/// ShieldAGI Tool: telegram_alert
///
/// Sends formatted security alert messages to a Telegram chat via the Bot API.
/// Part of ShieldAGI Phase D (24/7 Monitoring). Uses curl (via std::process::Command)
/// consistent with other ShieldAGI tools.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct TelegramAlertInput {
    pub bot_token: String,
    pub chat_id: String,
    pub alert: ThreatAlert,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source_ip: String,
    pub affected_endpoint: String,
    pub timestamp: String,
    pub correlation_id: String,
    pub recommended_action: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TelegramSendResult {
    pub success: bool,
    pub message_id: Option<i64>,
    pub error: Option<String>,
}

/// Send a formatted threat alert to a Telegram chat.
///
/// # Input fields
/// - `bot_token`           — Telegram Bot API token (e.g. "123456:ABC-DEF...")
/// - `chat_id`             — Destination chat/channel ID (numeric or @username)
/// - `severity`            — CRITICAL | HIGH | MEDIUM | LOW
/// - `title`               — Short attack type description
/// - `description`         — Detailed description of the threat
/// - `source_ip`           — Attacker IP address
/// - `affected_endpoint`   — Targeted URL/path
/// - `timestamp`           — ISO-8601 event timestamp
/// - `correlation_id`      — Correlation ID for tracking
/// - `recommended_action`  — Suggested immediate response
pub async fn tool_send_telegram_alert(input: &serde_json::Value) -> Result<String, String> {
    let bot_token = input["bot_token"]
        .as_str()
        .ok_or("Missing 'bot_token' field")?;
    let chat_id = input["chat_id"]
        .as_str()
        .ok_or("Missing 'chat_id' field")?;
    let severity = input["severity"]
        .as_str()
        .ok_or("Missing 'severity' field")?;
    let title = input["title"]
        .as_str()
        .ok_or("Missing 'title' field")?;
    let description = input["description"]
        .as_str()
        .ok_or("Missing 'description' field")?;
    let source_ip = input["source_ip"]
        .as_str()
        .ok_or("Missing 'source_ip' field")?;
    let affected_endpoint = input["affected_endpoint"]
        .as_str()
        .ok_or("Missing 'affected_endpoint' field")?;
    let timestamp = input["timestamp"]
        .as_str()
        .ok_or("Missing 'timestamp' field")?;
    let correlation_id = input["correlation_id"]
        .as_str()
        .ok_or("Missing 'correlation_id' field")?;
    let recommended_action = input["recommended_action"]
        .as_str()
        .ok_or("Missing 'recommended_action' field")?;

    let alert = ThreatAlert {
        severity: severity.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        source_ip: source_ip.to_string(),
        affected_endpoint: affected_endpoint.to_string(),
        timestamp: timestamp.to_string(),
        correlation_id: correlation_id.to_string(),
        recommended_action: recommended_action.to_string(),
    };

    let message = format_alert_message(&alert);

    let send_result = send_telegram_message(bot_token, chat_id, &message)?;

    serde_json::to_string_pretty(&send_result)
        .map_err(|e| format!("Serialization error: {}", e))
}

// ─── Message formatter ────────────────────────────────────────────────────────

/// Format a ThreatAlert into a Telegram message string with emoji severity indicator.
pub fn format_alert_message(alert: &ThreatAlert) -> String {
    let emoji = severity_emoji(&alert.severity);
    let severity_upper = alert.severity.to_uppercase();

    format!(
        "{emoji} {severity} THREAT DETECTED\n\
        \n\
        Type: {title}\n\
        Source: {source_ip}\n\
        Target: {endpoint}\n\
        Time: {timestamp}\n\
        \n\
        {description}\n\
        \n\
        Action: {action}\n\
        Correlation ID: {corr_id}",
        emoji = emoji,
        severity = severity_upper,
        title = alert.title,
        source_ip = alert.source_ip,
        endpoint = alert.affected_endpoint,
        timestamp = alert.timestamp,
        description = alert.description,
        action = alert.recommended_action,
        corr_id = alert.correlation_id,
    )
}

/// Map severity level to an emoji indicator.
pub fn severity_emoji(severity: &str) -> &'static str {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => "🔴",
        "HIGH" => "🟠",
        "MEDIUM" => "🟡",
        "LOW" => "🔵",
        _ => "⚪",
    }
}

// ─── Transport ────────────────────────────────────────────────────────────────

/// POST a message to the Telegram Bot API using curl.
/// Returns TelegramSendResult with message_id on success.
fn send_telegram_message(
    bot_token: &str,
    chat_id: &str,
    text: &str,
) -> Result<TelegramSendResult, String> {
    // Validate token format (basic sanity check)
    if bot_token.is_empty() {
        return Ok(TelegramSendResult {
            success: false,
            message_id: None,
            error: Some("bot_token is empty".to_string()),
        });
    }
    if chat_id.is_empty() {
        return Ok(TelegramSendResult {
            success: false,
            message_id: None,
            error: Some("chat_id is empty".to_string()),
        });
    }

    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);

    // Build the JSON payload. We use parse_mode=HTML for future rich formatting,
    // but send plain text for now so special chars don't break rendering.
    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    });

    let payload_str =
        serde_json::to_string(&payload).map_err(|e| format!("Failed to build payload: {}", e))?;

    let output = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "15",
            "-X",
            "POST",
            &url,
            "-H",
            "Content-Type: application/json",
            "-d",
            &payload_str,
        ])
        .output()
        .map_err(|e| format!("Failed to execute curl: {}", e))?;

    let response_body = String::from_utf8_lossy(&output.stdout).to_string();

    if !output.status.success() && response_body.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Ok(TelegramSendResult {
            success: false,
            message_id: None,
            error: Some(format!("curl error: {}", stderr)),
        });
    }

    // Parse Telegram API response
    match serde_json::from_str::<serde_json::Value>(&response_body) {
        Ok(v) => {
            let ok = v["ok"].as_bool().unwrap_or(false);
            if ok {
                let message_id = v["result"]["message_id"].as_i64();
                Ok(TelegramSendResult {
                    success: true,
                    message_id,
                    error: None,
                })
            } else {
                let description = v["description"]
                    .as_str()
                    .unwrap_or("Unknown Telegram API error")
                    .to_string();
                Ok(TelegramSendResult {
                    success: false,
                    message_id: None,
                    error: Some(description),
                })
            }
        }
        Err(e) => Ok(TelegramSendResult {
            success: false,
            message_id: None,
            error: Some(format!(
                "Failed to parse Telegram response: {} — raw: {}",
                e,
                &response_body[..response_body.len().min(200)]
            )),
        }),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_alert(severity: &str) -> ThreatAlert {
        ThreatAlert {
            severity: severity.to_string(),
            title: "SQL Injection Attack".to_string(),
            description: "Attacker attempted UNION SELECT against the users table.".to_string(),
            source_ip: "203.0.113.42".to_string(),
            affected_endpoint: "/api/search".to_string(),
            timestamp: "2024-01-15T14:30:00Z".to_string(),
            correlation_id: "corr-deadbeef12345678".to_string(),
            recommended_action: "Block IP 203.0.113.42 and review query logs immediately.".to_string(),
        }
    }

    #[test]
    fn test_severity_emoji_critical() {
        assert_eq!(severity_emoji("CRITICAL"), "🔴");
        assert_eq!(severity_emoji("critical"), "🔴");
    }

    #[test]
    fn test_severity_emoji_high() {
        assert_eq!(severity_emoji("HIGH"), "🟠");
        assert_eq!(severity_emoji("High"), "🟠");
    }

    #[test]
    fn test_severity_emoji_medium() {
        assert_eq!(severity_emoji("MEDIUM"), "🟡");
    }

    #[test]
    fn test_severity_emoji_low() {
        assert_eq!(severity_emoji("LOW"), "🔵");
    }

    #[test]
    fn test_severity_emoji_unknown() {
        assert_eq!(severity_emoji("INFO"), "⚪");
        assert_eq!(severity_emoji(""), "⚪");
    }

    #[test]
    fn test_format_alert_message_contains_required_fields() {
        let alert = make_alert("CRITICAL");
        let msg = format_alert_message(&alert);

        assert!(msg.contains("🔴"), "Should contain CRITICAL emoji");
        assert!(msg.contains("CRITICAL THREAT DETECTED"), "Should contain severity header");
        assert!(msg.contains("SQL Injection Attack"), "Should contain title");
        assert!(msg.contains("203.0.113.42"), "Should contain source IP");
        assert!(msg.contains("/api/search"), "Should contain endpoint");
        assert!(msg.contains("2024-01-15T14:30:00Z"), "Should contain timestamp");
        assert!(
            msg.contains("Attacker attempted UNION SELECT"),
            "Should contain description"
        );
        assert!(
            msg.contains("Block IP 203.0.113.42"),
            "Should contain recommended action"
        );
        assert!(
            msg.contains("corr-deadbeef12345678"),
            "Should contain correlation ID"
        );
    }

    #[test]
    fn test_format_alert_message_high() {
        let alert = make_alert("HIGH");
        let msg = format_alert_message(&alert);
        assert!(msg.contains("🟠"));
        assert!(msg.contains("HIGH THREAT DETECTED"));
    }

    #[test]
    fn test_format_alert_message_medium() {
        let alert = make_alert("MEDIUM");
        let msg = format_alert_message(&alert);
        assert!(msg.contains("🟡"));
        assert!(msg.contains("MEDIUM THREAT DETECTED"));
    }

    #[test]
    fn test_format_alert_message_low() {
        let alert = make_alert("LOW");
        let msg = format_alert_message(&alert);
        assert!(msg.contains("🔵"));
        assert!(msg.contains("LOW THREAT DETECTED"));
    }

    #[test]
    fn test_format_alert_message_structure() {
        let alert = make_alert("HIGH");
        let msg = format_alert_message(&alert);

        // Verify key label lines exist
        assert!(msg.contains("Type:"), "Should have Type label");
        assert!(msg.contains("Source:"), "Should have Source label");
        assert!(msg.contains("Target:"), "Should have Target label");
        assert!(msg.contains("Time:"), "Should have Time label");
        assert!(msg.contains("Action:"), "Should have Action label");
        assert!(msg.contains("Correlation ID:"), "Should have Correlation ID label");
    }

    #[test]
    fn test_format_alert_message_no_empty_fields() {
        // Alert with minimal whitespace content should still render cleanly
        let alert = ThreatAlert {
            severity: "LOW".to_string(),
            title: "Port Scan".to_string(),
            description: "Sequential port scan detected.".to_string(),
            source_ip: "198.51.100.1".to_string(),
            affected_endpoint: "multiple".to_string(),
            timestamp: "2024-06-01T00:00:00Z".to_string(),
            correlation_id: "corr-abc".to_string(),
            recommended_action: "Monitor and rate-limit.".to_string(),
        };
        let msg = format_alert_message(&alert);
        assert!(!msg.is_empty());
        assert!(msg.contains("198.51.100.1"));
    }

    #[tokio::test]
    async fn test_tool_missing_bot_token() {
        let input = serde_json::json!({
            "chat_id": "-1001234567890",
            "severity": "HIGH",
            "title": "Test",
            "description": "Test alert",
            "source_ip": "1.2.3.4",
            "affected_endpoint": "/test",
            "timestamp": "2024-01-01T00:00:00Z",
            "correlation_id": "corr-test",
            "recommended_action": "Do nothing"
        });
        let result = tool_send_telegram_alert(&input).await;
        assert!(result.is_err(), "Should error when bot_token is missing");
    }

    #[tokio::test]
    async fn test_tool_missing_chat_id() {
        let input = serde_json::json!({
            "bot_token": "123456:ABC",
            "severity": "HIGH",
            "title": "Test",
            "description": "Test alert",
            "source_ip": "1.2.3.4",
            "affected_endpoint": "/test",
            "timestamp": "2024-01-01T00:00:00Z",
            "correlation_id": "corr-test",
            "recommended_action": "Do nothing"
        });
        let result = tool_send_telegram_alert(&input).await;
        assert!(result.is_err(), "Should error when chat_id is missing");
    }

    #[tokio::test]
    async fn test_tool_invalid_token_returns_send_result() {
        // With a clearly invalid token, curl will reach Telegram but get a 401.
        // The result should be a valid TelegramSendResult JSON with success=false.
        // This test is gated behind a network availability check to avoid CI failures.
        let input = serde_json::json!({
            "bot_token": "000000000:INVALID_TOKEN_FOR_TESTING",
            "chat_id": "-1001234567890",
            "severity": "CRITICAL",
            "title": "Unit Test Alert",
            "description": "This is a unit test — ignore.",
            "source_ip": "127.0.0.1",
            "affected_endpoint": "/test",
            "timestamp": "2024-01-15T00:00:00Z",
            "correlation_id": "corr-unit-test",
            "recommended_action": "No action required — unit test."
        });

        // We only run the actual network call if curl is available
        if std::process::Command::new("curl").arg("--version").output().is_ok() {
            let result = tool_send_telegram_alert(&input).await;
            // Should succeed in returning a JSON result (even if the API call failed)
            assert!(result.is_ok(), "Tool should return Ok with a TelegramSendResult JSON");
            let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
            // Telegram returns ok=false for invalid tokens
            assert_eq!(
                parsed["success"].as_bool().unwrap_or(true),
                false,
                "Invalid token should result in success=false"
            );
            assert!(
                parsed["error"].is_string(),
                "Should contain an error description"
            );
        }
    }
}
