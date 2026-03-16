/// ShieldAGI Phase C: Vulnerability Report Types
///
/// Canonical data structures for vulnerability reports produced by the
/// ShieldAGI scanning pipeline. These types flow between the scanner agents,
/// remediation_engine, pr_generator, and the reporting UI.
///
/// All types are fully serializable and support Default for incremental
/// construction in the scanning pipeline.

use serde::{Deserialize, Serialize};
use std::fmt;

// ═══════════════════════════════════════════════
// TARGET & SUMMARY TYPES
// ═══════════════════════════════════════════════

/// Identifies the target being scanned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    /// Public-facing domain, e.g. "app.example.com"
    pub domain: Option<String>,
    /// Repository path or remote URL, e.g. "/tmp/repos/myapp"
    pub repo: String,
    /// Detected framework: "nextjs" | "express" | "django" | "supabase" | "rust-web" | "unknown"
    pub framework: String,
}

impl Default for TargetInfo {
    fn default() -> Self {
        Self {
            domain: None,
            repo: String::new(),
            framework: "unknown".to_string(),
        }
    }
}

/// Aggregate statistics computed from a completed scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_critical: usize,
    pub total_high: usize,
    pub total_medium: usize,
    pub total_low: usize,
    /// Weighted risk score 0.0–10.0 (CVSS-inspired aggregation).
    pub risk_score: f32,
    /// Ordered list of vulnerability IDs / titles that should be fixed first.
    pub top_priorities: Vec<String>,
}

impl Default for ReportSummary {
    fn default() -> Self {
        Self {
            total_critical: 0,
            total_high: 0,
            total_medium: 0,
            total_low: 0,
            risk_score: 0.0,
            top_priorities: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════
// VULNERABILITY COMPONENTS
// ═══════════════════════════════════════════════

/// A single source file location implicated in a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedFile {
    /// Repository-relative path, e.g. "src/routes/users.js"
    pub path: String,
    /// 1-based line numbers within the file.
    pub lines: Vec<u32>,
}

impl Default for AffectedFile {
    fn default() -> Self {
        Self {
            path: String::new(),
            lines: Vec::new(),
        }
    }
}

/// Remediation playbook attached to a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationGuidance {
    /// Named remediation playbook, e.g. "parameterized-queries"
    pub playbook: String,
    /// Optional Chain Walls layer that mitigates this issue at the middleware level.
    pub chain_wall: Option<String>,
    /// Implementation effort: "TRIVIAL" | "SIMPLE" | "MODERATE" | "COMPLEX"
    pub complexity: String,
    /// Human-readable description of the recommended fix.
    pub fix_description: String,
    /// Other vulnerability IDs that must be fixed before this one (topological ordering).
    pub dependencies: Vec<String>,
}

impl Default for RemediationGuidance {
    fn default() -> Self {
        Self {
            playbook: String::new(),
            chain_wall: None,
            complexity: "MODERATE".to_string(),
            fix_description: String::new(),
            dependencies: Vec::new(),
        }
    }
}

/// A single vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Stable identifier, e.g. "VULN-001"
    pub id: String,
    /// Category slug: "sqli" | "xss" | "csrf" | "auth" | "ssrf" | "traversal"
    ///                 | "idor" | "misconfig" | "dependency" | "secret"
    pub category: String,
    /// "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    pub severity: String,
    /// CVSS v3 base score (0.0–10.0)
    pub cvss_score: f32,
    /// CVSS v3 vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    pub cvss_vector: String,
    /// Short, human-readable title.
    pub title: String,
    /// Full technical description.
    pub description: String,
    /// Source files containing the vulnerable code.
    pub affected_files: Vec<AffectedFile>,
    /// HTTP endpoint where the vulnerability is reachable, if applicable.
    pub endpoint: Option<String>,
    /// HTTP method for the vulnerable endpoint.
    pub method: Option<String>,
    /// Request parameter that carries the malicious payload.
    pub parameter: Option<String>,
    /// Whether the vulnerability was confirmed exploitable during testing.
    pub exploitable: bool,
    /// Minimal working proof-of-concept payload or request.
    pub proof_of_concept: Option<String>,
    /// Remediation guidance including playbook and complexity estimate.
    pub remediation: RemediationGuidance,
}

impl Default for Vulnerability {
    fn default() -> Self {
        Self {
            id: String::new(),
            category: String::new(),
            severity: "MEDIUM".to_string(),
            cvss_score: 0.0,
            cvss_vector: String::new(),
            title: String::new(),
            description: String::new(),
            affected_files: Vec::new(),
            endpoint: None,
            method: None,
            parameter: None,
            exploitable: false,
            proof_of_concept: None,
            remediation: RemediationGuidance::default(),
        }
    }
}

impl fmt::Display for Vulnerability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} — {}", self.severity, self.id, self.title)
    }
}

// ═══════════════════════════════════════════════
// ATTACK CHAIN
// ═══════════════════════════════════════════════

/// Describes how multiple vulnerabilities can be chained together for greater impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    /// Descriptive name for the chain, e.g. "SSRF → IDOR → Data Exfil"
    pub name: String,
    /// Ordered list of vulnerability IDs in the chain.
    pub vulnerability_ids: Vec<String>,
    /// Description of the combined impact if all steps succeed.
    pub combined_impact: String,
    /// The worst severity across the chain, e.g. "CRITICAL"
    pub combined_severity: String,
}

impl Default for AttackChain {
    fn default() -> Self {
        Self {
            name: String::new(),
            vulnerability_ids: Vec::new(),
            combined_impact: String::new(),
            combined_severity: "HIGH".to_string(),
        }
    }
}

// ═══════════════════════════════════════════════
// ROOT REPORT TYPE
// ═══════════════════════════════════════════════

/// Complete vulnerability report produced by a ShieldAGI scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityReport {
    /// Stable UUID for this report, e.g. "rpt-20260316-a1b2c3"
    pub report_id: String,
    /// The target that was scanned.
    pub target: TargetInfo,
    /// ISO-8601 timestamp of when the scan started.
    pub scan_timestamp: String,
    /// Pre-computed aggregate statistics.
    pub summary: ReportSummary,
    /// Individual vulnerability findings.
    pub vulnerabilities: Vec<Vulnerability>,
    /// Cross-vulnerability attack chains identified during analysis.
    pub attack_chains: Vec<AttackChain>,
}

impl Default for VulnerabilityReport {
    fn default() -> Self {
        Self {
            report_id: String::new(),
            target: TargetInfo::default(),
            scan_timestamp: String::new(),
            summary: ReportSummary::default(),
            vulnerabilities: Vec::new(),
            attack_chains: Vec::new(),
        }
    }
}

impl VulnerabilityReport {
    /// Sort vulnerabilities in-place by descending severity (CRITICAL → LOW),
    /// then by descending CVSS score within the same severity tier.
    pub fn sort_by_severity(&mut self) {
        self.vulnerabilities.sort_by(|a, b| {
            let sev_rank = |s: &str| match s {
                "CRITICAL" => 0u8,
                "HIGH" => 1,
                "MEDIUM" => 2,
                "LOW" => 3,
                _ => 4,
            };
            let tier_cmp = sev_rank(&a.severity).cmp(&sev_rank(&b.severity));
            if tier_cmp == std::cmp::Ordering::Equal {
                // Higher CVSS first — reverse float comparison
                b.cvss_score
                    .partial_cmp(&a.cvss_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            } else {
                tier_cmp
            }
        });
    }

    /// Return references to all CRITICAL-severity vulnerabilities.
    pub fn get_critical(&self) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == "CRITICAL")
            .collect()
    }

    /// Return references to all vulnerabilities in a given category.
    pub fn get_by_category<'a>(&'a self, cat: &str) -> Vec<&'a Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.category == cat)
            .collect()
    }

    /// Recompute the summary counts and risk score from `self.vulnerabilities`,
    /// then populate `top_priorities` with the IDs of up to 5 critical/high findings.
    pub fn calculate_risk_score(&mut self) {
        let mut n_critical = 0usize;
        let mut n_high = 0usize;
        let mut n_medium = 0usize;
        let mut n_low = 0usize;
        let mut weighted_sum = 0.0f32;
        let mut total_weight = 0.0f32;

        for v in &self.vulnerabilities {
            let weight: f32 = match v.severity.as_str() {
                "CRITICAL" => {
                    n_critical += 1;
                    4.0
                }
                "HIGH" => {
                    n_high += 1;
                    3.0
                }
                "MEDIUM" => {
                    n_medium += 1;
                    2.0
                }
                "LOW" => {
                    n_low += 1;
                    1.0
                }
                _ => 1.0,
            };

            // Clamp cvss_score to [0, 10] before weighting
            let score = v.cvss_score.max(0.0).min(10.0);
            weighted_sum += score * weight;
            total_weight += weight;
        }

        // Weighted mean, then scale so that an all-critical-10.0 scan → 10.0
        let raw_score = if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        };

        // Apply an exploitability multiplier (confirmed exploits raise the score)
        let exploitable_count = self.vulnerabilities.iter().filter(|v| v.exploitable).count();
        let exploit_factor = if exploitable_count > 0 {
            1.0 + (exploitable_count as f32 * 0.05).min(0.3)
        } else {
            1.0
        };

        let risk_score = (raw_score * exploit_factor).min(10.0);

        // Top priorities: up to 5 findings, CRITICAL first then HIGH, sorted by score
        let mut priority_vulns: Vec<&Vulnerability> = self
            .vulnerabilities
            .iter()
            .filter(|v| v.severity == "CRITICAL" || v.severity == "HIGH")
            .collect();
        priority_vulns.sort_by(|a, b| {
            let tier_a = if a.severity == "CRITICAL" { 0u8 } else { 1 };
            let tier_b = if b.severity == "CRITICAL" { 0u8 } else { 1 };
            tier_a
                .cmp(&tier_b)
                .then_with(|| b.cvss_score.partial_cmp(&a.cvss_score).unwrap_or(std::cmp::Ordering::Equal))
        });

        let top_priorities = priority_vulns
            .iter()
            .take(5)
            .map(|v| v.id.clone())
            .collect();

        self.summary = ReportSummary {
            total_critical: n_critical,
            total_high: n_high,
            total_medium: n_medium,
            total_low: n_low,
            risk_score,
            top_priorities,
        };
    }
}

// ═══════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vuln(id: &str, severity: &str, cvss: f32, category: &str, exploitable: bool) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            category: category.to_string(),
            severity: severity.to_string(),
            cvss_score: cvss,
            cvss_vector: format!("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            title: format!("{} in {}", severity, category),
            description: format!("Test vulnerability {}", id),
            affected_files: vec![AffectedFile {
                path: "src/app.js".to_string(),
                lines: vec![42, 43],
            }],
            endpoint: Some("/api/test".to_string()),
            method: Some("GET".to_string()),
            parameter: Some("q".to_string()),
            exploitable,
            proof_of_concept: None,
            remediation: RemediationGuidance {
                playbook: "parameterized-queries".to_string(),
                chain_wall: None,
                complexity: "SIMPLE".to_string(),
                fix_description: "Use parameterized queries".to_string(),
                dependencies: vec![],
            },
        }
    }

    #[test]
    fn test_defaults_are_sane() {
        let report = VulnerabilityReport::default();
        assert!(report.report_id.is_empty());
        assert_eq!(report.summary.risk_score, 0.0);
        assert_eq!(report.summary.total_critical, 0);
        assert!(report.vulnerabilities.is_empty());
        assert!(report.attack_chains.is_empty());
    }

    #[test]
    fn test_target_info_default() {
        let t = TargetInfo::default();
        assert_eq!(t.framework, "unknown");
        assert!(t.domain.is_none());
    }

    #[test]
    fn test_remediation_guidance_default() {
        let r = RemediationGuidance::default();
        assert_eq!(r.complexity, "MODERATE");
        assert!(r.chain_wall.is_none());
    }

    #[test]
    fn test_sort_by_severity_ordering() {
        let mut report = VulnerabilityReport::default();
        report.vulnerabilities = vec![
            make_vuln("V3", "LOW", 2.5, "misconfig", false),
            make_vuln("V1", "CRITICAL", 9.8, "sqli", true),
            make_vuln("V4", "MEDIUM", 5.5, "xss", false),
            make_vuln("V2", "HIGH", 7.2, "ssrf", false),
        ];

        report.sort_by_severity();

        assert_eq!(report.vulnerabilities[0].severity, "CRITICAL");
        assert_eq!(report.vulnerabilities[1].severity, "HIGH");
        assert_eq!(report.vulnerabilities[2].severity, "MEDIUM");
        assert_eq!(report.vulnerabilities[3].severity, "LOW");
    }

    #[test]
    fn test_sort_by_severity_ties_broken_by_cvss() {
        let mut report = VulnerabilityReport::default();
        report.vulnerabilities = vec![
            make_vuln("VA", "HIGH", 7.0, "xss", false),
            make_vuln("VB", "HIGH", 8.9, "csrf", false),
            make_vuln("VC", "HIGH", 7.5, "auth", false),
        ];

        report.sort_by_severity();

        assert_eq!(report.vulnerabilities[0].id, "VB"); // highest CVSS first
        assert_eq!(report.vulnerabilities[1].id, "VC");
        assert_eq!(report.vulnerabilities[2].id, "VA");
    }

    #[test]
    fn test_get_critical() {
        let mut report = VulnerabilityReport::default();
        report.vulnerabilities = vec![
            make_vuln("V1", "CRITICAL", 9.8, "sqli", true),
            make_vuln("V2", "HIGH", 7.2, "xss", false),
            make_vuln("V3", "CRITICAL", 9.1, "idor", true),
        ];

        let crits = report.get_critical();
        assert_eq!(crits.len(), 2);
        assert!(crits.iter().all(|v| v.severity == "CRITICAL"));
    }

    #[test]
    fn test_get_by_category() {
        let mut report = VulnerabilityReport::default();
        report.vulnerabilities = vec![
            make_vuln("V1", "HIGH", 8.0, "sqli", false),
            make_vuln("V2", "MEDIUM", 5.0, "xss", false),
            make_vuln("V3", "HIGH", 7.0, "sqli", true),
        ];

        let sqli = report.get_by_category("sqli");
        assert_eq!(sqli.len(), 2);
        assert!(sqli.iter().all(|v| v.category == "sqli"));

        let xss = report.get_by_category("xss");
        assert_eq!(xss.len(), 1);

        let empty = report.get_by_category("csrf");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_calculate_risk_score_empty() {
        let mut report = VulnerabilityReport::default();
        report.calculate_risk_score();
        assert_eq!(report.summary.risk_score, 0.0);
        assert_eq!(report.summary.total_critical, 0);
        assert!(report.summary.top_priorities.is_empty());
    }

    #[test]
    fn test_calculate_risk_score_all_critical() {
        let mut report = VulnerabilityReport::default();
        report.vulnerabilities = vec![
            make_vuln("V1", "CRITICAL", 10.0, "sqli", true),
            make_vuln("V2", "CRITICAL", 10.0, "rce", true),
        ];
        report.calculate_risk_score();

        assert_eq!(report.summary.total_critical, 2);
        assert_eq!(report.summary.total_high, 0);
        // score should be > 10.0 before clamping but clamped to 10.0
        assert!(report.summary.risk_score <= 10.0);
        assert!(report.summary.risk_score > 9.0);
        assert_eq!(report.summary.top_priorities.len(), 2);
    }

    #[test]
    fn test_calculate_risk_score_mixed() {
        let mut report = VulnerabilityReport::default();
        report.vulnerabilities = vec![
            make_vuln("V1", "CRITICAL", 9.8, "sqli", true),
            make_vuln("V2", "HIGH", 7.5, "xss", false),
            make_vuln("V3", "MEDIUM", 5.5, "csrf", false),
            make_vuln("V4", "LOW", 2.0, "misconfig", false),
        ];
        report.calculate_risk_score();

        assert_eq!(report.summary.total_critical, 1);
        assert_eq!(report.summary.total_high, 1);
        assert_eq!(report.summary.total_medium, 1);
        assert_eq!(report.summary.total_low, 1);
        assert!(report.summary.risk_score > 0.0);
        assert!(report.summary.risk_score <= 10.0);
        // Top priorities: V1 (CRITICAL) and V2 (HIGH)
        assert_eq!(report.summary.top_priorities.len(), 2);
        assert_eq!(report.summary.top_priorities[0], "V1");
    }

    #[test]
    fn test_calculate_risk_score_top_priorities_capped_at_five() {
        let mut report = VulnerabilityReport::default();
        for i in 0..8 {
            report.vulnerabilities.push(make_vuln(
                &format!("V{}", i),
                "CRITICAL",
                9.0,
                "sqli",
                false,
            ));
        }
        report.calculate_risk_score();
        assert!(report.summary.top_priorities.len() <= 5);
    }

    #[test]
    fn test_vulnerability_display() {
        let v = make_vuln("VULN-042", "HIGH", 8.1, "xss", false);
        let display = format!("{}", v);
        assert!(display.contains("HIGH"));
        assert!(display.contains("VULN-042"));
        assert!(display.contains("HIGH in xss"));
    }

    #[test]
    fn test_attack_chain_default() {
        let chain = AttackChain::default();
        assert_eq!(chain.combined_severity, "HIGH");
        assert!(chain.vulnerability_ids.is_empty());
    }

    #[test]
    fn test_round_trip_serialization() {
        let mut report = VulnerabilityReport {
            report_id: "rpt-20260316-test".to_string(),
            target: TargetInfo {
                domain: Some("app.example.com".to_string()),
                repo: "/tmp/testrepo".to_string(),
                framework: "express".to_string(),
            },
            scan_timestamp: "2026-03-16T12:00:00Z".to_string(),
            summary: ReportSummary::default(),
            vulnerabilities: vec![make_vuln("V1", "CRITICAL", 9.8, "sqli", true)],
            attack_chains: vec![AttackChain {
                name: "SQLI → Admin Takeover".to_string(),
                vulnerability_ids: vec!["V1".to_string()],
                combined_impact: "Full admin access via SQL injection".to_string(),
                combined_severity: "CRITICAL".to_string(),
            }],
        };
        report.calculate_risk_score();

        let json = serde_json::to_string(&report).expect("serialization failed");
        let deserialized: VulnerabilityReport =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(deserialized.report_id, "rpt-20260316-test");
        assert_eq!(deserialized.vulnerabilities.len(), 1);
        assert_eq!(deserialized.attack_chains.len(), 1);
        assert_eq!(deserialized.summary.total_critical, 1);
        assert!(deserialized.summary.risk_score > 0.0);
    }
}
