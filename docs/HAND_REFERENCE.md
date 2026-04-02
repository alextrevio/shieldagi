# ShieldAGI 2.0 — Hand Reference

## sentinel

**Schedule**: Every 5 minutes (`*/5 * * * *`)

**Purpose**: 24/7 autonomous traffic and log monitoring with AI-powered anomaly detection. Detects attack attempts in real-time and triggers incident response when threats are found.

**Tools**: `log_analyzer`, `traffic_monitor`, `anomaly_detect`, `threat_correlate`, `alert_send`, `knowledge_store`, `knowledge_query`, `shell`, `file_read`, `run_sentinel_cycle`, `send_telegram_alert`, `trigger_focused_scan`

**Metrics**:
| Metric | Type | Description |
|--------|------|-------------|
| `threats_detected` | counter | Total threats detected |
| `false_positives` | counter | Alerts dismissed as FP |
| `current_threat_level` | gauge | 0=clear, 1=low, 2=medium, 3=high, 4=critical |
| `response_time_ms` | gauge | Analysis cycle duration |
| `monitored_requests` | counter | Requests analyzed per cycle |
| `blocked_ips` | gauge | Currently blocked IPs |

**Each cycle executes**:
1. Log ingestion (app, web server, database, auth logs)
2. Pattern analysis for SQLi, XSS, brute force, scanning, SSRF, DDoS signatures
3. Anomaly detection against rolling 24-hour baselines (rate anomaly at >3 sigma)
4. Threat classification (CRITICAL/HIGH/MEDIUM/LOW)
5. Response: CRITICAL/HIGH triggers incident-responder; MEDIUM alerts via Telegram; LOW logged
6. Dashboard metrics push

**Configuration**:
```toml
[sentinel]
enabled = true
cron = "*/5 * * * *"

[sentinel.channels]
telegram = true
slack = true
```

**Dashboard Panels**: threat_timeline, attack_type_distribution, top_blocked_ips, response_time_histogram, active_alerts

---

## dep-guardian

**Schedule**: Every 6 hours (`0 */6 * * *`)

**Purpose**: Autonomous dependency vulnerability monitoring. Scans installed packages against CVE databases and auto-creates PRs for patched versions.

**Tools**: `dep_audit`, `cve_lookup`, `lockfile_update`, `git_clone`, `git_branch`, `git_commit`, `git_pr`, `run_tests`, `knowledge_store`, `knowledge_query`, `alert_send`, `shell`, `file_read`, `file_write`, `check_dependencies`, `send_telegram_alert`

**Metrics**:
| Metric | Type | Description |
|--------|------|-------------|
| `deps_monitored` | gauge | Total dependencies tracked |
| `vulns_found` | counter | Vulnerabilities discovered |
| `auto_patched` | counter | Dependencies auto-updated |
| `pending_review` | gauge | Updates needing human review |
| `unmaintained_deps` | gauge | Deps with no updates in 12+ months |

**Each cycle executes**:
1. Dependency inventory across all package managers (npm, pip, cargo, go)
2. Vulnerability scan against NVD, GitHub Advisories, npm audit, PyPI Advisory, OSV
3. Risk assessment: CVSS score, reachability, patch availability, breaking changes
4. Auto-remediation: create branch, update package, regenerate lockfile, run tests, open PR
5. Report: update knowledge_store and push dashboard summary

**Semver rules**: Patch updates auto-applied. Minor updates applied with tests. Major updates flagged for human review.

**Configuration**:
```toml
[dep_guardian]
enabled = true
cron = "0 */6 * * *"
auto_pr = true
```

---

## incident-responder

**Schedule**: Event-driven (`event:sentinel_alert`)

**Purpose**: Rapid-reaction incident response. When Sentinel detects a CRITICAL or HIGH threat, Incident Responder verifies, contains, analyzes, and can trigger emergency re-scan/re-patch cycles.

**Tools**: `threat_analyze`, `auto_patch`, `ip_block`, `waf_rule_add`, `rollback`, `alert_escalate`, `forensic_log`, `knowledge_store`, `knowledge_query`, `shell`, `file_read`, `file_write`, `git_branch`, `git_commit`, `git_pr`, `alert_send`, `respond_to_incident`, `send_telegram_alert`, `trigger_focused_scan`, `verify_fix`

**Metrics**:
| Metric | Type | Description |
|--------|------|-------------|
| `incidents_total` | counter | Total incidents handled |
| `incidents_by_severity` | counter | Breakdown by severity level |
| `mean_time_to_contain` | gauge | Avg containment time |
| `mean_time_to_resolve` | gauge | Avg resolution time |
| `auto_patches_applied` | counter | Emergency patches deployed |
| `false_positive_rate` | gauge | FP percentage |

**Response SLAs**:
- CRITICAL: Containment < 2 minutes, resolution < 30 minutes
- HIGH: Containment < 5 minutes, resolution < 2 hours
- MEDIUM: Assessment < 10 minutes, resolution < 24 hours

**Response protocol**:
1. Threat verification (< 30 seconds): confirm real attack vs false positive
2. Immediate containment (< 2 minutes): IP blocking, rate limiting, WAF rules per attack type
3. Forensic analysis (< 10 minutes): attack timeline, impact assessment
4. Auto-patch: if new vulnerability found, trigger targeted scan + remediator cycle
5. Incident report: structured JSON sent via Telegram, Slack, dashboard, knowledge_store
6. Post-incident: update threat intelligence, baselines, schedule re-scan if needed

**Escalation**:
```toml
[escalation]
critical_timeout_seconds = 120
high_timeout_seconds = 300
notify_on_escalation = ["telegram", "slack"]
```

**Alert channels**: Telegram, Slack, Discord
