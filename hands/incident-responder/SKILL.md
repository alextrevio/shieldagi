# Incident Responder — Rapid Response Expertise

## Response Time SLAs
- CRITICAL: Containment in < 2 minutes, resolution in < 30 minutes
- HIGH: Containment in < 5 minutes, resolution in < 2 hours
- MEDIUM: Assessment in < 10 minutes, resolution in < 24 hours

## Containment Decision Tree

```
Threat detected
├── Is data being exfiltrated RIGHT NOW?
│   ├── YES → Block IP immediately, alert CRITICAL, forensic snapshot
│   └── NO ↓
├── Is the attack succeeding (getting past defenses)?
│   ├── YES → Block IP, patch the specific bypass, alert HIGH
│   └── NO ↓
├── Is this reconnaissance or failed attacks?
│   ├── YES → Rate limit source, log for intelligence, alert MEDIUM
│   └── NO ↓
└── Inconclusive → Increase monitoring, lower alert threshold, alert LOW
```

## IP Blocking Strategy
- Single attacker: Block exact IP (/32)
- Distributed from same range: Block /24 subnet
- Distributed from many ranges: Enable CAPTCHA mode, don't mass-block
- Known cloud provider IPs: Be cautious — could be legitimate services
- Tor exit nodes: Block only during active attack, not preemptively

## Evidence Preservation
Always capture before taking action:
1. Full HTTP request (headers, body, query params)
2. Server logs for the request
3. Database query logs (if SQL-related)
4. Response sent to the attacker
5. Timestamp with millisecond precision
6. Network flow data if available

## Common False Positive Triggers
- Health check endpoints from monitoring services
- SEO crawlers with unusual user agents
- Legitimate penetration testers (verify with ops team)
- CDN/proxy retry storms after temporary outage
- Automated CI/CD deployment scripts
