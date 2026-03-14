# Sentinel — Security Monitoring Expertise

## Attack Signature Database

### SQL Injection Signatures
- `' OR 1=1 --` and variants
- `UNION SELECT NULL,NULL,...`
- `; DROP TABLE`
- `1' AND (SELECT * FROM ...)`
- Time-based: `'; WAITFOR DELAY '0:0:5'--`
- Error-based: `' AND 1=CONVERT(int, @@version)--`
- Encoded variants: `%27%20OR%201%3D1%20--`

### XSS Signatures
- `<script>alert(`, `<img onerror=`, `<svg onload=`
- Event handlers: `onfocus=`, `onmouseover=`, `onload=`
- Encoded: `%3Cscript%3E`, `&#60;script&#62;`
- Polyglot: `jaVasCript:/*-/*\`/*'/*"/**/(/* */oNcliCk=alert())`

### Path Traversal Signatures
- `../`, `..\\`, `%2e%2e%2f`, `%252e%252e%252f`
- Null byte: `%00`, `\0`
- Common targets: `/etc/passwd`, `/etc/shadow`, `web.config`, `.env`

### Scanner User-Agents
- `sqlmap`, `nikto`, `nuclei`, `gobuster`, `dirbuster`
- `Nmap Scripting Engine`, `WPScan`, `Acunetix`
- Empty or suspiciously generic user agents

## Baseline Metrics (defaults, adjust per target)
- Normal request rate: 10-100 req/min per endpoint
- Normal error rate: <2% of requests
- Normal response time: <500ms p95
- Normal auth failure rate: <5 failures/hour per IP
- Normal 404 rate: <1% of requests

## Escalation Thresholds
- Rate anomaly: >3σ from rolling 24h mean
- Error spike: >5x baseline error rate in 5 minutes
- Auth attack: >10 failures from same IP in 5 minutes
- Scan detection: >20 unique 404 paths from same IP in 5 minutes
- Response degradation: >3x baseline p95 latency
