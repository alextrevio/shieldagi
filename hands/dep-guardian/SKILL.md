# Dependency Guardian — Supply Chain Security Expertise

## CVE Severity Mapping
- CRITICAL (9.0-10.0): Remote code execution, authentication bypass in core deps
- HIGH (7.0-8.9): XSS in rendering libraries, SQLi in ORM, prototype pollution
- MEDIUM (4.0-6.9): ReDoS, information disclosure, CSRF in utilities
- LOW (0.1-3.9): Minor info leaks, theoretical attacks requiring unusual conditions

## Common High-Risk Dependencies (npm)
- `express` — route injection, prototype pollution history
- `jsonwebtoken` — algorithm confusion, signature bypass
- `axios` — SSRF, redirect following
- `lodash` — prototype pollution (CVE-2019-10744 and variants)
- `moment` — ReDoS, deprecated (suggest dayjs/date-fns)
- `serialize-javascript` — RCE via crafted input
- `node-fetch` — SSRF, header injection
- `tar` — path traversal (CVE-2021-32803)

## Common High-Risk Dependencies (Python)
- `django` — frequent security patches, always stay current
- `requests` — SSRF, certificate validation
- `pyyaml` — arbitrary code execution via yaml.load()
- `pillow` — buffer overflow, denial of service
- `jinja2` — SSTI (server-side template injection)
- `cryptography` — timing attacks, padding oracles

## Semver Safety Rules
- PATCH updates (1.2.3 → 1.2.4): Generally safe to auto-apply
- MINOR updates (1.2.3 → 1.3.0): Usually safe, run tests to verify
- MAJOR updates (1.2.3 → 2.0.0): Breaking changes likely, flag for human review

## Supply Chain Attack Indicators
- Package published by a new maintainer (account takeover)
- Install scripts (preinstall, postinstall) doing network requests
- Obfuscated code in a previously clean package
- Typosquatting: similar name to popular package
- Version published then quickly unpublished
