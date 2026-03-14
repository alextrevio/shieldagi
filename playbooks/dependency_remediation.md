# Dependency Vulnerability Remediation Playbook

## Priority: VARIES (based on CVE severity)
## OWASP: A06:2021 — Vulnerable and Outdated Components
## CWE: CWE-1035, CWE-1104

## Automated Steps

### 1. npm (Node.js / Next.js / Express)
```bash
# Audit current state
npm audit --json > audit-report.json

# Auto-fix what's possible
npm audit fix

# For breaking changes (major version bumps)
npm audit fix --force  # CAUTION: run tests after

# If a package has no fix available, check alternatives:
npx npm-check-updates --target minor  # Safe updates
npx npm-check-updates --target latest  # All updates (test heavily)

# Regenerate lockfile
rm -rf node_modules package-lock.json
npm install

# Verify
npm audit
```

### 2. pip (Python / Django)
```bash
# Install auditing tools
pip install pip-audit safety

# Audit
pip-audit --format json > audit-report.json
safety check --json > safety-report.json

# Update vulnerable packages
pip install --upgrade package_name==safe_version

# Regenerate requirements
pip freeze > requirements.txt

# Verify
pip-audit
```

### 3. cargo (Rust)
```bash
cargo install cargo-audit
cargo audit --json > audit-report.json
cargo update  # Update to latest compatible versions
cargo audit  # Verify
```

## Decision Matrix

| Situation | Action |
|-----------|--------|
| Patch available, no breaking changes | Auto-update, run tests, create PR |
| Patch available, breaking changes | Update, document changes, flag for human review |
| No patch, low severity | Add compensating control, monitor for patch |
| No patch, high/critical severity | Replace package if possible, add WAF rule, alert team |
| Package unmaintained | Evaluate alternatives, plan migration |

## Compensating Controls (when no patch exists)
1. WAF rules to block exploit payloads for the specific CVE
2. Input validation to prevent the vulnerable code path from triggering
3. Network segmentation to limit blast radius
4. Runtime protection (Node.js: --disallow-code-generation-from-strings)

## Verification
Re-run `dep_audit` — verified when zero known CVEs in dependency tree.
