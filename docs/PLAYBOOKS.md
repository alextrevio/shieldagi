# ShieldAGI 2.0 — Playbook Index

ShieldAGI uses remediation playbooks to fix each vulnerability category. The Shield Remediator agent selects the appropriate playbook based on the Vuln Reporter's findings.

All playbook source files are in `playbooks/`.

## Playbook Summary

| # | Playbook | Category | What It Fixes | Key Transforms | Complexity |
|---|----------|----------|---------------|----------------|------------|
| 1 | `sqli_remediation.md` | SQL Injection | String concatenation in SQL, template literal injection, raw queries, unsanitized `.rpc()` calls | Replace concat/interpolation with parameterized queries; enforce ORM usage; add input type validation | MODERATE |
| 2 | `xss_remediation.md` | Cross-Site Scripting | `dangerouslySetInnerHTML`, unescaped template vars, `innerHTML` assignments, reflected params | Add DOMPurify, implement CSP headers (`script-src 'self' 'nonce-{n}'`), encode all user output, add `X-Content-Type-Options: nosniff` | MODERATE |
| 3 | `csrf_remediation.md` | Cross-Site Request Forgery | Missing CSRF tokens on state-changing endpoints, permissive SameSite cookies | Implement double-submit cookie pattern, add token generation/validation to forms and API routes, set `SameSite=Strict` | SIMPLE |
| 4 | `auth_remediation.md` | Authentication | Missing rate limiting on auth, weak JWT config, no token rotation, no account lockout | Add sliding window rate limiting (5 req/min), set JWT expiry (15min access / 7d refresh), implement refresh token rotation, add lockout after N failures | MODERATE |
| 5 | `ssrf_remediation.md` | Server-Side Request Forgery | Server-side URL fetching without validation, access to internal networks and cloud metadata | Add URL validation, block private IP ranges (10/8, 172.16/12, 192.168/16, 127/8), block 169.254.169.254, implement domain allowlist, DNS rebinding protection | MODERATE |
| 6 | `rate_limit_remediation.md` | Rate Limiting | Unthrottled endpoints, missing 429 responses, no per-user/per-IP limits | Implement sliding window limiter per IP + user; auth endpoints: 5/min, API: 100/min, public: 30/min; add `Retry-After` header | SIMPLE |
| 7 | `traversal_remediation.md` | Path Traversal | `../` sequences in file paths, encoded traversal, null byte injection, unsandboxed file access | Resolve to absolute path + `startsWith()` check, block null bytes and double encoding, restrict access to designated directories | SIMPLE |
| 8 | `idor_remediation.md` | Insecure Direct Object Reference | Missing ownership validation on resource endpoints, sequential/predictable IDs | Add ownership middleware (`resource.owner_id === req.user.id`), write RLS policies with `auth.uid()` for Supabase, add `get_queryset()` filtering for Django | MODERATE |
| 9 | `misconfig_remediation.md` | Security Misconfiguration | Missing security headers, permissive CORS, insecure cookies, exposed server versions | Add HSTS, X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy; set secure cookie defaults; restrict CORS origins; disable version headers | SIMPLE |
| 10 | `dependency_remediation.md` | Vulnerable Dependencies | Packages with known CVEs, outdated lockfiles, unmaintained dependencies | Update to patched versions, regenerate lockfiles, run tests to verify compatibility; flag major version bumps for human review | TRIVIAL–COMPLEX |

## Complexity Levels

- **TRIVIAL**: Configuration change only (e.g., add a header, update a version number)
- **SIMPLE**: Single file modification (e.g., add middleware, update a route handler)
- **MODERATE**: Multi-file changes with framework-specific logic (e.g., parameterize queries across multiple routes)
- **COMPLEX**: Architectural changes requiring coordination (e.g., major dependency upgrade with API changes)

## Playbook Selection Logic

The Vuln Reporter assigns a playbook to each finding based on its `category` field:

```
category: "sqli"        → sqli_remediation.md
category: "xss"         → xss_remediation.md
category: "csrf"        → csrf_remediation.md
category: "auth"        → auth_remediation.md
category: "ssrf"        → ssrf_remediation.md
category: "rate_limit"  → rate_limit_remediation.md
category: "traversal"   → traversal_remediation.md
category: "idor"        → idor_remediation.md
category: "misconfig"   → misconfig_remediation.md
category: "dependency"  → dependency_remediation.md
```

The Shield Remediator processes playbooks in dependency order. For example, auth fixes are applied before IDOR fixes because IDOR remediation depends on a working auth context.
