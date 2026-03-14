# Security Misconfiguration Remediation Playbook

## Priority: MEDIUM-HIGH
## CVSS Range: 5.3 - 7.5
## OWASP: A05:2021 — Security Misconfiguration
## CWE: CWE-16, CWE-1021

## Required Security Headers (all frameworks)

| Header | Value | Purpose |
|--------|-------|---------|
| Strict-Transport-Security | max-age=31536000; includeSubDomains; preload | Force HTTPS |
| X-Frame-Options | DENY | Prevent clickjacking |
| X-Content-Type-Options | nosniff | Prevent MIME sniffing |
| Content-Security-Policy | See per-framework config | Prevent XSS, injection |
| Referrer-Policy | strict-origin-when-cross-origin | Control referrer leaks |
| Permissions-Policy | camera=(), microphone=(), geolocation=() | Restrict browser APIs |
| X-DNS-Prefetch-Control | off | Prevent DNS info leak |
| Cross-Origin-Opener-Policy | same-origin | Isolate browsing context |
| Cross-Origin-Resource-Policy | same-origin | Prevent cross-origin reads |

### Next.js — next.config.js + middleware.ts
```javascript
// next.config.js
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()' },
  { key: 'X-DNS-Prefetch-Control', value: 'off' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
];

module.exports = {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
  poweredByHeader: false, // Remove X-Powered-By: Next.js
};
```

### Express — helmet
```javascript
const helmet = require('helmet');
app.use(helmet());
app.disable('x-powered-by');

// CORS — specific origins ONLY
const cors = require('cors');
app.use(cors({
  origin: ['https://yourdomain.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
  maxAge: 86400,
}));
```

### Django — settings.py
```python
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_BROWSER_XSS_FILTER = False  # Deprecated, use CSP
SECURE_SSL_REDIRECT = True
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

CORS_ALLOWED_ORIGINS = ['https://yourdomain.com']
CORS_ALLOW_CREDENTIALS = True
```

### Supabase Edge Functions
```typescript
const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

// Apply to every response
function secureResponse(body: any, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS } });
}
```

## Cookie Security Checklist
- `Secure`: true (HTTPS only)
- `HttpOnly`: true (no JS access)
- `SameSite`: Strict (or Lax for OAuth flows)
- `Path`: / (or specific path)
- `Domain`: explicit domain (not wildcard)
- `Max-Age`: short-lived for session cookies

## Verification
Re-run `header_audit` — verified when all required headers are present with correct values.
