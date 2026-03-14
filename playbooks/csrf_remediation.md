# CSRF Remediation Playbook

## Priority: HIGH
## CVSS Range: 6.5 - 8.8
## OWASP: A01:2021 — Broken Access Control
## CWE: CWE-352

## Remediation by Framework

### Next.js
```typescript
// lib/csrf.ts
import crypto from 'crypto';
import { cookies } from 'next/headers';

export function generateCsrfToken(): string {
  const token = crypto.randomBytes(32).toString('hex');
  return token;
}

export function validateCsrfToken(requestToken: string, cookieToken: string): boolean {
  if (!requestToken || !cookieToken) return false;
  return crypto.timingSafeEqual(
    Buffer.from(requestToken),
    Buffer.from(cookieToken)
  );
}

// middleware.ts — set CSRF cookie on every response
export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  if (!request.cookies.get('csrf_token')) {
    const token = crypto.randomBytes(32).toString('hex');
    response.cookies.set('csrf_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
    });
  }
  // Validate on state-changing requests
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(request.method)) {
    const origin = request.headers.get('origin');
    const allowedOrigins = [process.env.NEXT_PUBLIC_APP_URL];
    if (!origin || !allowedOrigins.includes(origin)) {
      return NextResponse.json({ error: 'CSRF validation failed' }, { status: 403 });
    }
  }
  return response;
}
```

### Express
```javascript
// middleware/csrf.js
const crypto = require('crypto');

function csrfProtection(req, res, next) {
  // Skip safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    // Generate token for forms
    if (!req.cookies.csrf_token) {
      const token = crypto.randomBytes(32).toString('hex');
      res.cookie('csrf_token', token, {
        httpOnly: true, secure: true, sameSite: 'strict'
      });
      req.csrfToken = token;
    }
    return next();
  }
  // Validate on state-changing methods
  const cookieToken = req.cookies.csrf_token;
  const headerToken = req.headers['x-csrf-token'] || req.body?._csrf;
  if (!cookieToken || !headerToken ||
      !crypto.timingSafeEqual(Buffer.from(cookieToken), Buffer.from(headerToken))) {
    return res.status(403).json({ error: 'CSRF validation failed' });
  }
  next();
}
module.exports = csrfProtection;
```

### Django
```python
# Verify CsrfViewMiddleware is active in settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # MUST be present
    # ...
]

# Set strict cookie settings
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = ['https://yourdomain.com']

# For API views using DRF, ensure CSRF is enforced:
# REST_FRAMEWORK = { 'DEFAULT_AUTHENTICATION_CLASSES': ['rest_framework.authentication.SessionAuthentication'] }
```

### Supabase Edge Functions
```typescript
Deno.serve(async (req) => {
  // Validate Origin header
  const origin = req.headers.get('origin');
  const allowed = ['https://yourdomain.com'];
  if (req.method !== 'GET' && (!origin || !allowed.includes(origin))) {
    return new Response(JSON.stringify({ error: 'CSRF rejected' }), { status: 403 });
  }
  // ... handler logic
});
```

## Cookie Configuration (all frameworks)
All auth cookies MUST have: `SameSite=Strict`, `Secure=true`, `HttpOnly=true`

## Verification
Re-run `csrf_test` — fix verified when cross-origin state-changing requests are rejected.
