# XSS Remediation Playbook

## Priority: HIGH-CRITICAL
## CVSS Range: 6.1 - 9.6
## OWASP: A03:2021 — Injection (Cross-Site Scripting)
## CWE: CWE-79

## Remediation Steps

### 1. Next.js / React

**dangerouslySetInnerHTML — Replace with DOMPurify:**
```typescript
// Before (vulnerable)
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// After (secure) — install: npm install dompurify @types/dompurify
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />

// Best: avoid dangerouslySetInnerHTML entirely
// Use a markdown renderer with sanitization built in
import ReactMarkdown from 'react-markdown';
<ReactMarkdown>{userContent}</ReactMarkdown>
```

**CSP Headers in Next.js middleware.ts:**
```typescript
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import crypto from 'crypto';

export function middleware(request: NextRequest) {
  const nonce = crypto.randomBytes(16).toString('base64');
  const response = NextResponse.next();

  response.headers.set('Content-Security-Policy', [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: https:`,
    `font-src 'self'`,
    `connect-src 'self' https://*.supabase.co`,
    `frame-ancestors 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
  ].join('; '));

  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '0'); // Disable legacy XSS filter (CSP is better)
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  return response;
}
```

### 2. Express

**Output encoding middleware:**
```javascript
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Sanitize all user-generated content before rendering
function sanitizeOutput(content) {
  if (typeof content !== 'string') return content;
  return DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
  });
}

// CSP headers via helmet
const helmet = require('helmet');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-origin" },
}));
```

### 3. Django

**Template auto-escaping (verify enabled):**
```python
# settings.py — ensure auto-escape is NOT disabled
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'OPTIONS': {
        'autoescape': True,  # This is default but verify it's not False
    },
}]

# In templates — NEVER use |safe on user content
# Before (vulnerable):
{{ user_bio|safe }}

# After (secure):
{{ user_bio }}  {# Auto-escaped by default #}

# If you need some HTML, use bleach:
import bleach
clean_bio = bleach.clean(user_bio, tags=['b', 'i', 'a', 'p'], attributes={'a': ['href']})
```

**Django CSP middleware:**
```python
# Install: pip install django-csp
# settings.py
MIDDLEWARE = [
    'csp.middleware.CSPMiddleware',
    # ... rest of middleware
]

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
```

### 4. Supabase Edge Functions

```typescript
// In edge functions that return HTML or handle user content
import DOMPurify from 'https://esm.sh/dompurify';

Deno.serve(async (req) => {
  const { content } = await req.json();
  const clean = DOMPurify.sanitize(content);

  return new Response(JSON.stringify({ content: clean }), {
    headers: {
      'Content-Type': 'application/json',
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
    },
  });
});
```

## Verification
Re-run `xss_inject` with all payload sets (basic, advanced, polyglot). Fix is verified when no payload executes in any context (reflected, stored, DOM-based).
