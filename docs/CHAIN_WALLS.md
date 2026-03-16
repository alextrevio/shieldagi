# ShieldAGI 2.0 — Chain Walls Guide

Chain Walls is a 7-layer defense middleware stack that ShieldAGI injects into your application during remediation. Each layer runs sequentially on every incoming request, providing defense-in-depth.

## The 7 Layers

| Layer | Name | What It Blocks |
|-------|------|----------------|
| 1 | **Rate Limiter** | DDoS, brute force, credential stuffing, API abuse. Sliding window per IP + per authenticated user. |
| 2 | **Input Sanitizer** | SQLi payloads, XSS vectors, path traversal sequences, null bytes, command injection. Validates types and lengths. |
| 3 | **Auth Validator** | Expired/forged JWTs, missing auth on protected routes, stale sessions. Handles token rotation. |
| 4 | **CSRF Guard** | Cross-site request forgery via double-submit cookie pattern. Validates Origin/Referer headers. Enforces SameSite. |
| 5 | **RBAC Enforcer** | Unauthorized access, privilege escalation, IDOR. Validates resource ownership against authenticated user. |
| 6 | **SSRF Shield** | Server-side request forgery. Blocks private IPs (10/8, 172.16/12, 192.168/16, 127/8), cloud metadata (169.254.169.254), DNS rebinding. |
| 7 | **Request Logger** | Nothing (passthrough). Logs every request with threat correlation ID, source IP, matched rules, and timing for forensic analysis. |

Request flow:
```
Request → [1] Rate Limit → [2] Sanitize → [3] Auth → [4] CSRF → [5] RBAC → [6] SSRF → [7] Log → Handler
              ↓ block         ↓ block       ↓ 401     ↓ 403      ↓ 403      ↓ block      ↓ log
              429             400           redirect   reject     reject     reject       (pass)
```

## Framework Setup

### Next.js

Chain Walls is implemented as Next.js middleware (`middleware.ts` at project root).

**File**: `chain-walls/nextjs/middleware.ts`

```typescript
// middleware.ts — mounted at project root
import { NextRequest, NextResponse } from 'next/server';
import { chainWalls } from './lib/chain-walls';

export async function middleware(req: NextRequest) {
  return chainWalls(req, [
    rateLimiter,
    inputSanitizer,
    authValidator,
    csrfGuard,
    rbacEnforcer,
    ssrfShield,
    requestLogger,
  ]);
}

export const config = {
  matcher: ['/api/:path*', '/dashboard/:path*'],
};
```

### Express

Chain Walls is an Express middleware stack mounted before all route handlers.

**File**: `chain-walls/express/chain-walls.middleware.js`

```javascript
// Mount before routes
const { chainWalls } = require('./middleware/chain-walls');

app.use(chainWalls({
  rateLimiter: { windowMs: 60000, maxRequests: 100 },
  csrf: { cookieName: '_csrf' },
  ssrf: { allowedDomains: ['api.example.com'] },
}));
```

### Django

Chain Walls is a Django middleware class added as the first entry in `MIDDLEWARE`.

**File**: `chain-walls/django/chain_walls.py`

```python
# settings.py
MIDDLEWARE = [
    'chain_walls.ChainWallsMiddleware',  # Must be first
    # ... other middleware
]

CHAIN_WALLS = {
    'RATE_LIMIT': {'window': 60, 'max_requests': 100},
    'CSRF': {'enabled': True},
    'SSRF': {'blocked_ranges': ['10.0.0.0/8', '172.16.0.0/12']},
}
```

### Supabase Edge Functions

Chain Walls wraps each edge function with a `withChainWalls()` higher-order function.

**File**: `chain-walls/supabase/chain-walls.ts`

```typescript
// supabase/functions/my-function/index.ts
import { withChainWalls } from '../_shared/chain-walls.ts';

Deno.serve(withChainWalls(async (req, user) => {
  // user is already authenticated and authorized
  // input is already sanitized
  return new Response(JSON.stringify({ ok: true }));
}));
```

## chain-walls.config.json

Each framework reads from a shared config file that controls layer behavior:

```json
{
  "version": "2.0",
  "layers": {
    "rateLimiter": {
      "enabled": true,
      "windowMs": 60000,
      "maxPerIP": 100,
      "maxPerUser": 200,
      "authEndpointMax": 5,
      "retryAfterHeader": true
    },
    "inputSanitizer": {
      "enabled": true,
      "stripHtml": true,
      "maxFieldLength": 10000,
      "blockPatterns": ["<script", "javascript:", "onerror=", "UNION SELECT"],
      "allowedTags": []
    },
    "authValidator": {
      "enabled": true,
      "jwtSecret": "${JWT_SECRET}",
      "accessTokenTTL": 900,
      "refreshTokenTTL": 604800,
      "rotateRefreshTokens": true,
      "publicPaths": ["/", "/login", "/signup", "/api/health"]
    },
    "csrfGuard": {
      "enabled": true,
      "cookieName": "__csrf",
      "headerName": "x-csrf-token",
      "sameSite": "Strict",
      "secureCookie": true
    },
    "rbacEnforcer": {
      "enabled": true,
      "ownershipField": "user_id",
      "roles": ["user", "admin"],
      "adminPaths": ["/api/admin/*"]
    },
    "ssrfShield": {
      "enabled": true,
      "blockedRanges": [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.169.254/32", "::1/128"
      ],
      "allowedDomains": [],
      "blockMetadataEndpoints": true
    },
    "requestLogger": {
      "enabled": true,
      "logLevel": "info",
      "includeHeaders": false,
      "includeBody": false,
      "correlationIdHeader": "x-correlation-id"
    }
  }
}
```

## Adding Custom Walls

To add a custom wall layer:

1. Create a handler function matching the wall interface for your framework:

```typescript
// Next.js example
import { NextRequest, NextResponse } from 'next/server';

export async function myCustomWall(
  req: NextRequest,
  config: WallConfig
): Promise<NextResponse | null> {
  // Return null to pass through to next wall
  // Return NextResponse to block the request

  const suspicious = checkMyCustomLogic(req);
  if (suspicious) {
    return NextResponse.json(
      { error: 'Blocked by custom wall' },
      { status: 403 }
    );
  }
  return null; // pass through
}
```

2. Register it in the chain:

```typescript
// middleware.ts
return chainWalls(req, [
  rateLimiter,
  inputSanitizer,
  authValidator,
  csrfGuard,
  rbacEnforcer,
  ssrfShield,
  myCustomWall,   // Add your wall here
  requestLogger,  // Logger should always be last
]);
```

3. Add configuration to `chain-walls.config.json`:

```json
{
  "layers": {
    "myCustomWall": {
      "enabled": true,
      "customOption": "value"
    }
  }
}
```

The wall interface is the same across frameworks: receive the request and config, return a block response or null to pass through. The request logger should always remain the final layer.
