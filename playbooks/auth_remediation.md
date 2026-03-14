# Authentication Remediation Playbook

## Priority: CRITICAL
## CVSS Range: 7.5 - 9.8
## OWASP: A07:2021 — Identification and Authentication Failures
## CWE: CWE-287, CWE-307, CWE-384

## Remediation by Framework

### Next.js + Supabase

**Rate limiting on auth endpoints:**
```typescript
// lib/rate-limit.ts
import { Redis } from '@upstash/redis';

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_URL!,
  token: process.env.UPSTASH_REDIS_TOKEN!,
});

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfter: number;
}

export async function rateLimit(
  identifier: string,
  maxAttempts: number = 5,
  windowSeconds: number = 60
): Promise<RateLimitResult> {
  const key = `rate_limit:${identifier}`;
  const current = await redis.incr(key);

  if (current === 1) {
    await redis.expire(key, windowSeconds);
  }

  const ttl = await redis.ttl(key);

  return {
    allowed: current <= maxAttempts,
    remaining: Math.max(0, maxAttempts - current),
    retryAfter: current > maxAttempts ? ttl : 0,
  };
}

// app/api/auth/login/route.ts
import { rateLimit } from '@/lib/rate-limit';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  const { allowed, remaining, retryAfter } = await rateLimit(`login:${ip}`, 5, 60);

  if (!allowed) {
    return NextResponse.json(
      { error: 'Too many login attempts. Try again later.' },
      {
        status: 429,
        headers: {
          'Retry-After': String(retryAfter),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  // ... actual login logic with Supabase Auth
  const { email, password } = await request.json();
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    // Rate limit per username too (prevent credential stuffing)
    await rateLimit(`login:user:${email}`, 10, 300);
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
  }

  return NextResponse.json({ session: data.session }, {
    headers: { 'X-RateLimit-Remaining': String(remaining) },
  });
}
```

**JWT configuration for Supabase:**
```sql
-- In Supabase dashboard > Authentication > Settings:
-- JWT expiry: 900 (15 minutes)
-- Refresh token rotation: ENABLED
-- Refresh token reuse interval: 0 (single use)

-- In your app, handle refresh automatically:
-- supabase.auth.onAuthStateChange() handles this with the JS SDK
```

**Account lockout:**
```typescript
// lib/account-lockout.ts
export async function checkAccountLockout(email: string): Promise<boolean> {
  const key = `lockout:${email}`;
  const attempts = await redis.get(key);

  if (attempts && Number(attempts) >= 10) {
    return true; // Account is locked
  }
  return false;
}

export async function recordFailedAttempt(email: string): Promise<void> {
  const key = `lockout:${email}`;
  const current = await redis.incr(key);
  if (current === 1) {
    await redis.expire(key, 1800); // 30 minute lockout window
  }

  if (current >= 10) {
    // Alert via Sentinel
    await redis.set(`lockout:alert:${email}`, 'true', { ex: 1800 });
  }
}

export async function clearLockout(email: string): Promise<void> {
  await redis.del(`lockout:${email}`);
}
```

### Express

**Rate limiting with express-rate-limit + Redis:**
```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const { createClient } = require('redis');

const redisClient = createClient({ url: process.env.REDIS_URL });
await redisClient.connect();

const authLimiter = rateLimit({
  store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) }),
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  // ... login logic
});

// JWT with refresh rotation
const jwt = require('jsonwebtoken');

function generateTokenPair(userId) {
  const accessToken = jwt.sign({ sub: userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ sub: userId, type: 'refresh' }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
  // Store refresh token hash in DB for single-use validation
  return { accessToken, refreshToken };
}

async function rotateRefreshToken(oldRefreshToken) {
  const decoded = jwt.verify(oldRefreshToken, process.env.JWT_REFRESH_SECRET);
  // Verify token exists in DB (single-use check)
  const stored = await db.query('SELECT * FROM refresh_tokens WHERE token_hash = $1 AND revoked = false', [hash(oldRefreshToken)]);
  if (!stored.rows.length) throw new Error('Token reuse detected — revoke all user sessions');
  // Revoke old token
  await db.query('UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1', [hash(oldRefreshToken)]);
  // Issue new pair
  return generateTokenPair(decoded.sub);
}
```

### Django

```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': ['rest_framework.throttling.AnonRateThrottle'],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '5/minute',
        'login': '5/minute',
    },
}

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 900  # 15 minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Account lockout with django-axes
# pip install django-axes
INSTALLED_APPS += ['axes']
AUTHENTICATION_BACKENDS = ['axes.backends.AxesStandaloneBackend', 'django.contrib.auth.backends.ModelBackend']
AXES_FAILURE_LIMIT = 10
AXES_COOLOFF_TIME = 0.5  # 30 minutes
AXES_LOCKOUT_PARAMETERS = ['username', 'ip_address']
```

### Supabase Edge Functions

```typescript
// supabase/functions/_shared/rate-limit.ts
const rateLimits = new Map<string, { count: number; resetAt: number }>();

export function checkRateLimit(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = rateLimits.get(key);

  if (!entry || now > entry.resetAt) {
    rateLimits.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  entry.count++;
  return entry.count <= max;
}
```

## MFA Integration Points
For all frameworks, prepare MFA hooks:
1. After successful password auth, check if MFA is enabled for user
2. If enabled, return a partial session that requires MFA completion
3. Accept TOTP code via /api/auth/mfa/verify
4. Only issue full access token after MFA completion

## Verification
Re-run `brute_force` tool — fix verified when:
- Rate limiting kicks in at configured threshold
- Account lockout activates after N failures
- JWT tokens expire correctly
- Refresh token rotation prevents reuse
