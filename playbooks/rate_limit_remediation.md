# Rate Limiting Remediation Playbook

## Priority: HIGH
## CVSS Range: 5.3 - 7.5
## OWASP: A04:2021 — Insecure Design
## CWE: CWE-770, CWE-799

## Universal Rate Limiter (Redis-backed sliding window)

### Next.js
```typescript
// lib/rate-limiter.ts
import { Redis } from '@upstash/redis';

const redis = new Redis({ url: process.env.UPSTASH_REDIS_URL!, token: process.env.UPSTASH_REDIS_TOKEN! });

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

const ENDPOINT_LIMITS: Record<string, RateLimitConfig> = {
  'auth': { windowMs: 60_000, maxRequests: 5 },
  'api': { windowMs: 60_000, maxRequests: 100 },
  'public': { windowMs: 60_000, maxRequests: 30 },
  'upload': { windowMs: 60_000, maxRequests: 10 },
};

export async function checkRateLimit(identifier: string, category: string = 'api') {
  const config = ENDPOINT_LIMITS[category] || ENDPOINT_LIMITS['api'];
  const now = Date.now();
  const windowStart = now - config.windowMs;
  const key = `rl:${category}:${identifier}`;

  // Sliding window using sorted sets
  await redis.zremrangebyscore(key, 0, windowStart);
  const count = await redis.zcard(key);

  if (count >= config.maxRequests) {
    const oldestEntry = await redis.zrange(key, 0, 0, { withScores: true });
    const retryAfter = oldestEntry.length ? Math.ceil((Number(oldestEntry[0].score) + config.windowMs - now) / 1000) : 60;
    return { allowed: false, remaining: 0, retryAfter };
  }

  await redis.zadd(key, { score: now, member: `${now}:${Math.random()}` });
  await redis.expire(key, Math.ceil(config.windowMs / 1000));

  return { allowed: true, remaining: config.maxRequests - count - 1, retryAfter: 0 };
}

// middleware.ts integration
import { checkRateLimit } from '@/lib/rate-limiter';

export async function middleware(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';
  const path = request.nextUrl.pathname;
  const category = path.startsWith('/api/auth') ? 'auth' : path.startsWith('/api') ? 'api' : 'public';

  const { allowed, remaining, retryAfter } = await checkRateLimit(ip, category);

  if (!allowed) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, {
      status: 429,
      headers: { 'Retry-After': String(retryAfter), 'X-RateLimit-Remaining': '0' },
    });
  }

  const response = NextResponse.next();
  response.headers.set('X-RateLimit-Remaining', String(remaining));
  return response;
}
```

### Express
```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

const createLimiter = (max, windowMs) => rateLimit({
  store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) }),
  windowMs, max,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Rate limit exceeded' },
});

app.use('/api/auth', createLimiter(5, 60_000));
app.use('/api', createLimiter(100, 60_000));
app.use('/', createLimiter(30, 60_000));
```

### Django
```python
# Using django-ratelimit
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request): ...

@ratelimit(key='user', rate='100/m', method='ALL', block=True)
def api_view(request): ...
```

### Supabase Edge Functions
```typescript
// In-memory rate limiter (per-function instance)
const windows = new Map<string, { count: number; reset: number }>();

function rateLimit(key: string, max: number, windowSec: number): boolean {
  const now = Math.floor(Date.now() / 1000);
  const entry = windows.get(key);
  if (!entry || now >= entry.reset) {
    windows.set(key, { count: 1, reset: now + windowSec });
    return true;
  }
  return ++entry.count <= max;
}
```

## Verification
Re-run `brute_force` with check_rate_limit=true. Verified when requests are blocked at threshold.
