/**
 * ShieldAGI Chain Walls — Supabase Edge Functions Implementation
 *
 * Wrap every edge function handler with withChainWalls():
 *
 * ```typescript
 * import { withChainWalls } from '../_shared/chain-walls.ts';
 *
 * Deno.serve(async (req) => {
 *   const result = await withChainWalls(req, { requireAuth: true });
 *   if (result.error) return result.error; // Chain wall rejection
 *
 *   const { user, body, ip, correlationId } = result;
 *   // ... your handler logic
 * });
 * ```
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// ═══════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════

interface ChainWallOptions {
  requireAuth?: boolean;
  requiredRole?: string;
  rateLimitMax?: number;
  rateLimitWindowMs?: number;
  allowedOrigins?: string[];
}

interface ChainWallResult {
  error?: Response;
  user?: { id: string; email: string; role: string };
  body?: any;
  ip: string;
  correlationId: string;
}

// ═══════════════════════════════════════════════
// IN-MEMORY STORES
// ═══════════════════════════════════════════════

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

const SECURITY_HEADERS: Record<string, string> = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
};

const DANGEROUS_PATTERNS = [
  /(<script[\s>])/i, /(javascript:)/i, /(on\w+\s*=)/i,
  /(\bUNION\b.*\bSELECT\b)/i, /(\bDROP\b.*\bTABLE\b)/i,
  /(\.\.\/)/i, /(%2e%2e)/i, /(%00)/,
];

const BLOCKED_PREFIXES = ['10.', '172.16.', '192.168.', '127.', '169.254.'];

// ═══════════════════════════════════════════════
// CHAIN WALLS WRAPPER
// ═══════════════════════════════════════════════

export async function withChainWalls(
  req: Request,
  options: ChainWallOptions = {}
): Promise<ChainWallResult> {
  const correlationId = crypto.randomUUID();
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  const url = new URL(req.url);

  // ── WALL 1: Rate Limiter ──
  const maxReq = options.rateLimitMax || 100;
  const windowMs = options.rateLimitWindowMs || 60_000;
  const rlKey = `${url.pathname}:${ip}`;
  const now = Date.now();
  const rlEntry = rateLimitStore.get(rlKey);

  if (rlEntry && now <= rlEntry.resetAt) {
    rlEntry.count++;
    if (rlEntry.count > maxReq) {
      return {
        error: errorResponse(429, 'Rate limit exceeded', correlationId),
        ip, correlationId,
      };
    }
  } else {
    rateLimitStore.set(rlKey, { count: 1, resetAt: now + windowMs });
  }

  // ── WALL 2: Input Sanitizer ──
  for (const [key, value] of url.searchParams) {
    if (value.length > 2000) {
      return { error: errorResponse(400, `Parameter too long: ${key}`, correlationId), ip, correlationId };
    }
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(value)) {
        return { error: errorResponse(400, `Malicious input in: ${key}`, correlationId), ip, correlationId };
      }
    }
  }

  let body: any = null;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    try {
      const contentType = req.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const text = await req.text();
        body = JSON.parse(text);

        // Recursively check body values
        const checkObj = (obj: any, prefix = ''): string | null => {
          for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string') {
              if (value.length > 10000) return `Body field too long: ${prefix}${key}`;
              for (const pattern of DANGEROUS_PATTERNS) {
                if (pattern.test(value)) return `Malicious input in body: ${prefix}${key}`;
              }
            } else if (typeof value === 'object' && value !== null) {
              const nested = checkObj(value, `${prefix}${key}.`);
              if (nested) return nested;
            }
          }
          return null;
        };
        const bodyErr = checkObj(body);
        if (bodyErr) {
          return { error: errorResponse(400, bodyErr, correlationId), ip, correlationId };
        }
      }
    } catch {
      return { error: errorResponse(400, 'Invalid request body', correlationId), ip, correlationId };
    }
  }

  // ── WALL 3: Auth Validator ──
  let user: { id: string; email: string; role: string } | undefined;

  if (options.requireAuth !== false) {
    const authHeader = req.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return { error: errorResponse(401, 'Missing authorization', correlationId), ip, correlationId };
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_ANON_KEY')!,
      { global: { headers: { Authorization: authHeader } } }
    );

    const { data: { user: supaUser }, error } = await supabase.auth.getUser();
    if (error || !supaUser) {
      return { error: errorResponse(401, 'Invalid or expired token', correlationId), ip, correlationId };
    }

    user = {
      id: supaUser.id,
      email: supaUser.email || '',
      role: supaUser.app_metadata?.role || 'user',
    };
  }

  // ── WALL 4: CSRF Guard ──
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    const origin = req.headers.get('origin');
    const allowedOrigins = options.allowedOrigins || [Deno.env.get('APP_URL') || ''];
    if (origin && allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
      return { error: errorResponse(403, 'CSRF: Origin not allowed', correlationId), ip, correlationId };
    }
  }

  // ── WALL 5: RBAC Enforcer ──
  if (options.requiredRole && user) {
    if (user.role !== options.requiredRole && user.role !== 'admin') {
      return { error: errorResponse(403, 'Insufficient permissions', correlationId), ip, correlationId };
    }
  }

  // ── WALL 6: SSRF Shield ──
  const allParams = { ...Object.fromEntries(url.searchParams), ...(body || {}) };
  for (const [key, value] of Object.entries(allParams)) {
    if (typeof value !== 'string') continue;
    if (!['url', 'redirect', 'callback', 'webhook'].some(k => key.toLowerCase().includes(k))) continue;
    try {
      const parsed = new URL(value);
      if (BLOCKED_PREFIXES.some(p => parsed.hostname.startsWith(p)) ||
          parsed.hostname === 'localhost' || !['http:', 'https:'].includes(parsed.protocol)) {
        return { error: errorResponse(403, 'SSRF: Blocked', correlationId), ip, correlationId };
      }
    } catch { /* not a URL */ }
  }

  // ── WALL 7: Request Logger ──
  console.log(JSON.stringify({
    type: 'request', timestamp: new Date().toISOString(), correlationId,
    ip, method: req.method, path: url.pathname, userId: user?.id || 'anonymous',
  }));

  return { user, body, ip, correlationId };
}

// ═══════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════

function errorResponse(status: number, message: string, correlationId: string): Response {
  return new Response(
    JSON.stringify({ error: message, correlationId }),
    {
      status,
      headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS },
    }
  );
}

export function secureResponse(data: any, status = 200, correlationId?: string): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...SECURITY_HEADERS,
  };
  if (correlationId) headers['X-Correlation-ID'] = correlationId;

  return new Response(JSON.stringify(data), { status, headers });
}
