/**
 * ShieldAGI Chain Walls — Next.js Implementation
 *
 * 7-layer security middleware for Next.js applications.
 * Drop this into your project's middleware.ts file.
 *
 * Every request passes through ALL walls in order.
 * If any wall rejects, the chain aborts with an appropriate error.
 *
 * Wall 1: Rate Limiter
 * Wall 2: Input Sanitizer
 * Wall 3: Auth Validator
 * Wall 4: CSRF Guard
 * Wall 5: RBAC Enforcer
 * Wall 6: SSRF Shield
 * Wall 7: Request Logger
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import crypto from 'crypto';

// ═══════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════

const CONFIG = {
  rateLimits: {
    auth: { windowMs: 60_000, max: 5 },
    api: { windowMs: 60_000, max: 100 },
    public: { windowMs: 60_000, max: 30 },
  },
  jwt: {
    secret: process.env.JWT_SECRET || '',
    maxAge: 900, // 15 minutes
  },
  cors: {
    allowedOrigins: (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean),
  },
  ssrf: {
    blockedPrefixes: ['10.', '172.16.', '192.168.', '127.', '169.254.', '0.'],
    blockedHosts: ['localhost', 'metadata.google.internal'],
  },
};

// ═══════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════

interface ChainContext {
  request: NextRequest;
  ip: string;
  path: string;
  method: string;
  correlationId: string;
  userId?: string;
  userRole?: string;
}

type WallResult =
  | { pass: true }
  | { pass: false; status: number; message: string };

type Wall = (ctx: ChainContext) => Promise<WallResult>;

// ═══════════════════════════════════════════════
// WALL 1: RATE LIMITER
// ═══════════════════════════════════════════════

// In-memory rate limiter (replace with Redis in production)
const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

const wall1_rateLimiter: Wall = async (ctx) => {
  const category = ctx.path.startsWith('/api/auth') ? 'auth'
    : ctx.path.startsWith('/api') ? 'api'
    : 'public';

  const config = CONFIG.rateLimits[category as keyof typeof CONFIG.rateLimits];
  const key = `${category}:${ctx.ip}`;
  const now = Date.now();

  const entry = rateLimitStore.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + config.windowMs });
    return { pass: true };
  }

  entry.count++;
  if (entry.count > config.max) {
    return {
      pass: false,
      status: 429,
      message: `Rate limit exceeded. Try again in ${Math.ceil((entry.resetAt - now) / 1000)}s`,
    };
  }

  return { pass: true };
};

// ═══════════════════════════════════════════════
// WALL 2: INPUT SANITIZER
// ═══════════════════════════════════════════════

const DANGEROUS_PATTERNS = [
  /(<script[\s>])/i,
  /(javascript:)/i,
  /(on\w+\s*=)/i,
  /(\bUNION\b.*\bSELECT\b)/i,
  /(\bDROP\b.*\bTABLE\b)/i,
  /(\bINSERT\b.*\bINTO\b)/i,
  /(\bDELETE\b.*\bFROM\b)/i,
  /(--\s*$)/,
  /(;\s*DROP\b)/i,
  /(\bEXEC\b.*\bxp_)/i,
  /(\.\.\/)/,
  /(%2e%2e)/i,
  /(%00)/,
];

const wall2_inputSanitizer: Wall = async (ctx) => {
  const url = ctx.request.nextUrl;

  // Check query parameters
  for (const [key, value] of url.searchParams) {
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(value)) {
        return {
          pass: false,
          status: 400,
          message: `Malicious input detected in parameter: ${key}`,
        };
      }
    }

    // Length check
    if (value.length > 2000) {
      return {
        pass: false,
        status: 400,
        message: `Parameter too long: ${key} (max 2000 chars)`,
      };
    }
  }

  return { pass: true };
};

// ═══════════════════════════════════════════════
// WALL 3: AUTH VALIDATOR
// ═══════════════════════════════════════════════

const PUBLIC_PATHS = [
  '/api/auth/login',
  '/api/auth/signup',
  '/api/auth/forgot-password',
  '/api/health',
  '/_next',
  '/favicon.ico',
];

const wall3_authValidator: Wall = async (ctx) => {
  // Skip auth for public paths
  if (PUBLIC_PATHS.some(p => ctx.path.startsWith(p)) || !ctx.path.startsWith('/api')) {
    return { pass: true };
  }

  const authHeader = ctx.request.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return { pass: false, status: 401, message: 'Missing or invalid authorization header' };
  }

  const token = authHeader.substring(7);

  try {
    // Basic JWT validation (structure check — full verification happens in the API route)
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { pass: false, status: 401, message: 'Malformed token' };
    }

    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // Check expiry
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return { pass: false, status: 401, message: 'Token expired' };
    }

    // Store user info in context for downstream walls
    ctx.userId = payload.sub;
    ctx.userRole = payload.role || 'user';

    return { pass: true };
  } catch {
    return { pass: false, status: 401, message: 'Invalid token' };
  }
};

// ═══════════════════════════════════════════════
// WALL 4: CSRF GUARD
// ═══════════════════════════════════════════════

const wall4_csrfGuard: Wall = async (ctx) => {
  // Only check state-changing methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(ctx.method)) {
    return { pass: true };
  }

  // Skip for API-key authenticated requests (non-browser)
  if (ctx.request.headers.get('x-api-key')) {
    return { pass: true };
  }

  // Validate Origin header
  const origin = ctx.request.headers.get('origin');
  if (origin && CONFIG.cors.allowedOrigins.length > 0) {
    if (!CONFIG.cors.allowedOrigins.includes(origin)) {
      return { pass: false, status: 403, message: 'CSRF: Origin not allowed' };
    }
  }

  return { pass: true };
};

// ═══════════════════════════════════════════════
// WALL 5: RBAC ENFORCER
// ═══════════════════════════════════════════════

const ADMIN_PATHS = [
  '/api/admin',
  '/api/users/manage',
  '/api/settings/system',
];

const wall5_rbacEnforcer: Wall = async (ctx) => {
  // Check admin-only paths
  if (ADMIN_PATHS.some(p => ctx.path.startsWith(p))) {
    if (ctx.userRole !== 'admin' && ctx.userRole !== 'service_role') {
      return { pass: false, status: 403, message: 'Insufficient permissions' };
    }
  }

  return { pass: true };
};

// ═══════════════════════════════════════════════
// WALL 6: SSRF SHIELD
// ═══════════════════════════════════════════════

const wall6_ssrfShield: Wall = async (ctx) => {
  // Check URL parameters for SSRF attempts
  const url = ctx.request.nextUrl;

  for (const [key, value] of url.searchParams) {
    if (key.includes('url') || key.includes('redirect') || key.includes('callback') || key.includes('next')) {
      try {
        const parsedUrl = new URL(value);

        // Block private IPs
        for (const prefix of CONFIG.ssrf.blockedPrefixes) {
          if (parsedUrl.hostname.startsWith(prefix)) {
            return { pass: false, status: 403, message: 'SSRF: Internal address blocked' };
          }
        }

        // Block known metadata hosts
        if (CONFIG.ssrf.blockedHosts.includes(parsedUrl.hostname)) {
          return { pass: false, status: 403, message: 'SSRF: Blocked hostname' };
        }

        // Block non-http(s) protocols
        if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
          return { pass: false, status: 403, message: 'SSRF: Blocked protocol' };
        }
      } catch {
        // Not a valid URL — that's fine, not an SSRF attempt
      }
    }
  }

  return { pass: true };
};

// ═══════════════════════════════════════════════
// WALL 7: REQUEST LOGGER
// ═══════════════════════════════════════════════

const wall7_requestLogger: Wall = async (ctx) => {
  // This wall NEVER rejects — it only logs
  const logEntry = {
    timestamp: new Date().toISOString(),
    correlationId: ctx.correlationId,
    ip: ctx.ip,
    method: ctx.method,
    path: ctx.path,
    userId: ctx.userId || 'anonymous',
    userAgent: ctx.request.headers.get('user-agent') || 'unknown',
  };

  // In production: send to structured logging service
  // For now, console.log with structured format
  console.log(JSON.stringify({ type: 'request', ...logEntry }));

  return { pass: true };
};

// ═══════════════════════════════════════════════
// CHAIN EXECUTOR
// ═══════════════════════════════════════════════

const WALLS: Wall[] = [
  wall1_rateLimiter,
  wall2_inputSanitizer,
  wall3_authValidator,
  wall4_csrfGuard,
  wall5_rbacEnforcer,
  wall6_ssrfShield,
  wall7_requestLogger,
];

const WALL_NAMES = [
  'Rate Limiter',
  'Input Sanitizer',
  'Auth Validator',
  'CSRF Guard',
  'RBAC Enforcer',
  'SSRF Shield',
  'Request Logger',
];

export async function middleware(request: NextRequest) {
  const ctx: ChainContext = {
    request,
    ip: request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown',
    path: request.nextUrl.pathname,
    method: request.method,
    correlationId: crypto.randomUUID(),
  };

  // Execute chain walls in order
  for (let i = 0; i < WALLS.length; i++) {
    const result = await WALLS[i](ctx);

    if (!result.pass) {
      console.log(JSON.stringify({
        type: 'chain_wall_reject',
        wall: WALL_NAMES[i],
        correlationId: ctx.correlationId,
        ip: ctx.ip,
        path: ctx.path,
        status: result.status,
        message: result.message,
      }));

      return NextResponse.json(
        { error: result.message, correlationId: ctx.correlationId },
        { status: result.status }
      );
    }
  }

  // All walls passed — add security headers and continue
  const response = NextResponse.next();

  // Security headers
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.headers.set('X-Correlation-ID', ctx.correlationId);
  response.headers.set('Cross-Origin-Opener-Policy', 'same-origin');

  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
