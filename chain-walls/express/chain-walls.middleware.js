/**
 * ShieldAGI Chain Walls — Express Implementation
 *
 * 7-layer security middleware chain for Express applications.
 * Mount BEFORE all route handlers: app.use(chainWalls());
 */

const crypto = require('crypto');
const helmet = require('helmet');

// ═══════════════════════════════════════════════
// WALL 1: RATE LIMITER
// ═══════════════════════════════════════════════

const rateLimitStore = new Map();

function wall1_rateLimiter(config = {}) {
  const limits = {
    auth: { windowMs: 60000, max: 5 },
    api: { windowMs: 60000, max: 100 },
    public: { windowMs: 60000, max: 30 },
    ...config,
  };

  return (req, res, next) => {
    const category = req.path.startsWith('/api/auth') ? 'auth'
      : req.path.startsWith('/api') ? 'api' : 'public';
    const limit = limits[category];
    const key = `${category}:${req.ip}`;
    const now = Date.now();

    const entry = rateLimitStore.get(key);
    if (!entry || now > entry.resetAt) {
      rateLimitStore.set(key, { count: 1, resetAt: now + limit.windowMs });
      res.set('X-RateLimit-Remaining', String(limit.max - 1));
      return next();
    }

    entry.count++;
    if (entry.count > limit.max) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.set('Retry-After', String(retryAfter));
      res.set('X-RateLimit-Remaining', '0');
      return res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter,
        correlationId: req.correlationId,
      });
    }

    res.set('X-RateLimit-Remaining', String(limit.max - entry.count));
    next();
  };
}

// ═══════════════════════════════════════════════
// WALL 2: INPUT SANITIZER
// ═══════════════════════════════════════════════

const DANGEROUS_PATTERNS = [
  /(<script[\s>])/i, /(javascript:)/i, /(on\w+\s*=)/i,
  /(\bUNION\b.*\bSELECT\b)/i, /(\bDROP\b.*\bTABLE\b)/i,
  /(;\s*DROP\b)/i, /(\bEXEC\b.*\bxp_)/i,
  /(\.\.\/)/i, /(%2e%2e)/i, /(%00)/,
];

function wall2_inputSanitizer() {
  return (req, res, next) => {
    const checkValue = (key, value) => {
      if (typeof value !== 'string') return null;
      if (value.length > 2000) return `Parameter too long: ${key}`;
      for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.test(value)) return `Malicious input in: ${key}`;
      }
      return null;
    };

    // Check query params
    for (const [key, value] of Object.entries(req.query)) {
      const err = checkValue(key, String(value));
      if (err) return res.status(400).json({ error: err, correlationId: req.correlationId });
    }

    // Check body params (if parsed)
    if (req.body && typeof req.body === 'object') {
      const checkObj = (obj, prefix = '') => {
        for (const [key, value] of Object.entries(obj)) {
          if (typeof value === 'string') {
            const err = checkValue(`${prefix}${key}`, value);
            if (err) return err;
          } else if (typeof value === 'object' && value !== null) {
            const nested = checkObj(value, `${prefix}${key}.`);
            if (nested) return nested;
          }
        }
        return null;
      };
      const bodyErr = checkObj(req.body);
      if (bodyErr) return res.status(400).json({ error: bodyErr, correlationId: req.correlationId });
    }

    next();
  };
}

// ═══════════════════════════════════════════════
// WALL 3: AUTH VALIDATOR
// ═══════════════════════════════════════════════

function wall3_authValidator(options = {}) {
  const publicPaths = options.publicPaths || [
    '/api/auth/login', '/api/auth/signup', '/api/auth/forgot-password', '/api/health',
  ];

  return (req, res, next) => {
    if (publicPaths.some(p => req.path.startsWith(p)) || !req.path.startsWith('/api')) {
      return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing authorization', correlationId: req.correlationId });
    }

    const token = authHeader.substring(7);
    try {
      const parts = token.split('.');
      if (parts.length !== 3) throw new Error('Malformed');

      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return res.status(401).json({ error: 'Token expired', correlationId: req.correlationId });
      }

      req.userId = payload.sub;
      req.userRole = payload.role || 'user';
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token', correlationId: req.correlationId });
    }
  };
}

// ═══════════════════════════════════════════════
// WALL 4: CSRF GUARD
// ═══════════════════════════════════════════════

function wall4_csrfGuard(options = {}) {
  const allowedOrigins = options.allowedOrigins || [];

  return (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    if (req.headers['x-api-key']) return next();

    const origin = req.headers.origin;
    if (origin && allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
      return res.status(403).json({ error: 'CSRF: Origin not allowed', correlationId: req.correlationId });
    }
    next();
  };
}

// ═══════════════════════════════════════════════
// WALL 5: RBAC ENFORCER
// ═══════════════════════════════════════════════

function wall5_rbacEnforcer(options = {}) {
  const adminPaths = options.adminPaths || ['/api/admin', '/api/users/manage'];

  return (req, res, next) => {
    if (adminPaths.some(p => req.path.startsWith(p))) {
      if (req.userRole !== 'admin' && req.userRole !== 'service_role') {
        return res.status(403).json({ error: 'Insufficient permissions', correlationId: req.correlationId });
      }
    }
    next();
  };
}

// ═══════════════════════════════════════════════
// WALL 6: SSRF SHIELD
// ═══════════════════════════════════════════════

function wall6_ssrfShield() {
  const blockedPrefixes = ['10.', '172.16.', '192.168.', '127.', '169.254.', '0.'];
  const blockedHosts = ['localhost', 'metadata.google.internal'];

  return (req, res, next) => {
    const allParams = { ...req.query, ...(req.body || {}) };

    for (const [key, value] of Object.entries(allParams)) {
      if (typeof value !== 'string') continue;
      if (!['url', 'redirect', 'callback', 'next', 'return_url', 'webhook'].some(k => key.toLowerCase().includes(k))) continue;

      try {
        const parsed = new URL(value);
        if (blockedPrefixes.some(p => parsed.hostname.startsWith(p)) ||
            blockedHosts.includes(parsed.hostname) ||
            !['http:', 'https:'].includes(parsed.protocol)) {
          return res.status(403).json({ error: 'SSRF: Blocked request', correlationId: req.correlationId });
        }
      } catch { /* Not a URL, skip */ }
    }
    next();
  };
}

// ═══════════════════════════════════════════════
// WALL 7: REQUEST LOGGER
// ═══════════════════════════════════════════════

function wall7_requestLogger() {
  return (req, res, next) => {
    const start = Date.now();

    res.on('finish', () => {
      console.log(JSON.stringify({
        type: 'request',
        timestamp: new Date().toISOString(),
        correlationId: req.correlationId,
        ip: req.ip,
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration: Date.now() - start,
        userId: req.userId || 'anonymous',
        userAgent: req.headers['user-agent'] || 'unknown',
      }));
    });

    next();
  };
}

// ═══════════════════════════════════════════════
// CHAIN WALLS FACTORY
// ═══════════════════════════════════════════════

function chainWalls(options = {}) {
  const router = require('express').Router();

  // Correlation ID
  router.use((req, res, next) => {
    req.correlationId = crypto.randomUUID();
    res.set('X-Correlation-ID', req.correlationId);
    next();
  });

  // Security headers via helmet
  router.use(helmet({
    contentSecurityPolicy: options.csp || {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  }));

  // Mount all walls in order
  router.use(wall1_rateLimiter(options.rateLimits));
  router.use(wall2_inputSanitizer());
  router.use(wall3_authValidator(options));
  router.use(wall4_csrfGuard(options));
  router.use(wall5_rbacEnforcer(options));
  router.use(wall6_ssrfShield());
  router.use(wall7_requestLogger());

  return router;
}

module.exports = { chainWalls, wall1_rateLimiter, wall2_inputSanitizer, wall3_authValidator,
  wall4_csrfGuard, wall5_rbacEnforcer, wall6_ssrfShield, wall7_requestLogger };
