"""
ShieldAGI Chain Walls — Django Implementation

Add to MIDDLEWARE in settings.py (FIRST position):

    MIDDLEWARE = [
        'shieldagi.chain_walls.ChainWallsMiddleware',
        'django.middleware.security.SecurityMiddleware',
        # ... rest of middleware
    ]

Configuration in settings.py:

    SHIELDAGI = {
        'RATE_LIMITS': {
            'auth': {'window_seconds': 60, 'max_requests': 5},
            'api': {'window_seconds': 60, 'max_requests': 100},
            'public': {'window_seconds': 60, 'max_requests': 30},
        },
        'ALLOWED_ORIGINS': ['https://yourdomain.com'],
        'ADMIN_PATHS': ['/api/admin/', '/api/users/manage/'],
        'PUBLIC_PATHS': ['/api/auth/login/', '/api/auth/signup/', '/api/health/'],
    }
"""

import json
import re
import time
import uuid
import logging
from collections import defaultdict
from django.conf import settings
from django.http import JsonResponse

logger = logging.getLogger('shieldagi.chain_walls')

# ═══════════════════════════════════════════════
# IN-MEMORY RATE LIMIT STORE
# ═══════════════════════════════════════════════

_rate_limit_store: dict[str, dict] = {}

DANGEROUS_PATTERNS = [
    re.compile(r'(<script[\s>])', re.I),
    re.compile(r'(javascript:)', re.I),
    re.compile(r'(on\w+\s*=)', re.I),
    re.compile(r'(\bUNION\b.*\bSELECT\b)', re.I),
    re.compile(r'(\bDROP\b.*\bTABLE\b)', re.I),
    re.compile(r'(;\s*DROP\b)', re.I),
    re.compile(r'(\.\.\/)', re.I),
    re.compile(r'(%2e%2e)', re.I),
    re.compile(r'(%00)'),
]

BLOCKED_PREFIXES = ('10.', '172.16.', '192.168.', '127.', '169.254.', '0.')


def _get_config():
    return getattr(settings, 'SHIELDAGI', {})


def _get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'unknown')


def _error_response(status, message, correlation_id):
    return JsonResponse(
        {'error': message, 'correlationId': correlation_id},
        status=status,
    )


class ChainWallsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        config = _get_config()
        correlation_id = str(uuid.uuid4())
        ip = _get_client_ip(request)
        path = request.path
        method = request.method

        request.correlation_id = correlation_id
        request.client_ip = ip

        # ── WALL 1: Rate Limiter ──
        result = self._wall_rate_limiter(ip, path, config)
        if result:
            self._log_rejection('Rate Limiter', correlation_id, ip, path, result)
            return _error_response(429, result, correlation_id)

        # ── WALL 2: Input Sanitizer ──
        result = self._wall_input_sanitizer(request)
        if result:
            self._log_rejection('Input Sanitizer', correlation_id, ip, path, result)
            return _error_response(400, result, correlation_id)

        # ── WALL 3: Auth Validator ──
        public_paths = config.get('PUBLIC_PATHS', ['/api/auth/login/', '/api/auth/signup/', '/api/health/'])
        if path.startswith('/api/') and not any(path.startswith(p) for p in public_paths):
            result = self._wall_auth_validator(request)
            if result:
                self._log_rejection('Auth Validator', correlation_id, ip, path, result)
                return _error_response(401, result, correlation_id)

        # ── WALL 4: CSRF Guard ──
        if method not in ('GET', 'HEAD', 'OPTIONS'):
            result = self._wall_csrf_guard(request, config)
            if result:
                self._log_rejection('CSRF Guard', correlation_id, ip, path, result)
                return _error_response(403, result, correlation_id)

        # ── WALL 5: RBAC Enforcer ──
        admin_paths = config.get('ADMIN_PATHS', ['/api/admin/'])
        if any(path.startswith(p) for p in admin_paths):
            if not (hasattr(request, 'user') and request.user.is_staff):
                self._log_rejection('RBAC Enforcer', correlation_id, ip, path, 'Insufficient permissions')
                return _error_response(403, 'Insufficient permissions', correlation_id)

        # ── WALL 6: SSRF Shield ──
        result = self._wall_ssrf_shield(request)
        if result:
            self._log_rejection('SSRF Shield', correlation_id, ip, path, result)
            return _error_response(403, result, correlation_id)

        # ── WALL 7: Request Logger ──
        start_time = time.time()

        response = self.get_response(request)

        duration = int((time.time() - start_time) * 1000)
        logger.info(json.dumps({
            'type': 'request',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'correlationId': correlation_id,
            'ip': ip,
            'method': method,
            'path': path,
            'status': response.status_code,
            'duration_ms': duration,
            'userId': str(getattr(request.user, 'id', 'anonymous')) if hasattr(request, 'user') else 'anonymous',
        }))

        # Security headers
        response['X-Correlation-ID'] = correlation_id
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response['Cross-Origin-Opener-Policy'] = 'same-origin'

        return response

    def _wall_rate_limiter(self, ip, path, config):
        category = 'auth' if '/auth/' in path else 'api' if path.startswith('/api/') else 'public'
        limits = config.get('RATE_LIMITS', {}).get(category, {'window_seconds': 60, 'max_requests': 100})
        key = f'{category}:{ip}'
        now = time.time()

        entry = _rate_limit_store.get(key)
        if not entry or now > entry['reset_at']:
            _rate_limit_store[key] = {'count': 1, 'reset_at': now + limits['window_seconds']}
            return None

        entry['count'] += 1
        if entry['count'] > limits['max_requests']:
            retry_after = int(entry['reset_at'] - now)
            return f'Rate limit exceeded. Try again in {retry_after}s'
        return None

    def _wall_input_sanitizer(self, request):
        for key, value in request.GET.items():
            if len(value) > 2000:
                return f'Parameter too long: {key}'
            for pattern in DANGEROUS_PATTERNS:
                if pattern.search(value):
                    return f'Malicious input in: {key}'

        if request.content_type == 'application/json' and request.body:
            try:
                body = json.loads(request.body)
                err = self._check_dict(body)
                if err:
                    return err
            except json.JSONDecodeError:
                return 'Invalid JSON body'
        return None

    def _check_dict(self, obj, prefix=''):
        if not isinstance(obj, dict):
            return None
        for key, value in obj.items():
            if isinstance(value, str):
                if len(value) > 10000:
                    return f'Body field too long: {prefix}{key}'
                for pattern in DANGEROUS_PATTERNS:
                    if pattern.search(value):
                        return f'Malicious input in body: {prefix}{key}'
            elif isinstance(value, dict):
                err = self._check_dict(value, f'{prefix}{key}.')
                if err:
                    return err
        return None

    def _wall_auth_validator(self, request):
        if hasattr(request, 'user') and request.user.is_authenticated:
            return None
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return 'Missing authorization'
        # Django REST Framework handles full JWT validation — we just check presence
        return None

    def _wall_csrf_guard(self, request, config):
        if request.META.get('HTTP_X_API_KEY'):
            return None
        origin = request.META.get('HTTP_ORIGIN')
        allowed = config.get('ALLOWED_ORIGINS', [])
        if origin and allowed and origin not in allowed:
            return f'CSRF: Origin not allowed'
        return None

    def _wall_ssrf_shield(self, request):
        params = {**request.GET.dict(), **(json.loads(request.body) if request.body and request.content_type == 'application/json' else {})}
        for key, value in params.items():
            if not isinstance(value, str):
                continue
            if not any(k in key.lower() for k in ('url', 'redirect', 'callback', 'webhook')):
                continue
            try:
                from urllib.parse import urlparse
                parsed = urlparse(value)
                if parsed.hostname and (
                    any(parsed.hostname.startswith(p) for p in BLOCKED_PREFIXES) or
                    parsed.hostname == 'localhost' or
                    parsed.scheme not in ('http', 'https')
                ):
                    return 'SSRF: Blocked request'
            except Exception:
                pass
        return None

    def _log_rejection(self, wall_name, correlation_id, ip, path, message):
        logger.warning(json.dumps({
            'type': 'chain_wall_reject',
            'wall': wall_name,
            'correlationId': correlation_id,
            'ip': ip,
            'path': path,
            'message': message,
        }))
