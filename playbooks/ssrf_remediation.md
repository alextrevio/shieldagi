# SSRF Remediation Playbook

## Priority: HIGH-CRITICAL
## CVSS Range: 6.5 - 9.8
## OWASP: A10:2021 — Server-Side Request Forgery
## CWE: CWE-918

## Remediation by Framework

### Universal SSRF Protection Module

```typescript
// lib/ssrf-guard.ts — Use in ALL frameworks
import { URL } from 'url';
import dns from 'dns/promises';
import net from 'net';

const BLOCKED_IP_RANGES = [
  // IPv4 private ranges
  { start: '10.0.0.0', end: '10.255.255.255' },
  { start: '172.16.0.0', end: '172.31.255.255' },
  { start: '192.168.0.0', end: '192.168.255.255' },
  { start: '127.0.0.0', end: '127.255.255.255' },
  // Link-local
  { start: '169.254.0.0', end: '169.254.255.255' },
  // Cloud metadata
  { start: '169.254.169.254', end: '169.254.169.254' },
  // Loopback
  { start: '0.0.0.0', end: '0.255.255.255' },
];

const BLOCKED_HOSTNAMES = [
  'localhost',
  'metadata.google.internal',
  'metadata.google.com',
  '169.254.169.254',
  'instance-data',
  'kubernetes.default',
];

function ipToLong(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
}

function isPrivateIP(ip: string): boolean {
  if (net.isIPv6(ip)) {
    return ip.startsWith('::1') || ip.startsWith('fe80:') ||
           ip.startsWith('fc00:') || ip.startsWith('fd00:');
  }
  const ipLong = ipToLong(ip);
  return BLOCKED_IP_RANGES.some(range =>
    ipLong >= ipToLong(range.start) && ipLong <= ipToLong(range.end)
  );
}

export async function validateUrl(urlString: string, allowlist?: string[]): Promise<{ safe: boolean; reason?: string }> {
  try {
    const url = new URL(urlString);

    // Protocol check
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { safe: false, reason: `Blocked protocol: ${url.protocol}` };
    }

    // Hostname blocklist
    if (BLOCKED_HOSTNAMES.includes(url.hostname.toLowerCase())) {
      return { safe: false, reason: `Blocked hostname: ${url.hostname}` };
    }

    // Allowlist check (if configured)
    if (allowlist && allowlist.length > 0) {
      const allowed = allowlist.some(domain =>
        url.hostname === domain || url.hostname.endsWith(`.${domain}`)
      );
      if (!allowed) {
        return { safe: false, reason: `Hostname not in allowlist: ${url.hostname}` };
      }
    }

    // DNS resolution check — prevent DNS rebinding
    const addresses = await dns.resolve4(url.hostname).catch(() => []);
    const addresses6 = await dns.resolve6(url.hostname).catch(() => []);
    const allAddresses = [...addresses, ...addresses6];

    for (const ip of allAddresses) {
      if (isPrivateIP(ip)) {
        return { safe: false, reason: `Hostname ${url.hostname} resolves to private IP: ${ip}` };
      }
    }

    // Port check — block unusual ports
    const port = url.port ? parseInt(url.port) : (url.protocol === 'https:' ? 443 : 80);
    if (![80, 443, 8080, 8443].includes(port)) {
      return { safe: false, reason: `Unusual port: ${port}` };
    }

    return { safe: true };
  } catch (e) {
    return { safe: false, reason: `Invalid URL: ${e}` };
  }
}
```

### Next.js Integration
```typescript
// app/api/fetch-url/route.ts
import { validateUrl } from '@/lib/ssrf-guard';

export async function POST(request: NextRequest) {
  const { url } = await request.json();
  const validation = await validateUrl(url, ['api.example.com', 'cdn.example.com']);

  if (!validation.safe) {
    return NextResponse.json({ error: `SSRF blocked: ${validation.reason}` }, { status: 403 });
  }

  const response = await fetch(url, {
    redirect: 'manual', // Don't follow redirects (redirect chain SSRF)
    signal: AbortSignal.timeout(5000),
  });

  // Validate redirect target too
  if (response.status >= 300 && response.status < 400) {
    const redirectUrl = response.headers.get('location');
    if (redirectUrl) {
      const redirectValidation = await validateUrl(redirectUrl);
      if (!redirectValidation.safe) {
        return NextResponse.json({ error: 'SSRF blocked: redirect to internal resource' }, { status: 403 });
      }
    }
  }

  return NextResponse.json({ data: await response.text() });
}
```

### Express Integration
```javascript
const { validateUrl } = require('./lib/ssrf-guard');

app.post('/api/fetch', async (req, res) => {
  const { url } = req.body;
  const { safe, reason } = await validateUrl(url);
  if (!safe) return res.status(403).json({ error: `SSRF blocked: ${reason}` });
  // ... proceed with fetch
});
```

### Django Integration
```python
# lib/ssrf_guard.py
import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]

def validate_url(url_string, allowlist=None):
    parsed = urlparse(url_string)
    if parsed.scheme not in ('http', 'https'):
        return False, f'Blocked protocol: {parsed.scheme}'

    try:
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        for network in BLOCKED_NETWORKS:
            if addr in network:
                return False, f'Resolves to private IP: {ip}'
    except socket.gaierror:
        return False, 'DNS resolution failed'

    return True, None
```

## Verification
Re-run `ssrf_probe` — fix verified when all internal probes (metadata, localhost, private IPs) return 403.
