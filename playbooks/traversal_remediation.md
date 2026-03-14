# Path Traversal Remediation Playbook

## Priority: HIGH
## CVSS Range: 5.3 - 8.6
## OWASP: A01:2021 — Broken Access Control
## CWE: CWE-22, CWE-23

## Universal Path Sanitizer

```typescript
// lib/path-guard.ts
import path from 'path';

const ALLOWED_BASE_DIRS = [
  '/app/public',
  '/app/uploads',
  '/app/static',
];

export function sanitizePath(userPath: string, baseDir: string): { safe: boolean; resolved: string; reason?: string } {
  // Strip null bytes
  const cleaned = userPath.replace(/\0/g, '');
  // Decode multiple layers of URL encoding
  let decoded = cleaned;
  for (let i = 0; i < 3; i++) {
    try { decoded = decodeURIComponent(decoded); } catch { break; }
  }
  // Resolve to absolute
  const resolved = path.resolve(baseDir, decoded);
  // Verify it stays within the base directory
  if (!resolved.startsWith(path.resolve(baseDir) + path.sep) && resolved !== path.resolve(baseDir)) {
    return { safe: false, resolved, reason: `Path escapes base directory: ${resolved}` };
  }
  // Block sensitive file patterns
  const sensitivePatterns = [/\.env/, /\.git/, /node_modules/, /\.ssh/, /etc\/passwd/, /etc\/shadow/];
  if (sensitivePatterns.some(p => p.test(resolved))) {
    return { safe: false, resolved, reason: 'Access to sensitive file blocked' };
  }
  return { safe: true, resolved };
}
```

### Next.js
```typescript
import { sanitizePath } from '@/lib/path-guard';

export async function GET(request: NextRequest) {
  const filename = request.nextUrl.searchParams.get('file');
  if (!filename) return NextResponse.json({ error: 'Missing file parameter' }, { status: 400 });
  const { safe, resolved, reason } = sanitizePath(filename, '/app/public/uploads');
  if (!safe) return NextResponse.json({ error: reason }, { status: 403 });
  // ... serve file from resolved path
}
```

### Express
```javascript
const { sanitizePath } = require('./lib/path-guard');
app.get('/files/:filename', (req, res) => {
  const { safe, resolved, reason } = sanitizePath(req.params.filename, '/app/uploads');
  if (!safe) return res.status(403).json({ error: reason });
  res.sendFile(resolved);
});
```

### Django
```python
import os

def serve_file(request, filename):
    base_dir = os.path.abspath('/app/uploads')
    requested = os.path.abspath(os.path.join(base_dir, filename))
    if not requested.startswith(base_dir + os.sep):
        return HttpResponseForbidden('Path traversal blocked')
    return FileResponse(open(requested, 'rb'))
```

## Verification
Re-run `path_traverse` with all encoding levels — verified when no path escapes the base directory.
