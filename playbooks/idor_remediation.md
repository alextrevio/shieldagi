# IDOR Remediation Playbook

## Priority: HIGH
## CVSS Range: 6.5 - 8.6
## OWASP: A01:2021 — Broken Access Control
## CWE: CWE-639

## Remediation by Framework

### Next.js + Supabase (RLS is your primary defense)

**Supabase RLS policies:**
```sql
-- EVERY table must have RLS enabled
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

-- SELECT: users can only read their own documents
CREATE POLICY "Users read own documents"
  ON public.documents FOR SELECT
  USING (auth.uid() = user_id);

-- INSERT: users can only create documents for themselves
CREATE POLICY "Users create own documents"
  ON public.documents FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- UPDATE: users can only update their own documents
CREATE POLICY "Users update own documents"
  ON public.documents FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- DELETE: users can only delete their own documents
CREATE POLICY "Users delete own documents"
  ON public.documents FOR DELETE
  USING (auth.uid() = user_id);

-- For shared resources, use a junction table:
CREATE POLICY "Users read shared documents"
  ON public.documents FOR SELECT
  USING (
    auth.uid() = user_id
    OR EXISTS (
      SELECT 1 FROM document_shares
      WHERE document_shares.document_id = documents.id
      AND document_shares.shared_with = auth.uid()
    )
  );
```

**API route validation (defense in depth):**
```typescript
// app/api/documents/[id]/route.ts
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const supabase = createServerClient(cookies());
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  // RLS handles this, but defense in depth:
  const { data, error } = await supabase
    .from('documents')
    .select('*')
    .eq('id', params.id)
    .single();

  if (!data) return NextResponse.json({ error: 'Not found' }, { status: 404 });
  return NextResponse.json(data);
}
```

### Express

```javascript
// middleware/ownership.js
function requireOwnership(resourceKey = 'user_id') {
  return async (req, res, next) => {
    const resourceId = req.params.id;
    const userId = req.user.id;

    const resource = await db.query(
      `SELECT ${resourceKey} FROM ${req.resourceTable} WHERE id = $1`,
      [resourceId]
    );

    if (!resource.rows.length) return res.status(404).json({ error: 'Not found' });
    if (resource.rows[0][resourceKey] !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }
    req.resource = resource.rows[0];
    next();
  };
}

// Usage
app.get('/api/documents/:id', authenticate, requireOwnership('user_id'), (req, res) => {
  res.json(req.resource);
});
```

### Django

```python
# Use get_queryset() filtering — NEVER fetch then check
class DocumentViewSet(viewsets.ModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # This ensures users ONLY see their own documents
        return Document.objects.filter(owner=self.request.user)

    # NEVER do this:
    # def retrieve(self, request, pk=None):
    #     doc = Document.objects.get(pk=pk)  # BAD — fetches ANY document
    #     if doc.owner != request.user: ...   # Race condition + info leak
```

## Additional Measures
1. Use UUIDs instead of sequential IDs (prevents enumeration)
2. Never expose internal IDs in URLs when possible (use slugs)
3. Log all access-denied events for the Sentinel Hand to monitor

## Verification
Re-run `idor_test` with two user contexts — verified when user B cannot access user A's resources.
