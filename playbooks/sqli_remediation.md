# SQL Injection Remediation Playbook

## Priority: CRITICAL
## CVSS Range: 7.5 - 10.0
## OWASP: A03:2021 — Injection
## CWE: CWE-89

## Detection Patterns

### What the Code Auditor found:
- String concatenation in SQL queries
- Template literals with user-controlled variables in SQL
- Raw query methods with unsanitized parameters
- ORM bypass patterns (.raw(), .extra(), cursor.execute() with f-strings)

### What the Attack Executor proved:
- sqlmap confirmed injection (boolean/time/union/stacked/error-based)
- Database type and version extracted
- Tables/data accessible via injection

## Remediation Steps

### 1. Next.js + Supabase

**Before (vulnerable):**
```typescript
// Edge function with raw SQL
const { data } = await supabase.rpc('search_users', {
  query: `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`
});

// Direct query construction
const result = await supabase
  .from('products')
  .select('*')
  .filter('name', 'ilike', userInput); // SAFE — but watch for .rpc()
```

**After (secure):**
```typescript
// Use Supabase SDK methods — they parameterize automatically
const { data } = await supabase
  .from('users')
  .select('*')
  .ilike('name', `%${searchTerm}%`);

// If you MUST use .rpc(), use parameterized functions
// In your Supabase migration:
// CREATE FUNCTION search_users(search_term text)
// RETURNS SETOF users AS $$
//   SELECT * FROM users WHERE name ILIKE '%' || search_term || '%';
// $$ LANGUAGE sql SECURITY DEFINER;

const { data } = await supabase.rpc('search_users', {
  search_term: searchTerm  // Passed as parameter, not interpolated
});
```

### 2. Express

**Before (vulnerable):**
```javascript
app.get('/users', async (req, res) => {
  const { search } = req.query;
  const result = await pool.query(
    `SELECT * FROM users WHERE name LIKE '%${search}%'`
  );
  res.json(result.rows);
});
```

**After (secure):**
```javascript
app.get('/users', async (req, res) => {
  const { search } = req.query;
  const result = await pool.query(
    'SELECT * FROM users WHERE name ILIKE $1',
    [`%${search}%`]
  );
  res.json(result.rows);
});
```

### 3. Django

**Before (vulnerable):**
```python
def search_users(request):
    term = request.GET.get('q')
    users = User.objects.raw(f"SELECT * FROM users WHERE name LIKE '%{term}%'")
    # Also vulnerable:
    users = User.objects.extra(where=[f"name LIKE '%{term}%'"])
```

**After (secure):**
```python
def search_users(request):
    term = request.GET.get('q')
    users = User.objects.filter(name__icontains=term)
    # If you need raw SQL:
    users = User.objects.raw(
        "SELECT * FROM users WHERE name ILIKE %s",
        [f'%{term}%']
    )
```

### 4. General Rules (all frameworks)
1. NEVER concatenate user input into SQL strings
2. ALWAYS use parameterized queries / prepared statements
3. Use the framework's ORM whenever possible
4. If raw SQL is required, use parameter binding ($1, %s, ?)
5. Add input type validation BEFORE the query:
   ```typescript
   // Validate type and length
   if (typeof searchTerm !== 'string' || searchTerm.length > 200) {
     return res.status(400).json({ error: 'Invalid search term' });
   }
   ```

## Chain Wall Integration
The **Input Sanitizer** (Chain Wall #2) adds a pre-query validation layer:
- Rejects requests containing SQL keywords in unexpected parameters
- Validates parameter types match expected schema
- Enforces maximum parameter length

## Verification
After applying fixes, the Attack Executor re-runs `sqlmap_attack` against each previously injectable endpoint. The fix is verified when sqlmap reports: "all tested parameters do not appear to be injectable."
