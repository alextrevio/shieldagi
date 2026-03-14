/**
 * ShieldAGI Vulnerable Test Application
 *
 * ⚠️  THIS APP IS DELIBERATELY VULNERABLE ⚠️
 * It contains ALL OWASP Top 10 vulnerabilities for testing ShieldAGI's
 * scanning, exploitation, and remediation capabilities.
 *
 * NEVER deploy this to production or expose it to the internet.
 * Run ONLY inside the shieldagi-sandbox Docker network.
 */

const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ═══════════════════════════════════════════════
// VULN: No security headers (A05: Security Misconfiguration)
// Missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
// ═══════════════════════════════════════════════

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ═══════════════════════════════════════════════
// VULN: SQL Injection (A03: Injection)
// String concatenation in SQL queries
// ═══════════════════════════════════════════════

app.get('/api/users/search', async (req, res) => {
  const { name } = req.query;
  // VULNERABLE: Direct string interpolation in SQL
  const result = await pool.query(`SELECT id, name, email FROM users WHERE name LIKE '%${name}%'`);
  res.json(result.rows);
});

app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  // VULNERABLE: SQL injection in login
  const result = await pool.query(
    `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`
  );

  if (result.rows.length > 0) {
    // VULN: Weak JWT secret (A07: Identification and Authentication Failures)
    const token = jwt.sign(
      { sub: result.rows[0].id, email: result.rows[0].email, role: result.rows[0].role },
      process.env.JWT_SECRET, // 'super-weak-secret-for-testing'
      { expiresIn: '30d' } // VULN: Token lives too long
    );
    // VULN: Cookie without Secure, HttpOnly, SameSite (A05)
    res.cookie('session', token);
    res.json({ token, user: result.rows[0] });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ═══════════════════════════════════════════════
// VULN: No rate limiting (A07: Auth Failures)
// No brute force protection at all
// ═══════════════════════════════════════════════

// ═══════════════════════════════════════════════
// VULN: XSS - Stored (A03: Injection)
// User content rendered without sanitization
// ═══════════════════════════════════════════════

app.post('/api/comments', async (req, res) => {
  const { content, post_id } = req.body;
  // VULNERABLE: Stores raw HTML/script content
  await pool.query('INSERT INTO comments (content, post_id) VALUES ($1, $2)', [content, post_id]);
  res.json({ success: true });
});

app.get('/api/comments/:postId', async (req, res) => {
  const result = await pool.query('SELECT * FROM comments WHERE post_id = $1', [req.params.postId]);
  // VULNERABLE: Returns raw HTML content that will be rendered unsanitized
  res.json(result.rows);
});

// XSS - Reflected
app.get('/api/search', (req, res) => {
  const { q } = req.query;
  // VULNERABLE: Reflects user input in HTML response
  res.send(`<html><body><h1>Search results for: ${q}</h1></body></html>`);
});

// ═══════════════════════════════════════════════
// VULN: CSRF (A01: Broken Access Control)
// No CSRF tokens, no origin validation
// ═══════════════════════════════════════════════

app.post('/api/users/update-email', async (req, res) => {
  const token = req.cookies.session || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { newEmail } = req.body;
    // VULNERABLE: No CSRF protection — this can be triggered from any origin
    await pool.query('UPDATE users SET email = $1 WHERE id = $2', [newEmail, decoded.sub]);
    res.json({ success: true });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ═══════════════════════════════════════════════
// VULN: SSRF (A10: Server-Side Request Forgery)
// Accepts arbitrary URLs for server-side fetching
// ═══════════════════════════════════════════════

app.post('/api/fetch-url', async (req, res) => {
  const { url } = req.body;
  try {
    // VULNERABLE: No URL validation, can fetch internal resources
    const response = await fetch(url);
    const data = await response.text();
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════
// VULN: IDOR (A01: Broken Access Control)
// No ownership validation on resource access
// ═══════════════════════════════════════════════

app.get('/api/documents/:id', async (req, res) => {
  // VULNERABLE: Any authenticated user can access any document by ID
  const result = await pool.query('SELECT * FROM documents WHERE id = $1', [req.params.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  res.json(result.rows[0]);
});

app.delete('/api/documents/:id', async (req, res) => {
  // VULNERABLE: Any user can delete any document
  await pool.query('DELETE FROM documents WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════
// VULN: Path Traversal (A01: Broken Access Control)
// No path sanitization on file access
// ═══════════════════════════════════════════════

app.get('/api/files/:filename', (req, res) => {
  const { filename } = req.params;
  // VULNERABLE: No path sanitization — ../../etc/passwd works
  const filePath = path.join(__dirname, 'uploads', filename);
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json({ error: 'File not found' });
  }
});

// ═══════════════════════════════════════════════
// VULN: Hardcoded secrets (A02: Cryptographic Failures)
// ═══════════════════════════════════════════════

const ADMIN_API_KEY = 'sk-admin-12345-super-secret-key';
const DATABASE_BACKUP_KEY = 'backup-key-do-not-share-2024';

app.get('/api/admin/backup', (req, res) => {
  if (req.headers['x-api-key'] === ADMIN_API_KEY) {
    res.json({ status: 'Backup started', key: DATABASE_BACKUP_KEY });
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});

// ═══════════════════════════════════════════════
// VULN: Information disclosure in errors
// ═══════════════════════════════════════════════

app.use((err, req, res, next) => {
  // VULNERABLE: Exposes stack trace and internal details
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    database: process.env.DATABASE_URL,
  });
});

// Health check (intentionally safe)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0-vulnerable' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`⚠️  VULNERABLE TEST APP running on port ${PORT}`);
  console.log(`⚠️  DO NOT expose to the internet`);
});
