// Load .env if present (Node 20.12+; silently ignored otherwise)
try { if (typeof process.loadEnvFile === 'function') process.loadEnvFile(); } catch (_) {}

// server.js — SmartBiz backend
// Portable: config via env vars, paths relative to this file.
const express  = require('express');
const cors     = require('cors');
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

const PORT        = parseInt(process.env.PORT, 10) || 3000;
const HOST        = process.env.HOST || '0.0.0.0';
const DB_PATH     = process.env.DB_PATH || path.join(__dirname, 'data', 'submissions.db');
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || crypto.randomBytes(24).toString('hex');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*')
  .split(',').map(s => s.trim()).filter(Boolean);

// Ensure data dir exists (portable — works on fresh clones)
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous  = NORMAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS submissions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    business_name TEXT    NOT NULL,
    answers_json  TEXT    NOT NULL,
    user_agent    TEXT,
    ip            TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_created_at ON submissions (created_at);
`);

const insertStmt = db.prepare(`
  INSERT INTO submissions (business_name, answers_json, user_agent, ip)
  VALUES (?, ?, ?, ?)
`);

const app = express();
app.set('trust proxy', true);

app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) {
      return cb(null, true);
    }
    return cb(new Error('Origin not allowed'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'x-admin-token']
}));
app.use(express.json({ limit: '256kb' }));

// --- tiny in-memory rate limiter ---
const rateMap = new Map();
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_MAX = 10;

function rateLimit(req, res, next) {
  const ip  = req.ip || 'unknown';
  const now = Date.now();
  const e   = rateMap.get(ip) || { count: 0, reset: now + RATE_WINDOW_MS };
  if (now > e.reset) { e.count = 0; e.reset = now + RATE_WINDOW_MS; }
  e.count++;
  rateMap.set(ip, e);
  if (e.count > RATE_MAX) {
    return res.status(429).json({ ok: false, error: 'Too many submissions. Please try again later.' });
  }
  next();
}

// --- POST: receive a submission ---
app.post('/api/submissions', rateLimit, (req, res) => {
  try {
    const { businessName, answers } = req.body || {};

    if (typeof businessName !== 'string' || !businessName.trim()) {
      return res.status(400).json({ ok: false, error: 'businessName is required.' });
    }
    if (!answers || typeof answers !== 'object' || Array.isArray(answers)) {
      return res.status(400).json({ ok: false, error: 'answers must be an object.' });
    }

    const cleanName  = businessName.trim().slice(0, 200);
    const answersStr = JSON.stringify(answers);
    if (answersStr.length > 100_000) {
      return res.status(413).json({ ok: false, error: 'Answers are too large.' });
    }

    const info = insertStmt.run(
      cleanName,
      answersStr,
      String(req.get('user-agent') || '').slice(0, 400),
      String(req.ip || '').slice(0, 64)
    );

    console.log(`[${new Date().toISOString()}] saved #${info.lastInsertRowid} "${cleanName}"`);
    res.status(201).json({ ok: true, id: info.lastInsertRowid });
  } catch (err) {
    console.error('POST /api/submissions error:', err);
    res.status(500).json({ ok: false, error: 'Could not save submission.' });
  }
});

// --- admin auth ---
function requireAdmin(req, res, next) {
  const token = req.get('x-admin-token') || req.query.token;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ ok: false, error: 'Unauthorized.' });
  }
  next();
}

// --- GET: list ---
app.get('/api/submissions', requireAdmin, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 1000);
  const rows = db.prepare(`
    SELECT id, business_name, created_at, ip, user_agent
    FROM submissions ORDER BY id DESC LIMIT ?
  `).all(limit);
  res.json({ ok: true, count: rows.length, submissions: rows });
});

// --- GET: one ---
app.get('/api/submissions/:id', requireAdmin, (req, res) => {
  const row = db.prepare('SELECT * FROM submissions WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ ok: false, error: 'Not found.' });
  res.json({
    ok: true,
    submission: {
      id:           row.id,
      businessName: row.business_name,
      createdAt:    row.created_at,
      ip:           row.ip,
      userAgent:    row.user_agent,
      answers:      JSON.parse(row.answers_json)
    }
  });
});

// --- health ---
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// --- static frontend ---
app.use(express.static(path.join(__dirname, 'public')));

// --- start ---
app.listen(PORT, HOST, () => {
  console.log(`SmartBiz backend listening on http://${HOST}:${PORT}`);
  console.log(`DB file: ${DB_PATH}`);
  console.log(`Admin token: ${ADMIN_TOKEN}`);
  if (!process.env.ADMIN_TOKEN) {
    console.log('(generated — set ADMIN_TOKEN env var to keep it stable across restarts)');
  }
});
