// ============================================================
// MSME Tool — License & Usage Tracking Server
// Stack : Node.js + Express + better-sqlite3 (all free)
// Host  : Railway / Render / Fly.io  (free tier)
// ============================================================

const express  = require('express');
const Database = require('better-sqlite3');
const crypto   = require('crypto');
const path     = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Your master admin password (change this before deploying) ──
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'msme@admin2024';

// ── Open / create SQLite database ──────────────────────────────
const db = new Database(path.join(__dirname, 'licenses.db'));

// ── Schema ─────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    key            TEXT PRIMARY KEY,
    client_name    TEXT NOT NULL,
    client_email   TEXT,
    plan           TEXT DEFAULT 'starter',   -- starter | professional | enterprise
    entity_limit   INTEGER DEFAULT 5,        -- max unique entities per billing cycle
    report_limit   INTEGER DEFAULT 100,      -- max report runs per billing cycle
    expires_on     TEXT,                     -- YYYY-MM-DD, NULL = never
    locked_domain  TEXT,                     -- optional domain lock e.g. big4.com
    active         INTEGER DEFAULT 1,        -- 0 = suspended
    notes          TEXT,
    created_at     TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS usage_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key    TEXT NOT NULL,
    entity_name    TEXT,                     -- company name the tool was run for
    report_type    TEXT,                     -- 'full' | 'summary' etc.
    vendor_count   INTEGER DEFAULT 0,
    row_count      INTEGER DEFAULT 0,
    ip_address     TEXT,
    origin         TEXT,
    logged_at      TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(license_key) REFERENCES licenses(key)
  );

  CREATE TABLE IF NOT EXISTS entities (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key    TEXT NOT NULL,
    entity_name    TEXT NOT NULL,
    first_seen     TEXT DEFAULT (datetime('now')),
    last_seen      TEXT DEFAULT (datetime('now')),
    run_count      INTEGER DEFAULT 1,
    UNIQUE(license_key, entity_name)
  );
`);

app.use(express.json());

// ── CORS: allow the tool HTML to call this API from anywhere ───
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-License-Key');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Helper: get billing-cycle start (1st of current month) ─────
function cycleStart() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-01`;
}

// ── Helper: simple admin auth ───────────────────────────────────
function requireAdmin(req, res, next) {
  const pw = req.headers['x-admin-password'] || req.query.pw;
  if (pw !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ═══════════════════════════════════════════════════════════════
// PUBLIC API  (called by the MSME tool HTML)
// ═══════════════════════════════════════════════════════════════

// ── POST /api/validate ──────────────────────────────────────────
// Body: { key, entityName, vendorCount, rowCount }
// Returns: { valid, message, plan, entityLimit, reportLimit,
//            entitiesUsed, reportsUsed, entitiesRemaining, reportsRemaining }
app.post('/api/validate', (req, res) => {
  const { key, entityName = 'Unknown', vendorCount = 0, rowCount = 0 } = req.body;
  const origin = req.headers.origin || req.headers.referer || 'unknown';
  const ip     = req.ip;

  if (!key) return res.json({ valid: false, message: 'No license key provided.' });

  const lic = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key);
  if (!lic)        return res.json({ valid: false, message: 'Invalid license key.' });
  if (!lic.active) return res.json({ valid: false, message: 'License is suspended. Contact support.' });

  // Expiry check
  if (lic.expires_on && new Date(lic.expires_on) < new Date()) {
    return res.json({ valid: false, message: `License expired on ${lic.expires_on}. Please renew.` });
  }

  // Domain lock check (only if locked_domain is set)
  if (lic.locked_domain && origin !== 'unknown') {
    if (!origin.includes(lic.locked_domain)) {
      return res.json({ valid: false, message: `This license is locked to ${lic.locked_domain}.` });
    }
  }

  const cs = cycleStart();

  // Count entities used this cycle
  const entitiesUsed = db.prepare(
    `SELECT COUNT(DISTINCT entity_name) as c FROM usage_log
     WHERE license_key=? AND logged_at >= ?`
  ).get(key, cs).c;

  // Count reports run this cycle
  const reportsUsed = db.prepare(
    `SELECT COUNT(*) as c FROM usage_log WHERE license_key=? AND logged_at >= ?`
  ).get(key, cs).c;

  // Check limits
  const isNewEntity = !db.prepare(
    `SELECT 1 FROM usage_log WHERE license_key=? AND entity_name=? AND logged_at >= ?`
  ).get(key, entityName, cs);

  if (isNewEntity && entitiesUsed >= lic.entity_limit) {
    return res.json({
      valid: false,
      message: `Entity limit reached (${lic.entity_limit} entities/cycle on your ${lic.plan} plan). Contact your account manager to upgrade.`,
      plan: lic.plan, entitiesUsed, entityLimit: lic.entity_limit
    });
  }

  if (reportsUsed >= lic.report_limit) {
    return res.json({
      valid: false,
      message: `Report limit reached (${lic.report_limit} reports/cycle on your ${lic.plan} plan). Contact your account manager to upgrade.`,
      plan: lic.plan, reportsUsed, reportLimit: lic.report_limit
    });
  }

  // ── Log the usage ─────────────────────────────────────────────
  db.prepare(`
    INSERT INTO usage_log(license_key, entity_name, report_type, vendor_count, row_count, ip_address, origin)
    VALUES (?,?,?,?,?,?,?)
  `).run(key, entityName, 'full', vendorCount, rowCount, ip, origin);

  // Track entity (upsert)
  db.prepare(`
    INSERT INTO entities(license_key, entity_name) VALUES(?,?)
    ON CONFLICT(license_key, entity_name) DO UPDATE SET
      last_seen = datetime('now'), run_count = run_count + 1
  `).run(key, entityName);

  return res.json({
    valid          : true,
    message        : `Licensed to: ${lic.client_name}`,
    clientName     : lic.client_name,
    plan           : lic.plan,
    entityLimit    : lic.entity_limit,
    reportLimit    : lic.report_limit,
    entitiesUsed   : entitiesUsed + (isNewEntity ? 1 : 0),
    reportsUsed    : reportsUsed + 1,
    entitiesRemaining: lic.entity_limit - entitiesUsed - (isNewEntity ? 1 : 0),
    reportsRemaining : lic.report_limit - reportsUsed - 1,
    expiresOn      : lic.expires_on || 'Never',
  });
});

// ═══════════════════════════════════════════════════════════════
// ADMIN API  (only you — protected by ADMIN_PASSWORD)
// ═══════════════════════════════════════════════════════════════

// ── POST /admin/license/create ─────────────────────────────────
app.post('/admin/license/create', requireAdmin, (req, res) => {
  const { clientName, clientEmail, plan='starter', entityLimit=5, reportLimit=100, expiresOn=null, lockedDomain=null, notes='' } = req.body;
  if (!clientName) return res.status(400).json({ error: 'clientName required' });

  const key = 'MSME-' + crypto.randomBytes(4).toString('hex').toUpperCase() +
              '-' + crypto.randomBytes(4).toString('hex').toUpperCase();

  db.prepare(`
    INSERT INTO licenses(key,client_name,client_email,plan,entity_limit,report_limit,expires_on,locked_domain,notes)
    VALUES(?,?,?,?,?,?,?,?,?)
  `).run(key, clientName, clientEmail||'', plan, entityLimit, reportLimit, expiresOn, lockedDomain, notes);

  res.json({ success: true, key, clientName, plan, entityLimit, reportLimit, expiresOn });
});

// ── GET /admin/licenses ────────────────────────────────────────
app.get('/admin/licenses', requireAdmin, (req, res) => {
  const licenses = db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all();
  const cs = cycleStart();
  const result = licenses.map(l => {
    const eu = db.prepare(`SELECT COUNT(DISTINCT entity_name) as c FROM usage_log WHERE license_key=? AND logged_at>=?`).get(l.key,cs).c;
    const ru = db.prepare(`SELECT COUNT(*) as c FROM usage_log WHERE license_key=? AND logged_at>=?`).get(l.key,cs).c;
    const total = db.prepare(`SELECT COUNT(*) as c FROM usage_log WHERE license_key=?`).get(l.key).c;
    return { ...l, entitiesUsedThisCycle: eu, reportsUsedThisCycle: ru, totalReportsAllTime: total };
  });
  res.json(result);
});

// ── GET /admin/license/:key/usage ──────────────────────────────
app.get('/admin/license/:key/usage', requireAdmin, (req, res) => {
  const key = req.params.key;
  const lic = db.prepare('SELECT * FROM licenses WHERE key=?').get(key);
  if (!lic) return res.status(404).json({ error: 'Not found' });

  const entities = db.prepare(`SELECT * FROM entities WHERE license_key=? ORDER BY last_seen DESC`).all(key);
  const recent   = db.prepare(`SELECT * FROM usage_log WHERE license_key=? ORDER BY logged_at DESC LIMIT 100`).all(key);
  const monthly  = db.prepare(`
    SELECT strftime('%Y-%m', logged_at) as month,
           COUNT(DISTINCT entity_name) as entities,
           COUNT(*) as reports
    FROM usage_log WHERE license_key=? GROUP BY month ORDER BY month DESC
  `).all(key);

  res.json({ license: lic, entities, recent, monthly });
});

// ── POST /admin/license/:key/suspend ──────────────────────────
app.post('/admin/license/:key/suspend', requireAdmin, (req, res) => {
  db.prepare('UPDATE licenses SET active=0 WHERE key=?').run(req.params.key);
  res.json({ success: true });
});

// ── POST /admin/license/:key/activate ─────────────────────────
app.post('/admin/license/:key/activate', requireAdmin, (req, res) => {
  db.prepare('UPDATE licenses SET active=1 WHERE key=?').run(req.params.key);
  res.json({ success: true });
});

// ── GET /admin/dashboard ───────────────────────────────────────
app.get('/admin/dashboard', requireAdmin, (req, res) => {
  const cs = cycleStart();
  const totalLicenses  = db.prepare('SELECT COUNT(*) as c FROM licenses').get().c;
  const activeLicenses = db.prepare('SELECT COUNT(*) as c FROM licenses WHERE active=1').get().c;
  const reportsThisCycle = db.prepare(`SELECT COUNT(*) as c FROM usage_log WHERE logged_at>=?`).get(cs).c;
  const entitiesThisCycle = db.prepare(`SELECT COUNT(DISTINCT entity_name||'|'||license_key) as c FROM usage_log WHERE logged_at>=?`).get(cs).c;
  const topUsers = db.prepare(`
    SELECT l.client_name, COUNT(*) as reports, COUNT(DISTINCT u.entity_name) as entities
    FROM usage_log u JOIN licenses l ON l.key=u.license_key
    WHERE u.logged_at>=? GROUP BY u.license_key ORDER BY reports DESC LIMIT 10
  `).all(cs);
  res.json({ totalLicenses, activeLicenses, reportsThisCycle, entitiesThisCycle, topUsers });
});

// ── Serve admin UI ─────────────────────────────────────────────
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/', (req, res) => {
  res.json({ status: 'MSME License Server running', version: '1.0' });
});

app.listen(PORT, () => console.log(`MSME License Server on port ${PORT}`));
