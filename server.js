// ============================================================
// MSME Tool — License & Usage Tracking Server
// Stack : Node.js + Express + JSON file DB (no compilation)
// Host  : Render / Railway free tier
// ============================================================

const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'msme@admin2024';

// ── Pure JSON file database — zero native modules ──────────────
const DB_FILE = path.join('/tmp', 'db.json');   // /tmp survives restarts on Render

function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    const blank = { licenses: {}, usage_log: [], entities: {} };
    fs.writeFileSync(DB_FILE, JSON.stringify(blank, null, 2));
    return blank;
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e) { return { licenses: {}, usage_log: [], entities: {} }; }
}
function writeDB(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }

function cycleStart() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-01`;
}
function nowISO() { return new Date().toISOString().slice(0,19).replace('T',' '); }
function requireAdmin(req, res, next) {
  const pw = req.headers['x-admin-password'] || req.query.pw;
  if (pw !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-License-Key,X-Admin-Password');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── POST /api/validate ─────────────────────────────────────────
app.post('/api/validate', (req, res) => {
  const { key, entityName = 'Unknown', vendorCount = 0, rowCount = 0 } = req.body;
  const origin = req.headers.origin || req.headers.referer || 'unknown';
  if (!key) return res.json({ valid: false, message: 'No license key provided.' });

  const db  = readDB();
  const lic = db.licenses[key];
  if (!lic)        return res.json({ valid: false, message: 'Invalid license key. Contact your account manager.' });
  if (!lic.active) return res.json({ valid: false, message: 'License suspended. Contact support.' });
  if (lic.expires_on && new Date(lic.expires_on) < new Date())
    return res.json({ valid: false, message: `License expired on ${lic.expires_on}. Please renew.` });
  if (lic.locked_domain && origin !== 'unknown' && !origin.includes(lic.locked_domain))
    return res.json({ valid: false, message: `License locked to ${lic.locked_domain}.` });

  const cs            = cycleStart();
  const cycleLogs     = db.usage_log.filter(u => u.license_key === key && u.logged_at >= cs);
  const entitiesUsed  = new Set(cycleLogs.map(u => u.entity_name)).size;
  const reportsUsed   = cycleLogs.length;
  const isNewEntity   = !cycleLogs.find(u => u.entity_name === entityName);

  if (isNewEntity && entitiesUsed >= lic.entity_limit)
    return res.json({ valid: false, message: `Entity limit reached (${lic.entity_limit}/month on ${lic.plan} plan). Upgrade to continue.` });
  if (reportsUsed >= lic.report_limit)
    return res.json({ valid: false, message: `Report limit reached (${lic.report_limit}/month on ${lic.plan} plan). Upgrade to continue.` });

  db.usage_log.push({ id: Date.now(), license_key: key, entity_name: entityName,
    vendor_count: vendorCount, row_count: rowCount, origin, logged_at: nowISO() });

  const eKey = `${key}||${entityName}`;
  if (!db.entities[eKey])
    db.entities[eKey] = { license_key: key, entity_name: entityName, first_seen: nowISO(), run_count: 0 };
  db.entities[eKey].last_seen = nowISO();
  db.entities[eKey].run_count++;
  writeDB(db);

  const eu = entitiesUsed + (isNewEntity ? 1 : 0);
  return res.json({ valid: true, message: `Licensed to: ${lic.client_name}`,
    clientName: lic.client_name, plan: lic.plan,
    entityLimit: lic.entity_limit,    reportLimit: lic.report_limit,
    entitiesUsed: eu,                 reportsUsed: reportsUsed + 1,
    entitiesRemaining: lic.entity_limit - eu,
    reportsRemaining:  lic.report_limit - reportsUsed - 1,
    expiresOn: lic.expires_on || 'Never' });
});

// ── POST /admin/license/create ─────────────────────────────────
app.post('/admin/license/create', requireAdmin, (req, res) => {
  const { clientName, clientEmail='', plan='starter', entityLimit=5,
          reportLimit=100, expiresOn=null, lockedDomain=null, notes='' } = req.body;
  if (!clientName) return res.status(400).json({ error: 'clientName required' });
  const key = 'MSME-' + crypto.randomBytes(4).toString('hex').toUpperCase()
            + '-'     + crypto.randomBytes(4).toString('hex').toUpperCase();
  const db = readDB();
  db.licenses[key] = { key, client_name: clientName, client_email: clientEmail, plan,
    entity_limit: +entityLimit, report_limit: +reportLimit, expires_on: expiresOn,
    locked_domain: lockedDomain, active: true, notes, created_at: nowISO() };
  writeDB(db);
  res.json({ success: true, key, clientName, plan, entityLimit, reportLimit, expiresOn });
});

// ── GET /admin/licenses ────────────────────────────────────────
app.get('/admin/licenses', requireAdmin, (req, res) => {
  const db = readDB(); const cs = cycleStart();
  res.json(Object.values(db.licenses).map(l => {
    const cl = db.usage_log.filter(u => u.license_key === l.key && u.logged_at >= cs);
    return { ...l,
      entitiesUsedThisCycle: new Set(cl.map(u => u.entity_name)).size,
      reportsUsedThisCycle:  cl.length,
      totalReportsAllTime:   db.usage_log.filter(u => u.license_key === l.key).length };
  }).sort((a,b) => b.created_at.localeCompare(a.created_at)));
});

// ── GET /admin/license/:key/usage ──────────────────────────────
app.get('/admin/license/:key/usage', requireAdmin, (req, res) => {
  const key = req.params.key; const db = readDB();
  const lic = db.licenses[key];
  if (!lic) return res.status(404).json({ error: 'Not found' });
  const entities = Object.values(db.entities).filter(e => e.license_key === key)
    .sort((a,b) => b.last_seen.localeCompare(a.last_seen));
  const recent = db.usage_log.filter(u => u.license_key === key)
    .sort((a,b) => b.logged_at.localeCompare(a.logged_at)).slice(0,100);
  const mMap = {};
  db.usage_log.filter(u => u.license_key === key).forEach(u => {
    const m = u.logged_at.slice(0,7);
    if (!mMap[m]) mMap[m] = { month: m, entities: new Set(), reports: 0 };
    mMap[m].entities.add(u.entity_name); mMap[m].reports++;
  });
  const monthly = Object.values(mMap)
    .map(m => ({ month: m.month, entities: m.entities.size, reports: m.reports }))
    .sort((a,b) => b.month.localeCompare(a.month));
  res.json({ license: lic, entities, recent, monthly });
});

// ── Suspend / Activate ─────────────────────────────────────────
app.post('/admin/license/:key/suspend',  requireAdmin, (req,res) => {
  const db = readDB(); if (db.licenses[req.params.key]) { db.licenses[req.params.key].active = false; writeDB(db); } res.json({success:true}); });
app.post('/admin/license/:key/activate', requireAdmin, (req,res) => {
  const db = readDB(); if (db.licenses[req.params.key]) { db.licenses[req.params.key].active = true;  writeDB(db); } res.json({success:true}); });

// ── GET /admin/dashboard ───────────────────────────────────────
app.get('/admin/dashboard', requireAdmin, (req, res) => {
  const db = readDB(); const cs = cycleStart();
  const all = Object.values(db.licenses);
  const cl  = db.usage_log.filter(u => u.logged_at >= cs);
  const tMap = {};
  cl.forEach(u => {
    const n = db.licenses[u.license_key]?.client_name || u.license_key;
    if (!tMap[u.license_key]) tMap[u.license_key] = { client_name: n, reports: 0, entities: new Set() };
    tMap[u.license_key].reports++; tMap[u.license_key].entities.add(u.entity_name);
  });
  res.json({ totalLicenses: all.length, activeLicenses: all.filter(l=>l.active).length,
    reportsThisCycle: cl.length,
    entitiesThisCycle: new Set(cl.map(u=>`${u.license_key}|${u.entity_name}`)).size,
    topUsers: Object.values(tMap).map(u=>({...u, entities:u.entities.size})).sort((a,b)=>b.reports-a.reports).slice(0,10) });
});

app.get('/admin', (req,res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/',      (req,res) => res.json({ status: 'MSME License Server running', version: '1.0' }));

app.listen(PORT, () => console.log(`MSME License Server on port ${PORT}`));
