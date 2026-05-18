const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'msme@admin2024';
const DB_FILE = path.join(__dirname, 'db.json');  // persists across restarts

function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    const blank = { licenses: {}, usage_log: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(blank, null, 2));
    return blank;
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e) { return { licenses: {}, usage_log: [] }; }
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-Admin-Password');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── POST /api/validate ─────────────────────────────────────────
app.post('/api/validate', (req, res) => {
  const { key, entityName = 'Unknown', vendorCount = 0, rowCount = 0, loginOnly = false } = req.body;
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

  const cs        = cycleStart();
  const cycleLogs = db.usage_log.filter(u => u.license_key === key && u.logged_at >= cs);

  // loginOnly = true means just validate the key (called at login screen, not a real run)
  if (loginOnly) {
    return res.json({ valid: true, message: `Licensed to: ${lic.client_name}`,
      clientName: lic.client_name, plan: lic.plan,
      vendorLimit: lic.vendor_limit, runLimit: lic.run_limit,
      vendorsUsed: cycleLogs.reduce((s,u)=>s+(u.vendor_count||0),0),
      runsUsed: cycleLogs.length,
      expiresOn: lic.expires_on || 'Never' });
  }

  // ── Two limits: total vendors processed + total runs ──────────
  // vendorsUsed = SUM of vendorCount across all runs this cycle
  // runsUsed    = COUNT of runs this cycle
  const vendorsUsed = cycleLogs.reduce((s, u) => s + (u.vendor_count || 0), 0);
  const runsUsed    = cycleLogs.length;

  // Check vendor limit BEFORE this run
  if (vendorsUsed + vendorCount > lic.vendor_limit) {
    const remaining = Math.max(0, lic.vendor_limit - vendorsUsed);
    return res.json({ valid: false,
      message: `Vendor limit reached. You have ${remaining} vendors remaining this month (limit: ${lic.vendor_limit}). This run has ${vendorCount} vendors. Contact your account manager to upgrade.`,
      vendorsUsed, vendorLimit: lic.vendor_limit, remaining
    });
  }

  // Check run limit
  if (runsUsed >= lic.run_limit) {
    return res.json({ valid: false,
      message: `Report run limit reached (${lic.run_limit} runs/month on ${lic.plan} plan). Contact your account manager to upgrade.`,
      runsUsed, runLimit: lic.run_limit
    });
  }

  // ── Log usage ─────────────────────────────────────────────────
  db.usage_log.push({
    id: Date.now(), license_key: key,
    entity_name: entityName,
    vendor_count: vendorCount,
    row_count: rowCount,
    origin, logged_at: nowISO()
  });
  writeDB(db);

  const newVendorsUsed = vendorsUsed + vendorCount;
  return res.json({
    valid: true,
    message: `Licensed to: ${lic.client_name}`,
    clientName:       lic.client_name,
    plan:             lic.plan,
    vendorLimit:      lic.vendor_limit,
    runLimit:         lic.run_limit,
    vendorsUsed:      newVendorsUsed,
    runsUsed:         runsUsed + 1,
    vendorsRemaining: lic.vendor_limit - newVendorsUsed,
    runsRemaining:    lic.run_limit - runsUsed - 1,
    expiresOn:        lic.expires_on || 'Never'
  });
});

// ── POST /admin/license/create ─────────────────────────────────
app.post('/admin/license/create', requireAdmin, (req, res) => {
  const { clientName, clientEmail='', plan='starter',
          vendorLimit=50, runLimit=10,
          expiresOn=null, lockedDomain=null, notes='' } = req.body;
  if (!clientName) return res.status(400).json({ error: 'clientName required' });
  const key = 'MSME-' + crypto.randomBytes(4).toString('hex').toUpperCase()
            + '-'     + crypto.randomBytes(4).toString('hex').toUpperCase();
  const db = readDB();
  db.licenses[key] = {
    key, client_name: clientName, client_email: clientEmail, plan,
    vendor_limit: +vendorLimit, run_limit: +runLimit,
    expires_on: expiresOn, locked_domain: lockedDomain,
    active: true, notes, created_at: nowISO()
  };
  writeDB(db);
  res.json({ success: true, key, clientName, plan, vendorLimit, runLimit, expiresOn });
});

// ── GET /admin/licenses ────────────────────────────────────────
app.get('/admin/licenses', requireAdmin, (req, res) => {
  const db = readDB(); const cs = cycleStart();
  res.json(Object.values(db.licenses).map(l => {
    const cl = db.usage_log.filter(u => u.license_key === l.key && u.logged_at >= cs);
    const allLogs = db.usage_log.filter(u => u.license_key === l.key);
    return {
      ...l,
      vendorsUsedThisCycle: cl.reduce((s,u) => s + (u.vendor_count||0), 0),
      runsUsedThisCycle:    cl.length,
      totalRunsAllTime:     allLogs.length,
      totalVendorsAllTime:  allLogs.reduce((s,u) => s + (u.vendor_count||0), 0),
    };
  }).sort((a,b) => b.created_at.localeCompare(a.created_at)));
});

// ── GET /admin/license/:key/usage ──────────────────────────────
app.get('/admin/license/:key/usage', requireAdmin, (req, res) => {
  const key = req.params.key; const db = readDB();
  const lic = db.licenses[key];
  if (!lic) return res.status(404).json({ error: 'Not found' });

  const recent = db.usage_log.filter(u => u.license_key === key)
    .sort((a,b) => b.logged_at.localeCompare(a.logged_at)).slice(0,100);

  // Monthly rollup
  const mMap = {};
  db.usage_log.filter(u => u.license_key === key).forEach(u => {
    const m = u.logged_at.slice(0,7);
    if (!mMap[m]) mMap[m] = { month: m, vendors: 0, runs: 0, entities: new Set() };
    mMap[m].vendors += (u.vendor_count || 0);
    mMap[m].runs++;
    mMap[m].entities.add(u.entity_name);
  });
  const monthly = Object.values(mMap)
    .map(m => ({ month: m.month, vendors: m.vendors, runs: m.runs, entities: m.entities.size }))
    .sort((a,b) => b.month.localeCompare(a.month));

  res.json({ license: lic, recent, monthly });
});

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
    if (!tMap[u.license_key]) tMap[u.license_key] = { client_name: n, runs: 0, vendors: 0 };
    tMap[u.license_key].runs++;
    tMap[u.license_key].vendors += (u.vendor_count || 0);
  });
  res.json({
    totalLicenses:    all.length,
    activeLicenses:   all.filter(l=>l.active).length,
    runsThisCycle:    cl.length,
    vendorsThisCycle: cl.reduce((s,u) => s + (u.vendor_count||0), 0),
    topUsers: Object.values(tMap).sort((a,b)=>b.runs-a.runs).slice(0,10)
  });
});

app.get('/admin', (req,res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/',      (req,res) => res.json({ status: 'MSME License Server running', version: '1.0' }));

app.listen(PORT, () => console.log(`MSME License Server on port ${PORT}`));
