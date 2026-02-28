const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbDir = path.join(__dirname, '../data');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(path.join(dbDir, 'tenantvault.db'));

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

// ── Create Tables ──
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS properties (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    address TEXT DEFAULT '',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    filesize INTEGER DEFAULT 0,
    mimetype TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    doc_type TEXT DEFAULT 'Unclassified',
    confidence INTEGER DEFAULT 0,
    tenant_name TEXT DEFAULT '',
    unit TEXT DEFAULT '',
    property TEXT DEFAULT '',
    uploaded_at TEXT NOT NULL,
    filed_at TEXT DEFAULT NULL,
    uploaded_by TEXT DEFAULT '',
    matched_template TEXT DEFAULT NULL
  );

  CREATE TABLE IF NOT EXISTS templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    doc_type TEXT DEFAULT 'Unclassified',
    keywords TEXT DEFAULT '[]',
    added_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS doc_types (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    icon TEXT DEFAULT '📄',
    keywords TEXT DEFAULT '[]',
    sort_order INTEGER DEFAULT 0
  );
`);

// ── Seed default doc types if empty ──
const count = db.prepare('SELECT COUNT(*) as c FROM doc_types').get().c;
if (count === 0) {
  const defaults = [
    { name: 'Lease Agreement', icon: '📄', keywords: ['lease','rental agreement','tenancy','rent agreement','residential lease'], order: 1 },
    { name: 'Application',     icon: '📝', keywords: ['application','apply','applicant','rental application'], order: 2 },
    { name: 'ID/Verification', icon: '🪪', keywords: ["driver's license",'passport','identification','ssn','pay stub','w2','bank statement'], order: 3 },
    { name: 'Move-In/Out',     icon: '🔑', keywords: ['move in','move out','move-in','move-out','checklist','inspection','walkthrough'], order: 4 },
    { name: 'Notice',          icon: '📬', keywords: ['notice','eviction','3 day','30 day','60 day','vacate','terminate','breach'], order: 5 },
    { name: 'Maintenance',     icon: '🔧', keywords: ['maintenance','repair','work order','fix','plumb','electric','hvac'], order: 6 },
    { name: 'Payment',         icon: '💰', keywords: ['receipt','payment','rent','paid','invoice','balance','deposit','fee'], order: 7 },
    { name: 'Unclassified',    icon: '❓', keywords: [], order: 99 },
  ];

  const insert = db.prepare('INSERT INTO doc_types (id, name, icon, keywords, sort_order) VALUES (?, ?, ?, ?, ?)');
  const { v4: uuidv4 } = require('uuid');
  for (const dt of defaults) {
    insert.run(uuidv4(), dt.name, dt.icon, JSON.stringify(dt.keywords), dt.order);
  }
  console.log('Default document types seeded.');
}

module.exports = db;
