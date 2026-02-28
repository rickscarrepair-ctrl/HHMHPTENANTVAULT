const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ──
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'tenantvault-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));

// ── File Upload ──
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const unique = uuidv4();
    const ext = path.extname(file.originalname);
    cb(null, unique + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    const allowed = /pdf|jpg|jpeg|png|tiff|tif|webp/i;
    const ext = path.extname(file.originalname).slice(1);
    if (allowed.test(ext)) cb(null, true);
    else cb(new Error('Invalid file type'));
  }
});

// ── Auth Middleware ──
function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Not logged in' });
}

// ════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════
app.post('/api/auth/register', (req, res) => {
  const { username, password, inviteCode } = req.body;
  const validInvite = process.env.INVITE_CODE || 'TENANTVAULT2024';

  if (inviteCode !== validInvite) return res.status(403).json({ error: 'Invalid invite code' });
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(400).json({ error: 'Username already taken' });

  const hash = bcrypt.hashSync(password, 10);
  const id = uuidv4();
  db.prepare('INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)').run(id, username, hash, new Date().toISOString());

  req.session.userId = id;
  req.session.username = username;
  res.json({ success: true, username });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ success: true, username: user.username });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, username: req.session.username });
});

// ════════════════════════════════════════
//  PROPERTIES
// ════════════════════════════════════════
app.get('/api/properties', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM properties ORDER BY name').all();
  res.json(rows);
});

app.post('/api/properties', requireAuth, (req, res) => {
  const { name, address } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const existing = db.prepare('SELECT id FROM properties WHERE name = ?').get(name);
  if (existing) return res.status(400).json({ error: 'Property already exists' });
  const id = uuidv4();
  db.prepare('INSERT INTO properties (id, name, address, created_at) VALUES (?, ?, ?, ?)').run(id, name, address || '', new Date().toISOString());
  res.json({ id, name, address });
});

app.delete('/api/properties/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM properties WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ════════════════════════════════════════
//  DOCUMENTS
// ════════════════════════════════════════
app.get('/api/documents', requireAuth, (req, res) => {
  const { property, docType, unit, status, q } = req.query;
  let sql = 'SELECT * FROM documents WHERE 1=1';
  const params = [];

  if (property) { sql += ' AND property = ?'; params.push(property); }
  if (docType) { sql += ' AND doc_type = ?'; params.push(docType); }
  if (unit) { sql += ' AND unit = ?'; params.push(unit); }
  if (status) { sql += ' AND status = ?'; params.push(status); }
  if (q) {
    sql += ' AND (tenant_name LIKE ? OR filename LIKE ? OR doc_type LIKE ? OR unit LIKE ? OR property LIKE ?)';
    const like = `%${q}%`;
    params.push(like, like, like, like, like);
  }
  sql += ' ORDER BY uploaded_at DESC';

  const rows = db.prepare(sql).all(...params);
  res.json(rows);
});

app.post('/api/documents/upload', requireAuth, upload.array('files', 50), (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'No files uploaded' });

  const docs = req.files.map(file => {
    const id = uuidv4();
    const now = new Date().toISOString();
    const classified = classifyByKeywords(file.originalname);

    db.prepare(`INSERT INTO documents 
      (id, filename, stored_filename, filesize, mimetype, status, doc_type, confidence,
       tenant_name, unit, property, uploaded_at, uploaded_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, file.originalname, file.filename, file.size, file.mimetype,
         'pending', classified.type, classified.confidence,
         '', '', '', now, req.session.userId);

    return { id, filename: file.originalname, docType: classified.type, confidence: classified.confidence, status: 'pending' };
  });

  res.json({ success: true, documents: docs });
});

app.patch('/api/documents/:id', requireAuth, (req, res) => {
  const { docType, tenantName, unit, property, status } = req.body;
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return res.status(404).json({ error: 'Document not found' });

  db.prepare(`UPDATE documents SET 
    doc_type = COALESCE(?, doc_type),
    tenant_name = COALESCE(?, tenant_name),
    unit = COALESCE(?, unit),
    property = COALESCE(?, property),
    status = COALESCE(?, status),
    filed_at = CASE WHEN ? = 'filed' AND status != 'filed' THEN ? ELSE filed_at END
    WHERE id = ?`)
  .run(docType, tenantName, unit, property, status, status, new Date().toISOString(), req.params.id);

  res.json({ success: true });
});

app.delete('/api/documents/:id', requireAuth, (req, res) => {
  const doc = db.prepare('SELECT stored_filename FROM documents WHERE id = ?').get(req.params.id);
  if (doc) {
    const filePath = path.join(__dirname, '../uploads', doc.stored_filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    db.prepare('DELETE FROM documents WHERE id = ?').run(req.params.id);
  }
  res.json({ success: true });
});

app.get('/api/documents/:id/file', requireAuth, (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  const filePath = path.join(__dirname, '../uploads', doc.stored_filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found on disk' });
  res.setHeader('Content-Disposition', `inline; filename="${doc.filename}"`);
  res.sendFile(filePath);
});

// ════════════════════════════════════════
//  TEMPLATES
// ════════════════════════════════════════
app.get('/api/templates', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM templates ORDER BY added_at DESC').all());
});

app.post('/api/templates', requireAuth, (req, res) => {
  const { name, docType, keywords } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const id = uuidv4();
  db.prepare('INSERT INTO templates (id, name, doc_type, keywords, added_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, name, docType || 'Unclassified', JSON.stringify(keywords || []), new Date().toISOString());
  res.json({ id, name, docType });
});

app.delete('/api/templates/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM templates WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ════════════════════════════════════════
//  DOC TYPES
// ════════════════════════════════════════
app.get('/api/doctypes', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM doc_types ORDER BY sort_order').all();
  res.json(rows.map(r => ({ ...r, keywords: JSON.parse(r.keywords || '[]') })));
});

app.post('/api/doctypes', requireAuth, (req, res) => {
  const { name, icon, keywords } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const existing = db.prepare('SELECT id FROM doc_types WHERE name = ?').get(name);
  if (existing) return res.status(400).json({ error: 'Type already exists' });
  const id = uuidv4();
  const maxOrder = db.prepare('SELECT MAX(sort_order) as m FROM doc_types').get();
  db.prepare('INSERT INTO doc_types (id, name, icon, keywords, sort_order) VALUES (?, ?, ?, ?, ?)')
    .run(id, name, icon || '📄', JSON.stringify(keywords || []), (maxOrder.m || 0) + 1);
  res.json({ id, name, icon, keywords });
});

app.delete('/api/doctypes/:id', requireAuth, (req, res) => {
  const dt = db.prepare('SELECT name FROM doc_types WHERE id = ?').get(req.params.id);
  if (dt && dt.name === 'Unclassified') return res.status(400).json({ error: 'Cannot delete Unclassified' });
  if (dt) db.prepare("UPDATE documents SET doc_type = 'Unclassified' WHERE doc_type = ?").run(dt.name);
  db.prepare('DELETE FROM doc_types WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ════════════════════════════════════════
//  STATS
// ════════════════════════════════════════
app.get('/api/stats', requireAuth, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as c FROM documents').get().c;
  const filed = db.prepare("SELECT COUNT(*) as c FROM documents WHERE status = 'filed'").get().c;
  const review = db.prepare("SELECT COUNT(*) as c FROM documents WHERE status = 'review'").get().c;
  const unclassified = db.prepare("SELECT COUNT(*) as c FROM documents WHERE doc_type = 'Unclassified'").get().c;
  const properties = db.prepare('SELECT COUNT(*) as c FROM properties').get().c;
  res.json({ total, filed, review, unclassified, properties });
});

// ════════════════════════════════════════
//  KEYWORD CLASSIFIER
// ════════════════════════════════════════
function classifyByKeywords(text) {
  const lower = text.toLowerCase();
  const docTypes = db.prepare('SELECT * FROM doc_types').all();
  let best = { type: 'Unclassified', confidence: 0 };

  for (const dt of docTypes) {
    const keywords = JSON.parse(dt.keywords || '[]');
    if (!keywords.length) continue;
    let hits = 0;
    for (const kw of keywords) { if (lower.includes(kw)) hits++; }
    if (hits > 0) {
      const conf = Math.min(80 + (hits - 1) * 5, 95);
      if (conf > best.confidence) best = { type: dt.name, confidence: conf };
    }
  }
  return best;
}

// ── Serve frontend for all other routes ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => console.log(`TenantVault running on port ${PORT}`));
