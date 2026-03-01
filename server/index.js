const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const https = require('https');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'hhmhp-tenantvault-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

function ensureDir(dir) { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); }

const storage = multer.diskStorage({
  destination: (req, file, cb) => { ensureDir(path.join(__dirname, '../uploads')); cb(null, path.join(__dirname, '../uploads')); },
  filename: (req, file, cb) => { cb(null, uuidv4() + path.extname(file.originalname)); }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    /pdf|jpg|jpeg|png|tiff|tif|webp/i.test(path.extname(file.originalname).slice(1)) ? cb(null, true) : cb(new Error('Invalid file type'));
  }
});

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Not logged in' });
}

// ════════════════════════════════════════
//  CLAUDE AI
// ════════════════════════════════════════
function getMimeType(filename) {
  const map = { '.pdf': 'application/pdf', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.tiff': 'image/tiff', '.tif': 'image/tiff' };
  return map[path.extname(filename).toLowerCase()] || 'image/jpeg';
}

async function callClaude(messages, systemPrompt) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('No API key');

  const body = JSON.stringify({ model: 'claude-opus-4-6', max_tokens: 1024, system: systemPrompt, messages });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(body) }
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const p = JSON.parse(data);
          if (p.error) reject(new Error(p.error.message));
          else resolve(p.content[0].text);
        } catch(e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function classifyDocumentWithAI(filePath, filename, templates) {
  const mimeType = getMimeType(filename);
  const base64 = fs.readFileSync(filePath).toString('base64');

  const templateContext = templates.length
    ? '\n\nKNOWN TEMPLATES:\n' + templates.map(t => `- "${t.name}" → ${t.doc_type} (keywords: ${JSON.parse(t.keywords||'[]').join(', ')})`).join('\n')
    : '';

  const tenants = db.prepare("SELECT name FROM tenants ORDER BY name").all().map(r => r.name);
  const tenantContext = tenants.length ? `\n\nKNOWN TENANTS: ${tenants.join(', ')}` : '';

  const systemPrompt = `You are a document classifier for HHMHP property management.
${templateContext}${tenantContext}
Respond ONLY with valid JSON (no markdown):
{"docType":"document type","tenantName":"tenant full name or empty","unit":"unit number or empty","property":"property name or empty","confidence":85,"matchedTemplate":"matched template name or empty","summary":"one sentence"}`;

  const contentType = mimeType === 'application/pdf' ? 'document' : 'image';
  const result = await callClaude([{
    role: 'user',
    content: [
      { type: contentType, source: { type: 'base64', media_type: mimeType, data: base64 } },
      { type: 'text', text: `Classify this document. Filename: "${filename}"` }
    ]
  }], systemPrompt);

  return JSON.parse(result.replace(/```json\n?|\n?```/g, '').trim());
}

async function analyzeTemplateWithAI(filePath, filename) {
  const mimeType = getMimeType(filename);
  const base64 = fs.readFileSync(filePath).toString('base64');

  const systemPrompt = `You are a document analysis assistant for HHMHP property management.
Analyze this sample document and extract its characteristics for future recognition.
Respond ONLY with valid JSON (no markdown):
{"suggestedName":"short descriptive name","docType":"Lease Agreement|Application|ID/Verification|Move-In/Out|Notice|Maintenance|Payment|Other","keywords":["key","words","from","document"],"description":"one sentence about this document"}`;

  const contentType = mimeType === 'application/pdf' ? 'document' : 'image';
  const result = await callClaude([{
    role: 'user',
    content: [
      { type: contentType, source: { type: 'base64', media_type: mimeType, data: base64 } },
      { type: 'text', text: `Analyze this template. Filename: "${filename}"` }
    ]
  }], systemPrompt);

  return JSON.parse(result.replace(/```json\n?|\n?```/g, '').trim());
}

// ════════════════════════════════════════
//  AUTH
// ════════════════════════════════════════
app.post('/api/auth/register', (req, res) => {
  const { username, password, inviteCode } = req.body;
  if (inviteCode !== (process.env.INVITE_CODE || 'TENANTVAULT2024')) return res.status(403).json({ error: 'Invalid invite code' });
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) return res.status(400).json({ error: 'Username already taken' });
  const id = uuidv4();
  db.prepare('INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)').run(id, username, bcrypt.hashSync(password, 10), new Date().toISOString());
  req.session.userId = id; req.session.username = username;
  res.json({ success: true, username });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid username or password' });
  req.session.userId = user.id; req.session.username = user.username;
  res.json({ success: true, username: user.username });
});

app.post('/api/auth/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, username: req.session.username });
});

// ════════════════════════════════════════
//  PROPERTIES
// ════════════════════════════════════════
app.get('/api/properties', requireAuth, (req, res) => res.json(db.prepare('SELECT * FROM properties ORDER BY name').all()));

app.post('/api/properties', requireAuth, (req, res) => {
  const { name, address } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  if (db.prepare('SELECT id FROM properties WHERE name = ?').get(name)) return res.status(400).json({ error: 'Property already exists' });
  const id = uuidv4();
  db.prepare('INSERT INTO properties (id, name, address, created_at) VALUES (?, ?, ?, ?)').run(id, name, address || '', new Date().toISOString());
  res.json({ id, name, address });
});

app.delete('/api/properties/:id', requireAuth, (req, res) => { db.prepare('DELETE FROM properties WHERE id = ?').run(req.params.id); res.json({ success: true }); });

// ════════════════════════════════════════
//  DOCUMENTS
// ════════════════════════════════════════
app.get('/api/documents', requireAuth, (req, res) => {
  const { property, docType, unit, q } = req.query;
  const statuses = req.query.status ? req.query.status.split(',') : null;
  let sql = 'SELECT * FROM documents WHERE 1=1';
  const params = [];
  if (statuses) { sql += ` AND status IN (${statuses.map(() => '?').join(',')})`; params.push(...statuses); }
  if (property) { sql += ' AND property = ?'; params.push(property); }
  if (docType) { sql += ' AND doc_type = ?'; params.push(docType); }
  if (unit) { sql += ' AND unit = ?'; params.push(unit); }
  if (q) { sql += ' AND (tenant_name LIKE ? OR filename LIKE ? OR doc_type LIKE ? OR unit LIKE ? OR property LIKE ?)'; const l = `%${q}%`; params.push(l,l,l,l,l); }
  sql += ' ORDER BY uploaded_at DESC';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/documents/upload', requireAuth, upload.array('files', 50), async (req, res) => {
  if (!req.files?.length) return res.status(400).json({ error: 'No files uploaded' });
  const hasAI = !!process.env.ANTHROPIC_API_KEY;
  const templates = db.prepare('SELECT * FROM templates').all();
  const docs = [];

  for (const file of req.files) {
    const id = uuidv4();
    const now = new Date().toISOString();
    let docType = 'Unclassified', confidence = 0, tenantName = '', unit = '', property = '', matchedTemplate = '';

    if (hasAI) {
      try {
        const ai = await classifyDocumentWithAI(path.join(__dirname, '../uploads', file.filename), file.originalname, templates);
        docType = ai.docType || 'Unclassified';
        confidence = ai.confidence || 70;
        tenantName = ai.tenantName || '';
        unit = ai.unit || '';
        property = ai.property || '';
        matchedTemplate = ai.matchedTemplate || '';
      } catch(e) {
        console.error('AI failed for', file.originalname, e.message);
        const kw = classifyByKeywords(file.originalname);
        docType = kw.type; confidence = kw.confidence;
      }
    } else {
      const kw = classifyByKeywords(file.originalname);
      docType = kw.type; confidence = kw.confidence;
    }

    const autoFile = hasAI && confidence >= 80 && tenantName && property;
    const status = autoFile ? 'filed' : 'review';
    const filedAt = autoFile ? now : null;

    db.prepare(`INSERT INTO documents (id, filename, stored_filename, filesize, mimetype, status, doc_type, confidence, tenant_name, unit, property, uploaded_at, filed_at, uploaded_by, matched_template)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, file.originalname, file.filename, file.size, file.mimetype, status, docType, confidence, tenantName, unit, property, now, filedAt, req.session.userId, matchedTemplate);

    docs.push({ id, filename: file.originalname, docType, confidence, tenantName, unit, property, status, matchedTemplate, autoFiled: autoFile });
  }

  res.json({ success: true, documents: docs, aiUsed: hasAI });
});

app.patch('/api/documents/:id', requireAuth, (req, res) => {
  const { docType, tenantName, unit, property, status } = req.body;
  if (!db.prepare('SELECT id FROM documents WHERE id = ?').get(req.params.id)) return res.status(404).json({ error: 'Not found' });
  db.prepare(`UPDATE documents SET doc_type=COALESCE(?,doc_type), tenant_name=COALESCE(?,tenant_name), unit=COALESCE(?,unit), property=COALESCE(?,property), status=COALESCE(?,status), filed_at=CASE WHEN ?='filed' AND status!='filed' THEN ? ELSE filed_at END WHERE id=?`)
  .run(docType, tenantName, unit, property, status, status, new Date().toISOString(), req.params.id);
  res.json({ success: true });
});

app.delete('/api/documents/:id', requireAuth, (req, res) => {
  const doc = db.prepare('SELECT stored_filename FROM documents WHERE id = ?').get(req.params.id);
  if (doc) { const fp = path.join(__dirname, '../uploads', doc.stored_filename); if (fs.existsSync(fp)) fs.unlinkSync(fp); db.prepare('DELETE FROM documents WHERE id = ?').run(req.params.id); }
  res.json({ success: true });
});

app.get('/api/documents/:id/file', requireAuth, (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  const fp = path.join(__dirname, '../uploads', doc.stored_filename);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'File not found' });
  res.setHeader('Content-Disposition', `inline; filename="${doc.filename}"`);
  res.sendFile(fp);
});

// ════════════════════════════════════════
//  TEMPLATES — AI-powered upload
// ════════════════════════════════════════
app.get('/api/templates', requireAuth, (req, res) => res.json(db.prepare('SELECT * FROM templates ORDER BY added_at DESC').all()));

app.post('/api/templates/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const hasAI = !!process.env.ANTHROPIC_API_KEY;
  let analysis = { suggestedName: req.file.originalname.replace(/\.[^.]+$/, ''), docType: 'Unclassified', keywords: [], description: '' };

  if (hasAI) {
    try {
      analysis = await analyzeTemplateWithAI(path.join(__dirname, '../uploads', req.file.filename), req.file.originalname);
    } catch(e) { console.error('Template AI failed:', e.message); }
  }

  // Delete temp file — templates don't need to stay
  const fp = path.join(__dirname, '../uploads', req.file.filename);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);

  res.json({ success: true, analysis, aiUsed: hasAI });
});

app.post('/api/templates', requireAuth, (req, res) => {
  const { name, docType, keywords } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const id = uuidv4();
  db.prepare('INSERT INTO templates (id, name, doc_type, keywords, added_at) VALUES (?, ?, ?, ?, ?)').run(id, name, docType || 'Unclassified', JSON.stringify(keywords || []), new Date().toISOString());
  res.json({ id, name, docType });
});

app.delete('/api/templates/:id', requireAuth, (req, res) => { db.prepare('DELETE FROM templates WHERE id = ?').run(req.params.id); res.json({ success: true }); });

// ════════════════════════════════════════
//  DOC TYPES
// ════════════════════════════════════════
app.get('/api/doctypes', requireAuth, (req, res) => res.json(db.prepare('SELECT * FROM doc_types ORDER BY sort_order').all().map(r => ({ ...r, keywords: JSON.parse(r.keywords || '[]') }))));

app.post('/api/doctypes', requireAuth, (req, res) => {
  const { name, icon, keywords } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  if (db.prepare('SELECT id FROM doc_types WHERE name = ?').get(name)) return res.status(400).json({ error: 'Type already exists' });
  const id = uuidv4();
  const max = db.prepare('SELECT MAX(sort_order) as m FROM doc_types').get();
  db.prepare('INSERT INTO doc_types (id, name, icon, keywords, sort_order) VALUES (?, ?, ?, ?, ?)').run(id, name, icon || '📄', JSON.stringify(keywords || []), (max.m || 0) + 1);
  res.json({ id, name, icon, keywords });
});

app.delete('/api/doctypes/:id', requireAuth, (req, res) => {
  const dt = db.prepare('SELECT name FROM doc_types WHERE id = ?').get(req.params.id);
  if (dt?.name === 'Unclassified') return res.status(400).json({ error: 'Cannot delete Unclassified' });
  if (dt) db.prepare("UPDATE documents SET doc_type='Unclassified' WHERE doc_type=?").run(dt.name);
  db.prepare('DELETE FROM doc_types WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});


// ════════════════════════════════════════
//  PROPERTY DASHBOARD
// ════════════════════════════════════════
app.get('/api/dashboard', requireAuth, (req, res) => {
  const properties = db.prepare('SELECT * FROM properties ORDER BY name').all();
  const tenants = db.prepare('SELECT * FROM tenants').all();
  const documents = db.prepare("SELECT * FROM documents WHERE status = 'filed'").all();
  const docTypes = db.prepare('SELECT name FROM doc_types').all().map(d => d.name).filter(d => d !== 'Unclassified');

  const propertyStats = properties.map(prop => {
    const propTenants = tenants.filter(t => t.property === prop.name);
    const propDocs = documents.filter(d => d.property === prop.name);
    const docTypeCounts = {};
    docTypes.forEach(dt => { docTypeCounts[dt] = propDocs.filter(d => d.doc_type === dt).length; });
    return {
      ...prop,
      tenantCount: propTenants.length,
      docCount: propDocs.length,
      docTypeCounts
    };
  });

  // Unassigned tenants
  const unassigned = tenants.filter(t => !t.property).length;

  res.json({ properties: propertyStats, totalTenants: tenants.length, totalDocs: documents.length, unassigned, docTypes });
});

// ════════════════════════════════════════
//  MISSING DOCUMENTS
// ════════════════════════════════════════
app.get('/api/missing-docs', requireAuth, (req, res) => {
  const requiredTypes = ['Lease Agreement', 'Application', 'ID/Verification'];
  const tenants = db.prepare("SELECT * FROM tenants WHERE name != 'Manager' AND name != 'HHMHP'").all();
  const documents = db.prepare("SELECT * FROM documents WHERE status = 'filed'").all();

  const missing = [];
  for (const tenant of tenants) {
    const tenantDocs = documents.filter(d => d.tenant_name && d.tenant_name.toLowerCase().includes(tenant.name.toLowerCase()));
    const missingTypes = requiredTypes.filter(rt => !tenantDocs.find(d => d.doc_type === rt));
    if (missingTypes.length > 0) {
      missing.push({
        tenant: tenant.name,
        unit: tenant.unit,
        property: tenant.property,
        missingTypes,
        docCount: tenantDocs.length
      });
    }
  }

  missing.sort((a, b) => b.missingTypes.length - a.missingTypes.length);
  res.json({ missing, requiredTypes });
});

// ════════════════════════════════════════
//  TENANT PROFILE
// ════════════════════════════════════════
app.get('/api/tenants/:id/profile', requireAuth, (req, res) => {
  const tenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(req.params.id);
  if (!tenant) return res.status(404).json({ error: 'Not found' });

  const documents = db.prepare("SELECT * FROM documents WHERE status = 'filed' AND tenant_name LIKE ? ORDER BY filed_at DESC").all(`%${tenant.name}%`);
  const requiredTypes = ['Lease Agreement', 'Application', 'ID/Verification', 'Move-In/Out'];
  const missingTypes = requiredTypes.filter(rt => !documents.find(d => d.doc_type === rt));

  res.json({ tenant, documents, missingTypes });
});

// ════════════════════════════════════════
//  PDF EXPORT (tenant file summary)
// ════════════════════════════════════════
app.get('/api/tenants/:id/export', requireAuth, (req, res) => {
  const tenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(req.params.id);
  if (!tenant) return res.status(404).json({ error: 'Not found' });

  const documents = db.prepare("SELECT * FROM documents WHERE status = 'filed' AND tenant_name LIKE ? ORDER BY doc_type, filed_at DESC").all(`%${tenant.name}%`);

  // Generate simple HTML report that browser can print to PDF
  const docRows = documents.map(d => `
    <tr>
      <td>${d.doc_type}</td>
      <td>${d.filename}</td>
      <td>${d.filed_at ? new Date(d.filed_at).toLocaleDateString() : '—'}</td>
    </tr>`).join('');

  const requiredTypes = ['Lease Agreement', 'Application', 'ID/Verification', 'Move-In/Out'];
  const missingTypes = requiredTypes.filter(rt => !documents.find(d => d.doc_type === rt));
  const missingHtml = missingTypes.length
    ? `<div style="background:#fdf2f2;border:1px solid #e74c3c;border-radius:8px;padding:12px 16px;margin-bottom:24px;">
        <strong style="color:#c0392b;">⚠ Missing Documents:</strong> ${missingTypes.join(', ')}
       </div>` : '';

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Tenant File — ${tenant.name}</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 40px; color: #1a1a1a; max-width: 800px; margin: 0 auto; }
    h1 { color: #2d5a3d; font-size: 28px; margin-bottom: 4px; }
    .subtitle { color: #666; font-size: 14px; margin-bottom: 32px; }
    .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 32px; background: #f5f2ed; padding: 20px; border-radius: 8px; }
    .meta-item label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #888; display: block; margin-bottom: 4px; }
    .meta-item span { font-size: 15px; font-weight: 600; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th { background: #2d5a3d; color: white; padding: 10px 14px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
    td { padding: 10px 14px; border-bottom: 1px solid #eee; font-size: 13px; }
    tr:nth-child(even) td { background: #f9f9f9; }
    .footer { margin-top: 40px; font-size: 11px; color: #999; border-top: 1px solid #eee; padding-top: 16px; }
    @media print { body { padding: 20px; } }
  </style>
</head>
<body>
  <h1>📂 ${tenant.name}</h1>
  <div class="subtitle">HHMHP TenantVault — Tenant File Export — ${new Date().toLocaleDateString()}</div>
  <div class="meta">
    <div class="meta-item"><label>Unit</label><span>${tenant.unit || '—'}</span></div>
    <div class="meta-item"><label>Property</label><span>${tenant.property || '—'}</span></div>
    <div class="meta-item"><label>Total Documents</label><span>${documents.length}</span></div>
    <div class="meta-item"><label>Notes</label><span>${tenant.notes || '—'}</span></div>
  </div>
  ${missingHtml}
  <h3 style="margin-bottom:12px;">Filed Documents</h3>
  ${documents.length ? `<table><thead><tr><th>Type</th><th>Filename</th><th>Filed Date</th></tr></thead><tbody>${docRows}</tbody></table>`
    : '<p style="color:#999;">No documents filed yet.</p>'}
  <div class="footer">Generated by HHMHP TenantVault · ${new Date().toISOString()}</div>
  <script>window.onload = () => window.print();</script>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// ════════════════════════════════════════
//  TENANTS
// ════════════════════════════════════════
app.get('/api/tenants', requireAuth, (req, res) => {
  const { q } = req.query;
  let sql = 'SELECT * FROM tenants';
  const params = [];
  if (q) { sql += ' WHERE name LIKE ? OR unit LIKE ? OR property LIKE ?'; const l = `%${q}%`; params.push(l,l,l); }
  sql += ' ORDER BY name COLLATE NOCASE';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/tenants', requireAuth, (req, res) => {
  const { name, unit, property, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  if (db.prepare('SELECT id FROM tenants WHERE name = ? COLLATE NOCASE').get(name)) return res.status(400).json({ error: 'Tenant already exists' });
  const id = uuidv4();
  db.prepare('INSERT INTO tenants (id, name, unit, property, notes, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, name, unit||'', property||'', notes||'', new Date().toISOString());
  res.json({ id, name, unit, property, notes });
});

app.patch('/api/tenants/:id', requireAuth, (req, res) => {
  const { name, unit, property, notes } = req.body;
  if (!db.prepare('SELECT id FROM tenants WHERE id = ?').get(req.params.id)) return res.status(404).json({ error: 'Not found' });
  db.prepare('UPDATE tenants SET name=COALESCE(?,name), unit=COALESCE(?,unit), property=COALESCE(?,property), notes=COALESCE(?,notes) WHERE id=?').run(name, unit, property, notes, req.params.id);
  res.json({ success: true });
});

app.delete('/api/tenants/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM tenants WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ════════════════════════════════════════
//  STATUS & STATS
// ════════════════════════════════════════
app.get('/api/status', requireAuth, (req, res) => {
  const key = process.env.ANTHROPIC_API_KEY;
  res.json({
    aiEnabled: !!(key && key.length > 10),
    keyPrefix: key ? key.substring(0, 10) + '...' : 'not set'
  });
});

app.get('/api/stats', requireAuth, (req, res) => res.json({
  total: db.prepare('SELECT COUNT(*) as c FROM documents').get().c,
  filed: db.prepare("SELECT COUNT(*) as c FROM documents WHERE status='filed'").get().c,
  review: db.prepare("SELECT COUNT(*) as c FROM documents WHERE status='review'").get().c,
  unclassified: db.prepare("SELECT COUNT(*) as c FROM documents WHERE doc_type='Unclassified'").get().c,
  properties: db.prepare('SELECT COUNT(*) as c FROM properties').get().c,
  aiEnabled: !!process.env.ANTHROPIC_API_KEY
}));

// ════════════════════════════════════════
//  KEYWORD FALLBACK
// ════════════════════════════════════════
function classifyByKeywords(text) {
  const lower = text.toLowerCase();
  const docTypes = db.prepare('SELECT * FROM doc_types').all();
  let best = { type: 'Unclassified', confidence: 0 };
  for (const dt of docTypes) {
    const kws = JSON.parse(dt.keywords || '[]');
    if (!kws.length) continue;
    let hits = 0;
    for (const kw of kws) { if (lower.includes(kw)) hits++; }
    if (hits > 0) { const conf = Math.min(80 + (hits-1)*5, 95); if (conf > best.confidence) best = { type: dt.name, confidence: conf }; }
  }
  return best;
}

app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));
app.listen(PORT, () => console.log(`HHMHP TenantVault running on port ${PORT}`));
