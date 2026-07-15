// server.js — Backend simples para o Portal Plantão Card
// Banco de dados em arquivo JSON (sem necessidade de instalar banco de dados externo)

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const { v4: uuid } = require('uuid');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo-em-producao';
const DB_FILE = path.join(__dirname, 'db.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads'); // onde os PDFs gerados ficam salvos

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ---------- "Banco de dados" em JSON ----------
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], sessions: [], reports: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ---------- App ----------
const app = express();
app.use(cors());
app.use(express.json());

// Servir os arquivos estáticos (index.html, login.html, cadastro.html)
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
app.use(express.static(PUBLIC_DIR));

// Servir os PDFs de relatório gerados
app.use('/uploads', express.static(UPLOADS_DIR));

// ---------- Geração de PDF ----------
function gerarPdfRelatorio({ title, body, sender, date }) {
  return new Promise((resolve, reject) => {
    const filename = `relatorio-${Date.now()}-${uuid().slice(0, 8)}.pdf`;
    const filepath = path.join(UPLOADS_DIR, filename);
    const doc = new PDFDocument({ margin: 50 });
    const stream = fs.createWriteStream(filepath);
    doc.pipe(stream);

    doc.fontSize(20).fillColor('#fa0000').text('Plantão Card', { align: 'left' });
    doc.moveDown(0.3);
    doc.fontSize(14).fillColor('#1A1714').text(title, { align: 'left' });
    doc.moveDown(0.2);
    doc.fontSize(10).fillColor('#8A837E')
      .text(`Gerado por: ${sender}`)
      .text(`Data: ${new Date(date).toLocaleString('pt-BR')}`);
    doc.moveDown(1);
    doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#EDE9E4').stroke();
    doc.moveDown(1);

    doc.fontSize(12).fillColor('#1A1714').text(body || '(Sem conteúdo)', {
      align: 'left',
      lineGap: 4
    });

    doc.end();
    stream.on('finish', () => resolve({ filename, filepath }));
    stream.on('error', reject);
  });
}

// ---------- Auth helpers ----------
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Token ausente' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const db = loadDB();
    const session = db.sessions.find(s => s.token === token);
    if (!session) return res.status(401).json({ message: 'Sessão inválida' });
    const user = db.users.find(u => u.id === payload.id);
    if (!user) return res.status(401).json({ message: 'Usuário não encontrado' });
    req.user = user;
    req.token = token;
    req.db = db;
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Token inválido ou expirado' });
  }
}

function publicUser(u) {
  const { password, ...rest } = u;
  return rest;
}

// ---------- Rotas de autenticação ----------

// Cadastro
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role, sector } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Nome, email e senha são obrigatórios' });
    }
    const db = loadDB();
    const exists = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (exists) {
      return res.status(409).json({ message: 'Já existe uma conta com este email' });
    }
    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: uuid(),
      name,
      email,
      password: hash,
      role: role || '',
      sector: sector || '',
      func: '',
      registration: '',
      entryDate: '',
      createdAt: new Date().toISOString()
    };
    db.users.push(user);
    saveDB(db);

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    db.sessions.push({ token, userId: user.id, userAgent: req.headers['user-agent'] || '', createdAt: new Date().toISOString() });
    saveDB(db);

    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Erro ao cadastrar' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Informe email e senha' });
    const db = loadDB();
    const user = db.users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
    if (!user) return res.status(401).json({ message: 'Email ou senha inválidos' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'Email ou senha inválidos' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    db.sessions.push({ token, userId: user.id, userAgent: req.headers['user-agent'] || '', createdAt: new Date().toISOString() });
    saveDB(db);

    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Erro ao entrar' });
  }
});

app.post('/api/logout', authMiddleware, (req, res) => {
  const db = req.db;
  db.sessions = db.sessions.filter(s => s.token !== req.token);
  saveDB(db);
  res.json({ ok: true });
});

// ---------- Perfil ----------
app.get('/api/me', authMiddleware, (req, res) => {
  res.json(publicUser(req.user));
});

app.put('/api/profile', authMiddleware, (req, res) => {
  const db = req.db;
  const user = db.users.find(u => u.id === req.user.id);
  const { name, email, role, sector, func, registration, entryDate, password } = req.body;
  if (name !== undefined) user.name = name;
  if (email !== undefined) user.email = email;
  if (role !== undefined) user.role = role;
  if (sector !== undefined) user.sector = sector;
  if (func !== undefined) user.func = func;
  if (registration !== undefined) user.registration = registration;
  if (entryDate !== undefined) user.entryDate = entryDate;
  saveDB(db);
  res.json(publicUser(user));
});

// ---------- Sessões ----------
app.get('/api/sessions', authMiddleware, (req, res) => {
  const db = req.db;
  const sessions = db.sessions
    .filter(s => s.userId === req.user.id)
    .map(s => ({ token: s.token.slice(0, 8) + '…', userAgent: s.userAgent, createdAt: s.createdAt, current: s.token === req.token }));
  res.json(sessions);
});

app.delete('/api/sessions/others', authMiddleware, (req, res) => {
  const db = req.db;
  db.sessions = db.sessions.filter(s => s.userId !== req.user.id || s.token === req.token);
  saveDB(db);
  res.json({ ok: true });
});

// ---------- Funcionários (para destinatários de relatório) ----------
app.get('/api/employees', authMiddleware, (req, res) => {
  const db = req.db;
  const list = db.users
    .filter(u => u.id !== req.user.id)
    .map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role }));
  res.json(list);
});

// ---------- Relatórios ----------
app.get('/api/reports/sent', authMiddleware, (req, res) => {
  const db = req.db;
  const list = db.reports.filter(r => r.senderId === req.user.id);
  res.json(list);
});

app.get('/api/inbox', authMiddleware, (req, res) => {
  const db = req.db;
  const list = db.reports
    .filter(r => r.recipients.includes(req.user.email))
    .map(r => ({ ...r, myRead: (r.readBy || []).includes(req.user.email) }));
  res.json(list);
});

// Gera um relatório em PDF. Destinatários são opcionais: se informados, o
// relatório também é enviado (aparece na caixa de entrada deles); se não,
// fica só no histórico de quem gerou.
app.post('/api/reports/generate', authMiddleware, async (req, res) => {
  try {
    const db = req.db;
    const { title, body } = req.body;
    const recipients = Array.isArray(req.body.recipients) ? req.body.recipients : [];
    if (!title) {
      return res.status(400).json({ message: 'Título é obrigatório' });
    }
    const date = new Date().toISOString();
    const { filename } = await gerarPdfRelatorio({ title, body, sender: req.user.name, date });

    const report = {
      id: Date.now(),
      title,
      body: body || '',
      sender: req.user.name,
      senderId: req.user.id,
      recipients,
      status: recipients.length ? 'Enviado' : 'Gerado',
      readBy: [],
      date,
      file: { url: '/uploads/' + filename, originalname: filename }
    };
    db.reports.push(report);
    saveDB(db);

    // notificar destinatários conectados via SSE, se houver
    recipients.forEach(email => notify(email, 'new-report', report));

    res.json(report);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

// Envia (ou reenvia) um relatório já gerado para novos destinatários
app.post('/api/reports/:id/send', authMiddleware, (req, res) => {
  const db = req.db;
  const report = db.reports.find(r => String(r.id) === req.params.id && r.senderId === req.user.id);
  if (!report) return res.status(404).json({ message: 'Relatório não encontrado' });
  const novos = Array.isArray(req.body.recipients) ? req.body.recipients : [];
  if (!novos.length) return res.status(400).json({ message: 'Selecione ao menos um destinatário' });

  novos.forEach(email => { if (!report.recipients.includes(email)) report.recipients.push(email); });
  report.status = 'Enviado';
  saveDB(db);
  novos.forEach(email => notify(email, 'new-report', report));
  res.json(report);
});

app.post('/api/reports/:id/read', authMiddleware, (req, res) => {
  const db = req.db;
  const report = db.reports.find(r => String(r.id) === req.params.id);
  if (!report) return res.status(404).json({ message: 'Relatório não encontrado' });
  report.readBy = report.readBy || [];
  if (!report.readBy.includes(req.user.email)) report.readBy.push(req.user.email);
  saveDB(db);
  res.json({ ok: true });
});

// ---------- Notificações (Server-Sent Events) ----------
const sseClients = {}; // email -> [res, res...]

function notify(email, event, data) {
  const list = sseClients[email];
  if (!list) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  list.forEach(res => res.write(payload));
}

app.get('/api/notifications', (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(401).end();
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).end(); }
  const db = loadDB();
  const user = db.users.find(u => u.id === payload.id);
  if (!user) return res.status(401).end();

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });
  res.flushHeaders();

  sseClients[user.email] = sseClients[user.email] || [];
  sseClients[user.email].push(res);

  req.on('close', () => {
    sseClients[user.email] = (sseClients[user.email] || []).filter(r => r !== res);
  });
});

// Qualquer outra rota: serve o index.html (fallback simples)
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(PUBLIC_DIR, req.path === '/' ? 'index.html' : req.path), err => {
    if (err) res.status(404).send('Não encontrado');
  });
});

app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em http://localhost:${PORT}`);
});
