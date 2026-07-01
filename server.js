// server.js — Backend com PostgreSQL
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { Pool } = require('pg');
const { v4: uuid } = require('uuid');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo-em-producao';
const UPLOADS_DIR = path.join(__dirname, 'uploads');

const fs = require('fs');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ---------- PostgreSQL ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT '',
      sector TEXT DEFAULT '',
      func TEXT DEFAULT '',
      registration TEXT DEFAULT '',
      entry_date TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      user_agent TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS reports (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT DEFAULT '',
      sender TEXT NOT NULL,
      sender_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      recipients JSONB NOT NULL DEFAULT '[]',
      read_by JSONB NOT NULL DEFAULT '[]',
      status TEXT DEFAULT 'Recebido',
      file_url TEXT,
      file_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('✅ Tabelas prontas');
}

// ---------- App ----------
const app = express();
app.use(cors());
app.use(express.json());

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });
app.use('/uploads', express.static(UPLOADS_DIR));

// ---------- Auth helpers ----------
async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Token ausente' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows: sessions } = await pool.query('SELECT * FROM sessions WHERE token=$1', [token]);
    if (!sessions.length) return res.status(401).json({ message: 'Sessão inválida' });
    const { rows: users } = await pool.query('SELECT * FROM users WHERE id=$1', [payload.id]);
    if (!users.length) return res.status(401).json({ message: 'Usuário não encontrado' });
    req.user = users[0];
    req.token = token;
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Token inválido ou expirado' });
  }
}

function publicUser(u) {
  return {
    id: u.id, name: u.name, email: u.email,
    role: u.role, sector: u.sector, func: u.func,
    registration: u.registration, entryDate: u.entry_date,
    createdAt: u.created_at
  };
}

// ---------- Cadastro ----------
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role, sector } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: 'Nome, email e senha são obrigatórios' });

    const { rows } = await pool.query('SELECT id FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    if (rows.length) return res.status(409).json({ message: 'Já existe uma conta com este email' });

    const hash = await bcrypt.hash(password, 10);
    const id = uuid();
    await pool.query(
      'INSERT INTO users(id,name,email,password,role,sector) VALUES($1,$2,$3,$4,$5,$6)',
      [id, name, email, hash, role||'', sector||'']
    );

    const token = jwt.sign({ id }, JWT_SECRET, { expiresIn: '7d' });
    await pool.query(
      'INSERT INTO sessions(token,user_id,user_agent) VALUES($1,$2,$3)',
      [token, id, req.headers['user-agent']||'']
    );

    const { rows: u } = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
    res.json({ token, user: publicUser(u[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Erro ao cadastrar' });
  }
});

// ---------- Login ----------
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Informe email e senha' });

    const { rows } = await pool.query('SELECT * FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    if (!rows.length) return res.status(401).json({ message: 'Email ou senha inválidos' });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'Email ou senha inválidos' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    await pool.query(
      'INSERT INTO sessions(token,user_id,user_agent) VALUES($1,$2,$3)',
      [token, user.id, req.headers['user-agent']||'']
    );

    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Erro ao entrar' });
  }
});

// ---------- Logout ----------
app.post('/api/logout', authMiddleware, async (req, res) => {
  await pool.query('DELETE FROM sessions WHERE token=$1', [req.token]);
  res.json({ ok: true });
});

// ---------- Perfil ----------
app.get('/api/me', authMiddleware, (req, res) => res.json(publicUser(req.user)));

app.put('/api/profile', authMiddleware, async (req, res) => {
  const { name, email, role, sector, func, registration, entryDate } = req.body;
  await pool.query(
    `UPDATE users SET
      name=COALESCE($1,name), email=COALESCE($2,email), role=COALESCE($3,role),
      sector=COALESCE($4,sector), func=COALESCE($5,func),
      registration=COALESCE($6,registration), entry_date=COALESCE($7,entry_date)
     WHERE id=$8`,
    [name, email, role, sector, func, registration, entryDate, req.user.id]
  );
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
  res.json(publicUser(rows[0]));
});

// ---------- Sessões ----------
app.get('/api/sessions', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM sessions WHERE user_id=$1', [req.user.id]);
  res.json(rows.map(s => ({
    token: s.token.slice(0,8) + '…',
    userAgent: s.user_agent,
    createdAt: s.created_at,
    current: s.token === req.token
  })));
});

app.delete('/api/sessions/others', authMiddleware, async (req, res) => {
  await pool.query('DELETE FROM sessions WHERE user_id=$1 AND token!=$2', [req.user.id, req.token]);
  res.json({ ok: true });
});

// ---------- Funcionários ----------
app.get('/api/employees', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT id,name,email,role FROM users WHERE id!=$1', [req.user.id]);
  res.json(rows);
});

// ---------- Relatórios ----------
app.get('/api/reports/sent', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM reports WHERE sender_id=$1 ORDER BY created_at DESC', [req.user.id]
  );
  res.json(rows.map(formatReport));
});

app.get('/api/inbox', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM reports WHERE recipients @> $1::jsonb ORDER BY created_at DESC`,
    [JSON.stringify([req.user.email])]
  );
  res.json(rows.map(r => ({ ...formatReport(r), myRead: (r.read_by||[]).includes(req.user.email) })));
});

app.post('/api/reports/upload', authMiddleware, upload.single('file'), async (req, res) => {
  const { title, body } = req.body;
  let recipients = [];
  try { recipients = JSON.parse(req.body.recipients || '[]'); } catch {}
  if (!title || !recipients.length)
    return res.status(400).json({ message: 'Título e destinatários são obrigatórios' });

  const fileUrl = req.file ? '/uploads/' + req.file.filename : null;
  const fileName = req.file ? req.file.originalname : null;

  const { rows } = await pool.query(
    `INSERT INTO reports(title,body,sender,sender_id,recipients,file_url,file_name)
     VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [title, body||'', req.user.name, req.user.id, JSON.stringify(recipients), fileUrl, fileName]
  );

  const report = formatReport(rows[0]);
  recipients.forEach(email => notify(email, 'new-report', report));
  res.json(report);
});

app.post('/api/reports/:id/read', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM reports WHERE id=$1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ message: 'Não encontrado' });
  const readBy = rows[0].read_by || [];
  if (!readBy.includes(req.user.email)) {
    readBy.push(req.user.email);
    await pool.query('UPDATE reports SET read_by=$1 WHERE id=$2', [JSON.stringify(readBy), req.params.id]);
  }
  res.json({ ok: true });
});

function formatReport(r) {
  return {
    id: r.id, title: r.title, body: r.body,
    sender: r.sender, senderId: r.sender_id,
    recipients: r.recipients, readBy: r.read_by,
    status: r.status, date: r.created_at,
    file: r.file_url ? { url: r.file_url, originalname: r.file_name } : null
  };
}

// ---------- Notificações SSE ----------
const sseClients = {};
function notify(email, event, data) {
  (sseClients[email] || []).forEach(res =>
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  );
}

app.get('/api/notifications', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(401).end();
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [payload.id]);
    if (!rows.length) return res.status(401).end();
    const email = rows[0].email;

    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.flushHeaders();

    sseClients[email] = sseClients[email] || [];
    sseClients[email].push(res);
    req.on('close', () => {
      sseClients[email] = (sseClients[email] || []).filter(r => r !== res);
    });
  } catch { res.status(401).end(); }
});

// ---------- Fallback HTML ----------
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(PUBLIC_DIR, req.path === '/' ? 'login.html' : req.path), err => {
    if (err) res.status(404).send('Não encontrado');
  });
});

// ---------- Iniciar ----------
initDB().then(() => {
  app.listen(PORT, () => console.log(`✅ Servidor rodando em http://localhost:${PORT}`));
}).catch(e => {
  console.error('Erro ao iniciar banco:', e);
  process.exit(1);
});
