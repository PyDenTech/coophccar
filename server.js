const express = require('express');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'coophccar-admin-secret-2025';

// ==========================================
// OTP STORE (em memória)
// ==========================================
const otpStore = new Map(); // email -> { code, expiresAt, attempts }

// ==========================================
// EMAIL TRANSPORT
// ==========================================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || ''
  }
});

const SMTP_FROM = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@coophccar.org.br';

// ==========================================
// MIDDLEWARE
// ==========================================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==========================================
// DATABASE SETUP
// ==========================================
const db = new Database(path.join(__dirname, 'database.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'editor',
      active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS execucao (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tipo TEXT NOT NULL,
      descricao TEXT NOT NULL,
      valor REAL NOT NULL,
      data TEXT NOT NULL,
      categoria TEXT,
      comprovante_url TEXT,
      observacoes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS planos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT NOT NULL,
      descricao TEXT NOT NULL,
      vigencia_inicio TEXT NOT NULL,
      vigencia_fim TEXT NOT NULL,
      status TEXT NOT NULL,
      arquivo_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS parcerias (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      parceiro TEXT NOT NULL,
      instrumento TEXT NOT NULL,
      objeto TEXT NOT NULL,
      valor REAL,
      vigencia_inicio TEXT,
      vigencia_fim TEXT,
      status TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS emendas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      proponente TEXT NOT NULL,
      objeto TEXT NOT NULL,
      valor REAL NOT NULL,
      ano INTEGER NOT NULL,
      status TEXT NOT NULL,
      conta_especifica TEXT,
      comprovante_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS documentos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT NOT NULL,
      categoria TEXT NOT NULL,
      descricao TEXT,
      arquivo_url TEXT NOT NULL,
      publico TEXT DEFAULT 'Sim',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS prestacao (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT NOT NULL,
      tipo TEXT NOT NULL,
      ano_referencia INTEGER NOT NULL,
      descricao TEXT,
      arquivo_url TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS noticias (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT NOT NULL,
      resumo TEXT NOT NULL,
      conteudo TEXT,
      imagem_url TEXT,
      publicado TEXT DEFAULT 'Não',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS galeria (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT NOT NULL,
      descricao TEXT,
      imagem_url TEXT NOT NULL,
      album TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Adicionar coluna active se não existir (migração)
  try {
    db.prepare("SELECT active FROM users LIMIT 1").get();
  } catch (e) {
    db.exec("ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1");
  }

  // Adicionar coluna updated_at em users se não existir
  try {
    db.prepare("SELECT updated_at FROM users LIMIT 1").get();
  } catch (e) {
    db.exec("ALTER TABLE users ADD COLUMN updated_at DATETIME DEFAULT NULL");
  }

  // Criar admin padrão se não existir
  const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@coophccar.org.br');
  if (!adminExists) {
    const hash = bcrypt.hashSync('admin123', 10);
    db.prepare('INSERT INTO users (name, email, password, role, active) VALUES (?, ?, ?, ?, ?)').run(
      'Administrador', 'admin@coophccar.org.br', hash, 'admin', 1
    );
    console.log('Admin padrão criado: admin@coophccar.org.br / admin123');
  }
}

initDatabase();

// ==========================================
// AUTH MIDDLEWARE
// ==========================================
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido.' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    // Verificar se o usuário ainda existe e está ativo
    const user = db.prepare('SELECT id, name, email, role, active FROM users WHERE id = ?').get(decoded.id);
    if (!user || !user.active) {
      return res.status(401).json({ error: 'Usuário desativado ou não encontrado.' });
    }
    req.user = { ...decoded, role: user.role, name: user.name };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

// Middleware: somente admin
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso restrito a administradores.' });
  }
  next();
}

// ==========================================
// AUTH ROUTES
// ==========================================
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.status(401).json({ error: 'Credenciais inválidas.' });
  }

  if (!user.active) {
    return res.status(401).json({ error: 'Conta desativada. Contate o administrador.' });
  }

  if (!bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Credenciais inválidas.' });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role }
  });
});

// Verificar token (para o frontend validar a sessão)
app.get('/api/auth/verify', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, name, email, role, active FROM users WHERE id = ?').get(req.user.id);
  if (!user || !user.active) {
    return res.status(401).json({ error: 'Sessão inválida.' });
  }
  res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// Alterar própria senha
app.put('/api/auth/password', authMiddleware, (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Senha atual e nova senha são obrigatórias.' });
  }
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'A nova senha deve ter pelo menos 6 caracteres.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(current_password, user.password)) {
    return res.status(400).json({ error: 'Senha atual incorreta.' });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE users SET password = ?, updated_at = ? WHERE id = ?').run(hash, new Date().toISOString(), req.user.id);
  res.json({ success: true });
});

// Solicitar OTP para recuperação de senha
app.post('/api/auth/forgot', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'E-mail é obrigatório.' });
  }

  const user = db.prepare('SELECT id, name, email, active FROM users WHERE email = ?').get(email);
  if (!user || !user.active) {
    // Responder OK mesmo se não existe (segurança: não revelar quais emails existem)
    return res.json({ success: true });
  }

  // Gerar OTP de 6 dígitos
  const code = crypto.randomInt(100000, 999999).toString();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutos
  otpStore.set(email, { code, expiresAt, attempts: 0 });

  // Enviar por e-mail
  try {
    if (process.env.SMTP_USER) {
      await transporter.sendMail({
        from: `"COOPHCCAR" <${SMTP_FROM}>`,
        to: email,
        subject: 'Código de Recuperação de Senha - COOPHCCAR',
        html: `
          <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:20px;">
            <div style="background:#0a4520;padding:20px;text-align:center;border-radius:8px 8px 0 0;">
              <h2 style="color:#fff;margin:0;">COOPHCCAR</h2>
              <p style="color:rgba(255,255,255,0.7);margin:4px 0 0;font-size:0.85rem;">Recuperação de Senha</p>
            </div>
            <div style="background:#fff;padding:24px;border:1px solid #ddd;border-top:3px solid #d4a017;">
              <p>Olá <strong>${user.name}</strong>,</p>
              <p>Seu código de verificação é:</p>
              <div style="background:#f4f9f6;border:2px solid #116530;border-radius:8px;padding:16px;text-align:center;margin:16px 0;">
                <span style="font-size:2rem;font-weight:700;letter-spacing:8px;color:#0a4520;">${code}</span>
              </div>
              <p style="font-size:0.85rem;color:#666;">Este código expira em <strong>10 minutos</strong>.</p>
              <p style="font-size:0.85rem;color:#666;">Se você não solicitou a recuperação de senha, ignore este e-mail.</p>
            </div>
            <div style="text-align:center;padding:12px;font-size:0.75rem;color:#999;">
              COOPHCCAR – Cooperativa dos Produtores e Horticultores Canaã dos Carajás
            </div>
          </div>
        `
      });
    } else {
      // Sem SMTP configurado: logar no console (para desenvolvimento)
      console.log(`\n  [OTP] Código para ${email}: ${code}\n`);
    }
  } catch (err) {
    console.error('Erro ao enviar e-mail:', err.message);
    // Mesmo com erro no envio, logamos no console
    console.log(`\n  [OTP] Código para ${email}: ${code}\n`);
  }

  res.json({ success: true });
});

// Verificar OTP
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) {
    return res.status(400).json({ error: 'E-mail e código são obrigatórios.' });
  }

  const otp = otpStore.get(email);
  if (!otp) {
    return res.status(400).json({ error: 'Nenhum código solicitado para este e-mail.' });
  }

  if (Date.now() > otp.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'Código expirado. Solicite um novo.' });
  }

  if (otp.attempts >= 5) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'Muitas tentativas. Solicite um novo código.' });
  }

  if (otp.code !== code) {
    otp.attempts++;
    return res.status(400).json({ error: 'Código incorreto.' });
  }

  // OTP válido - gerar reset token
  otpStore.delete(email);
  const reset_token = jwt.sign({ email, purpose: 'reset' }, JWT_SECRET, { expiresIn: '15m' });
  res.json({ success: true, reset_token });
});

// Redefinir senha com reset token
app.post('/api/auth/reset-password', (req, res) => {
  const { reset_token, new_password } = req.body;
  if (!reset_token || !new_password) {
    return res.status(400).json({ error: 'Token e nova senha são obrigatórios.' });
  }
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'A senha deve ter pelo menos 6 caracteres.' });
  }

  try {
    const decoded = jwt.verify(reset_token, JWT_SECRET);
    if (decoded.purpose !== 'reset') {
      return res.status(400).json({ error: 'Token inválido.' });
    }

    const user = db.prepare('SELECT id FROM users WHERE email = ? AND active = 1').get(decoded.email);
    if (!user) {
      return res.status(400).json({ error: 'Usuário não encontrado.' });
    }

    const hash = bcrypt.hashSync(new_password, 10);
    db.prepare('UPDATE users SET password = ?, updated_at = ? WHERE id = ?').run(hash, new Date().toISOString(), user.id);
    res.json({ success: true });
  } catch (err) {
    return res.status(400).json({ error: 'Token expirado ou inválido. Solicite novamente.' });
  }
});

// ==========================================
// PUBLIC API (transparência - sem autenticação)
// ==========================================
const publicTables = ['execucao', 'planos', 'parcerias', 'emendas', 'documentos', 'prestacao'];

app.get('/api/public/transparencia', (req, res) => {
  const data = {};
  publicTables.forEach(table => {
    data[table] = db.prepare(`SELECT * FROM ${table} ORDER BY id DESC`).all();
  });
  const receitas = db.prepare("SELECT COALESCE(SUM(valor),0) as total FROM execucao WHERE tipo='Receita'").get().total;
  const despesas = db.prepare("SELECT COALESCE(SUM(valor),0) as total FROM execucao WHERE tipo='Despesa'").get().total;
  data.resumo = { receitas, despesas, saldo: receitas - despesas };
  res.json(data);
});

publicTables.forEach(table => {
  app.get(`/api/public/${table}`, (req, res) => {
    const rows = db.prepare(`SELECT * FROM ${table} ORDER BY id DESC`).all();
    res.json(rows);
  });
});

// ==========================================
// ADMIN ROUTES (protegidas)
// ==========================================
app.use('/api/admin', authMiddleware);

// Dashboard stats
app.get('/api/admin/stats', (req, res) => {
  const stats = {
    execucao: db.prepare('SELECT COUNT(*) as count FROM execucao').get().count,
    emendas: db.prepare('SELECT COUNT(*) as count FROM emendas').get().count,
    documentos: db.prepare('SELECT COUNT(*) as count FROM documentos').get().count,
    parcerias: db.prepare('SELECT COUNT(*) as count FROM parcerias').get().count,
    planos: db.prepare('SELECT COUNT(*) as count FROM planos').get().count,
    prestacao: db.prepare('SELECT COUNT(*) as count FROM prestacao').get().count,
    noticias: db.prepare('SELECT COUNT(*) as count FROM noticias').get().count,
    galeria: db.prepare('SELECT COUNT(*) as count FROM galeria').get().count,
    usuarios: db.prepare('SELECT COUNT(*) as count FROM users').get().count
  };
  res.json(stats);
});

// Tabelas e colunas permitidas
const allowedTables = ['execucao', 'planos', 'parcerias', 'emendas', 'documentos', 'prestacao', 'noticias', 'galeria', 'usuarios'];
const adminOnlyTables = ['usuarios'];

const tableColumns = {
  execucao: ['tipo', 'descricao', 'valor', 'data', 'categoria', 'comprovante_url', 'observacoes'],
  planos: ['titulo', 'descricao', 'vigencia_inicio', 'vigencia_fim', 'status', 'arquivo_url'],
  parcerias: ['parceiro', 'instrumento', 'objeto', 'valor', 'vigencia_inicio', 'vigencia_fim', 'status'],
  emendas: ['proponente', 'objeto', 'valor', 'ano', 'status', 'conta_especifica', 'comprovante_url'],
  documentos: ['titulo', 'categoria', 'descricao', 'arquivo_url', 'publico'],
  prestacao: ['titulo', 'tipo', 'ano_referencia', 'descricao', 'arquivo_url'],
  noticias: ['titulo', 'resumo', 'conteudo', 'imagem_url', 'publicado'],
  galeria: ['titulo', 'descricao', 'imagem_url', 'album'],
  usuarios: ['name', 'email', 'password', 'role', 'active']
};

// Middleware de permissão por tabela
function checkTablePermission(req, res, next) {
  const { table } = req.params;
  if (!allowedTables.includes(table)) {
    return res.status(400).json({ error: 'Tabela inválida.' });
  }
  if (adminOnlyTables.includes(table) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso restrito a administradores.' });
  }
  next();
}

// LIST
app.get('/api/admin/:table', checkTablePermission, (req, res) => {
  const { table } = req.params;
  const dbTable = table === 'usuarios' ? 'users' : table;
  const rows = db.prepare(`SELECT * FROM ${dbTable} ORDER BY id DESC`).all();
  if (table === 'usuarios') {
    rows.forEach(r => delete r.password);
  }
  res.json(rows);
});

// GET ONE
app.get('/api/admin/:table/:id', checkTablePermission, (req, res) => {
  const { table, id } = req.params;
  const dbTable = table === 'usuarios' ? 'users' : table;
  const row = db.prepare(`SELECT * FROM ${dbTable} WHERE id = ?`).get(id);
  if (!row) return res.status(404).json({ error: 'Registro não encontrado.' });
  if (table === 'usuarios') delete row.password;
  res.json(row);
});

// CREATE
app.post('/api/admin/:table', checkTablePermission, (req, res) => {
  const { table } = req.params;
  const dbTable = table === 'usuarios' ? 'users' : table;
  const allowed = tableColumns[table];
  const data = {};

  allowed.forEach(col => {
    if (req.body[col] !== undefined && req.body[col] !== '') {
      data[col] = req.body[col];
    }
  });

  // Validações para usuários
  if (table === 'usuarios') {
    if (!data.name || !data.email || !data.password) {
      return res.status(400).json({ error: 'Nome, e-mail e senha são obrigatórios.' });
    }
    if (data.password.length < 6) {
      return res.status(400).json({ error: 'A senha deve ter pelo menos 6 caracteres.' });
    }
    data.password = bcrypt.hashSync(data.password, 10);
    if (!data.active) data.active = 1;
    else data.active = data.active === '1' || data.active === 'Sim' ? 1 : 0;
    if (!['admin', 'editor'].includes(data.role)) data.role = 'editor';
  }

  const cols = Object.keys(data);
  const vals = Object.values(data);
  const placeholders = cols.map(() => '?').join(', ');

  try {
    const result = db.prepare(`INSERT INTO ${dbTable} (${cols.join(', ')}) VALUES (${placeholders})`).run(...vals);
    const resp = { id: result.lastInsertRowid, ...data };
    delete resp.password;
    res.json(resp);
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'E-mail já cadastrado.' });
    }
    res.status(500).json({ error: 'Erro ao salvar: ' + err.message });
  }
});

// UPDATE
app.put('/api/admin/:table/:id', checkTablePermission, (req, res) => {
  const { table, id } = req.params;
  const dbTable = table === 'usuarios' ? 'users' : table;
  const allowed = tableColumns[table];
  const data = {};

  allowed.forEach(col => {
    if (req.body[col] !== undefined) {
      // Para password, só incluir se não vazio
      if (col === 'password' && req.body[col] === '') return;
      data[col] = req.body[col];
    }
  });

  if (table === 'usuarios') {
    // Impedir editor de alterar role ou active
    if (req.user.role !== 'admin') {
      delete data.role;
      delete data.active;
    }
    if (data.password) {
      if (data.password.length < 6) {
        return res.status(400).json({ error: 'A senha deve ter pelo menos 6 caracteres.' });
      }
      data.password = bcrypt.hashSync(data.password, 10);
    }
    if (data.active !== undefined) {
      data.active = data.active === '1' || data.active === 'Sim' || data.active === 1 ? 1 : 0;
    }
    if (data.role && !['admin', 'editor'].includes(data.role)) {
      data.role = 'editor';
    }
    // Impedir desativar o próprio usuário
    if (parseInt(id) === req.user.id && data.active === 0) {
      return res.status(400).json({ error: 'Você não pode desativar sua própria conta.' });
    }
    // Impedir remover o próprio admin
    if (parseInt(id) === req.user.id && data.role && data.role !== 'admin') {
      return res.status(400).json({ error: 'Você não pode rebaixar seu próprio perfil.' });
    }
  }

  if (Object.keys(data).length === 0) {
    return res.status(400).json({ error: 'Nenhum dado para atualizar.' });
  }

  data.updated_at = new Date().toISOString();
  const sets = Object.keys(data).map(k => `${k} = ?`).join(', ');
  const vals = [...Object.values(data), id];

  try {
    db.prepare(`UPDATE ${dbTable} SET ${sets} WHERE id = ?`).run(...vals);
    const resp = { id: parseInt(id), ...data };
    delete resp.password;
    res.json(resp);
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'E-mail já cadastrado.' });
    }
    res.status(500).json({ error: 'Erro ao atualizar.' });
  }
});

// DELETE
app.delete('/api/admin/:table/:id', checkTablePermission, (req, res) => {
  const { table, id } = req.params;
  const dbTable = table === 'usuarios' ? 'users' : table;

  if (table === 'usuarios') {
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'Você não pode excluir seu próprio usuário.' });
    }
    // Impedir excluir o último admin
    const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='admin' AND active=1").get().c;
    const target = db.prepare('SELECT role FROM users WHERE id = ?').get(id);
    if (target && target.role === 'admin' && adminCount <= 1) {
      return res.status(400).json({ error: 'Não é possível excluir o último administrador.' });
    }
  }

  db.prepare(`DELETE FROM ${dbTable} WHERE id = ?`).run(id);
  res.json({ success: true });
});

// ==========================================
// SPA FALLBACK
// ==========================================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ==========================================
// START SERVER
// ==========================================
app.listen(PORT, () => {
  console.log(`\n  COOPHCCAR Admin Server`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  http://localhost:${PORT}/login.html`);
  console.log(`  http://localhost:${PORT}/admin.html\n`);
  console.log(`  Login padrão: admin@coophccar.org.br / admin123\n`);
});
