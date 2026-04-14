const express = require('express');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 13000;
const JWT_SECRET = process.env.JWT_SECRET || 'coophccar-admin-secret-2025';

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
      role TEXT DEFAULT 'admin',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

  // Criar admin padrão se não existir
  const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@coophccar.org.br');
  if (!adminExists) {
    const hash = bcrypt.hashSync('admin123', 10);
    db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)').run(
      'Administrador', 'admin@coophccar.org.br', hash, 'admin'
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
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
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

// ==========================================
// PUBLIC API (transparência - sem autenticação)
// ==========================================
const publicTables = ['execucao', 'planos', 'parcerias', 'emendas', 'documentos', 'prestacao'];

app.get('/api/public/transparencia', (req, res) => {
  const data = {};
  publicTables.forEach(table => {
    data[table] = db.prepare(`SELECT * FROM ${table} ORDER BY id DESC`).all();
  });
  // Resumo financeiro
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

// CRUD genérico para todas as tabelas de transparência
const allowedTables = ['execucao', 'planos', 'parcerias', 'emendas', 'documentos', 'prestacao', 'noticias', 'galeria', 'usuarios'];

// Colunas permitidas por tabela (whitelist)
const tableColumns = {
  execucao: ['tipo', 'descricao', 'valor', 'data', 'categoria', 'comprovante_url', 'observacoes'],
  planos: ['titulo', 'descricao', 'vigencia_inicio', 'vigencia_fim', 'status', 'arquivo_url'],
  parcerias: ['parceiro', 'instrumento', 'objeto', 'valor', 'vigencia_inicio', 'vigencia_fim', 'status'],
  emendas: ['proponente', 'objeto', 'valor', 'ano', 'status', 'conta_especifica', 'comprovante_url'],
  documentos: ['titulo', 'categoria', 'descricao', 'arquivo_url', 'publico'],
  prestacao: ['titulo', 'tipo', 'ano_referencia', 'descricao', 'arquivo_url'],
  noticias: ['titulo', 'resumo', 'conteudo', 'imagem_url', 'publicado'],
  galeria: ['titulo', 'descricao', 'imagem_url', 'album'],
  usuarios: ['name', 'email', 'password', 'role']
};

// LIST
app.get('/api/admin/:table', (req, res) => {
  const { table } = req.params;
  if (!allowedTables.includes(table)) return res.status(400).json({ error: 'Tabela inválida.' });

  const dbTable = table === 'usuarios' ? 'users' : table;
  const rows = db.prepare(`SELECT * FROM ${dbTable} ORDER BY id DESC`).all();

  if (table === 'usuarios') {
    rows.forEach(r => delete r.password);
  }
  res.json(rows);
});

// GET ONE
app.get('/api/admin/:table/:id', (req, res) => {
  const { table, id } = req.params;
  if (!allowedTables.includes(table)) return res.status(400).json({ error: 'Tabela inválida.' });

  const dbTable = table === 'usuarios' ? 'users' : table;
  const row = db.prepare(`SELECT * FROM ${dbTable} WHERE id = ?`).get(id);
  if (!row) return res.status(404).json({ error: 'Registro não encontrado.' });

  if (table === 'usuarios') delete row.password;
  res.json(row);
});

// CREATE
app.post('/api/admin/:table', (req, res) => {
  const { table } = req.params;
  if (!allowedTables.includes(table)) return res.status(400).json({ error: 'Tabela inválida.' });

  const dbTable = table === 'usuarios' ? 'users' : table;
  const allowed = tableColumns[table];
  const data = {};

  allowed.forEach(col => {
    if (req.body[col] !== undefined && req.body[col] !== '') {
      data[col] = req.body[col];
    }
  });

  if (table === 'usuarios' && data.password) {
    data.password = bcrypt.hashSync(data.password, 10);
  }

  const cols = Object.keys(data);
  const vals = Object.values(data);
  const placeholders = cols.map(() => '?').join(', ');

  try {
    const result = db.prepare(`INSERT INTO ${dbTable} (${cols.join(', ')}) VALUES (${placeholders})`).run(...vals);
    res.json({ id: result.lastInsertRowid, ...data });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'Registro duplicado (e-mail já cadastrado).' });
    }
    res.status(500).json({ error: 'Erro ao salvar.' });
  }
});

// UPDATE
app.put('/api/admin/:table/:id', (req, res) => {
  const { table, id } = req.params;
  if (!allowedTables.includes(table)) return res.status(400).json({ error: 'Tabela inválida.' });

  const dbTable = table === 'usuarios' ? 'users' : table;
  const allowed = tableColumns[table];
  const data = {};

  allowed.forEach(col => {
    if (req.body[col] !== undefined && req.body[col] !== '') {
      data[col] = req.body[col];
    }
  });

  if (table === 'usuarios' && data.password) {
    data.password = bcrypt.hashSync(data.password, 10);
  } else if (table === 'usuarios') {
    delete data.password;
  }

  if (Object.keys(data).length === 0) {
    return res.status(400).json({ error: 'Nenhum dado para atualizar.' });
  }

  data.updated_at = new Date().toISOString();
  const sets = Object.keys(data).map(k => `${k} = ?`).join(', ');
  const vals = [...Object.values(data), id];

  try {
    db.prepare(`UPDATE ${dbTable} SET ${sets} WHERE id = ?`).run(...vals);
    res.json({ id: parseInt(id), ...data });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'E-mail já cadastrado.' });
    }
    res.status(500).json({ error: 'Erro ao atualizar.' });
  }
});

// DELETE
app.delete('/api/admin/:table/:id', (req, res) => {
  const { table, id } = req.params;
  if (!allowedTables.includes(table)) return res.status(400).json({ error: 'Tabela inválida.' });

  const dbTable = table === 'usuarios' ? 'users' : table;

  // Impedir exclusão do próprio usuário
  if (table === 'usuarios' && parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'Você não pode excluir seu próprio usuário.' });
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
