const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const { Resend } = require('resend'); // ✅ NEW

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'crimewatch-secret-key';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';
const VIEW_PASS  = process.env.VIEW_PASS  || 'view123';

// ✅ NEW - Resend email client
const resend = new Resend(process.env.RESEND_API_KEY);

// ✅ NEW - OTP temporary store
const otpStore = {};

// ✅ NEW - Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ── DATABASE ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    const res = await client.query(sql, params);
    return res;
  } finally {
    client.release();
  }
}

async function initDB() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      pin TEXT,
      email TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  // ✅ NEW - Add email column if it doesn't exist (for existing databases)
  await query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      type TEXT,
      location TEXT,
      date TEXT,
      description TEXT,
      image_url TEXT,
      username TEXT,
      user_name TEXT,
      status TEXT DEFAULT 'Pending',
      submitted TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  console.log('✅ Database tables ready');
}

// ── MIDDLEWARE ──
app.use(cors());
app.use(express.static(__dirname));
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ── FILE UPLOAD ──
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// ── AUTH MIDDLEWARE ──
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(h.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}
function admin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── AUTH ROUTES ──
app.post('/api/auth/register', async (req, res) => {
  const { name, username, password, pin, email } = req.body; // ✅ added email
  if (!name || !username || !password) return res.status(400).json({ error: 'Missing fields' });
  const existing = await query('SELECT id FROM users WHERE username=$1', [username.toLowerCase()]);
  if (existing.rows.length) return res.status(409).json({ error: 'Username taken' });
  const hashed = await bcrypt.hash(password, 10);
  await query(
    'INSERT INTO users(name,username,password,pin,email) VALUES($1,$2,$3,$4,$5)',
    [name, username.toLowerCase(), hashed, pin || null, email || null]
  );
  res.status(201).json({ message: 'Account created' });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await query('SELECT * FROM users WHERE username=$1', [username?.toLowerCase()]);
  const user = result.rows[0];
  if (!user || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({
    token: jwt.sign({ role: 'user', username: user.username, name: user.name }, JWT_SECRET, { expiresIn: '7d' }),
    name: user.name, username: user.username, role: 'user', email: user.email || null
  });
});

app.post('/api/auth/login-pin', async (req, res) => {
  const { username, pin } = req.body;
  const result = await query('SELECT * FROM users WHERE username=$1 AND pin=$2', [username?.toLowerCase(), pin]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid username or PIN' });
  res.json({
    token: jwt.sign({ role: 'user', username: user.username, name: user.name }, JWT_SECRET, { expiresIn: '7d' }),
    name: user.name, username: user.username, role: 'user'
  });
});

app.post('/api/auth/admin-login', (req, res) => {
  if (req.body.password !== ADMIN_PASS) return res.status(401).json({ error: 'Wrong password' });
  res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '8h' }), role: 'admin' });
});

app.post('/api/auth/view-login', (req, res) => {
  if (req.body.password !== VIEW_PASS) return res.status(401).json({ error: 'Wrong password' });
  res.json({ token: jwt.sign({ role: 'view' }, JWT_SECRET, { expiresIn: '8h' }), role: 'view' });
});

// ✅ NEW - Send OTP to email
app.post('/api/auth/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const otp = generateOTP();
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 }; // 5 minutes

  try {
    await resend.emails.send({
      from: 'CrimeWatch <onboarding@resend.dev>',
      to: email,
      subject: 'Your CrimeWatch Login OTP',
      html: `
        <div style="font-family:Arial,sans-serif;background:#0a0c10;color:#e8eaf0;padding:30px;border-radius:8px;max-width:400px;">
          <h2 style="color:#e63946;letter-spacing:3px;">CRIME<span style="color:#fff">WATCH</span></h2>
          <p style="color:#9aa0b0;margin-top:10px;">Your One-Time Password:</p>
          <div style="background:#1e2330;border:1px solid #e63946;border-radius:6px;padding:20px;text-align:center;margin:20px 0;">
            <span style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#e63946;">${otp}</span>
          </div>
          <p style="color:#5a6070;font-size:12px;">This OTP expires in <strong>5 minutes</strong>. Do not share it with anyone.</p>
        </div>
      `
    });
    res.json({ message: 'OTP sent successfully' });
  } catch (err) {
    console.error('Email error:', err);
    res.status(500).json({ error: 'Failed to send OTP email' });
  }
});

// ✅ NEW - Verify OTP
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

  const record = otpStore[email];
  if (!record) return res.status(400).json({ error: 'No OTP found for this email' });
  if (Date.now() > record.expires) {
    delete otpStore[email];
    return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
  }
  if (record.otp !== otp) return res.status(400).json({ error: 'Wrong OTP. Try again.' });

  delete otpStore[email]; // ✅ Clear after use
  res.json({ success: true, message: 'OTP verified!' });
});

// ── REPORT ROUTES ──
app.post('/api/reports', auth, upload.single('image'), async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Users only' });
  const { type, location, date, description } = req.body;
  if (!type || !location || !date || !description) return res.status(400).json({ error: 'Missing fields' });
  const id = 'CW-' + Math.floor(100000 + Math.random() * 900000);
  const imageUrl = req.file ? '/uploads/' + req.file.filename : null;
  const submitted = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  await query(
    'INSERT INTO reports(id,type,location,date,description,image_url,username,user_name,status,submitted) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
    [id, type, location, date, description, imageUrl, req.user.username, req.user.name, 'Pending', submitted]
  );
  res.status(201).json({ message: 'Report submitted', id });
});

app.get('/api/reports/mine', auth, async (req, res) => {
  const result = await query('SELECT * FROM reports WHERE username=$1 ORDER BY created_at DESC', [req.user.username]);
  res.json(result.rows);
});

app.get('/api/reports/approved', auth, async (req, res) => {
  const result = await query("SELECT * FROM reports WHERE status='Approved' ORDER BY created_at DESC");
  res.json(result.rows);
});

app.get('/api/reports/stats', auth, admin, async (req, res) => {
  const total    = await query('SELECT COUNT(*) FROM reports');
  const pending  = await query("SELECT COUNT(*) FROM reports WHERE status='Pending'");
  const approved = await query("SELECT COUNT(*) FROM reports WHERE status='Approved'");
  const rejected = await query("SELECT COUNT(*) FROM reports WHERE status='Rejected'");
  res.json({
    total:    parseInt(total.rows[0].count),
    pending:  parseInt(pending.rows[0].count),
    approved: parseInt(approved.rows[0].count),
    rejected: parseInt(rejected.rows[0].count),
  });
});

app.get('/api/reports', auth, admin, async (req, res) => {
  const { status } = req.query;
  const result = status && status !== 'all'
    ? await query('SELECT * FROM reports WHERE status=$1 ORDER BY created_at DESC', [status])
    : await query('SELECT * FROM reports ORDER BY created_at DESC');
  res.json(result.rows);
});

app.patch('/api/reports/:id/status', auth, admin, async (req, res) => {
  await query('UPDATE reports SET status=$1 WHERE id=$2', [req.body.status, req.params.id]);
  res.json({ message: 'Updated' });
});

app.put('/api/reports/:id', auth, admin, async (req, res) => {
  const { type, location, date, description } = req.body;
  await query('UPDATE reports SET type=$1,location=$2,date=$3,description=$4 WHERE id=$5', [type, location, date, description, req.params.id]);
  res.json({ message: 'Updated' });
});

app.delete('/api/reports/:id', auth, admin, async (req, res) => {
  const result = await query('SELECT image_url FROM reports WHERE id=$1', [req.params.id]);
  if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
  const rep = result.rows[0];
  if (rep.image_url) { try { fs.unlinkSync(path.join(__dirname, rep.image_url)); } catch {} }
  await query('DELETE FROM reports WHERE id=$1', [req.params.id]);
  res.json({ message: 'Deleted' });
});

app.get('/api/admin/users', auth, admin, async (req, res) => {
  const result = await query('SELECT id,name,username,pin,email,created_at FROM users ORDER BY created_at DESC');
  res.json(result.rows);
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// ── START ──
initDB().then(() => {
  app.listen(PORT, () => console.log('✅ CrimeWatch running on port ' + PORT));
}).catch(err => {
  console.error('❌ DB init failed:', err.message);
  process.exit(1);
});
