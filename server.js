const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'crimewatch-secret-key';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';
const VIEW_PASS  = process.env.VIEW_PASS  || 'view123';

// ── EMAIL via Brevo HTTP API ──
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendEmailOTP(to, otp) {
  console.log(`📧 Sending OTP to ${to} via Brevo HTTP API...`);

  if (!process.env.BREVO_API_KEY) {
    throw new Error('BREVO_API_KEY must be set in Railway environment variables.');
  }
  if (!process.env.BREVO_SENDER_EMAIL) {
    throw new Error('BREVO_SENDER_EMAIL must be set in Railway environment variables.');
  }

  const response = await axios.post(
    'https://api.brevo.com/v3/smtp/email',
    {
      sender: {
        name: 'CrimeWatch',
        email: process.env.BREVO_SENDER_EMAIL
      },
      to: [{ email: to }],
      subject: 'Your CrimeWatch Verification Code',
      htmlContent: `
        <div style="font-family:Arial,sans-serif;background:#0a0c10;color:#e8eaf0;padding:30px;border-radius:8px;max-width:400px;">
          <h2 style="color:#e63946;letter-spacing:3px;">CRIME<span style="color:#fff">WATCH</span></h2>
          <p style="color:#9aa0b0;margin-top:10px;">Your One-Time Password:</p>
          <div style="background:#1e2330;border:1px solid #e63946;border-radius:6px;padding:20px;text-align:center;margin:20px 0;">
            <span style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#e63946;">${otp}</span>
          </div>
          <p style="color:#5a6070;font-size:12px;">This OTP expires in <strong>5 minutes</strong>. Do not share it with anyone.</p>
        </div>
      `
    },
    {
      headers: {
        'api-key': process.env.BREVO_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      timeout: 10000
    }
  );

  console.log(`✅ OTP sent to ${to} — Brevo messageId: ${response.data.messageId}`);
}

// ── DATABASE ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

async function query(sql, params = []) {
  let retries = 3;
  while (retries > 0) {
    try {
      const client = await pool.connect();
      try {
        const res = await client.query(sql, params);
        return res;
      } finally {
        client.release();
      }
    } catch (err) {
      retries--;
      if (retries === 0) throw err;
      console.log("DB retry...", err.message);
      await new Promise(r => setTimeout(r, 2000));
    }
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
      phone TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  // Add columns for existing databases that may not have them yet
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`);
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT`);
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE`);
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS security_question TEXT`);
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS security_answer TEXT`);
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
      contact TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await query(`ALTER TABLE reports ADD COLUMN IF NOT EXISTS contact TEXT`);
  await query(`
    CREATE TABLE IF NOT EXISTS otps (
      email TEXT PRIMARY KEY,
      otp TEXT NOT NULL,
      expires BIGINT NOT NULL
    )
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS report_rate_limits (
      username TEXT NOT NULL,
      report_date DATE NOT NULL,
      count INTEGER DEFAULT 1,
      PRIMARY KEY (username, report_date)
    )
  `);
  console.log('✅ Database tables ready');
}

// ── MIDDLEWARE ──
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: false
}));
app.options('*', cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: false
}));
app.use(express.static(__dirname));
app.use(express.json({ limit: '10mb' }));

// ── CLOUDINARY CONFIG ──
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ── FILE UPLOAD via Cloudinary ──
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'crimewatch',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1200, quality: 'auto', fetch_format: 'auto' }],
  },
});
const upload = multer({
  storage: cloudinaryStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
});

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

// ── RATE LIMITING ──
const DAILY_REPORT_LIMIT = 5;

async function checkRateLimit(username) {
  const today = new Date().toISOString().split('T')[0];
  const result = await query(
    'SELECT count FROM report_rate_limits WHERE username=$1 AND report_date=$2',
    [username, today]
  );
  if (!result.rows.length) {
    await query(
      'INSERT INTO report_rate_limits(username, report_date, count) VALUES($1, $2, 1)',
      [username, today]
    );
    return { allowed: true, count: 1, limit: DAILY_REPORT_LIMIT };
  }
  const count = result.rows[0].count;
  if (count >= DAILY_REPORT_LIMIT) {
    return { allowed: false, count, limit: DAILY_REPORT_LIMIT };
  }
  await query(
    'UPDATE report_rate_limits SET count = count + 1 WHERE username=$1 AND report_date=$2',
    [username, today]
  );
  return { allowed: true, count: count + 1, limit: DAILY_REPORT_LIMIT };
}

// ── DUPLICATE DETECTION ──
async function checkDuplicate(username, type, location, description) {
  const exactMatch = await query(
    `SELECT id FROM reports
     WHERE username = $1
       AND LOWER(TRIM(type)) = LOWER(TRIM($2))
       AND LOWER(TRIM(location)) = LOWER(TRIM($3))
       AND created_at > NOW() - INTERVAL '24 hours'
     LIMIT 1`,
    [username, type, location]
  );
  if (exactMatch.rows.length > 0) return { id: exactMatch.rows[0].id, reason: 'same type and location' };

  const locationWords = location.trim().toLowerCase().split(/\s+/).filter(w => w.length >= 3);
  if (locationWords.length > 0) {
    const conditions = locationWords.map((_, i) => `LOWER(location) LIKE $${i + 3}`).join(' OR ');
    const likeParams = locationWords.map(w => `%${w}%`);
    const fuzzyMatch = await query(
      `SELECT id FROM reports
       WHERE username = $1
         AND LOWER(TRIM(type)) = LOWER(TRIM($2))
         AND created_at > NOW() - INTERVAL '24 hours'
         AND (${conditions})
       LIMIT 1`,
      [username, type, ...likeParams]
    );
    if (fuzzyMatch.rows.length > 0) return { id: fuzzyMatch.rows[0].id, reason: 'similar location and type' };
  }

  const descWords = description.trim().toLowerCase().split(/\s+/).filter(w => w.length >= 4);
  if (descWords.length >= 5) {
    const descConditions = descWords.slice(0, 8).map((_, i) => `LOWER(description) LIKE $${i + 3}`).join(' OR ');
    const descParams = descWords.slice(0, 8).map(w => `%${w}%`);
    const descCandidates = await query(
      `SELECT id, description FROM reports
       WHERE username = $1
         AND LOWER(TRIM(type)) = LOWER(TRIM($2))
         AND created_at > NOW() - INTERVAL '24 hours'
         AND (${descConditions})
       LIMIT 10`,
      [username, type, ...descParams]
    );
    for (const row of descCandidates.rows) {
      const existingWords = row.description.toLowerCase().split(/\s+/);
      const matchCount = descWords.filter(w => existingWords.some(ew => ew.includes(w))).length;
      if (matchCount >= 5) {
        return { id: row.id, reason: 'very similar description' };
      }
    }
  }

  return null;
}

// ── AUTH ROUTES ──
app.post('/api/auth/register', async (req, res) => {
  const { name, username, password, pin, email, phone } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (!phone) return res.status(400).json({ error: 'Contact number is required.' });
  // Validate Indian mobile number: 10 digits, starts with 6-9
  if (!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid 10-digit Indian mobile number.' });

  const existing = await query('SELECT id FROM users WHERE username=$1', [username.toLowerCase()]);
  if (existing.rows.length) return res.status(409).json({ error: 'Username taken' });
  const hashed = await bcrypt.hash(password, 10);
  await query(
    'INSERT INTO users(name,username,password,pin,email,phone,email_verified) VALUES($1,$2,$3,$4,$5,$6,$7)',
    [name, username.toLowerCase(), hashed, pin || null, email || null, phone, false]
  );
  res.status(201).json({ message: 'Account created' });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await query('SELECT * FROM users WHERE username=$1', [username?.toLowerCase()]);
  const user = result.rows[0];
  if (!user || !await bcrypt.compare(password, user.password))
    return res.status(401).json({ error: 'Invalid credentials' });
  res.json({
    token: jwt.sign({ role: 'user', username: user.username, name: user.name }, JWT_SECRET, { expiresIn: '7d' }),
    name: user.name, username: user.username, role: 'user',
    email: user.email || null,
    emailVerified: user.email_verified || false
  });
});

app.post('/api/auth/login-pin', async (req, res) => {
  const { username, pin } = req.body;
  const result = await query('SELECT * FROM users WHERE username=$1 AND pin=$2', [username?.toLowerCase(), pin]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid username or PIN' });
  res.json({
    token: jwt.sign({ role: 'user', username: user.username, name: user.name }, JWT_SECRET, { expiresIn: '7d' }),
    name: user.name, username: user.username, role: 'user',
    email: user.email || null,
    emailVerified: user.email_verified || false
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

// ── OTP ROUTES ──
app.post('/api/auth/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const otp = generateOTP();
  const expires = Date.now() + 5 * 60 * 1000;
  try {
    await query(
      'INSERT INTO otps(email, otp, expires) VALUES($1,$2,$3) ON CONFLICT(email) DO UPDATE SET otp=$2, expires=$3',
      [email, otp, expires]
    );
    await sendEmailOTP(email, otp);
    res.json({ message: 'OTP sent successfully' });
  } catch (err) {
    console.error('❌ OTP send error:', err.message);
    let userMsg = 'Failed to send OTP. Please try again.';
    if (err.message.includes('BREVO_API_KEY')) {
      userMsg = 'Email not configured on server. Contact admin.';
    } else if (err.message.includes('BREVO_SENDER_EMAIL')) {
      userMsg = 'Sender email not configured on server. Contact admin.';
    } else if (err.response?.data?.message) {
      userMsg = 'Email service error: ' + err.response.data.message;
    }
    res.status(500).json({ error: userMsg, detail: err.message });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
  try {
    const result = await query('SELECT * FROM otps WHERE email=$1', [email]);
    const record = result.rows[0];
    if (!record) return res.status(400).json({ error: 'No OTP found. Please request a new one.' });
    if (Date.now() > parseInt(record.expires)) {
      await query('DELETE FROM otps WHERE email=$1', [email]);
      return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
    }
    if (record.otp !== otp) return res.status(400).json({ error: 'Wrong OTP. Try again.' });
    await query('DELETE FROM otps WHERE email=$1', [email]);
    await query('UPDATE users SET email_verified=TRUE WHERE email=$1', [email]);
    res.json({ success: true, message: 'OTP verified!' });
  } catch (err) {
    console.error('❌ Verify OTP error:', err.message);
    res.status(500).json({ error: 'Verification failed. Try again.' });
  }
});

// ── REPORT ROUTES ──
app.post('/api/reports', auth, upload.single('image'), async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Users only' });

  const { type, location, date, description, contact } = req.body;
  if (!type || !location || !date || !description)
    return res.status(400).json({ error: 'Missing fields' });

  const userRecord = await query('SELECT email_verified FROM users WHERE username=$1', [req.user.username]);
  const userRow = userRecord.rows[0];
  if (!userRow || !userRow.email_verified) {
    if (req.file?.filename) {
      try { await cloudinary.uploader.destroy(req.file.filename); } catch {}
    }
    return res.status(403).json({
      error: 'Identity not verified. Please verify your email before submitting reports.',
      unverified: true
    });
  }

  try {
    const rateCheck = await checkRateLimit(req.user.username);
    if (!rateCheck.allowed) {
      if (req.file?.filename) {
        try { await cloudinary.uploader.destroy(req.file.filename); } catch {}
      }
      return res.status(429).json({
        error: `Daily report limit reached. You can submit up to ${rateCheck.limit} reports per day. Try again tomorrow.`
      });
    }
  } catch (err) {
    console.error('Rate limit check failed:', err.message);
  }

  try {
    const duplicate = await checkDuplicate(req.user.username, type, location, description);
    if (duplicate) {
      if (req.file?.filename) {
        try { await cloudinary.uploader.destroy(req.file.filename); } catch {}
      }
      return res.status(409).json({
        error: `A similar report (${duplicate.id}) was already submitted with ${duplicate.reason} in the last 24 hours.`,
        duplicate_id: duplicate.id
      });
    }
  } catch (err) {
    console.error('Duplicate check failed:', err.message);
  }

  const id = 'CW-' + Math.floor(100000 + Math.random() * 900000);
  const imageUrl = req.file ? req.file.path : null;
  const submitted = new Date().toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric'
  });

  await query(
    'INSERT INTO reports(id,type,location,date,description,image_url,username,user_name,status,submitted,contact) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
    [id, type, location, date, description, imageUrl, req.user.username, req.user.name, 'Pending', submitted, contact || null]
  );

  res.status(201).json({ message: 'Report submitted', id });
});

app.get('/api/reports/my-limit', auth, async (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  const result = await query(
    'SELECT count FROM report_rate_limits WHERE username=$1 AND report_date=$2',
    [req.user.username, today]
  );
  const used = result.rows.length ? result.rows[0].count : 0;
  res.json({ used, limit: DAILY_REPORT_LIMIT, remaining: Math.max(0, DAILY_REPORT_LIMIT - used) });
});

app.get('/api/reports/mine', auth, async (req, res) => {
  const result = await query('SELECT * FROM reports WHERE username=$1 ORDER BY created_at DESC', [req.user.username]);
  res.json(result.rows);
});

app.get('/api/reports/approved', auth, async (req, res) => {
  const result = await query("SELECT * FROM reports WHERE status IN ('Approved','Solved') ORDER BY created_at DESC");
  res.json(result.rows);
});

app.get('/api/reports/stats', auth, admin, async (req, res) => {
  const total    = await query('SELECT COUNT(*) FROM reports');
  const pending  = await query("SELECT COUNT(*) FROM reports WHERE status='Pending'");
  const approved = await query("SELECT COUNT(*) FROM reports WHERE status='Approved'");
  const rejected = await query("SELECT COUNT(*) FROM reports WHERE status='Rejected'");
  const solved   = await query("SELECT COUNT(*) FROM reports WHERE status='Solved'");
  res.json({
    total:    parseInt(total.rows[0].count),
    pending:  parseInt(pending.rows[0].count),
    approved: parseInt(approved.rows[0].count),
    rejected: parseInt(rejected.rows[0].count),
    solved:   parseInt(solved.rows[0].count),
  });
});

app.get('/api/reports', auth, admin, async (req, res) => {
  const { status } = req.query;
  const result = status && status !== 'all'
    ? await query('SELECT * FROM reports WHERE status=$1 ORDER BY created_at DESC', [status])
    : await query('SELECT * FROM reports ORDER BY created_at DESC');
  res.json(result.rows);
});

app.patch('/api/reports/:id/status', auth, async (req, res) => {
  await query('UPDATE reports SET status=$1 WHERE id=$2', [req.body.status, req.params.id]);
  res.json({ message: 'Updated' });
});

app.put('/api/reports/:id', auth, admin, async (req, res) => {
  const { type, location, date, description } = req.body;
  await query(
    'UPDATE reports SET type=$1,location=$2,date=$3,description=$4 WHERE id=$5',
    [type, location, date, description, req.params.id]
  );
  res.json({ message: 'Updated' });
});

app.delete('/api/reports/:id', auth, admin, async (req, res) => {
  const result = await query('SELECT image_url FROM reports WHERE id=$1', [req.params.id]);
  if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
  const rep = result.rows[0];
  if (rep.image_url) {
    try {
      const parts = rep.image_url.split('/');
      const filenameWithExt = parts[parts.length - 1];
      const publicId = 'crimewatch/' + filenameWithExt.split('.')[0];
      await cloudinary.uploader.destroy(publicId);
    } catch (e) {
      console.error('Cloudinary delete error:', e.message);
    }
  }
  await query('DELETE FROM reports WHERE id=$1', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ── ADMIN USERS — now includes phone ──
app.get('/api/admin/users', auth, admin, async (req, res) => {
  const result = await query('SELECT id,name,username,pin,email,phone,created_at FROM users ORDER BY created_at DESC');
  res.json(result.rows);
});

app.get('/api/auth/verify-status', auth, async (req, res) => {
  const result = await query('SELECT email_verified, email FROM users WHERE username=$1', [req.user.username]);
  const user = result.rows[0];
  res.json({ emailVerified: user ? user.email_verified : false, email: user ? user.email : null });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── START ──
initDB().then(() => {
  app.listen(PORT, () => console.log('✅ CrimeWatch running on port ' + PORT));
}).catch(err => {
  console.error('❌ DB init failed:', err.message);
  process.exit(1);
});
