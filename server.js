const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'crimewatch-secret-key';
const ADMIN_PASS = 'admin123';
const VIEW_PASS = 'view123';
const DB_PATH = path.join(__dirname, 'crimewatch.db');

app.use(cors());
app.use(express.static(__dirname));
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

let DB;
function save() { fs.writeFileSync(DB_PATH, Buffer.from(DB.export())); }
function run(sql, params=[]) { DB.run(sql, params); save(); }
function get(sql, params=[]) { const s=DB.prepare(sql); s.bind(params); if(s.step()){const r=s.getAsObject();s.free();return r;} s.free(); return null; }
function all(sql, params=[]) { const s=DB.prepare(sql); s.bind(params); const rows=[]; while(s.step()) rows.push(s.getAsObject()); s.free(); return rows; }

function auth(req,res,next){
  const h=req.headers.authorization;
  if(!h) return res.status(401).json({error:'No token'});
  try{req.user=jwt.verify(h.split(' ')[1],JWT_SECRET);next();}
  catch{res.status(401).json({error:'Invalid token'});}
}
function admin(req,res,next){
  if(req.user.role!=='admin') return res.status(403).json({error:'Admin only'});
  next();
}

// Auth
app.post('/api/auth/register', async (req,res)=>{
  const {name,username,password,pin}=req.body;
  if(!name||!username||!password) return res.status(400).json({error:'Missing fields'});
  if(get('SELECT id FROM users WHERE username=?',[username.toLowerCase()])) return res.status(409).json({error:'Username taken'});
  run('INSERT INTO users(name,username,password,pin) VALUES(?,?,?,?)',[name,username.toLowerCase(),await bcrypt.hash(password,10),pin||null]);
  res.status(201).json({message:'Account created'});
});

app.post('/api/auth/login', async (req,res)=>{
  const {username,password}=req.body;
  const user=get('SELECT * FROM users WHERE username=?',[username?.toLowerCase()]);
  if(!user||!await bcrypt.compare(password,user.password)) return res.status(401).json({error:'Invalid credentials'});
  res.json({token:jwt.sign({role:'user',username:user.username,name:user.name},JWT_SECRET,{expiresIn:'7d'}),name:user.name,username:user.username,role:'user'});
});

app.post('/api/auth/login-pin',(req,res)=>{
  const {username,pin}=req.body;
  const user=get('SELECT * FROM users WHERE username=? AND pin=?',[username?.toLowerCase(),pin]);
  if(!user) return res.status(401).json({error:'Invalid username or PIN'});
  res.json({token:jwt.sign({role:'user',username:user.username,name:user.name},JWT_SECRET,{expiresIn:'7d'}),name:user.name,username:user.username,role:'user'});
});

app.post('/api/auth/admin-login',(req,res)=>{
  if(req.body.password!==ADMIN_PASS) return res.status(401).json({error:'Wrong password'});
  res.json({token:jwt.sign({role:'admin'},JWT_SECRET,{expiresIn:'8h'}),role:'admin'});
});

app.post('/api/auth/view-login',(req,res)=>{
  if(req.body.password!==VIEW_PASS) return res.status(401).json({error:'Wrong password'});
  res.json({token:jwt.sign({role:'view'},JWT_SECRET,{expiresIn:'8h'}),role:'view'});
});

// Reports
app.post('/api/reports', auth, upload.single('image'),(req,res)=>{
  if(req.user.role!=='user') return res.status(403).json({error:'Users only'});
  const {type,location,date,description}=req.body;
  if(!type||!location||!date||!description) return res.status(400).json({error:'Missing fields'});
  const id='CW-'+Math.floor(100000+Math.random()*900000);
  const imageUrl=req.file?'/uploads/'+req.file.filename:null;
  const submitted=new Date().toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});
  run('INSERT INTO reports(id,type,location,date,description,image_url,username,user_name,status,submitted) VALUES(?,?,?,?,?,?,?,?,?,?)',
    [id,type,location,date,description,imageUrl,req.user.username,req.user.name,'Pending',submitted]);
  res.status(201).json({message:'Report submitted',id});
});

app.get('/api/reports/mine', auth,(req,res)=>{
  res.json(all('SELECT * FROM reports WHERE username=? ORDER BY rowid DESC',[req.user.username]));
});

app.get('/api/reports/approved', auth,(req,res)=>{
  res.json(all("SELECT * FROM reports WHERE status='Approved' ORDER BY rowid DESC"));
});

app.get('/api/reports/stats', auth, admin,(req,res)=>{
  res.json({
    total: get('SELECT COUNT(*) as c FROM reports').c,
    pending: get("SELECT COUNT(*) as c FROM reports WHERE status='Pending'").c,
    approved: get("SELECT COUNT(*) as c FROM reports WHERE status='Approved'").c,
    rejected: get("SELECT COUNT(*) as c FROM reports WHERE status='Rejected'").c,
  });
});

app.get('/api/reports', auth, admin,(req,res)=>{
  const {status}=req.query;
  res.json(status&&status!=='all'
    ? all('SELECT * FROM reports WHERE status=? ORDER BY rowid DESC',[status])
    : all('SELECT * FROM reports ORDER BY rowid DESC'));
});

app.patch('/api/reports/:id/status', auth, admin,(req,res)=>{
  run('UPDATE reports SET status=? WHERE id=?',[req.body.status,req.params.id]);
  res.json({message:'Updated'});
});

app.put('/api/reports/:id', auth, admin,(req,res)=>{
  const {type,location,date,description}=req.body;
  run('UPDATE reports SET type=?,location=?,date=?,description=? WHERE id=?',[type,location,date,description,req.params.id]);
  res.json({message:'Updated'});
});

app.delete('/api/reports/:id', auth, admin,(req,res)=>{
  const rep=get('SELECT image_url FROM reports WHERE id=?',[req.params.id]);
  if(!rep) return res.status(404).json({error:'Not found'});
  if(rep.image_url){try{fs.unlinkSync(path.join(__dirname,rep.image_url));}catch{}}
  run('DELETE FROM reports WHERE id=?',[req.params.id]);
  res.json({message:'Deleted'});
});


app.get('/api/admin/users', auth, admin, (req,res) => {
  res.json(all('SELECT id,name,username,pin,rowid as created_at FROM users ORDER BY rowid DESC'));
});
app.get('/api/health',(req,res)=>res.json({status:'ok'}));

// Start
initSqlJs().then(SQL=>{
  DB = fs.existsSync(DB_PATH) ? new SQL.Database(fs.readFileSync(DB_PATH)) : new SQL.Database();
  DB.run(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,username TEXT UNIQUE,password TEXT,pin TEXT)`);
  DB.run(`CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,type TEXT,location TEXT,date TEXT,description TEXT,image_url TEXT,username TEXT,user_name TEXT,status TEXT DEFAULT 'Pending',submitted TEXT)`);
  save();
  app.listen(PORT,()=>console.log('✅ CrimeWatch running on http://localhost:'+PORT));
});
