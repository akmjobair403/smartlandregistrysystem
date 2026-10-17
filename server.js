require('dotenv').config();

// Refuse to start with missing or example credentials. Never ship working demo secrets.
const requiredSecrets = ['SESSION_SECRET', 'NID_HASH_SECRET', 'NID_ENCRYPTION_SECRET', 'ADMIN_PASSWORD'];
const placeholderPattern = /^(REPLACE_WITH_|replace-with-|change-this|your[-_ ]|example$)/i;
for (const key of requiredSecrets) {
  const value = String(process.env[key] || '');
  if (!value || placeholderPattern.test(value)) {
    throw new Error(`Missing or placeholder ${key}. Copy .env.example to .env and set a unique value before starting GeoTerra.`);
  }
  if (key !== 'ADMIN_PASSWORD' && value.length < 32) {
    throw new Error(`${key} must be at least 32 characters long.`);
  }
}
if (String(process.env.ADMIN_PASSWORD).length < 12) {
  throw new Error('ADMIN_PASSWORD must be at least 12 characters long.');
}

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve('./data');
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './private_uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const dbFile = path.resolve(process.env.DATABASE_FILE || './data/geoterra.sqlite');
const db = new Database(dbFile);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, full_name TEXT NOT NULL, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, nid_hash TEXT UNIQUE, phone TEXT NOT NULL DEFAULT '', district TEXT NOT NULL DEFAULT '', upazila TEXT NOT NULL DEFAULT '',
 role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active',
 police_station TEXT NOT NULL DEFAULT '', post_office TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lands (
 id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 land_number TEXT NOT NULL, dag_number TEXT NOT NULL DEFAULT '', mouza TEXT NOT NULL,
 mouza_number TEXT NOT NULL DEFAULT '', district TEXT NOT NULL, upazila TEXT NOT NULL DEFAULT '',
 union_name TEXT NOT NULL DEFAULT '', area REAL NOT NULL, unit TEXT NOT NULL DEFAULT 'Decimals',
 coordinates TEXT NOT NULL DEFAULT '', crop TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
 registration_type TEXT NOT NULL DEFAULT 'own', purchase_mode TEXT NOT NULL DEFAULT 'individual', share_count INTEGER NOT NULL DEFAULT 1, shareholder_nids_enc TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
 id TEXT PRIMARY KEY, reference TEXT NOT NULL UNIQUE, owner_id TEXT NOT NULL REFERENCES users(id),
 land_id TEXT NOT NULL REFERENCES lands(id), original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE,
 size_bytes INTEGER NOT NULL, category TEXT NOT NULL DEFAULT 'Dolil PDF', status TEXT NOT NULL DEFAULT 'Pending Review', uploaded_at TEXT NOT NULL,
 reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS reviews (
 id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 admin_id TEXT NOT NULL REFERENCES users(id), decision TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title TEXT NOT NULL, message TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id TEXT PRIMARY KEY, actor_id TEXT, actor_username TEXT NOT NULL DEFAULT '',
 action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
 username TEXT PRIMARY KEY COLLATE NOCASE, failures INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS land_access (
 land_id TEXT NOT NULL REFERENCES lands(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 access_role TEXT NOT NULL DEFAULT 'co-owner', created_at TEXT NOT NULL,
 PRIMARY KEY(land_id,user_id)
);
`);

try { db.exec('ALTER TABLE users ADD COLUMN nid_hash TEXT'); } catch (e) { if (!String(e.message).includes('duplicate column')) throw e; }
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nid_hash ON users(nid_hash) WHERE nid_hash IS NOT NULL');
for (const [table,col,definition] of [['users','upazila',"TEXT NOT NULL DEFAULT ''"],['users','police_station',"TEXT NOT NULL DEFAULT ''"],['users','post_office',"TEXT NOT NULL DEFAULT ''"],['lands','registration_type',"TEXT NOT NULL DEFAULT 'own'"],['lands','purchase_mode',"TEXT NOT NULL DEFAULT 'individual'"],['lands','share_count',"INTEGER NOT NULL DEFAULT 1"],['lands','shareholder_nids_enc',"TEXT NOT NULL DEFAULT ''"],['documents','category',"TEXT NOT NULL DEFAULT 'Dolil PDF'"]]) { try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${definition}`); } catch(e) { if (!String(e.message).includes('duplicate column')) throw e; } }
const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const audit = (req, actor, action, detail='') => db.prepare(
 'INSERT INTO audit_logs(id,actor_id,actor_username,action,detail,ip,created_at) VALUES(?,?,?,?,?,?,?)'
).run(id(), actor?.id || null, actor?.username || 'anonymous', action, detail.slice(0,500), req.ip, now());

const csrfProtection = require('csurf')({ cookie: false });
app.disable('x-powered-by');
app.set('trust proxy', process.env.NODE_ENV === 'production' ? 1 : false);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));
app.use(session({
 name: 'geoterra.sid',
 secret: process.env.SESSION_SECRET,
 resave: false, saveUninitialized: false, rolling: false,
 store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
 cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 15 * 60 * 1000, path: '/' }
}));
// Global API throttling plus stricter auth limits helps absorb basic floods; a reverse proxy/WAF is still required for real DDoS protection.
app.use('/api', rateLimit({ windowMs: 60*1000, limit: 120, standardHeaders: true, legacyHeaders: false, message: {error:'Too many requests. Please retry shortly.'} }));
app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, limit: 12, standardHeaders: true, legacyHeaders: false, message:{error:'Too many authentication requests. Try again later.'} }));
app.use('/api/admin/auth', rateLimit({ windowMs: 15*60*1000, limit: 6, standardHeaders: true, legacyHeaders: false, message:{error:'Too many administrator login attempts. Try again later.'} }));
app.use((req,res,next) => {
 if (req.path.startsWith('/api/')) {
   res.setHeader('Cache-Control','no-store');
   res.setHeader('Pragma','no-cache');
 }
 next();
});
app.use((req,res,next) => {
 if (['POST','PUT','PATCH','DELETE'].includes(req.method) && req.path.startsWith('/api/') && req.path !== '/api/auth/captcha' && req.path !== '/api/auth/register' && req.path !== '/api/auth/login' && req.path !== '/api/admin/auth/login') {
   return csrfProtection(req,res,next);
 }
 next();
});
app.get('/api/csrf', csrfProtection, (req,res) => res.json({ csrfToken: req.csrfToken() }));

const clean = (v, max=200) => String(v ?? '').trim().slice(0,max);
const normalizeNid = v => String(v ?? '').replace(/\D/g,'');
const hashNid = v => crypto.createHmac('sha256', process.env.NID_HASH_SECRET).update(normalizeNid(v)).digest('hex');
const nidEncryptionKey=()=>crypto.createHash('sha256').update(process.env.NID_ENCRYPTION_SECRET).digest();
const encryptSensitive=value=>{if(!value)return '';const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',nidEncryptionKey(),iv),encrypted=Buffer.concat([cipher.update(String(value),'utf8'),cipher.final()]);return [iv.toString('base64'),cipher.getAuthTag().toString('base64'),encrypted.toString('base64')].join('.');};
const decryptSensitive=value=>{try{if(!value)return '';const [iv,tag,data]=value.split('.'),decipher=crypto.createDecipheriv('aes-256-gcm',nidEncryptionKey(),Buffer.from(iv,'base64'));decipher.setAuthTag(Buffer.from(tag,'base64'));return Buffer.concat([decipher.update(Buffer.from(data,'base64')),decipher.final()]).toString('utf8');}catch{return '[unavailable: encryption secret changed]';}};
function requireAuth(req,res,next) {
 if (!req.session.userId) return res.status(401).json({error:'Please sign in to continue.'});
 const user = db.prepare('SELECT id,full_name,username,phone,district,upazila,police_station,post_office,role,status,created_at FROM users WHERE id=?').get(req.session.userId);
 if (!user || user.status !== 'active') { req.session.destroy(()=>{}); return res.status(401).json({error:'Your session is no longer valid.'}); }
 req.user = user; next();
}
function requireAdmin(req,res,next) {
 requireAuth(req,res,()=> {
   if (req.user.role !== 'admin') return res.status(403).json({error:'Administrator access required.'});
   next();
 });
}
function notify(userId,title,message) {
 db.prepare('INSERT INTO notifications(id,user_id,title,message,created_at) VALUES(?,?,?,?,?)').run(id(),userId,title,message,now());
}
function ensureAdmin() {
 const username = clean(process.env.ADMIN_USERNAME || 'admin',40);
 const password = process.env.ADMIN_PASSWORD;
 const existing = db.prepare('SELECT id,role FROM users WHERE username=?').get(username);
 const hash = bcrypt.hashSync(password, 12);
 if (!existing) {
   db.prepare('INSERT INTO users(id,full_name,username,password_hash,role,created_at) VALUES(?,?,?,?,?,?)')
     .run(id(), clean(process.env.ADMIN_NAME || 'Portal Administrator',100), username, hash, 'admin', now());
 } else {
   // Treat environment credentials as the source of truth for the configured administrator account.
   db.prepare("UPDATE users SET password_hash=?, role='admin', full_name=? WHERE id=?")
     .run(hash, clean(process.env.ADMIN_NAME || 'Portal Administrator',100), existing.id);
 }
}
ensureAdmin();

// Server-validated visual CAPTCHA for local development.
app.get('/api/auth/captcha', (req,res) => {
 try {
  const answer = crypto.randomBytes(4).toString('hex').slice(0,6).toUpperCase();
  req.session.captchaAnswer = answer;
  req.session.captchaIssued = Date.now();
  const chars = [...answer].map((ch,i)=>`<text x="${20+i*27}" y="39" transform="rotate(${crypto.randomInt(-22,23)} ${20+i*27} 30)" fill="hsl(${crypto.randomInt(130,175)},75%,${crypto.randomInt(45,70)}%)" font-size="${crypto.randomInt(23,31)}" font-family="monospace" font-weight="900">${ch}</text>`).join('');
  const lines = Array.from({length:7},()=>`<path d="M${crypto.randomInt(0,170)} ${crypto.randomInt(0,60)} Q${crypto.randomInt(30,150)} ${crypto.randomInt(0,60)} ${crypto.randomInt(160,210)} ${crypto.randomInt(0,60)}" stroke="#64748b" stroke-width="${crypto.randomInt(1,3)}" opacity=".55" fill="none"/>`).join('');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="190" height="58" viewBox="0 0 190 58"><rect width="190" height="58" rx="8" fill="#081321"/>${lines}${chars}<path d="M4 51 L184 7" stroke="#10b981" stroke-width="2" opacity=".5"/></svg>`;
  res.set('Cache-Control','no-store');
  req.session.save(err => {
   if (err) {
    console.error('CAPTCHA session save failed:', err.message);
    return res.status(503).json({error:'Could not create CAPTCHA session. Please restart the server and try again.'});
   }
   return res.json({ image: 'data:image/svg+xml;base64,'+Buffer.from(svg).toString('base64'), siteKey: process.env.TURNSTILE_SITE_KEY || null, mode: process.env.TURNSTILE_SECRET_KEY ? 'turnstile' : 'visual-captcha' });
  });
 } catch (err) {
  console.error('CAPTCHA generation failed:', err.message);
  return res.status(500).json({error:'Could not generate CAPTCHA. Please refresh and try again.'});
 }
});
async function validateCaptcha(req, token) {
 if (process.env.TURNSTILE_SECRET_KEY) {
   if (!token) return false;
   const body = new URLSearchParams({secret:process.env.TURNSTILE_SECRET_KEY, response:token, remoteip:req.ip});
   try { const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body}); return !!(await r.json()).success; } catch { return false; }
 }
 const answer=String(token??'').trim().toUpperCase(), expected=String(req.session.captchaAnswer||'');
 const fresh=!!expected && Date.now()-Number(req.session.captchaIssued||0)<5*60*1000;
 delete req.session.captchaAnswer; delete req.session.captchaIssued;
 return fresh && answer.length===expected.length && crypto.timingSafeEqual(Buffer.from(answer),Buffer.from(expected));
}
app.post('/api/auth/register', async (req,res) => {
 const fullName=clean(req.body.fullName,100), username=clean(req.body.username,40), password=String(req.body.password||'');
 const phone=clean(req.body.phone,30), district=clean(req.body.district,80), upazila=clean(req.body.upazila,100), policeStation=clean(req.body.policeStation,100), postOffice=clean(req.body.postOffice,120), nidRaw=String(req.body.nid??'').trim(), nid=normalizeNid(nidRaw), captcha=String(req.body.captcha||'');
 if (!fullName || !/^[a-zA-Z0-9_.-]{3,40}$/.test(username) || !/[A-Za-z]/.test(password) || !/\d/.test(password) || password.length<8 || password.length>72 || !district || !upazila || !policeStation || !postOffice || !/^\d{10}$/.test(nidRaw)) return res.status(400).json({error:'Complete all required fields. NID must contain exactly 10 digits. Username must be 3–40 letters/numbers; password must be 8+ characters with letters and numbers.'});
 if (!(await validateCaptcha(req,captcha))) return res.status(400).json({error:'CAPTCHA verification failed. Please try again.'});
 try {
   const userId=id(), hash=await bcrypt.hash(password,12);
   db.prepare('INSERT INTO users(id,full_name,username,password_hash,nid_hash,phone,district,upazila,police_station,post_office,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
     .run(userId,fullName,username,hash,hashNid(nid),phone,district,upazila,policeStation,postOffice,now());
   req.session.regenerate(err => {
     if (err) return res.status(500).json({error:'Could not create secure session.'});
     req.session.userId=userId;
     const user=db.prepare('SELECT id,full_name,username,phone,district,upazila,police_station,post_office,role,created_at FROM users WHERE id=?').get(userId);
     audit(req,user,'User registered');
     res.status(201).json({user});
   });
 } catch(e) {
   if (String(e.code)==='SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({error:String(e.message).includes('nid_hash')?'That NID is already registered.':'That username is already in use.'});
   res.status(500).json({error:'Registration could not be completed.'});
 }
});
app.post('/api/auth/login', async (req,res) => {
 const username=clean(req.body.username,40), password=String(req.body.password||''), captcha=String(req.body.captcha||'');
 if (!(await validateCaptcha(req,captcha))) return res.status(400).json({error:'CAPTCHA verification failed. Please try again.'});
 const normalizedIdentifier=normalizeNid(username);
 const loginKey=/^[0-9]{10}$/.test(normalizedIdentifier)?'nid:'+hashNid(normalizedIdentifier):username;
 const attempt=db.prepare('SELECT failures,locked_until FROM login_attempts WHERE username=?').get(loginKey);
 if (attempt && attempt.locked_until>Date.now()) return res.status(429).json({error:`Account temporarily locked. Try again in ${Math.ceil((attempt.locked_until-Date.now())/1000)} seconds.`});
 const user=db.prepare('SELECT * FROM users WHERE username=? OR nid_hash=?').get(username, /^[0-9]{10}$/.test(normalizedIdentifier) ? hashNid(normalizedIdentifier) : '__no_nid_match__');
 if (!user || !await bcrypt.compare(password,user.password_hash) || user.status!=='active') {
   const failures=(attempt?.failures||0)+1, locked=failures>=5?Date.now()+60_000:0;
   db.prepare(`INSERT INTO login_attempts(username,failures,locked_until) VALUES(?,?,?)
     ON CONFLICT(username) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until`).run(loginKey,failures>=5?0:failures,locked);
   audit(req,null,'Failed sign-in',username);
   return res.status(401).json({error:locked?'Too many failed attempts. Account locked for 60 seconds.':'Incorrect username or password.'});
 }
 db.prepare('DELETE FROM login_attempts WHERE username=?').run(loginKey);
 req.session.regenerate(err => {
   if(err) return res.status(500).json({error:'Could not create secure session.'});
   req.session.userId=user.id;
   audit(req,user,'Successful sign-in');
   res.json({user:{id:user.id,full_name:user.full_name,username:user.username,phone:user.phone,district:user.district,upazila:user.upazila,police_station:user.police_station,post_office:user.post_office,role:user.role,created_at:user.created_at}});
 });
});
app.post('/api/admin/auth/login', async (req,res) => {
 const username=clean(req.body.username,40), password=String(req.body.password||''), captcha=String(req.body.captcha||'');
 if (!(await validateCaptcha(req,captcha))) return res.status(400).json({error:'CAPTCHA verification failed.'});
 const key='admin:'+username;
 const attempt=db.prepare('SELECT failures,locked_until FROM login_attempts WHERE username=?').get(key);
 if(attempt && attempt.locked_until>Date.now()) return res.status(429).json({error:`Administrator login locked. Try again in ${Math.ceil((attempt.locked_until-Date.now())/1000)} seconds.`});
 const user=db.prepare("SELECT * FROM users WHERE username=? AND role='admin'").get(username);
 if(!user || !await bcrypt.compare(password,user.password_hash)) {
   const failures=(attempt?.failures||0)+1, locked=failures>=3?Date.now()+10*60*1000:0;
   db.prepare(`INSERT INTO login_attempts(username,failures,locked_until) VALUES(?,?,?)
     ON CONFLICT(username) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until`).run(key,failures>=3?0:failures,locked);
   audit(req,user||null,'Failed administrator sign-in',username);
   return res.status(401).json({error:locked?'Three failed attempts. Administrator account locked for 10 minutes.':'Invalid administrator credentials.'});
 }
 db.prepare('DELETE FROM login_attempts WHERE username=?').run(key);
 req.session.regenerate(err=>{
   if(err) return res.status(500).json({error:'Could not create secure session.'});
   req.session.userId=user.id;
   audit(req,user,'Successful administrator sign-in');
   res.json({user:{id:user.id,full_name:user.full_name,username:user.username,role:user.role}});
 });
});
app.get('/api/me', requireAuth, (req,res)=>res.json({user:req.user}));
app.post('/api/logout', requireAuth, (req,res)=>{
 audit(req,req.user,'Signed out');
 req.session.destroy(()=>{res.clearCookie('geoterra.sid');res.json({ok:true});});
});

app.get('/api/dashboard', requireAuth, (req,res)=>{
 const lands=db.prepare(`SELECT l.*, CASE WHEN EXISTS(SELECT 1 FROM documents d WHERE d.land_id=l.id) AND NOT EXISTS(SELECT 1 FROM documents d WHERE d.land_id=l.id AND d.status!='Approved by Portal Administrator') THEN 1 ELSE 0 END AS verified, CASE WHEN EXISTS(SELECT 1 FROM documents d WHERE d.land_id=l.id AND d.status='Correction Required') THEN 'Correction Required' WHEN EXISTS(SELECT 1 FROM documents d WHERE d.land_id=l.id AND d.status='Rejected') THEN 'Rejected' WHEN EXISTS(SELECT 1 FROM documents d WHERE d.land_id=l.id AND d.status IN ('Pending Review','Under Review')) THEN 'Pending Review' WHEN EXISTS(SELECT 1 FROM documents d WHERE d.land_id=l.id) AND NOT EXISTS(SELECT 1 FROM documents d WHERE d.land_id=l.id AND d.status!='Approved by Portal Administrator') THEN 'Verified by Portal Administrator' ELSE 'No document' END AS land_status FROM lands l WHERE l.owner_id=? OR EXISTS(SELECT 1 FROM land_access a WHERE a.land_id=l.id AND a.user_id=?) ORDER BY l.created_at DESC`).all(req.user.id,req.user.id);
 const docs=db.prepare('SELECT DISTINCT d.id,d.reference,d.land_id,d.original_name,d.size_bytes,d.category,d.status,d.uploaded_at,d.reason,l.land_number,l.mouza FROM documents d JOIN lands l ON l.id=d.land_id LEFT JOIN land_access a ON a.land_id=l.id WHERE d.owner_id=? OR a.user_id=? ORDER BY d.uploaded_at DESC').all(req.user.id,req.user.id);
 const notifications=db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 30').all(req.user.id);
 res.json({lands,documents:docs,notifications,stats:{lands:lands.length,documents:docs.length,pending:docs.filter(d=>d.status==='Pending Review'||d.status==='Under Review').length,approved:docs.filter(d=>d.status==='Approved by Portal Administrator').length,rejected:docs.filter(d=>d.status==='Rejected').length}});
});
app.post('/api/lands', requireAuth, (req,res)=>{
 const b=req.body, land={id:id(),owner_id:req.user.id,land_number:clean(b.land_number,60),dag_number:clean(b.dag_number,60),mouza:clean(b.mouza,120),mouza_number:clean(b.mouza_number,40),district:clean(b.district||req.user.district,80),upazila:clean(b.upazila,80),union_name:clean(b.union_name,80),area:Number(b.area),unit:clean(b.unit||'Decimals',20),coordinates:clean(b.coordinates,80),crop:clean(b.crop,100),notes:clean(b.notes,500),registration_type:['own','new'].includes(b.registrationType)?b.registrationType:'own',purchase_mode:b.purchaseMode==='shared'?'shared':'individual',share_count:Math.max(1,Math.min(100,Number(b.shareCount)||1)),shareholder_nids_enc:encryptSensitive(clean(b.shareholderNids,2000)),created_at:now(),updated_at:now()};
 if(!land.land_number||!land.mouza||!land.district||!land.upazila||!land.union_name||!Number.isFinite(land.area)||land.area<=0||land.area>1e9) return res.status(400).json({error:'Land number, mouza, district, upazila, post office, and a valid positive area are required.'});
 if(land.registration_type==='new'&&land.purchase_mode==='shared'){const ids=clean(b.shareholderNids,2000).split(/[\s,;]+/).filter(Boolean);if(land.share_count<2||ids.length!==land.share_count||ids.some(n=>!/^\d{10}$/.test(n)))return res.status(400).json({error:'For shared purchases, enter exactly one 10-digit NID for each listed co-owner/person; the count must match.'});}
 db.prepare(`INSERT INTO lands(id,owner_id,land_number,dag_number,mouza,mouza_number,district,upazila,union_name,area,unit,coordinates,crop,notes,registration_type,purchase_mode,share_count,shareholder_nids_enc,created_at,updated_at)
 VALUES(@id,@owner_id,@land_number,@dag_number,@mouza,@mouza_number,@district,@upazila,@union_name,@area,@unit,@coordinates,@crop,@notes,@registration_type,@purchase_mode,@share_count,@shareholder_nids_enc,@created_at,@updated_at)`).run(land);
 audit(req,req.user,'Created land record',land.land_number);
 res.status(201).json({land});
});
app.put('/api/lands/:id', requireAuth, (req,res)=>{
 const old=db.prepare('SELECT * FROM lands WHERE id=? AND owner_id=?').get(req.params.id,req.user.id);
 if(!old)return res.status(404).json({error:'Land record not found.'});
 const b=req.body, area=Number(b.area);
 if(!clean(b.land_number,60)||!clean(b.mouza,120)||!Number.isFinite(area)||area<=0) return res.status(400).json({error:'Valid land number, mouza, and positive area are required.'});
 db.prepare(`UPDATE lands SET land_number=?,dag_number=?,mouza=?,mouza_number=?,district=?,upazila=?,union_name=?,area=?,unit=?,coordinates=?,crop=?,notes=?,updated_at=? WHERE id=? AND owner_id=?`)
 .run(clean(b.land_number,60),clean(b.dag_number,60),clean(b.mouza,120),clean(b.mouza_number,40),clean(b.district,80),clean(b.upazila,80),clean(b.union_name,80),area,clean(b.unit||'Decimals',20),clean(b.coordinates,80),clean(b.crop,100),clean(b.notes,500),now(),req.params.id,req.user.id);
 audit(req,req.user,'Updated land record',req.params.id);
 res.json({ok:true});
});
app.delete('/api/lands/:id', requireAuth, (req,res)=>{
 const hasDocs=db.prepare('SELECT 1 FROM documents WHERE land_id=? LIMIT 1').get(req.params.id);
 if(hasDocs)return res.status(409).json({error:'This land record has submitted documents and cannot be deleted.'});
 const r=db.prepare('DELETE FROM lands WHERE id=? AND owner_id=?').run(req.params.id,req.user.id);
 if(!r.changes)return res.status(404).json({error:'Land record not found.'});
 audit(req,req.user,'Deleted land record',req.params.id); res.json({ok:true});
});

const maxBytes=Math.max(1,Number(process.env.MAX_UPLOAD_MB||10))*1024*1024;
const storage=multer.diskStorage({destination:UPLOAD_DIR,filename:(req,file,cb)=>{const ext=file.mimetype==='application/pdf'?'.pdf':file.mimetype==='image/jpeg'?'.jpg':file.mimetype==='image/png'?'.png':file.mimetype==='image/webp'?'.webp':'.bin';cb(null,crypto.randomUUID()+ext)}});
const upload=multer({storage,limits:{fileSize:maxBytes,files:1},fileFilter:(req,file,cb)=> {
 if(!['application/pdf','image/jpeg','image/png','image/webp'].includes(file.mimetype)) return cb(new Error('Only PDF, JPEG, PNG, or WEBP files are accepted.'));
 cb(null,true);
}});
app.post('/api/lands/:id/documents', requireAuth, (req,res,next)=>{
 upload.single('document')(req,res,err=>{if(err)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?`PDF exceeds ${Math.floor(maxBytes/1024/1024)} MB limit.`:err.message||'Upload failed.'});next();});
}, (req,res)=>{
 const land=db.prepare('SELECT * FROM lands WHERE id=? AND owner_id=?').get(req.params.id,req.user.id);
 if(!land){if(req.file)fs.rmSync(req.file.path,{force:true});return res.status(404).json({error:'Land record not found.'});}
 if(!req.file)return res.status(400).json({error:'Choose a PDF file to upload.'});
 const fd=fs.openSync(req.file.path,'r'); const sig=Buffer.alloc(12);fs.readSync(fd,sig,0,12,0);fs.closeSync(fd);
 const goodPdf=req.file.mimetype==='application/pdf'&&sig.subarray(0,5).toString()==='%PDF-';
 const goodImage=(req.file.mimetype==='image/jpeg'&&sig[0]===0xff&&sig[1]===0xd8)||(req.file.mimetype==='image/png'&&sig.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))||(req.file.mimetype==='image/webp'&&sig.subarray(0,4).toString()==='RIFF'&&sig.subarray(8,12).toString()==='WEBP');
 if(!goodPdf&&!goodImage){fs.rmSync(req.file.path,{force:true});return res.status(400).json({error:'File contents do not match a supported PDF or image type.'});}
 const ref='GT-'+new Date().toISOString().slice(0,10).replaceAll('-','')+'-'+crypto.randomBytes(4).toString('hex').toUpperCase();
 const category=clean(req.body.category||'Dolil PDF',60);
 const allowedCategories=['Dolil PDF','Owner NID PDF','Owner photo','Previous owner NID','Previous owner photo','Payment receipt','Previous owner Dolil PDF','Shareholder NID'];
 if(!allowedCategories.includes(category)){fs.rmSync(req.file.path,{force:true});return res.status(400).json({error:'Invalid document category.'});}
 const doc={id:id(),reference:ref,owner_id:req.user.id,land_id:land.id,original_name:path.basename(req.file.originalname).slice(0,200),stored_name:path.basename(req.file.filename),size_bytes:req.file.size,category,status:'Pending Review',uploaded_at:now(),reason:''};
 db.prepare('INSERT INTO documents(id,reference,owner_id,land_id,original_name,stored_name,size_bytes,category,status,uploaded_at,reason) VALUES(@id,@reference,@owner_id,@land_id,@original_name,@stored_name,@size_bytes,@category,@status,@uploaded_at,@reason)').run(doc);
 notify(req.user.id,category+' received',`${category} submission ${ref} is waiting for administrator review.`);
 audit(req,req.user,'Uploaded document',`${category}: ${ref}`);
 res.status(201).json({document:{...doc,land_number:land.land_number,mouza:land.mouza}});
});
app.post('/api/documents/:id/resubmit', requireAuth, (req,res,next)=>{
 upload.single('document')(req,res,err=>{
  if(err)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?`PDF exceeds ${Math.floor(maxBytes/1024/1024)} MB limit.`:err.message||'Upload failed.'});
  next();
 });
}, (req,res)=>{
 const doc=db.prepare('SELECT * FROM documents WHERE id=? AND owner_id=?').get(req.params.id,req.user.id);
 if(!doc){if(req.file)fs.rmSync(req.file.path,{force:true});return res.status(404).json({error:'Document not found.'});}
 if(!['Rejected','Correction Required'].includes(doc.status)){
  if(req.file)fs.rmSync(req.file.path,{force:true});
  return res.status(409).json({error:'Only rejected documents or documents requiring correction can be resubmitted. Approved documents cannot be edited.'});
 }
 if(!req.file){return res.status(400).json({error:'Choose a replacement PDF file.'});}
 const fd=fs.openSync(req.file.path,'r');const sig=Buffer.alloc(5);fs.readSync(fd,sig,0,5,0);fs.closeSync(fd);
 if(req.file.mimetype!=='application/pdf'||sig.toString()!=='%PDF-'){
  fs.rmSync(req.file.path,{force:true});return res.status(400).json({error:'Only a valid PDF file can be resubmitted.'});
 }
 const oldStored=doc.stored_name;
 const reference='GT-'+new Date().toISOString().slice(0,10).replaceAll('-','')+'-'+crypto.randomBytes(4).toString('hex').toUpperCase();
 db.prepare("UPDATE documents SET reference=?,original_name=?,stored_name=?,size_bytes=?,status='Pending Review',uploaded_at=?,reason='' WHERE id=? AND owner_id=? AND status IN ('Rejected','Correction Required')")
  .run(reference,path.basename(req.file.originalname).slice(0,200),path.basename(req.file.filename),req.file.size,now(),doc.id,req.user.id);
 const refreshed=db.prepare('SELECT * FROM documents WHERE id=?').get(doc.id);
 if(oldStored && oldStored!==refreshed.stored_name)fs.rmSync(path.join(UPLOAD_DIR,path.basename(oldStored)),{force:true});
 notify(req.user.id,'Document resubmitted',`${doc.category} ${reference} has been resubmitted and is waiting for administrator review.`);
 audit(req,req.user,'Resubmitted document',`${doc.category}: ${reference}`);
 res.json({ok:true,document:{id:refreshed.id,reference:refreshed.reference,status:refreshed.status,original_name:refreshed.original_name}});
});

app.get('/api/documents/:id/file', requireAuth, (req,res)=>{
 const doc=db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
 if(!doc || (req.user.role!=='admin' && doc.owner_id!==req.user.id))return res.status(404).json({error:'Document not found.'});
 const full=path.join(UPLOAD_DIR,path.basename(doc.stored_name));
 if(!fs.existsSync(full))return res.status(404).json({error:'Stored document is unavailable.'});
 res.setHeader('Content-Type',doc.stored_name.endsWith('.pdf')?'application/pdf':doc.stored_name.endsWith('.jpg')?'image/jpeg':doc.stored_name.endsWith('.png')?'image/png':'image/webp');res.setHeader('Content-Disposition',`inline; filename="document-${doc.reference}.pdf"`);
 res.sendFile(full);
});
app.post('/api/notifications/:id/read', requireAuth, (req,res)=>{
 db.prepare('UPDATE notifications SET read_at=? WHERE id=? AND user_id=?').run(now(),req.params.id,req.user.id);res.json({ok:true});
});

app.get('/api/admin/overview', requireAdmin, (req,res)=>{
 const count=(sql)=>db.prepare(sql).get().n;
 res.json({users:count("SELECT COUNT(*) n FROM users WHERE role='user'"),lands:count('SELECT COUNT(*) n FROM lands'),documents:count('SELECT COUNT(*) n FROM documents'),pending:count("SELECT COUNT(*) n FROM documents WHERE status IN ('Pending Review','Under Review')"),approved:count("SELECT COUNT(*) n FROM documents WHERE status='Approved by Portal Administrator'"),rejected:count("SELECT COUNT(*) n FROM documents WHERE status='Rejected'")});
});
app.get('/api/admin/users', requireAdmin, (req,res)=>{
 const q='%'+clean(req.query.q,100)+'%';
 res.json({users:db.prepare(`SELECT u.id,u.full_name,u.username,u.phone,u.district,u.status,u.created_at,
 (SELECT COUNT(*) FROM lands l WHERE l.owner_id=u.id) land_count,
 (SELECT COUNT(*) FROM documents d WHERE d.owner_id=u.id) document_count
 FROM users u WHERE u.role='user' AND (u.full_name LIKE ? OR u.username LIKE ? OR u.phone LIKE ? OR u.district LIKE ?) ORDER BY u.created_at DESC LIMIT 500`).all(q,q,q,q)});
});
app.get('/api/admin/documents', requireAdmin, (req,res)=>{
 const status=clean(req.query.status,80), q='%'+clean(req.query.q,100)+'%';
 let sql=`SELECT d.*,u.full_name,u.username,l.land_number,l.dag_number,l.mouza,l.district,l.upazila FROM documents d JOIN users u ON u.id=d.owner_id JOIN lands l ON l.id=d.land_id WHERE (d.reference LIKE ? OR d.original_name LIKE ? OR u.full_name LIKE ? OR u.username LIKE ? OR l.land_number LIKE ?)`;
 const args=[q,q,q,q,q];
 if(status){sql+=' AND d.status=?';args.push(status);}
 sql+=' ORDER BY d.uploaded_at DESC LIMIT 500';
 res.json({documents:db.prepare(sql).all(...args)});
});
app.get('/api/admin/documents/:id/reviews', requireAdmin, (req,res)=>{
 const doc=db.prepare('SELECT id FROM documents WHERE id=?').get(req.params.id);
 if(!doc)return res.status(404).json({error:'Document not found.'});
 res.json({reviews:db.prepare('SELECT r.*,u.full_name admin_name,u.username admin_username FROM reviews r JOIN users u ON u.id=r.admin_id WHERE r.document_id=? ORDER BY r.created_at DESC').all(doc.id)});
});
app.post('/api/admin/documents/:id/review', requireAdmin, (req,res)=>{
 const decision=clean(req.body.decision,40), reason=clean(req.body.reason,1000);
 const allowed=['Under Review','Approved by Portal Administrator','Rejected','Correction Required'];
 if(!allowed.includes(decision))return res.status(400).json({error:'Invalid review decision.'});
 if(['Rejected','Correction Required'].includes(decision)&&reason.length<3)return res.status(400).json({error:'A reason is required for rejection or correction requests.'});
 const doc=db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
 if(!doc)return res.status(404).json({error:'Document not found.'});
 const transaction=db.transaction(()=>{
   db.prepare('UPDATE documents SET status=?,reason=? WHERE id=?').run(decision,reason,doc.id);
   db.prepare('INSERT INTO reviews(id,document_id,admin_id,decision,reason,created_at) VALUES(?,?,?,?,?,?)').run(id(),doc.id,req.user.id,decision,reason,now());
   notify(doc.owner_id,'Document status updated',`${doc.category} ${doc.reference}: ${decision}${reason?' — '+reason:''}`);
   // Once every submitted document for a shared land record is approved, attach it to registered co-owners by NID hash.
   const land=db.prepare('SELECT * FROM lands WHERE id=?').get(doc.land_id);
   const pending=db.prepare("SELECT COUNT(*) n FROM documents WHERE land_id=? AND status!='Approved by Portal Administrator'").get(doc.land_id).n;
   if(land && land.registration_type==='new' && land.purchase_mode==='shared' && pending===0){
     const nids=decryptSensitive(land.shareholder_nids_enc).split(/[\s,;]+/).filter(n=>/^\d{10}$/.test(n));
     for(const nid of nids){const hash=hashNid(nid);const co=db.prepare("SELECT id FROM users WHERE nid_hash=? AND status='active' AND role='user'").get(hash);if(co && co.id!==land.owner_id){db.prepare("INSERT OR IGNORE INTO land_access(land_id,user_id,access_role,created_at) VALUES(?,?,?,?)").run(land.id,co.id,'co-owner',now());notify(co.id,'Shared land verified',`Land ${land.land_number} in ${land.district} has passed portal document review and is now visible in your land panel.`);}}
   }
   audit(req,req.user,'Document review decision',`${doc.reference}: ${decision}`);
 });
 transaction();
 res.json({ok:true,status:decision});
});
app.post('/api/admin/users/:id/status', requireAdmin, (req,res)=>{
 const status=clean(req.body.status,20);
 if(!['active','suspended'].includes(status))return res.status(400).json({error:'Invalid account status.'});
 const r=db.prepare("UPDATE users SET status=? WHERE id=? AND role='user'").run(status,req.params.id);
 if(!r.changes)return res.status(404).json({error:'User not found.'});
 audit(req,req.user,'Changed user status',`${req.params.id}: ${status}`);res.json({ok:true});
});
app.get('/api/admin/sessions', requireAdmin, (req,res)=>{
 const file=path.join(DATA_DIR,'sessions.sqlite'); const active=[];
 try { const sd=new Database(file,{readonly:true,fileMustExist:true}); const rows=sd.prepare('SELECT sid, sess, expired FROM sessions WHERE expired > ?').all(Date.now());
   for(const row of rows){try{const sess=JSON.parse(row.sess);if(!sess.userId)continue;const u=db.prepare('SELECT id,full_name,username,role,status,district FROM users WHERE id=?').get(sess.userId);if(u)active.push({...u,expires_at:new Date(row.expired).toISOString(),current:sess.userId===req.user.id});}catch{}}
   sd.close();
 } catch(e) { /* session store may not have been created yet */ }
 res.json({sessions:active});
});
app.get('/api/admin/crops', requireAdmin, (req,res)=>{
 const rows=db.prepare(`WITH verified AS (SELECT l.*, CASE WHEN LOWER(l.unit) IN ('square feet','sq ft','sqft') THEN l.area/435.6 WHEN LOWER(l.unit) IN ('acre','acres') THEN l.area*100 WHEN LOWER(l.unit) IN ('square metre','square metres','sqm','m²') THEN l.area/40.468564224 WHEN LOWER(l.unit) IN ('katha') THEN l.area*1.65 WHEN LOWER(l.unit) IN ('bigha') THEN l.area*33 ELSE l.area END area_decimals FROM lands l WHERE TRIM(COALESCE(l.crop,''))!='' AND EXISTS(SELECT 1 FROM documents d WHERE d.land_id=l.id) AND NOT EXISTS(SELECT 1 FROM documents d WHERE d.land_id=l.id AND d.status!='Approved by Portal Administrator'))
 SELECT COALESCE(NULLIF(TRIM(crop),''),'Not specified') crop, COUNT(*) plots, ROUND(SUM(area_decimals),3) area_decimals, ROUND(100.0*SUM(area_decimals)/(SELECT SUM(area_decimals) FROM verified),1) percentage FROM verified GROUP BY COALESCE(NULLIF(TRIM(crop),''),'Not specified') ORDER BY area_decimals DESC`).all();
 res.json({crops:rows});
});
app.get('/api/admin/audit', requireAdmin, (req,res)=>res.json({logs:db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 300').all()}));

app.get('/health', (req,res)=>res.json({ok:true,service:'GeoTerra'}));
app.use(express.static(path.join(__dirname,'public'), {extensions:['html']}));
app.get('/', (req,res)=>res.sendFile(path.join(__dirname,'public','user.html')));
app.use((err,req,res,next)=>{
 console.error(err);
 if(req.path.startsWith('/api/'))return res.status(err.code=== 'EBADCSRFTOKEN'?403:500).json({error:err.code==='EBADCSRFTOKEN'?'Security token expired. Refresh and try again.':'Unexpected server error.'});
 res.status(500).send('Unexpected server error.');
});
app.listen(PORT,()=>console.log(`GeoTerra running at http://localhost:${PORT}`));
