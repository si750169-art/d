const express=require('express');
const session=require('express-session');
const bcrypt=require('bcryptjs');
const Database=require('better-sqlite3');
const multer=require('multer');
const path=require('path');
const fs=require('fs');
const crypto=require('crypto');

const app=express();
app.set('trust proxy', true);

app.use((req, res, next) => {
    const ip =
        req.headers['cf-connecting-ip'] ||
        req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
        req.socket.remoteAddress;

    req.visitorIP = ip;
    next();
});
const ip = req.visitorIP;

await db.run(
    `INSERT INTO audit_logs (username, action, ip, created_at)
     VALUES (?, ?, ?, datetime('now'))`,
    [req.user.username, action, ip]
);
app.get('/api/admin/logs', requireAuth, async (req, res) => {
    if (req.user.username !== 'code_alpha') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const logs = await db.all(`
        SELECT *
        FROM audit_logs
        ORDER BY created_at DESC
    `);

    res.json(logs);
});
const db=new Database(path.join(__dirname,'cia.db'));
const uploads=path.join(__dirname,'uploads'); fs.mkdirSync(uploads,{recursive:true});
app.set('trust proxy', false);
app.use(express.json({limit:'2mb'})); app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||'cia-rp-change-this-secret-2026',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',maxAge:1000*60*60*24*30}}));
app.use(express.static(path.join(__dirname,'public')));

// Real persistent database. Empty on first install except for the requested Command account.
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,rank TEXT NOT NULL,unit TEXT NOT NULL,clearance TEXT NOT NULL,in_game_name TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS applications(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,age INTEGER NOT NULL,unit TEXT NOT NULL,experience TEXT NOT NULL,why TEXT NOT NULL,status TEXT DEFAULT 'PENDING',dashboard_token TEXT UNIQUE NOT NULL,linked_user INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(linked_user) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,sender_id INTEGER,sender_label TEXT NOT NULL,recipient_user INTEGER,recipient_application INTEGER,subject TEXT NOT NULL,body TEXT NOT NULL,type TEXT DEFAULT 'MESSAGE',created_at TEXT DEFAULT CURRENT_TIMESTAMP,read INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,author INTEGER NOT NULL,classification TEXT NOT NULL,file TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,actor INTEGER,actor_label TEXT,action TEXT NOT NULL,ip TEXT,details TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);

const RANKS=['AGENT','AGENT OFFICER','COMMAND OF CIA'];
const ADMIN=['AGENT OFFICER','COMMAND OF CIA'];
const COMMAND=['COMMAND OF CIA'];
const clearanceRank={RESTRICTED:1,CONFIDENTIAL:2,SECRET:3,'TOP SECRET':4,OMEGA:5};
const upload=multer({dest:uploads,limits:{fileSize:20*1024*1024},fileFilter:(req,file,cb)=>cb(null,file.mimetype==='application/pdf')});

function ip(req){return (req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim().replace('::ffff:','')}
function audit(req,action,details=''){const u=req.session.user;db.prepare('INSERT INTO audit(actor,actor_label,action,ip,details) VALUES(?,?,?,?,?)').run(u?.id||null,u?.username||u?.rank||'PUBLIC',action,ip(req),details)}
function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:'AUTH_REQUIRED'});next()}
function admin(req,res,next){if(!req.session.user||!ADMIN.includes(req.session.user.rank))return res.status(403).json({error:'FORBIDDEN'});next()}
function command(req,res,next){if(!req.session.user||!COMMAND.includes(req.session.user.rank))return res.status(403).json({error:'COMMAND_ONLY'});next()}
function canView(user,c){return (clearanceRank[user.clearance]||0)>=(clearanceRank[c]||99)}
function safeUser(u){if(!u)return null;const x={...u};delete x.password;return x}
function cleanUsername(name,id){const base=String(name).toLowerCase().replace(/[^a-z0-9_-]/g,'').slice(0,18)||'agent';return base+'_'+String(id).padStart(3,'0')}
function randomPassword(){return crypto.randomBytes(6).toString('base64url')+'!9'}
function ensureCommand(){let u=db.prepare('SELECT * FROM users WHERE username=?').get('code_alpha');if(!u){db.prepare('INSERT INTO users(username,password,rank,unit,clearance) VALUES(?,?,?,?,?)').run('code_alpha',bcrypt.hashSync('cia command91',12),'COMMAND OF CIA','CIA COMMAND','OMEGA')}}
try{db.exec('ALTER TABLE users ADD COLUMN in_game_name TEXT')}catch(e){}
ensureCommand();
try{db.prepare('UPDATE users SET in_game_name=COALESCE(in_game_name,username) WHERE in_game_name IS NULL').run()}catch(e){}

// Cookie parser for the application token.
app.use((req,res,next)=>{const raw=req.headers.cookie||'';req.cookies={};raw.split(';').forEach(x=>{const i=x.indexOf('=');if(i>0)req.cookies[x.slice(0,i).trim()]=decodeURIComponent(x.slice(i+1).trim())});next()});
// Public application. The applicant receives a persistent private dashboard token.
app.post('/api/applications',(req,res)=>{
 const {name,age,unit,experience,why}=req.body;
 if(!name||!age||!unit||!experience||!why)return res.status(400).json({error:'MISSING_FIELDS'});
 const token=crypto.randomBytes(32).toString('hex');
 const r=db.prepare('INSERT INTO applications(name,age,unit,experience,why,dashboard_token) VALUES(?,?,?,?,?,?)').run(String(name).trim(),Number(age),unit,String(experience).trim(),String(why).trim(),token);
 audit(req,'APPLICATION_SUBMITTED',`application=${r.lastInsertRowid}`);
 res.cookie('cia_application',token,{httpOnly:true,sameSite:'lax',maxAge:1000*60*60*24*365});
 res.json({ok:true,id:r.lastInsertRowid,token});
});
app.get('/api/application/me',(req,res)=>{const token=req.cookies?.cia_application||req.headers['x-application-token']||req.query.token;if(!token)return res.json({application:null});const a=db.prepare('SELECT id,name,age,unit,experience,why,status,linked_user,created_at,updated_at FROM applications WHERE dashboard_token=?').get(token);if(!a)return res.json({application:null});const messages=db.prepare('SELECT id,sender_label,subject,body,type,created_at,read FROM messages WHERE recipient_application=? ORDER BY id DESC').all(a.id);let credentials=null;if(a.linked_user){const u=db.prepare('SELECT username,rank,unit,clearance FROM users WHERE id=?').get(a.linked_user);credentials=u}
 res.json({application:a,messages,credentials});
});
// Cookie parser for the application token.
app.use((req,res,next)=>{const raw=req.headers.cookie||'';req.cookies={};raw.split(';').forEach(x=>{const i=x.indexOf('=');if(i>0)req.cookies[x.slice(0,i).trim()]=decodeURIComponent(x.slice(i+1).trim())});next()});

app.post('/api/login',(req,res,next)=>{try{const username=String(req.body.username||'').trim();const password=String(req.body.password||'');const u=db.prepare('SELECT * FROM users WHERE username=?').get(username);if(!u||!bcrypt.compareSync(password,u.password)){audit(req,'LOGIN_FAILED',`username=${username}`);return res.status(401).json({error:'INVALID_CREDENTIALS'})}req.session.regenerate(err=>{if(err)return next(err);req.session.user=u;req.session.save(err2=>{if(err2)return next(err2);audit(req,'LOGIN_SUCCESS',`rank=${u.rank}`);res.json({user:safeUser(u)})})})}catch(e){next(e)}});
app.post('/api/logout',auth,(req,res)=>{audit(req,'LOGOUT');req.session.destroy(()=>res.json({ok:true}))});
app.get('/api/me',(req,res)=>res.json({user:safeUser(req.session.user)}));

app.get('/api/dashboard',auth,(req,res)=>{const u=req.session.user;const messages=db.prepare('SELECT id,sender_label,subject,body,type,created_at,read FROM messages WHERE recipient_user=? ORDER BY id DESC').all(u.id);const reports=db.prepare('SELECT id,title,author,classification,created_at FROM reports ORDER BY id DESC').all().filter(r=>canView(u,r.classification));res.json({user:safeUser(u),messages,reports})});
app.post('/api/messages/:id/read',auth,(req,res)=>{db.prepare('UPDATE messages SET read=1 WHERE id=? AND recipient_user=?').run(req.params.id,req.session.user.id);res.json({ok:true})});

app.get('/api/admin/applications',admin,(req,res)=>res.json(db.prepare('SELECT id,name,age,unit,experience,why,status,linked_user,created_at,updated_at FROM applications ORDER BY id DESC').all()));
app.post('/api/admin/application/:id/approve',admin,(req,res)=>{
 const a=db.prepare('SELECT * FROM applications WHERE id=?').get(req.params.id);if(!a)return res.sendStatus(404);if(a.status==='APPROVED')return res.status(400).json({error:'ALREADY_APPROVED'});
 let username=cleanUsername(a.name,a.id);while(db.prepare('SELECT id FROM users WHERE username=?').get(username))username=cleanUsername(a.name,a.id)+'_'+crypto.randomBytes(2).toString('hex');
 const password=randomPassword(),rank='AGENT',clearance='RESTRICTED';const info=db.prepare('INSERT INTO users(username,password,rank,unit,clearance,in_game_name) VALUES(?,?,?,?,?,?)').run(username,bcrypt.hashSync(password,12),rank,a.unit,clearance,a.name);
 db.prepare('UPDATE applications SET status=?,linked_user=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run('APPROVED',info.lastInsertRowid,a.id);
 const body=`Your CIA application has been APPROVED.\n\nUSERNAME: ${username}\nPASSWORD: ${password}\nUNIT: ${a.unit}\nRANK: ${rank}\nCLEARANCE: ${clearance}\n\nKeep these credentials private.`;
 db.prepare('INSERT INTO messages(sender_id,sender_label,recipient_user,recipient_application,subject,body,type) VALUES(?,?,?,?,?,?,?)').run(req.session.user.id,req.session.user.rank,info.lastInsertRowid,a.id,'ACCOUNT ISSUED',body,'CREDENTIALS');
 db.prepare('INSERT INTO messages(sender_id,sender_label,recipient_application,subject,body,type) VALUES(?,?,?,?,?,?)').run(req.session.user.id,req.session.user.rank,a.id,'APPLICATION APPROVED',body,'CREDENTIALS');
 audit(req,'APPLICATION_APPROVED',`application=${a.id};user=${username};newUser=${info.lastInsertRowid}`);
 res.json({ok:true,username,password});
});
app.post('/api/admin/application/:id/reject',admin,(req,res)=>{db.prepare('UPDATE applications SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run('REJECTED',req.params.id);audit(req,'APPLICATION_REJECTED',`application=${req.params.id}`);res.json({ok:true})});

app.get('/api/admin/users',admin,(req,res)=>res.json(db.prepare('SELECT id,username,in_game_name,rank,unit,clearance,created_at FROM users ORDER BY id DESC').all()));
app.post('/api/admin/users',command,(req,res)=>{const {username,password,rank,unit,clearance}=req.body;if(!username||!password||!RANKS.includes(rank)||!unit||!Object.prototype.hasOwnProperty.call(clearanceRank,clearance))return res.status(400).json({error:'INVALID_DATA'});try{const x=db.prepare('INSERT INTO users(username,password,rank,unit,clearance,in_game_name) VALUES(?,?,?,?,?,?)').run(username,bcrypt.hashSync(password,12),rank,unit,clearance,req.body.in_game_name||username);audit(req,'USER_CREATED',`user=${username};rank=${rank}`);res.json({ok:true,id:x.lastInsertRowid})}catch(e){res.status(400).json({error:'USERNAME_EXISTS'})}});

// Agent Officer / Command can send targeted messages and tasks. Recipient is selected by username.
app.post('/api/admin/message',admin,(req,res)=>{const {target,subject,body,type='MESSAGE'}=req.body;if(!target||!subject||!body)return res.status(400).json({error:'MISSING_FIELDS'});if(String(target).startsWith('app:')){const id=Number(String(target).slice(4));const a=db.prepare('SELECT id FROM applications WHERE id=?').get(id);if(!a)return res.status(404).json({error:'APPLICATION_NOT_FOUND'});db.prepare('INSERT INTO messages(sender_id,sender_label,recipient_application,subject,body,type) VALUES(?,?,?,?,?,?)').run(req.session.user.id,req.session.user.rank,a.id,subject,body,type);audit(req,'APPLICATION_MESSAGE_SENT',`application=${id};type=${type};subject=${subject}`);return res.json({ok:true})}const u=db.prepare('SELECT id FROM users WHERE username=?').get(target);if(!u)return res.status(404).json({error:'USER_NOT_FOUND'});db.prepare('INSERT INTO messages(sender_id,sender_label,recipient_user,subject,body,type) VALUES(?,?,?,?,?,?)').run(req.session.user.id,req.session.user.rank,u.id,subject,body,type);audit(req,'MESSAGE_SENT',`to=${target};type=${type};subject=${subject}`);res.json({ok:true})});

app.post('/api/admin/reports',admin,upload.single('pdf'),(req,res)=>{if(!req.body.title||!req.file)return res.status(400).json({error:'TITLE_AND_PDF_REQUIRED'});const final=path.join(uploads,req.file.filename+'.pdf');fs.renameSync(req.file.path,final);const x=db.prepare('INSERT INTO reports(title,author,classification,file) VALUES(?,?,?,?)').run(req.body.title,req.session.user.id,req.body.classification||'CONFIDENTIAL',final);audit(req,'REPORT_REGISTERED',`report=${x.lastInsertRowid};title=${req.body.title}`);res.json({ok:true,id:x.lastInsertRowid})});
app.get('/api/reports/:id',auth,(req,res)=>{const r=db.prepare('SELECT * FROM reports WHERE id=?').get(req.params.id);if(!r||!canView(req.session.user,r.classification)||!fs.existsSync(r.file))return res.sendStatus(404);audit(req,'REPORT_VIEWED',`report=${r.id}`);res.type('application/pdf').sendFile(path.resolve(r.file))});

// Command-only audit log: IPs and all site actions are never exposed to lower ranks.
app.get('/api/command/audit',command,(req,res)=>res.json(db.prepare('SELECT id,actor,actor_label,action,ip,details,created_at FROM audit ORDER BY id DESC LIMIT 500').all()));

app.get('/api/sector',auth,(req,res)=>res.json(db.prepare('SELECT id,username,in_game_name,rank,unit,clearance,created_at FROM users ORDER BY CASE rank WHEN "COMMAND OF CIA" THEN 1 WHEN "AGENT OFFICER" THEN 2 ELSE 3 END, id').all()));

app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:'SERVER_ERROR',message:process.env.NODE_ENV==='development'?err.message:'Internal server error'});});
const PORT=Number(process.env.PORT||3000);
const HOST=process.env.HOST||'0.0.0.0';
app.listen(PORT,HOST,()=>console.log(`CIA RP running on http://${HOST}:${PORT}`));

