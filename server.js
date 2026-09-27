import express from "express";
import session from "express-session";
import Database from "better-sqlite3";
import argon2 from "argon2";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(path.join(__dirname, "earn777.sqlite"));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 referral_code TEXT UNIQUE NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tasks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 description TEXT NOT NULL,
 reward REAL NOT NULL CHECK(reward >= 0),
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS wallet_transactions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 type TEXT NOT NULL,
 amount REAL NOT NULL,
 description TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_IN_PRODUCTION",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: false }
}));
app.use(express.static(path.join(__dirname, "..")));

function auth(req,res,next){
  if(!req.session.user) return res.status(401).json({error:"Login required"});
  next();
}
function admin(req,res,next){
  if(!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({error:"Admin access required"});
  next();
}

app.post("/api/signup", async (req,res)=>{
  try{
    const {name,email,password}=req.body;
    if(!name || !email || !password || password.length < 8)
      return res.status(400).json({error:"Name, email and an 8+ character password are required"});
    const hash=await argon2.hash(password);
    const code="E"+Math.random().toString(36).slice(2,9).toUpperCase();
    const info=db.prepare("INSERT INTO users(name,email,password_hash,referral_code) VALUES(?,?,?,?)")
      .run(name,email.toLowerCase(),hash,code);
    req.session.user={id:Number(info.lastInsertRowid),name,email:email.toLowerCase(),role:"user"};
    res.json({ok:true,user:req.session.user});
  }catch(e){ res.status(400).json({error:"Email may already be registered"}); }
});

app.post("/api/login", async (req,res)=>{
  const {email,password}=req.body;
  const user=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").toLowerCase());
  if(!user || !(await argon2.verify(user.password_hash,password||"")))
    return res.status(401).json({error:"Invalid email or password"});
  req.session.user={id:user.id,name:user.name,email:user.email,role:user.role};
  res.json({ok:true,user:req.session.user});
});

app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",auth,(req,res)=>res.json({user:req.session.user}));

app.get("/api/tasks",(req,res)=>{
  res.json({tasks:db.prepare("SELECT id,title,description,reward FROM tasks WHERE active=1 ORDER BY id DESC").all()});
});

app.get("/api/admin/users",admin,(req,res)=>{
  res.json({users:db.prepare("SELECT id,name,email,role,referral_code,created_at FROM users ORDER BY id DESC").all()});
});

app.post("/api/admin/tasks",admin,(req,res)=>{
  const {title,description,reward}=req.body;
  if(!title||!description||typeof reward!=="number"||reward<0)
    return res.status(400).json({error:"Invalid task"});
  const info=db.prepare("INSERT INTO tasks(title,description,reward) VALUES(?,?,?)").run(title,description,reward);
  res.json({ok:true,id:Number(info.lastInsertRowid)});
});

app.get("/api/admin/stats",admin,(req,res)=>{
  const users=db.prepare("SELECT COUNT(*) c FROM users").get().c;
  const tasks=db.prepare("SELECT COUNT(*) c FROM tasks WHERE active=1").get().c;
  res.json({users,tasks});
});


// Development-only admin bootstrap: set ADMIN_EMAIL and ADMIN_PASSWORD before first run.
// In production, replace this with a secure one-time setup flow.
(async()=>{
  const adminEmail=process.env.ADMIN_EMAIL, adminPassword=process.env.ADMIN_PASSWORD;
  if(adminEmail && adminPassword){
    const existing=db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail.toLowerCase());
    if(!existing){
      const hash=await argon2.hash(adminPassword);
      const code="ADMIN"+Math.random().toString(36).slice(2,8).toUpperCase();
      db.prepare("INSERT INTO users(name,email,password_hash,role,referral_code) VALUES(?,?,?,?,?)")
        .run("Administrator",adminEmail.toLowerCase(),hash,"admin",code);
      console.log("Development admin created:",adminEmail);
    }
  }
})();

app.listen(3000,()=>console.log("EARN777 running at http://localhost:3000"));
