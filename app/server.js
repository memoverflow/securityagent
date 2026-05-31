"use strict";

const crypto = require("crypto");
// =====================================================================
//  ⚠️  授权 PENTEST 靶站 —— 故意包含安全漏洞
//  仅用于 AWS Security Agent 渗透测试验证，部署在自有且已验证所有权的域名。
//  请勿用于生产，请勿放置任何真实数据。
// =====================================================================

const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;

// ---- 密码哈希工具函数 (使用 Node.js 内置 scrypt KDF) ----
const SCRYPT_KEYLEN = 64;
const SCRYPT_SALT_LEN = 16;

function hashPassword(password) {
  const salt = crypto.randomBytes(SCRYPT_SALT_LEN).toString("hex");
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEYLEN).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const derived = crypto.scryptSync(password, salt, SCRYPT_KEYLEN).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(derived, "hex"));
}

// ---- 内存数据库与种子数据 (密码使用 scrypt 哈希存储) ----
const db = new Database(":memory:");
db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT, ssn TEXT);
  CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT);
`);
const seedUsers = [
  { id: 1, name: "alice", password: "alice-pass-123", ssn: "111-11-1111" },
  { id: 2, name: "bob",   password: "bob-pass-456",   ssn: "222-22-2222" },
  { id: 3, name: "admin", password: "sup3r-s3cret",   ssn: "999-99-9999" },
];
const insertUser = db.prepare("INSERT INTO users (id, name, password, ssn) VALUES (?, ?, ?, ?)");
for (const u of seedUsers) {
  insertUser.run(u.id, u.name, hashPassword(u.password), u.ssn);
}

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// 会话（使用加密随机生成的 secret）
app.use(
  session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" },
  }),
);

// 要求登录的中间件：未登录跳转 /login
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect("/login");
}

// 注意：此处故意不设置任何安全响应头（CSP / X-Frame-Options / HSTS 等）
// —— 漏洞 #5：缺失安全响应头基线

// ---- 首页：呈现为一个普通站点 ----
app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Acme Cloud</title>
<style>
  *{box-sizing:border-box} body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1f2933;background:#f7f9fc}
  header{background:#0b5fff;color:#fff;padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
  header .brand{font-weight:700;font-size:20px;letter-spacing:.3px}
  nav a{color:#dce6ff;text-decoration:none;margin-left:20px;font-size:14px}
  nav a:hover{color:#fff}
  .hero{max-width:880px;margin:56px auto 0;padding:0 24px;text-align:center}
  .hero h1{font-size:38px;margin:0 0 12px}
  .hero p{font-size:17px;color:#52606d;max-width:620px;margin:0 auto 28px}
  .cta{display:inline-block;background:#0b5fff;color:#fff;padding:12px 26px;border-radius:8px;text-decoration:none;font-weight:600}
  .features{max-width:960px;margin:64px auto;padding:0 24px;display:grid;grid-template-columns:repeat(3,1fr);gap:24px}
  .card{background:#fff;border:1px solid #e4e7eb;border-radius:12px;padding:24px}
  .card h3{margin:0 0 8px;font-size:16px}
  .card p{margin:0;font-size:14px;color:#616e7c;line-height:1.6}
  footer{text-align:center;color:#9aa5b1;font-size:13px;padding:40px 0}
</style></head>
<body>
  <header>
    <div class="brand">Acme Cloud</div>
    <nav>
      <a href="/">首页</a>
      <a href="/search?q=">搜索</a>
      <a href="/comments">社区</a>
      <a href="/login">登录</a>
    </nav>
  </header>
  <section class="hero">
    <h1>更简单的云端协作</h1>
    <p>Acme Cloud 帮助团队集中管理文档、任务与沟通，让协作更高效、更安全。</p>
    <a class="cta" href="/login">立即开始</a>
  </section>
  <section class="features">
    <div class="card"><h3>统一工作台</h3><p>所有项目、文件与讨论集中在一处，随时随地访问。</p></div>
    <div class="card"><h3>智能搜索</h3><p>快速定位你需要的内容，节省查找时间。</p></div>
    <div class="card"><h3>团队社区</h3><p>在留言板中交流想法，沉淀团队知识。</p></div>
  </section>
  <footer>© 2026 Acme Cloud. All rights reserved.</footer>
</body></html>`);
});

// ---- 健康检查（供 ALB target group） ----
app.get("/health", (_req, res) => res.json({ status: "ok" }));

// 登录页（普通表单，提交到 POST /login）
app.get("/login", (_req, res) => {
  res.type("html")
    .send(`<!doctype html><html lang="zh"><head><meta charset="utf-8">
    <title>登录 · Acme Cloud</title>
    <style>body{font-family:system-ui;max-width:380px;margin:60px auto;padding:0 20px;color:#1f2933}
    label{display:block;margin:14px 0 4px;font-size:14px}
    input{width:100%;padding:10px;border:1px solid #cbd2d9;border-radius:6px}
    button{margin-top:20px;width:100%;padding:11px;border:0;background:#0b5fff;color:#fff;border-radius:6px;font-weight:600}</style></head>
  <body>
    <h2>登录 Acme Cloud</h2>
    <form method="post" action="/login">
      <label>用户名</label><input name="name" autocomplete="username">
      <label>密码</label><input type="password" name="password" autocomplete="current-password">
      <button>登录</button>
    </form>
  </body></html>`);
});

// ---- 登录处理 ----
app.post("/login", (req, res) => {
  const { name = "", password = "" } = req.body;
  try {
    const row = db.prepare("SELECT id, name, password FROM users WHERE name = ?").get(name);
    if (row && verifyPassword(password, row.password)) {
      // 登录成功：建立会话
      req.session.user = { id: row.id, name: row.name };
      // 表单提交跳转到受保护页；API 调用返回 JSON
      if ((req.headers.accept || "").includes("application/json")) {
        return res.json({ ok: true, user: { id: row.id, name: row.name } });
      }
      return res.redirect("/dashboard");
    }
    return res.status(401).json({ ok: false, error: "invalid credentials" });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "internal error" });
  }
});

// 登出
app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ---- 受保护页：仅登录用户可访问 ----
app.get("/dashboard", requireAuth, (req, res) => {
  const u = req.session.user;
  res.type("html")
    .send(`<!doctype html><html lang="zh"><head><meta charset="utf-8">
    <title>控制台 · Acme Cloud</title>
    <style>body{font-family:system-ui;max-width:760px;margin:40px auto;padding:0 20px;color:#1f2933}
    .bar{display:flex;justify-content:space-between;align-items:center}
    a{color:#0b5fff;text-decoration:none;margin-right:16px}
    form{display:inline}</style></head>
  <body>
    <div class="bar">
      <h2>欢迎回来，${u.name}</h2>
      <form method="post" action="/logout"><button>退出</button></form>
    </div>
    <p>这是你的个人工作台。</p>
    <nav><a href="/comments">社区留言板</a><a href="/search">搜索</a></nav>
  </body></html>`);
});

// ---- 漏洞 #2：反射型 XSS（输入直接拼进 HTML） ----
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  const result = q
    ? `<p>你搜索了: ${q}</p><p style="color:#616e7c">没有找到匹配的结果。</p>`
    : `<p style="color:#616e7c">输入关键词以搜索文档与项目。</p>`;
  res.type("html")
    .send(`<!doctype html><html lang="zh"><head><meta charset="utf-8">
    <title>搜索 · Acme Cloud</title>
    <style>body{font-family:system-ui;max-width:680px;margin:40px auto;padding:0 20px;color:#1f2933}
    input{padding:10px;width:70%;border:1px solid #cbd2d9;border-radius:6px}
    button{padding:10px 18px;border:0;background:#0b5fff;color:#fff;border-radius:6px}</style></head>
  <body>
    <h2>搜索</h2>
    <form method="get" action="/search">
      <input name="q" placeholder="搜索..." value="${q}"><button>搜索</button>
    </form>
    ${result}
  </body></html>`);
});

// ---- 漏洞 #3：存储型 XSS（存储后原样渲染）—— 现为登录后攻击面 ----
app.post("/comment", requireAuth, (req, res) => {
  const body = req.body.body || "";
  db.prepare("INSERT INTO comments (body) VALUES (?)").run(body);
  res.redirect("/comments");
});

app.get("/comments", requireAuth, (_req, res) => {
  const rows = db.prepare("SELECT body FROM comments ORDER BY id DESC").all();
  const items = rows.map((r) => `<li>${r.body}</li>`).join("");
  res.type("html")
    .send(`<!doctype html><html lang="zh"><head><meta charset="utf-8">
    <title>社区 · Acme Cloud</title>
    <style>body{font-family:system-ui;max-width:680px;margin:40px auto;padding:0 20px;color:#1f2933}
    textarea{width:100%;padding:10px;border:1px solid #cbd2d9;border-radius:6px}
    button{margin-top:8px;padding:9px 18px;border:0;background:#0b5fff;color:#fff;border-radius:6px}</style></head>
  <body>
    <h2>社区留言板</h2>
    <form method="post" action="/comment">
      <textarea name="body" rows="3" placeholder="写点什么..."></textarea>
      <button>发布</button>
    </form>
    <ul>${items}</ul>
  </body></html>`);
});

// ---- 漏洞 #4：IDOR（不校验身份，返回任意用户敏感数据） ----
app.get("/api/user/:id", (req, res) => {
  const row = db
    .prepare("SELECT id, name, ssn FROM users WHERE id = ?")
    .get(req.params.id);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row); // 直接返回 ssn 等敏感字段，无任何授权检查
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`pentest target listening on 0.0.0.0:${PORT}`);
});
