"use strict";

// =====================================================================
//  ⚠️  授权 PENTEST 靶站 —— 故意包含安全漏洞
//  仅用于 AWS Security Agent 渗透测试验证，部署在自有且已验证所有权的域名。
//  请勿用于生产，请勿放置任何真实数据。
// =====================================================================

const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");

const app = express();
const PORT = process.env.PORT || 3000;

// ---- 内存数据库与种子数据 ----
const db = new Database(":memory:");
db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT, ssn TEXT, role TEXT);
  CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT);
  INSERT INTO users (id, name, password, ssn, role) VALUES
    (1, 'alice', 'alice-pass-123', '111-11-1111', 'user'),
    (2, 'bob',   'bob-pass-456',   '222-22-2222', 'user'),
    (3, 'admin', 'sup3r-s3cret',   '999-99-9999', 'admin');
`);

// ---- 漏洞 #12：硬编码密钥（源码泄露即泄露密钥） ----
const API_SIGNING_KEY = "acme-cloud-static-hmac-key-2026";

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// 会话（用于真实登录态；Security Agent 可用凭证登录后带 cookie 测受保护页）
app.use(
  session({
    secret: "acme-cloud-demo-secret",
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

// ---- 漏洞 #1：SQL 注入（字符串拼接） ----
// 例: name = ' OR '1'='1  可绕过认证
app.post("/login", (req, res) => {
  const { name = "", password = "" } = req.body;
  const sql = `SELECT id, name FROM users WHERE name = '${name}' AND password = '${password}'`;
  try {
    const row = db.prepare(sql).get();
    if (row) {
      // 登录成功：建立会话（真实登录态）
      req.session.user = { id: row.id, name: row.name };
      // 表单提交跳转到受保护页；API 调用返回 JSON
      if ((req.headers.accept || "").includes("application/json")) {
        return res.json({ ok: true, user: row });
      }
      return res.redirect("/dashboard");
    }
    return res.status(401).json({ ok: false, error: "invalid credentials" });
  } catch (e) {
    // 故意把 SQL 错误暴露给客户端 —— 便于注入探测（信息泄露）
    return res.status(500).json({ ok: false, error: e.message, sql });
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

// =====================================================================
//  移动端 / API 攻击面 —— 供 Acme Cloud Android App (APK) 调用
//  这些接口构成移动靶站的服务端，包含多个故意漏洞。
// =====================================================================

// ---- 漏洞 #10：弱会话 token（可预测 / 可伪造） ----
// 移动端登录成功后返回 token = base64("uid:" + id)，无签名、无随机性。
// 攻击者可枚举 id 伪造任意用户 token（含 admin）。
function makeToken(id) {
  return Buffer.from("uid:" + id).toString("base64");
}
function parseToken(token) {
  try {
    const s = Buffer.from(String(token || ""), "base64").toString("utf8");
    const m = s.match(/^uid:(\d+)$/);
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

// 移动端登录（同样是 SQL 注入点 —— 漏洞 #1 在 API 上的体现）
app.post("/api/login", (req, res) => {
  const { name = "", password = "" } = req.body;
  const sql = `SELECT id, name, role FROM users WHERE name = '${name}' AND password = '${password}'`;
  try {
    const row = db.prepare(sql).get();
    if (!row) return res.status(401).json({ ok: false, error: "invalid credentials" });
    return res.json({ ok: true, token: makeToken(row.id), user: row });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message, sql });
  }
});

// 当前用户信息：用可伪造 token 鉴权 —— 漏洞 #10 的利用点
app.get("/api/me", (req, res) => {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const uid = parseToken(token);
  if (!uid) return res.status(401).json({ error: "missing/invalid token" });
  const row = db.prepare("SELECT id, name, ssn, role FROM users WHERE id = ?").get(uid);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row); // 任意 uid 即可拿到对应用户全部字段（含 ssn）
});

// ---- 漏洞 #9：垂直越权（缺角色校验的 admin 接口） ----
// 任何持有任意有效 token 的人都能列出所有用户（含明文密码）。
app.get("/api/admin/users", (req, res) => {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const uid = parseToken(token);
  if (!uid) return res.status(401).json({ error: "missing/invalid token" });
  // 故意不校验 role 是否为 admin
  const rows = db.prepare("SELECT id, name, password, ssn, role FROM users").all();
  res.json({ users: rows });
});

// ---- 漏洞 #6：命令注入（用户输入直接进 shell） ----
// 例: host = 127.0.0.1; cat /etc/passwd
app.get("/api/ping", (req, res) => {
  const host = req.query.host || "127.0.0.1";
  try {
    const out = execSync(`ping -c 1 ${host}`, { timeout: 5000 }).toString();
    res.type("text").send(out);
  } catch (e) {
    res.status(500).type("text").send(String(e.stdout || e.message));
  }
});

// ---- 漏洞 #7：路径遍历（任意文件读取） ----
// 例: name = ../../../../etc/passwd
app.get("/api/file", (req, res) => {
  const name = req.query.name || "readme.txt";
  const full = path.join("/opt/app/files", name);
  try {
    const data = fs.readFileSync(full, "utf8"); // 不做 path 规范化校验
    res.type("text").send(data);
  } catch (e) {
    res.status(404).type("text").send("not found: " + full);
  }
});

// ---- 漏洞 #8：SSRF（服务端请求任意 URL） ----
// 例: url = http://169.254.169.254/latest/meta-data/iam/security-credentials/
app.get("/api/fetch", (req, res) => {
  const target = req.query.url || "";
  if (!target) return res.status(400).json({ error: "url required" });
  const lib = target.startsWith("https") ? https : http;
  try {
    lib
      .get(target, (r) => {
        let buf = "";
        r.on("data", (c) => (buf += c));
        r.on("end", () => res.type("text").send(buf));
      })
      .on("error", (e) => res.status(502).json({ error: e.message }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- 漏洞 #11：调试接口信息泄露（暴露环境变量 / 主机信息） ----
app.get("/api/debug", (_req, res) => {
  res.json({
    env: process.env, // 直接吐出全部环境变量
    cwd: process.cwd(),
    versions: process.versions,
    signingKey: API_SIGNING_KEY, // 连硬编码密钥也一起泄露
  });
});

// ---- 漏洞 #13：开放重定向 ----
// 例: /go?to=https://evil.example.com
app.get("/go", (req, res) => {
  const to = req.query.to || "/";
  res.redirect(to); // 不校验目标，任意跳转
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`pentest target listening on 0.0.0.0:${PORT}`);
});
