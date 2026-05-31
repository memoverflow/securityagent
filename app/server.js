'use strict';

// =====================================================================
//  ⚠️  授权 PENTEST 靶站 —— 故意包含安全漏洞
//  仅用于 AWS Security Agent 渗透测试验证，部署在自有且已验证所有权的域名。
//  请勿用于生产，请勿放置任何真实数据。
// =====================================================================

const express = require('express');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

// ---- 内存数据库与种子数据 ----
const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT, ssn TEXT);
  CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT);
  INSERT INTO users (id, name, password, ssn) VALUES
    (1, 'alice', 'alice-pass-123', '111-11-1111'),
    (2, 'bob',   'bob-pass-456',   '222-22-2222'),
    (3, 'admin', 'sup3r-s3cret',   '999-99-9999');
`);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// 注意：此处故意不设置任何安全响应头（CSP / X-Frame-Options / HSTS 等）
// —— 漏洞 #5：缺失安全响应头基线

// ---- 首页：明确标注靶站性质 ----
app.get('/', (_req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><title>Pentest Target</title></head>
<body style="font-family:system-ui;max-width:680px;margin:40px auto;line-height:1.6">
  <h1>⚠️ 授权渗透测试靶站</h1>
  <p>本站点<strong>故意包含安全漏洞</strong>，仅用于 <em>AWS Security Agent</em> 的渗透测试验证。</p>
  <p>部署在自有且已验证所有权的域名上，不含任何真实数据。</p>
  <hr>
  <h3>可用端点</h3>
  <ul>
    <li><code>POST /login</code> — 用户登录（name, password）</li>
    <li><code>GET  /search?q=</code> — 搜索</li>
    <li><code>GET  /comments</code> + <code>POST /comment</code> — 留言板</li>
    <li><code>GET  /api/user/:id</code> — 用户信息</li>
    <li><code>GET  /health</code> — 健康检查</li>
  </ul>
</body></html>`);
});

// ---- 健康检查（供 ALB target group） ----
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ---- 漏洞 #1：SQL 注入（字符串拼接） ----
// 例: name = ' OR '1'='1  可绕过认证
app.post('/login', (req, res) => {
  const { name = '', password = '' } = req.body;
  const sql = `SELECT id, name FROM users WHERE name = '${name}' AND password = '${password}'`;
  try {
    const row = db.prepare(sql).get();
    if (row) return res.json({ ok: true, user: row });
    return res.status(401).json({ ok: false, error: 'invalid credentials' });
  } catch (e) {
    // 故意把 SQL 错误暴露给客户端 —— 便于注入探测（信息泄露）
    return res.status(500).json({ ok: false, error: e.message, sql });
  }
});

// ---- 漏洞 #2：反射型 XSS（输入直接拼进 HTML） ----
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  res.type('html').send(`<!doctype html><html><body>
    <h2>搜索结果</h2>
    <p>你搜索了: ${q}</p>
  </body></html>`);
});

// ---- 漏洞 #3：存储型 XSS（存储后原样渲染） ----
app.post('/comment', (req, res) => {
  const body = req.body.body || '';
  db.prepare('INSERT INTO comments (body) VALUES (?)').run(body);
  res.json({ ok: true });
});

app.get('/comments', (_req, res) => {
  const rows = db.prepare('SELECT body FROM comments ORDER BY id DESC').all();
  const items = rows.map((r) => `<li>${r.body}</li>`).join('');
  res.type('html').send(`<!doctype html><html><body>
    <h2>留言板</h2><ul>${items}</ul>
  </body></html>`);
});

// ---- 漏洞 #4：IDOR（不校验身份，返回任意用户敏感数据） ----
app.get('/api/user/:id', (req, res) => {
  const row = db.prepare('SELECT id, name, ssn FROM users WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row); // 直接返回 ssn 等敏感字段，无任何授权检查
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`pentest target listening on 0.0.0.0:${PORT}`);
});
