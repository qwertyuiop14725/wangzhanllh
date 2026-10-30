/* ===========================================================================
   Cloudflare Pages Function
   一个文件搞定后台的三个接口：
     GET  /api/data    取配置
     POST /api/verify  校验管理员密码
     POST /api/save    写入配置（存 KV，永久生效）

   前提：在 Pages 项目里绑定一个 KV 命名空间，变量名必须是 SITES。
   没绑也能跑，只是退回「下载 index.html」模式。
   =========================================================================== */

var KEY = 'site-data';
var TRY = 'try:';
var DEFAULT_PWD = '410329';

function json(obj, code) {
  return new Response(JSON.stringify(obj), {
    status: code || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function sha256(s) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s))).then(function (buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (x) {
      return ('0' + x.toString(16)).slice(-2);
    }).join('');
  });
}

function hostOf(u) {
  try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return ''; }
}

/* 数据只保留认识的字段，顺手挡掉 javascript: 之类的网址 */
function norm(cats, sites) {
  var cs = [], ss = [], seen = {}, i, c, s, u;
  for (i = 0; i < (cats || []).length; i++) {
    c = cats[i];
    if (!c || !c.id || !c.name || seen[c.id]) continue;
    seen[c.id] = 1;
    cs.push({ id: String(c.id), name: String(c.name).slice(0, 40), note: String(c.note || '').slice(0, 80) });
  }
  for (i = 0; i < (sites || []).length; i++) {
    s = sites[i];
    if (!s || !s.url) continue;
    u = String(s.url).slice(0, 500);
    if (!/^https?:\/\//i.test(u)) continue;
    ss.push({
      name: String(s.name || hostOf(u) || '未命名').slice(0, 60),
      url: u,
      desc: String(s.desc || '').slice(0, 160),
      category: String(s.category || ''),
      hot: !!s.hot,
      notice: s.notice !== false
    });
  }
  return { categories: cs, sites: ss };
}

function load(kv) {
  return kv.get(KEY).then(function (raw) {
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
  });
}

export async function onRequestGet(context) {
  var path = new URL(context.request.url).pathname;
  if (!/\/api\/data\/?$/.test(path)) return json({ ok: false }, 404);

  var kv = context.env.SITES;
  if (!kv) return json({ ok: true, noKv: true, file: false, categories: [], sites: [] });

  var d = await load(kv);
  return json({
    ok: true,
    file: !!(d && d.sites && d.sites.length),
    updated: (d && d.updated) || '',
    categories: (d && d.categories) || [],
    sites: (d && d.sites) || []
  });
}

export async function onRequestPost(context) {
  var path = new URL(context.request.url).pathname;
  var isSave = /\/api\/save\/?$/.test(path);
  if (!isSave && !/\/api\/verify\/?$/.test(path)) return json({ ok: false }, 404);

  var kv = context.env.SITES;
  if (!kv) return json({ ok: false, msg: 'KV 没绑定' }, 501);

  var body = {};
  try { body = await context.request.json(); } catch (e) { return json({ ok: false, msg: 'bad json' }, 400); }

  // 每分钟最多试 8 次密码
  var ip = context.request.headers.get('CF-Connecting-IP') ||
           context.request.headers.get('X-Forwarded-For') || 'unknown';
  var n = parseInt((await kv.get(TRY + ip)) || '0', 10);
  if (n >= 8) return json({ ok: false, msg: 'too many attempts' }, 429);

  var cur = await load(kv);
  var hash = (cur && cur.admin && cur.admin.pwdHash) ? cur.admin.pwdHash : await sha256(DEFAULT_PWD);
  if ((await sha256(String(body.pwd || ''))) !== hash) {
    await kv.put(TRY + ip, String(n + 1), { expirationTtl: 60 });
    return json({ ok: false, msg: 'bad password' }, 401);
  }
  await kv.delete(TRY + ip);

  if (!isSave) return json({ ok: true });

  var clean = norm(body.categories, body.sites);
  if (!clean.sites.length) return json({ ok: false, msg: 'no valid site' }, 400);

  var out = {
    v: 1,
    updated: new Date().toISOString(),
    admin: (cur && cur.admin) ? cur.admin : { pwdHash: hash },
    categories: clean.categories,
    sites: clean.sites
  };
  if (body.newPwd && String(body.newPwd).length >= 4) {
    out.admin = { pwdHash: await sha256(String(body.newPwd)), updated: out.updated };
  }
  await kv.put(KEY, JSON.stringify(out));
  return json({ ok: true, updated: out.updated });
}

