/* ===========================================================================
   Cloudflare Pages Function —— 后台的三个接口都在这一份里
     GET  /api/data    取配置
     POST /api/verify  校验管理员密码
     POST /api/save    保存配置（写进 KV，永久生效）

   KV 绑定：变量名随便起（SITES、llhnb666、abc… 都能自动认出来），
   但绑定改完要重新部署一次才生效。
   没绑 KV 也能跑，会退回「下载 index.html」模式。
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

/* ---------- 密码：一律存 sha256 哈希，不存明文 ---------- */
function sha256(s) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s))).then(function (buf) {
    var b = new Uint8Array(buf), out = '', i;
    for (i = 0; i < b.length; i++) out += ('0' + b[i].toString(16)).slice(-2);
    return out;
  });
}
// 定长比较，别用 !== 提前返回
function eq(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  var diff = 0, i;
  for (i = 0; i < a.length; i++) diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  return diff === 0 && a.length > 0;
}

function hostOf(u) {
  try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return ''; }
}

/* 数据只留认识的字段，顺手挡掉 javascript: 之类的网址 */
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

/* ---------- KV：不管绑定名叫什么都找得出来 ---------- */
// KV 的特征是有 get / put；Pages 自带的 ASSETS 只有 fetch，会被排除
function isKV(v) {
  return !!v && typeof v.get === 'function' && typeof v.put === 'function';
}
function pickKV(env) {
  if (!env) return null;
  var order = ['SITES', 'SITE_DATA', 'NAV', 'KV', 'DATA'], i, k;
  for (i = 0; i < order.length; i++) if (isKV(env[order[i]])) return env[order[i]];
  for (k in env) if (isKV(env[k])) return env[k];
  return null;
}
// 实际收到哪些绑定名（只给名字不给值），排查绑定用
function envKeys(env) {
  var out = [];
  if (!env) return out;
  for (var k in env) out.push(k);
  return out;
}

function load(kv) {
  return kv.get(KEY).then(function (raw) {
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
  });
}

/* 取出已存的密码哈希。老版本可能存过明文，遇到就当场换成哈希 */
function pwdHashOf(cur) {
  if (cur && cur.admin && cur.admin.pwdHash) return cur.admin.pwdHash;
  return null;
}
function legacyPlain(cur) {
  return (cur && cur.admin && cur.admin.pwd) ? String(cur.admin.pwd) : '';
}

export async function onRequestGet(context) {
  var path = new URL(context.request.url).pathname;
  if (!/\/api\/data\/?$/.test(path)) return json({ ok: false }, 404);

  var kv = pickKV(context.env);
  if (!kv) {
    return json({ ok: true, noKv: true, file: false, keys: envKeys(context.env), categories: [], sites: [] });
  }
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

  var kv = pickKV(context.env);
  if (!kv) return json({ ok: false, msg: 'KV 没绑定', keys: envKeys(context.env) }, 501);

  var body = {};
  try { body = await context.request.json(); } catch (e) { return json({ ok: false, msg: 'bad json' }, 400); }

  // 每个 IP 每分钟最多试 8 次密码
  var ip = context.request.headers.get('CF-Connecting-IP') ||
           context.request.headers.get('X-Forwarded-For') || 'unknown';
  var n = parseInt((await kv.get(TRY + ip)) || '0', 10);
  if (n >= 8) return json({ ok: false, msg: 'too many attempts' }, 429);

  var cur = await load(kv);
  var plain = legacyPlain(cur);
  var want = pwdHashOf(cur) || (plain ? await sha256(plain) : await sha256(DEFAULT_PWD));
  if (!eq(await sha256(String(body.pwd || '')), want)) {
    await kv.put(TRY + ip, String(n + 1), { expirationTtl: 60 });
    return json({ ok: false, msg: 'bad password' }, 401);
  }
  await kv.delete(TRY + ip);

  // 老数据里存着明文密码，这次顺手升级成哈希
  if (plain && !pwdHashOf(cur)) {
    try { await kv.put(KEY, JSON.stringify(withAdmin(cur, { pwdHash: await sha256(plain) }))); cur = await load(kv); }
    catch (e) {}
  }

  if (!isSave) return json({ ok: true });

  var clean = norm(body.categories, body.sites);
  if (!clean.sites.length) return json({ ok: false, msg: 'no valid site' }, 400);

  var admin = (cur && cur.admin) ? cur.admin : { pwdHash: want };
  delete admin.pwd;                                  // 明文一律清掉
  if (body.newPwd && String(body.newPwd).length >= 4) {
    admin = { pwdHash: await sha256(String(body.newPwd)), updated: new Date().toISOString() };
  }

  var out = {
    v: 1,
    updated: new Date().toISOString(),
    admin: admin,
    categories: clean.categories,
    sites: clean.sites
  };
  await kv.put(KEY, JSON.stringify(out));
  return json({ ok: true, updated: out.updated });
}

function withAdmin(cur, admin) {
  var o = { v: 1, updated: new Date().toISOString(), admin: admin,
    categories: (cur && cur.categories) || [], sites: (cur && cur.sites) || [] };
  return o;
}
