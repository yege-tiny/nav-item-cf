// Cloudflare Pages Functions —— 全部后端 API（迁移自 Express routes/*）
// 运行环境: Cloudflare Workers。数据库: D1(env.DB)。对象存储: R2(env.BUCKET)。
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { sign, verify } from 'hono/jwt';
import { handle } from 'hono/cloudflare-pages';
import bcrypt from 'bcryptjs';
import { ensureDbInitialized } from '../lib/init.js';

const app = new Hono().basePath('/api');

app.use('*', cors());

// 首次请求自动建表 + 写入默认数据（幂等，无需手动执行 schema.sql）
app.use('*', async (c, next) => {
  try {
    await ensureDbInitialized(c.env);
  } catch (e) {
    return c.json({ error: '数据库初始化失败: ' + (e && e.message ? e.message : e) }, 500);
  }
  await next();
});

// ---------- 工具函数与安全配置 ----------
function jwtSecret(env) {
  return env.JWT_SECRET || 'nav-item-cf-jwt-secret-secure-key-2025';
}

// 登录防暴力破解：内存计数器
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCK_TIME_MS = 5 * 60 * 1000;

// 允许上传的文件扩展名与 MIME 类型白名单
const ALLOWED_IMAGE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.webp', '.svg', '.ico', '.gif']);
const ALLOWED_IMAGE_MIMES = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/svg+xml',
  'image/x-icon',
  'image/vnd.microsoft.icon',
  'image/gif'
]);
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

// 认证中间件: 校验 Authorization: Bearer <token>
async function auth(c, next) {
  const header = c.req.header('Authorization') || '';
  if (!header.startsWith('Bearer ')) {
    return c.json({ error: '未授权' }, 401);
  }
  try {
    const payload = await verify(header.slice(7), jwtSecret(c.env), 'HS256');
    c.set('user', payload);
    await next();
  } catch (e) {
    return c.json({ error: '无效token' }, 401);
  }
}

function getClientIp(c) {
  let ip = c.req.header('CF-Connecting-IP')
    || c.req.header('x-forwarded-for')
    || '';
  if (ip.includes(',')) ip = ip.split(',')[0].trim();
  if (ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');
  return ip || '127.0.0.1';
}

function getShanghaiTime() {
  const parts = new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', hour12: false,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  }).formatToParts(new Date());
  const p = {};
  parts.forEach(x => { p[x.type] = x.value; });
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
}

// ==================== 健康检查 ====================
app.get('/health', (c) => {
  return c.json({
    status: 'ok',
    platform: 'Cloudflare Pages / Workers',
    timestamp: new Date().toISOString()
  });
});

// ==================== 登录 ====================
app.post('/login', async (c) => {
  const { username, password } = await c.req.json().catch(() => ({}));
  const ip = getClientIp(c);
  const nowMs = Date.now();

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return c.json({ error: '请输入有效的用户名和密码' }, 400);
  }

  // 检查 IP 登录频率限制
  const attemptInfo = loginAttempts.get(ip);
  if (attemptInfo && attemptInfo.count >= MAX_ATTEMPTS) {
    if (nowMs - attemptInfo.lastAttempt < LOCK_TIME_MS) {
      const remainingSec = Math.ceil((LOCK_TIME_MS - (nowMs - attemptInfo.lastAttempt)) / 1000);
      return c.json({ error: `尝试次数过多，请 ${remainingSec} 秒后再试` }, 429);
    } else {
      loginAttempts.delete(ip);
    }
  }

  const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username.trim()).first();
  if (!user) {
    recordFailedAttempt(ip, nowMs);
    return c.json({ error: '用户名或密码错误' }, 401);
  }

  const ok = bcrypt.compareSync(password || '', user.password);
  if (!ok) {
    recordFailedAttempt(ip, nowMs);
    return c.json({ error: '用户名或密码错误' }, 401);
  }

  // 登录成功，清除失败计数
  loginAttempts.delete(ip);

  // 本次登录之前的记录 = 上次登录
  const lastLoginTime = user.last_login_time;
  const lastLoginIp = user.last_login_ip;
  // 本次登录
  const now = getShanghaiTime();
  // 把原「本次」下移为「上次」，再写入新的「本次」
  await c.env.DB.prepare(
    'UPDATE users SET prev_login_time = ?, prev_login_ip = ?, last_login_time = ?, last_login_ip = ? WHERE id = ?'
  ).bind(lastLoginTime ?? null, lastLoginIp ?? null, now, ip, user.id).run();

  // token 有效期（小时），默认 7 天，可用环境变量 TOKEN_TTL_HOURS 覆盖
  const ttlHours = parseInt(c.env.TOKEN_TTL_HOURS) || 24 * 7;
  const token = await sign(
    { id: user.id, username: user.username, exp: Math.floor(Date.now() / 1000) + ttlHours * 60 * 60 },
    jwtSecret(c.env)
  );
  return c.json({
    token,
    currentLoginTime: now, currentLoginIp: ip,   // 本次
    lastLoginTime, lastLoginIp,                  // 上次
  });
});

function recordFailedAttempt(ip, nowMs) {
  const current = loginAttempts.get(ip) || { count: 0, lastAttempt: nowMs };
  current.count += 1;
  current.lastAttempt = nowMs;
  loginAttempts.set(ip, current);
}

// ==================== 菜单 ====================
app.get('/menus', async (c) => {
  const page = c.req.query('page');
  const pageSize = c.req.query('pageSize');

  if (!page && !pageSize) {
    // 消除 N+1 串行查询：一次性查询主菜单与子菜单并在内存中组装
    const [menusRes, subMenusRes] = await Promise.all([
      c.env.DB.prepare('SELECT * FROM menus ORDER BY "order" ASC, id ASC').all(),
      c.env.DB.prepare('SELECT * FROM sub_menus ORDER BY "order" ASC, id ASC').all()
    ]);
    
    const menus = menusRes.results || [];
    const subMenus = subMenusRes.results || [];

    const subMenuMap = {};
    subMenus.forEach(sub => {
      if (!subMenuMap[sub.parent_id]) subMenuMap[sub.parent_id] = [];
      subMenuMap[sub.parent_id].push(sub);
    });

    const result = menus.map(menu => ({
      ...menu,
      subMenus: subMenuMap[menu.id] || []
    }));

    c.header('Cache-Control', 'public, max-age=60, s-maxage=300, stale-while-revalidate=600');
    return c.json(result);
  }

  const pageNum = parseInt(page) || 1;
  const size = parseInt(pageSize) || 10;
  const offset = (pageNum - 1) * size;
  const total = (await c.env.DB.prepare('SELECT COUNT(*) as total FROM menus').first()).total;
  const rows = (await c.env.DB.prepare('SELECT * FROM menus ORDER BY "order" ASC, id ASC LIMIT ? OFFSET ?')
    .bind(size, offset).all()).results;
  return c.json({ total, page: pageNum, pageSize: size, data: rows });
});

app.get('/menus/:id/submenus', async (c) => {
  const rows = (await c.env.DB.prepare('SELECT * FROM sub_menus WHERE parent_id = ? ORDER BY "order" ASC, id ASC')
    .bind(c.req.param('id')).all()).results;
  c.header('Cache-Control', 'public, max-age=60, s-maxage=300, stale-while-revalidate=600');
  return c.json(rows);
});

app.post('/menus', auth, async (c) => {
  const { name, order } = await c.req.json();
  if (!name || typeof name !== 'string' || !name.trim()) {
    return c.json({ error: '菜单名称不能为空' }, 400);
  }
  const r = await c.env.DB.prepare('INSERT INTO menus (name, "order") VALUES (?, ?)')
    .bind(name.trim(), parseInt(order) || 0).run();
  return c.json({ id: r.meta.last_row_id });
});

app.put('/menus/:id', auth, async (c) => {
  const { name, order } = await c.req.json();
  if (!name || typeof name !== 'string' || !name.trim()) {
    return c.json({ error: '菜单名称不能为空' }, 400);
  }
  const r = await c.env.DB.prepare('UPDATE menus SET name = ?, "order" = ? WHERE id = ?')
    .bind(name.trim(), parseInt(order) || 0, c.req.param('id')).run();
  return c.json({ changed: r.meta.changes });
});

app.delete('/menus/:id', auth, async (c) => {
  const r = await c.env.DB.prepare('DELETE FROM menus WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ deleted: r.meta.changes });
});

app.post('/menus/:id/submenus', auth, async (c) => {
  const { name, order } = await c.req.json();
  if (!name || typeof name !== 'string' || !name.trim()) {
    return c.json({ error: '子菜单名称不能为空' }, 400);
  }
  const r = await c.env.DB.prepare('INSERT INTO sub_menus (parent_id, name, "order") VALUES (?, ?, ?)')
    .bind(c.req.param('id'), name.trim(), parseInt(order) || 0).run();
  return c.json({ id: r.meta.last_row_id });
});

app.put('/menus/submenus/:id', auth, async (c) => {
  const { name, order } = await c.req.json();
  if (!name || typeof name !== 'string' || !name.trim()) {
    return c.json({ error: '子菜单名称不能为空' }, 400);
  }
  const r = await c.env.DB.prepare('UPDATE sub_menus SET name = ?, "order" = ? WHERE id = ?')
    .bind(name.trim(), parseInt(order) || 0, c.req.param('id')).run();
  return c.json({ changed: r.meta.changes });
});

app.delete('/menus/submenus/:id', auth, async (c) => {
  const r = await c.env.DB.prepare('DELETE FROM sub_menus WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ deleted: r.meta.changes });
});

// ==================== 卡片 ====================
/**
 * 全局搜索卡片（公开接口）
 * NOTE: 必须放在 /cards/:menuId 之前，否则 Hono 会将 'search' 作为 menuId 匹配
 */
app.get('/cards/search', async (c) => {
  const q = (c.req.query('q') || '').trim();
  if (!q) return c.json([]);
  const keyword = `%${q}%`;
  const rows = (await c.env.DB.prepare(
    'SELECT * FROM cards WHERE title LIKE ? OR url LIKE ? ORDER BY menu_id ASC, "order" ASC, id ASC'
  ).bind(keyword, keyword).all()).results;
  rows.forEach(card => {
    if (!card.custom_logo_path) {
      card.display_logo = card.logo_url || (card.url ? card.url.replace(/\/+$/, '') + '/favicon.ico' : '');
    } else {
      card.display_logo = '/uploads/' + card.custom_logo_path;
    }
  });
  return c.json(rows);
});

app.get('/cards/:menuId', async (c) => {
  const subMenuId = c.req.query('subMenuId');
  let rows;
  if (subMenuId) {
    rows = (await c.env.DB.prepare('SELECT * FROM cards WHERE sub_menu_id = ? ORDER BY "order" ASC, id ASC')
      .bind(subMenuId).all()).results;
  } else {
    rows = (await c.env.DB.prepare('SELECT * FROM cards WHERE menu_id = ? AND (sub_menu_id IS NULL OR sub_menu_id = 0) ORDER BY "order" ASC, id ASC')
      .bind(c.req.param('menuId')).all()).results;
  }
  rows.forEach(card => {
    if (!card.custom_logo_path) {
      card.display_logo = card.logo_url || (card.url ? card.url.replace(/\/+$/, '') + '/favicon.ico' : '');
    } else {
      card.display_logo = '/uploads/' + card.custom_logo_path;
    }
  });
  c.header('Cache-Control', 'public, max-age=60, s-maxage=300, stale-while-revalidate=600');
  return c.json(rows);
});

app.post('/cards', auth, async (c) => {
  const { menu_id, sub_menu_id, title, url, logo_url, custom_logo_path, desc, order } = await c.req.json();
  if (!title || !url) {
    return c.json({ error: '卡片名称和链接地址不能为空' }, 400);
  }
  const r = await c.env.DB.prepare(
    'INSERT INTO cards (menu_id, sub_menu_id, title, url, logo_url, custom_logo_path, desc, "order") VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(menu_id ?? null, sub_menu_id || null, title.trim(), url.trim(), logo_url ?? null, custom_logo_path ?? null, desc ?? null, parseInt(order) || 0).run();
  return c.json({ id: r.meta.last_row_id });
});

app.put('/cards/:id', auth, async (c) => {
  const { menu_id, sub_menu_id, title, url, logo_url, custom_logo_path, desc, order } = await c.req.json();
  if (!title || !url) {
    return c.json({ error: '卡片名称和链接地址不能为空' }, 400);
  }
  const r = await c.env.DB.prepare(
    'UPDATE cards SET menu_id = ?, sub_menu_id = ?, title = ?, url = ?, logo_url = ?, custom_logo_path = ?, desc = ?, "order" = ? WHERE id = ?'
  ).bind(menu_id ?? null, sub_menu_id || null, title.trim(), url.trim(), logo_url ?? null, custom_logo_path ?? null, desc ?? null, parseInt(order) || 0, c.req.param('id')).run();
  return c.json({ changed: r.meta.changes });
});

app.delete('/cards/:id', auth, async (c) => {
  const r = await c.env.DB.prepare('DELETE FROM cards WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ deleted: r.meta.changes });
});

// ==================== 文件上传（R2） ====================
function themePrefix(target) {
  return target === 'favicon' ? 'favicon-'
    : target === 'mobile' ? 'bg-mobile-'
    : 'bg-desktop-';
}

async function saveToR2(c, field, prefix) {
  const body = await c.req.parseBody();
  const file = body[field];
  if (!file || typeof file === 'string') return { error: '未接收到上传文件' };

  if (file.size > MAX_FILE_SIZE) {
    return { error: '文件大小超过限制 (最大 5MB)' };
  }

  const name = file.name || '';
  const dot = name.lastIndexOf('.');
  const ext = dot >= 0 ? name.slice(dot).toLowerCase() : '';
  
  if (!ALLOWED_IMAGE_EXTS.has(ext) && !ALLOWED_IMAGE_MIMES.has(file.type)) {
    return { error: '仅支持上传常见图片文件 (PNG, JPG, WEBP, SVG, ICO, GIF)' };
  }

  const cleanExt = ALLOWED_IMAGE_EXTS.has(ext) ? ext : '.png';
  const filename = `${prefix}${Date.now()}-${Math.random().toString(36).slice(2, 8)}${cleanExt}`;
  
  await c.env.BUCKET.put(filename, await file.arrayBuffer(), {
    httpMetadata: { contentType: file.type || 'image/png' }
  });
  return { filename };
}

app.post('/upload', auth, async (c) => {
  const result = await saveToR2(c, 'logo', '');
  if (result.error) return c.json({ error: result.error }, 400);
  return c.json({ filename: result.filename, url: '/uploads/' + result.filename });
});

// ==================== 广告 ====================
app.get('/ads', async (c) => {
  const page = c.req.query('page');
  const pageSize = c.req.query('pageSize');
  if (!page && !pageSize) {
    const rows = (await c.env.DB.prepare('SELECT * FROM ads').all()).results;
    c.header('Cache-Control', 'public, max-age=60, s-maxage=300, stale-while-revalidate=600');
    return c.json(rows);
  }
  const pageNum = parseInt(page) || 1;
  const size = parseInt(pageSize) || 10;
  const offset = (pageNum - 1) * size;
  const total = (await c.env.DB.prepare('SELECT COUNT(*) as total FROM ads').first()).total;
  const rows = (await c.env.DB.prepare('SELECT * FROM ads LIMIT ? OFFSET ?').bind(size, offset).all()).results;
  return c.json({ total, page: pageNum, pageSize: size, data: rows });
});

app.post('/ads', auth, async (c) => {
  const { position, img, url } = await c.req.json();
  const r = await c.env.DB.prepare('INSERT INTO ads (position, img, url) VALUES (?, ?, ?)')
    .bind(position, img, url).run();
  return c.json({ id: r.meta.last_row_id });
});

app.put('/ads/:id', auth, async (c) => {
  const { img, url } = await c.req.json();
  const r = await c.env.DB.prepare('UPDATE ads SET img = ?, url = ? WHERE id = ?')
    .bind(img, url, c.req.param('id')).run();
  return c.json({ changed: r.meta.changes });
});

app.delete('/ads/:id', auth, async (c) => {
  const r = await c.env.DB.prepare('DELETE FROM ads WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ deleted: r.meta.changes });
});

// ==================== 友情链接 ====================
app.get('/friends', async (c) => {
  const page = c.req.query('page');
  const pageSize = c.req.query('pageSize');
  if (!page && !pageSize) {
    const rows = (await c.env.DB.prepare('SELECT * FROM friends').all()).results;
    c.header('Cache-Control', 'public, max-age=60, s-maxage=300, stale-while-revalidate=600');
    return c.json(rows);
  }
  const pageNum = parseInt(page) || 1;
  const size = parseInt(pageSize) || 10;
  const offset = (pageNum - 1) * size;
  const total = (await c.env.DB.prepare('SELECT COUNT(*) as total FROM friends').first()).total;
  const rows = (await c.env.DB.prepare('SELECT * FROM friends LIMIT ? OFFSET ?').bind(size, offset).all()).results;
  return c.json({ total, page: pageNum, pageSize: size, data: rows });
});

app.post('/friends', auth, async (c) => {
  const { title, url, logo } = await c.req.json();
  const r = await c.env.DB.prepare('INSERT INTO friends (title, url, logo) VALUES (?, ?, ?)')
    .bind(title, url, logo).run();
  return c.json({ id: r.meta.last_row_id });
});

app.put('/friends/:id', auth, async (c) => {
  const { title, url, logo } = await c.req.json();
  const r = await c.env.DB.prepare('UPDATE friends SET title = ?, url = ?, logo = ? WHERE id = ?')
    .bind(title, url, logo, c.req.param('id')).run();
  return c.json({ changed: r.meta.changes });
});

app.delete('/friends/:id', auth, async (c) => {
  const r = await c.env.DB.prepare('DELETE FROM friends WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ deleted: r.meta.changes });
});

// ==================== 用户 ====================
app.get('/users/profile', auth, async (c) => {
  const user = await c.env.DB.prepare('SELECT id, username FROM users WHERE id = ?')
    .bind(c.get('user').id).first();
  if (!user) return c.json({ message: '用户不存在' }, 404);
  return c.json({ data: user });
});

app.get('/users/me', auth, async (c) => {
  const user = await c.env.DB.prepare(
    'SELECT id, username, last_login_time, last_login_ip, prev_login_time, prev_login_ip FROM users WHERE id = ?'
  ).bind(c.get('user').id).first();
  if (!user) return c.json({ message: '用户不存在' }, 404);
  return c.json({
    current_login_time: user.last_login_time,   // 本次
    current_login_ip: user.last_login_ip,
    last_login_time: user.prev_login_time,       // 上次
    last_login_ip: user.prev_login_ip,
  });
});

app.put('/users/password', auth, async (c) => {
  const { oldPassword, newPassword } = await c.req.json();
  if (!oldPassword || !newPassword) return c.json({ message: '请提供旧密码和新密码' }, 400);
  if (newPassword.length < 6) return c.json({ message: '新密码长度至少6位' }, 400);

  const user = await c.env.DB.prepare('SELECT password FROM users WHERE id = ?').bind(c.get('user').id).first();
  if (!user) return c.json({ message: '用户不存在' }, 404);
  if (!bcrypt.compareSync(oldPassword, user.password)) return c.json({ message: '旧密码错误' }, 400);

  const newHash = bcrypt.hashSync(newPassword, 10);
  await c.env.DB.prepare('UPDATE users SET password = ? WHERE id = ?').bind(newHash, c.get('user').id).run();
  return c.json({ message: '密码修改成功' });
});

app.get('/users', auth, async (c) => {
  const page = c.req.query('page');
  const pageSize = c.req.query('pageSize');
  if (!page && !pageSize) {
    const users = (await c.env.DB.prepare('SELECT id, username FROM users').all()).results;
    return c.json({ data: users });
  }
  const pageNum = parseInt(page) || 1;
  const size = parseInt(pageSize) || 10;
  const offset = (pageNum - 1) * size;
  const total = (await c.env.DB.prepare('SELECT COUNT(*) as total FROM users').first()).total;
  const users = (await c.env.DB.prepare('SELECT id, username FROM users LIMIT ? OFFSET ?').bind(size, offset).all()).results;
  return c.json({ total, page: pageNum, pageSize: size, data: users });
});

// ==================== 站点设置 ====================
app.get('/settings', async (c) => {
  const rows = (await c.env.DB.prepare('SELECT key, value FROM site_settings').all()).results;
  const settings = {};
  rows.forEach(row => { settings[row.key] = row.value; });
  c.header('Cache-Control', 'public, max-age=60, s-maxage=300, stale-while-revalidate=600');
  return c.json({ code: 200, data: settings });
});

app.put('/settings', auth, async (c) => {
  const settings = await c.req.json().catch(() => null);
  if (!settings || typeof settings !== 'object') return c.json({ code: 400, message: '参数无效' }, 400);

  const allowedKeys = [
    'site_name', 'admin_theme',
    'bg_desktop_type', 'bg_desktop_value',
    'bg_mobile_type', 'bg_mobile_value',
    'favicon_type', 'favicon_url'
  ];
  let updatedCount = 0;
  const stmt = c.env.DB.prepare('INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)');
  const batch = [];
  for (const [key, value] of Object.entries(settings)) {
    if (allowedKeys.includes(key)) {
      batch.push(stmt.bind(key, String(value)));
      updatedCount++;
    }
  }
  if (batch.length) await c.env.DB.batch(batch);
  return c.json({ code: 200, message: `已更新 ${updatedCount} 项设置` });
});

app.post('/settings/upload-bg', auth, async (c) => {
  const body = await c.req.parseBody();
  const result = await saveToR2(c, 'bg', themePrefix(body.target));
  if (result.error) return c.json({ code: 400, message: result.error }, 400);
  return c.json({ code: 200, data: { url: '/uploads/' + result.filename } });
});

// 列出某个目标（favicon/desktop/mobile）已上传的图片，仅返回该用途的图片
app.get('/settings/uploads', auth, async (c) => {
  const prefix = themePrefix(c.req.query('target'));
  const list = await c.env.BUCKET.list({ prefix });
  const items = (list.objects || []).map(o => ({
    key: o.key,
    url: '/uploads/' + o.key,
    size: o.size,
    uploaded: o.uploaded,
  }));
  // 按上传时间倒序，最新的排在前面
  items.sort((a, b) => new Date(b.uploaded).getTime() - new Date(a.uploaded).getTime());
  return c.json({ code: 200, data: items });
});

// 删除一张已上传的主题图片（仅允许 bg-/favicon- 前缀，避免误删卡片 logo 等）
app.delete('/settings/uploads/:key', auth, async (c) => {
  const key = c.req.param('key');
  if (!key || !(key.startsWith('bg-') || key.startsWith('favicon-')) || key.includes('/')) {
    return c.json({ code: 400, message: '非法文件名' }, 400);
  }
  await c.env.BUCKET.delete(key);
  return c.json({ code: 200, message: '已删除' });
});

// ==================== 数据备份 / 迁移 ====================
// 导出: 打包栏目、子栏目、卡片、广告、友链、站点设置为 JSON；不含用户账号，也不含 R2 中的图片文件
// 导入: 清空上述表后按备份内容重写；users 表不受影响
const BACKUP_VERSION = 1;
const BACKUP_TABLES = ['menus', 'sub_menus', 'cards', 'ads', 'friends', 'site_settings'];

// NOTE: 每张表允许写入的列名白名单，防止导入时通过恶意 JSON 列名注入 SQL
const TABLE_COLUMNS = {
  menus:         new Set(['id', 'name', 'order']),
  sub_menus:     new Set(['id', 'parent_id', 'name', 'order']),
  cards:         new Set(['id', 'menu_id', 'sub_menu_id', 'title', 'url', 'logo_url', 'custom_logo_path', 'desc', 'order']),
  ads:           new Set(['id', 'position', 'img', 'url']),
  friends:       new Set(['id', 'title', 'url', 'logo']),
  site_settings: new Set(['id', 'key', 'value']),
};

app.get('/backup/export', auth, async (c) => {
  const data = {};
  for (const t of BACKUP_TABLES) {
    const rows = (await c.env.DB.prepare(`SELECT * FROM ${t}`).all()).results || [];
    data[t] = rows;
  }
  const payload = {
    version: BACKUP_VERSION,
    exportedAt: new Date().toISOString(),
    source: 'nav-item-cf',
    data,
  };
  const filename = `nav-item-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  return new Response(JSON.stringify(payload, null, 2), {
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
    },
  });
});

app.post('/backup/import', auth, async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body) return c.json({ error: '备份文件格式无效' }, 400);
  // 兼容 { data: {...} }（直接是备份 JSON）和 { data: { data: {...} } }（外层再包一层）
  const payload = body.data && body.data.data ? body.data : body;
  const data = payload.data;
  if (!data || typeof data !== 'object') return c.json({ error: '备份文件格式无效' }, 400);

  // D1 不支持 PRAGMA foreign_keys 运行时切换，但 batch 里 DELETE + INSERT 由 D1 保证事务性
  // users 不在清空范围内，导入后仍用当前账号密码登录
  const clearOrder = ['cards', 'sub_menus', 'menus', 'ads', 'friends', 'site_settings'];
  const stmts = [];
  for (const t of clearOrder) {
    stmts.push(c.env.DB.prepare(`DELETE FROM ${t}`));
    // 重置自增序列
    stmts.push(c.env.DB.prepare(`DELETE FROM sqlite_sequence WHERE name = ?`).bind(t));
  }

  let inserted = 0;
  for (const t of BACKUP_TABLES) {
    const allowedCols = TABLE_COLUMNS[t];
    const rows = Array.isArray(data[t]) ? data[t] : [];
    for (const row of rows) {
      // 仅保留白名单内的列名，过滤掉恶意注入的列
      const cols = Object.keys(row).filter(c => allowedCols.has(c));
      if (cols.length === 0) continue;
      const placeholders = cols.map(() => '?').join(', ');
      const quoted = cols.map((col) => `"${col}"`).join(', ');
      const values = cols.map((col) => row[col]);
      stmts.push(c.env.DB.prepare(`INSERT INTO ${t} (${quoted}) VALUES (${placeholders})`).bind(...values));
      inserted++;
    }
  }

  try {
    await c.env.DB.batch(stmts);
    return c.json({ code: 200, message: `导入成功，共写入 ${inserted} 条记录`, inserted });
  } catch (e) {
    return c.json({ error: '导入失败: ' + (e && e.message ? e.message : String(e)) }, 500);
  }
});

export const onRequest = handle(app);
