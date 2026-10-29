
'use strict';

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const isProduction = process.env.NODE_ENV === 'production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const PROFILE_TABLE = 'identity_profiles';
const PROFILE_BUCKET = 'identity-avatars';
const DATA_DIR = process.env.DATA_DIR || (isProduction ? '/var/data' : path.join(__dirname, 'data'));
const SETTINGS_FILE = path.join(DATA_DIR, 'site-settings.json');

if (ADMIN_PASSWORD.length < 10) {
  console.warn('Set ADMIN_PASSWORD to at least 10 characters.');
}
if (SESSION_SECRET.length < 32) {
  console.warn('Set SESSION_SECRET to at least 32 random characters.');
}

fs.mkdirSync(DATA_DIR, { recursive: true });

app.disable('x-powered-by');
if (isProduction) app.set('trust proxy', 1);

app.use(express.json({ limit: '1mb' }));

app.use(session({
  name: 'masih_admin_session',
  secret: SESSION_SECRET || crypto.randomBytes(48).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: 4 * 60 * 60 * 1000
  }
}));

function readSettings() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.error('Could not read settings:', err.message);
    }
    return { services: [] };
  }
}

function writeSettings(settings) {
  const temp = SETTINGS_FILE + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(settings, null, 2), {
    encoding: 'utf8',
    mode: 0o600
  });
  fs.renameSync(temp, SETTINGS_FILE);
}

function requireAdmin(req, res, next) {
  if (!req.session || req.session.isAdmin !== true) {
    return res.status(401).json({
      error: 'ابتدا با رمز مدیر وارد شو.'
    });
  }
  next();
}

function requireCsrf(req, res, next) {
  const provided = req.get('X-CSRF-Token') || '';
  const expected = req.session?.csrfToken || '';

  if (
    !provided ||
    !expected ||
    provided.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))
  ) {
    return res.status(403).json({
      error: 'درخواست معتبر نیست؛ دوباره وارد پنل شو.'
    });
  }
  next();
}

function safeString(value, max, fallback = '') {
  if (typeof value !== 'string') return fallback;
  return value.trim().slice(0, max);
}

function normalizeSettings(input) {
  if (!input || !Array.isArray(input.services) || input.services.length > 200) {
    throw new Error('فهرست خدمات معتبر نیست.');
  }

  const services = input.services.map((service, index) => {
    if (!service || typeof service !== 'object') {
      throw new Error('اطلاعات خدمت معتبر نیست.');
    }

    const title = safeString(service.title, 140);
    if (!title) {
      throw new Error(`عنوان خدمت شماره ${index + 1} خالی است.`);
    }

    return {
      id: index,
      title,
      description: safeString(service.description, 1200),
      price: safeString(service.price, 100, 'توافقی') || 'توافقی',
      category: safeString(service.category, 80, 'خدمات تکمیلی') || 'خدمات تکمیلی',
      active: service.active !== false
    };
  });

  return {
    services,
    updatedAt: new Date().toISOString()
  };
}

const loginAttempts = new Map();

function checkLoginLimit(ip) {
  const now = Date.now();
  const old = loginAttempts.get(ip);

  if (!old || now - old.start > 15 * 60 * 1000) {
    loginAttempts.set(ip, { start: now, count: 0 });
    return true;
  }

  return old.count < 10;
}

function noteFailedLogin(ip) {
  const entry = loginAttempts.get(ip) || {
    start: Date.now(),
    count: 0
  };
  entry.count++;
  loginAttempts.set(ip, entry);
}

function secureEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  return aa.length === bb.length &&
    aa.length > 0 &&
    crypto.timingSafeEqual(aa, bb);
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/api/site-settings', (_req, res) => {
  res.json({ settings: readSettings() });
});

app.get('/api/admin/me', (req, res) => {
  res.json({
    authenticated: req.session?.isAdmin === true,
    csrfToken: req.session?.isAdmin ? req.session.csrfToken : ''
  });
});

app.post('/api/admin/login', (req, res, next) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';

  if (!checkLoginLimit(ip)) {
    return res.status(429).json({
      error: 'تلاش‌های زیاد. ۱۵ دقیقه دیگر دوباره امتحان کن.'
    });
  }

  if (
    !ADMIN_PASSWORD ||
    !SESSION_SECRET ||
    !secureEqual(req.body?.password || '', ADMIN_PASSWORD)
  ) {
    noteFailedLogin(ip);
    return res.status(401).json({
      error: 'رمز اشتباه است یا تنظیمات امنیتی سرور کامل نیست.'
    });
  }

  req.session.regenerate(err => {
    if (err) return next(err);

    req.session.isAdmin = true;
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');

    req.session.save(saveErr => {
      if (saveErr) return next(saveErr);
      loginAttempts.delete(ip);
      res.json({
        ok: true,
        csrfToken: req.session.csrfToken
      });
    });
  });
});

app.post('/api/admin/logout', requireAdmin, requireCsrf, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);

    res.clearCookie('masih_admin_session', {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict'
    });

    res.json({ ok: true });
  });
});

app.get('/api/admin/settings', requireAdmin, (_req, res) => {
  res.json({ settings: readSettings() });
});

app.put('/api/admin/settings', requireAdmin, requireCsrf, (req, res) => {
  try {
    const settings = normalizeSettings(req.body);
    writeSettings(settings);
    res.json({ ok: true, settings });
  } catch (err) {
    res.status(400).json({
      error: err.message || 'ذخیره تنظیمات انجام نشد.'
    });
  }
});

function supabaseHeaders(extra = {}) {
  return {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    ...extra
  };
}

function ensureSupabase(res) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    res.status(503).json({
      error: 'مدیریت هویت فعال نیست؛ تنظیمات Supabase را در سرور وارد کن.'
    });
    return false;
  }
  return true;
}

app.get('/api/admin/identities', requireAdmin, async (_req, res) => {
  if (!ensureSupabase(res)) return;

  try {
    const url =
      `${SUPABASE_URL}/rest/v1/${PROFILE_TABLE}` +
      '?select=tracking_code,display_name,username,bio,social_url,avatar_url,created_at' +
      '&order=created_at.desc&limit=200';

    const response = await fetch(url, {
      headers: supabaseHeaders()
    });

    if (!response.ok) {
      return res.status(502).json({
        error: `خواندن هویت‌ها ناموفق بود (${response.status}).`
      });
    }

    res.json({ identities: await response.json() });
  } catch (_err) {
    res.status(502).json({
      error: 'ارتباط با سرویس هویت برقرار نشد.'
    });
  }
});

app.patch('/api/admin/identities/:code', requireAdmin, requireCsrf, async (req, res) => {
  if (!ensureSupabase(res)) return;

  const code = String(req.params.code || '');
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(code)) {
    return res.status(400).json({ error: 'کد هویت نامعتبر است.' });
  }

  const body = req.body || {};
  const patch = {};

  for (const key of ['display_name', 'username', 'bio', 'social_url']) {
    if (Object.prototype.hasOwnProperty.call(body, key)) {
      patch[key] = safeString(
        body[key],
        key === 'bio' || key === 'social_url' ? 500 : 100
      );
    }
  }

  if (!Object.keys(patch).length) {
    return res.status(400).json({
      error: 'تغییری برای ذخیره ارسال نشده است.'
    });
  }

  if (
    patch.social_url &&
    !/^https:\/\//i.test(patch.social_url) &&
    !/^@[A-Za-z0-9_]{4,}$/.test(patch.social_url)
  ) {
    return res.status(400).json({
      error: 'لینک اجتماعی باید HTTPS یا آیدی معتبر تلگرام باشد.'
    });
  }

  try {
    const url =
      `${SUPABASE_URL}/rest/v1/${PROFILE_TABLE}` +
      `?tracking_code=eq.${encodeURIComponent(code)}`;

    const response = await fetch(url, {
      method: 'PATCH',
      headers: supabaseHeaders({
        'Content-Type': 'application/json',
        Prefer: 'return=minimal'
      }),
      body: JSON.stringify(patch)
    });

    if (!response.ok) {
      return res.status(502).json({
        error: `ویرایش هویت ناموفق بود (${response.status}).`
      });
    }

    res.json({ ok: true });
  } catch (_err) {
    res.status(502).json({ error: 'ذخیره هویت ناموفق بود.' });
  }
});

app.delete('/api/admin/identities/:code', requireAdmin, requireCsrf, async (req, res) => {
  if (!ensureSupabase(res)) return;

  const code = String(req.params.code || '');
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(code)) {
    return res.status(400).json({ error: 'کد هویت نامعتبر است.' });
  }

  try {
    const lookupUrl =
      `${SUPABASE_URL}/rest/v1/${PROFILE_TABLE}` +
      `?select=tracking_code,avatar_url` +
      `&tracking_code=eq.${encodeURIComponent(code)}&limit=1`;

    const lookup = await fetch(lookupUrl, {
      headers: supabaseHeaders()
    });

    if (!lookup.ok) {
      return res.status(502).json({ error: 'خواندن هویت ناموفق بود.' });
    }

    const rows = await lookup.json();

    if (!rows.length) {
      return res.status(404).json({ error: 'این هویت پیدا نشد.' });
    }

    const removeUrl =
      `${SUPABASE_URL}/rest/v1/${PROFILE_TABLE}` +
      `?tracking_code=eq.${encodeURIComponent(code)}`;

    const removed = await fetch(removeUrl, {
      method: 'DELETE',
      headers: supabaseHeaders({ Prefer: 'return=minimal' })
    });

    if (!removed.ok) {
      return res.status(502).json({ error: 'حذف هویت ناموفق بود.' });
    }

    const avatar = rows[0].avatar_url || '';
    const marker = `/storage/v1/object/public/${PROFILE_BUCKET}/`;
    const position = avatar.indexOf(marker);

    if (position >= 0) {
      const objectPath = avatar
        .slice(position + marker.length)
        .split('/')
        .map(encodeURIComponent)
        .join('/');

      await fetch(
        `${SUPABASE_URL}/storage/v1/object/${PROFILE_BUCKET}/${objectPath}`,
        {
          method: 'DELETE',
          headers: supabaseHeaders()
        }
      ).catch(() => {});
    }

    res.json({ ok: true });
  } catch (_err) {
    res.status(502).json({ error: 'حذف هویت ناموفق بود.' });
  }
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/index.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'مسیر پیدا نشد.' });
  }
  res.status(404).send('صفحه پیدا نشد.');
});

app.use((err, _req, res, _next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ error: 'خطای داخلی سرور رخ داد.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`SIFLA server listening on ${PORT}`);
});
