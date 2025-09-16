// ====== imports / setup ======
process.env.NODE_ENV ||= 'production';
require('dotenv').config();
process.on('uncaughtException', err => console.error('UNCAUGHT', err));
process.on('unhandledRejection', err => console.error('UNHANDLED', err));
const { bot, WEBAPP_URL } = require('./bot'); // импорт один раз
// === Telegram helper (кнопки для отметки приёма)
function appUrlFor(tgId) {
  const base = (process.env.WEBAPP_URL || WEBAPP_URL || '').replace(/\/+$/,'');
  return `${base}/main?tg=${tgId}`;
}

async function sendReminder(tgId, text) {
  try {
    await bot.sendMessage(tgId, text, {
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [{ text: 'Отметить приём 💊', web_app: { url: appUrlFor(tgId) } }],
          [{ text: 'Открыть в браузере', url: appUrlFor(tgId) }]
        ]
      }
    });
  } catch (e) {
    console.error('Ошибка отправки напоминания:', e?.response?.body || e);
  }
}


// локально (без WEBAPP_URL) работаем в polling, на Render — webhook
const isPolling = !process.env.WEBAPP_URL && !process.env.TELEGRAM_WEBHOOK;
const path = require('path');
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const pg = require('pg');
pg.defaults.ssl = true;
const { Pool } = pg;

console.log('Boot server.js at', new Date().toISOString());
// ⬇️ СНАЧАЛА создаём app
const app = express();

// ⬇️ ПОТОМ вешаем middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ type: 'text/plain', limit: '10mb' }));
app.use((req, _res, next) => {
  // Если пришёл text/plain, а внутри JSON — аккуратно распарсим в объект
  if (typeof req.body === 'string' &&
      (req.headers['content-type'] || '').startsWith('text/plain')) {
    try { req.body = JSON.parse(req.body); } catch (_) {}
  }
  next();
});
app.use(cors({
  origin: true,
  credentials: true,
  allowedHeaders: ['Content-Type','X-Telegram-InitData','x-telegram-initdata','tgwebappdata']
}));



// ====== DB pool ======
const dsn = process.env.DATABASE_URL;
if (!dsn) throw new Error('DATABASE_URL is empty');

const pool = new Pool({
  connectionString: dsn,
  ssl: { rejectUnauthorized: false },
});
// ==== helpers: нормализация дат и вставка дозы ====
function isoTsOrZ(iso) {
  // 'YYYY-MM-DD' => начало дня в UTC; иначе — корректный ISO
  if (/^\d{4}-\d{2}-\d{2}$/.test(String(iso))) return `${iso}T00:00:00.000Z`;
  const d = new Date(iso || Date.now());
  if (Number.isNaN(d.getTime())) throw new Error('Bad date');
  return d.toISOString();
}

async function addIntake(pool, userId, iso, mg) {
  // сначала пробуем схему с timestamptz колонкой "at"
  const ts = isoTsOrZ(iso);
  try {
    await pool.query(
      `INSERT INTO derma.intakes (user_id, at, mg) VALUES ($1, $2::timestamptz, $3)`,
      [userId, ts, mg]
    );
    return;
  } catch (e) {
    // если колонки "at" нет — пробуем схему с колонкой "day" (DATE)
    if (e.code === '42703' || /column\s+"?at"?\s+does not exist/i.test(String(e.message))) {
      const day = String(iso || '').slice(0, 10);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) throw new Error('Bad date');
      await pool.query(
        `INSERT INTO derma.intakes (user_id, day, mg) VALUES ($1, $2::date, $3)`,
        [userId, day, mg]
      );
      return;
    }
    throw e;
  }
}

try { console.log('PG host:', new URL(dsn).hostname); } catch {}

// ====== TG WebApp auth helpers ======
// Берём токен из ENV, а если его забыли — из уже созданного экземпляра бота
const BOT_TOKEN = process.env.BOT_TOKEN || (bot?.telegram?.token ?? '');
console.log('Auth token ends with:', (BOT_TOKEN || '').slice(-6));
if (!BOT_TOKEN) {
  console.error('BOT_TOKEN is missing'); process.exit(1);
}

function parseAndVerifyInitData(initData) {
  if (!BOT_TOKEN) throw new Error('BOT_TOKEN missing');

  const sp = new URLSearchParams(initData);
  const hash = sp.get('hash');
  sp.delete('hash');

  // Собираем data_check_string строго по доке
  const entries = [];
  sp.forEach((v, k) => entries.push(`${k}=${v}`));
  entries.sort(); // сортируем по ключу
  const dataCheckString = entries.join('\n');

  // secret_key = HMAC_SHA256(bot_token) с ключом "WebAppData"
  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const sign   = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');

  if (!hash || sign !== hash) throw new Error('bad initData hash');

  const authDateMs = Number(sp.get('auth_date') || '0') * 1000;
  if (!authDateMs || Date.now() - authDateMs > 24 * 60 * 60 * 1000) {
    throw new Error('stale initData');
  }
  const user = sp.get('user') ? JSON.parse(sp.get('user')) : null;
  return { user };
}

// DEV-дружественная аутентификация: initData (Telegram) или ?tg=<num> (dev).
// DEV-дружественная аутентификация: initData (Telegram) или ?tg=<num> (dev).
async function tgAuth(req, res, next){
  // ⬇️ dev-ветка ДОЛЖНА зеркалить обычную по части БД
  const isLocal = req.hostname === 'localhost' || req.hostname === '127.0.0.1';
  const devTg   = req.query.tg || req.header('X-Dev-TG');

  if (isLocal && devTg) {
    try {
      const tgId = Number(devTg);
      if (!tgId || Number.isNaN(tgId)) return res.status(401).json({ error: 'BOT_INVALID' });

      // как в «боевой» ветке: фиксируем search_path и создаём пользователя
      await pool.query('SET search_path = derma, public');
      const ins = await pool.query(
        `INSERT INTO derma.users(tg_id) VALUES ($1)
         ON CONFLICT (tg_id) DO NOTHING RETURNING id`, [tgId]
      );

      req.isFreshUser = ins.rowCount > 0;
      req.tg = tgId;
      req.tgUser = { id: tgId };   // чтобы ниже по коду было одинаково
      return next();
    } catch (e) {
      console.error('tgAuth DEV error', e);
      return res.status(401).json({ error: 'BOT_INVALID' });
    }
  }

  // ⬇️ дальше — как у тебя было (обычная ветка с initData/проверкой хэша)
  try{
    let tgId = null, parsed = null;
    const rawHeader = req.get('X-Telegram-InitData') || req.get('x-telegram-initdata') || '';
    const rawQuery  = req.query.tgWebAppData || req.query.initData || '';

    if (rawHeader) { try { parsed = parseAndVerifyInitData(rawHeader); } catch(_) {} }
    if (!parsed && rawQuery) { try { parsed = parseAndVerifyInitData(rawQuery); } catch(_) {} }
    if (parsed?.user?.id) { tgId = Number(parsed.user.id); req.tgUser = parsed.user; }
    if (!tgId && /^\d+$/.test(String(req.query.tg||''))) tgId = Number(req.query.tg);
    if (!tgId) return res.status(401).json({ error: 'BOT_INVALID' });

    await pool.query('SET search_path = derma, public');
    const ins = await pool.query(
      `INSERT INTO derma.users(tg_id) VALUES ($1)
       ON CONFLICT (tg_id) DO NOTHING RETURNING id`, [tgId]
    );
    req.isFreshUser = ins.rowCount > 0;
    req.tg = tgId;
    next();
  } catch(e) {
    console.error('tgAuth error', e);
    res.status(401).json({ error: 'BOT_INVALID' });
  }
}
// ====== helpers ======
async function ensureUser(req) {
  try {
    let tgId = Number(req.tg) || null;
    if (!tgId && req.tgUser?.id) tgId = Number(req.tgUser.id);
    if (!tgId && (req.query?.tg || req.body?.tg)) tgId = Number(req.query.tg || req.body.tg);
    if (!tgId || Number.isNaN(tgId)) return null;

    await pool.query('SET search_path = derma, public');

    const ins = await pool.query(
      `INSERT INTO derma.users (tg_id)
       VALUES ($1::bigint)
       ON CONFLICT (tg_id) DO NOTHING
       RETURNING id, tg_id`,
      [tgId]
    );

    let userRow;
    if (ins.rows.length) {
      req.isFreshUser = true;          // ⬅️ ВАЖНО: пользователь создан «с нуля»
      userRow = ins.rows[0];
    } else {
      const r2 = await pool.query('SELECT id, tg_id FROM derma.users WHERE tg_id = $1::bigint', [tgId]);
      userRow = r2.rows[0] || null;
      req.isFreshUser = false;
    }
    return userRow;
  } catch (e) {
    console.error('ensureUser error:', e);
    req.isFreshUser = false;
    return null;
  }
}

async function userIdByTg(tgId) {
  if (!tgId) return null;
  // на всякий случай фиксируем search_path для текущего коннекта
  await pool.query('SET search_path = derma, public');
  const { rows } = await pool.query(
    'SELECT id FROM derma.users WHERE tg_id = $1::bigint',
    [Number(tgId)]
  );
  return rows[0]?.id || null;
}


// ====== open routes ======
app.get('/api/health', (_, res) => res.json({ ok: true }));
// === STATE FLOW ENDPOINTS (first-run routing) ================================

/**
 * Определяем, врач ли пользователь, и пройден ли его онбординг.
 * isDoctor: true, если users.is_doctor = true ИЛИ уже есть doctor_code/profile.
 * onbDone: true, если есть doctor_code (active) ИЛИ doctor_profile.
 */
async function decideDoctorState(uid) {
  await pool.query('SET search_path = derma, public');
  const u = await pool.query('SELECT is_doctor FROM derma.users WHERE id=$1', [uid]);
  let isDoctor = !!u.rows[0]?.is_doctor;

  const code = await pool.query(
    'SELECT code FROM derma.doctor_codes WHERE doctor_id=$1 AND active',
    [uid]
  );
  const prof = await pool.query(
    'SELECT 1 FROM derma.doctor_profiles WHERE user_id=$1',
    [uid]
  );

  const hasDoctorAssets = !!(code.rows[0]?.code || prof.rows[0]);
  if (!isDoctor && hasDoctorAssets) isDoctor = true;

  return { isDoctor, onbDone: hasDoctorAssets };
}

/**
 * GET /api/state/next/index
 * Ответ: { page: '/dark/splash-video.html' | '/dark/welcome-rt.html' }
 * Логика: splash показываем только при самом первом EVER заходе (req.isFreshUser).
 */
// === FIRST ENTRY / RE-ENTRY DECISION ===
app.get('/api/state/next/index', tgAuth, async (req, res) => {
  try {
    // форс-сплэш для тестов: /index.html?forceSplash=1
    if (String(req.query.forceSplash) === '1') {
      return res.json({ ok: true, page: '/dark/splash-video.html' });
    }

    // 1) Самый первый вход — показываем сплэш
    if (req.isFreshUser) {
      return res.json({ ok: true, page: '/dark/splash-video.html' });
    }

    // 2) Повторный вход — решаем по роли и статусу онбординга
    const uid = await userIdByTg(req.tg || req.tgUser?.id);
    let page = '/dark/main.html'; // по умолчанию — пациент

    if (uid) {
      // decideDoctorState уже есть в файле и возвращает isDoctor + onbDone
      const { isDoctor, onbDone } = await decideDoctorState(uid);
      if (isDoctor) {
        page = onbDone
          ? '/dark/doctor-cabinet-mint-rose.html'       // врач с завершённым онбордингом
          : '/dark/doctor-onboarding-mint-rose.html';   // врач без завершённого онбординга
      }
    }

    return res.json({ ok: true, page });
  } catch (e) {
    console.error('NEXT/INDEX ERROR:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});


/**
 * GET /api/state/next/welcome
 * Возвращает, куда идти ПОСЛЕ welcome:
 *  - пациент (первый раз): warnings → profile → plan → main
 *  - пациент (повторный): main
 *  - врач (первый раз): doctor-onboarding → doctor-cabinet
 *  - врач (повторный): doctor-cabinet
 *
 * Ответ: { page: '/dark/....html', role: 'patient'|'doctor' }
 */
app.get('/api/state/next/welcome', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const uid = await userIdByTg(req.tg || req.tgUser?.id);
    if (!uid) return res.status(401).json({ ok: false, error: 'unauthorized' });

    const { isDoctor, onbDone } = await decideDoctorState(uid);

    if (isDoctor) {
      // врач: если онбординг не завершён → на онбординг; иначе → кабинет
      const page = onbDone
        ? '/dark/doctor-cabinet-mint-rose.html'
        : '/dark/doctor-onboarding-mint-rose.html';
      return res.json({ ok: true, role: 'doctor', page });
    }

    // пациент: смотрим согласие, профиль, план
    const u = await pool.query(
      `SELECT accepted_terms_at, weight_kg
         FROM derma.users
        WHERE id = $1`,
      [uid]
    );
    const consented  = Boolean(u.rows[0]?.accepted_terms_at);
    const hasProfile = Number(u.rows[0]?.weight_kg) > 0; // 0 = нет профиля      // профиль считаем заполненным, если есть вес
    const p = await pool.query(
      'SELECT 1 FROM derma.plans WHERE patient_id=$1',
      [uid]
    );
  const hasPlan    = Boolean(p.rows[0]);     

    const page = !consented ? '/dark/warnings.html'
               : !hasProfile ? '/dark/profile.html'
               : !hasPlan   ? '/dark/plan.html'
               :              '/dark/main.html';

    res.json({ ok: true, role: 'patient', page });
  } catch (e) {
    console.error('NEXT/WELCOME ERROR:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});


app.get('/api/db-test', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `select current_database() db, current_user usr, now() "now"`
    );
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});
// Проверка, каким ботом мы сейчас живём
app.get('/api/_bot', async (_, res) => {
  try {
    const me = await bot.getMe();
    res.json({ ok: true, username: me.username, id: me.id });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});
// ===== DEBUG: покажет, долетело ли initData, валиден ли хеш и куда подключена БД
app.get('/api/debug', async (req, res) => {
  try {
    const rawHeader = req.get('X-Telegram-InitData') || '';
    const rawQuery  = req.query.tgWebAppData || req.query.initData || '';
    let valid = false, user = null, err = null;

    try {
      const parsed = parseAndVerifyInitData(rawHeader || rawQuery);
      valid = !!parsed?.user?.id;
      user = parsed?.user || null;
    } catch (e) { err = String(e.message || e); }

    const { rows: [db] } = await pool.query(`SELECT current_database() AS db, current_user AS "user"`);
    const { rows: [sp] } = await pool.query(`SHOW search_path`);

    res.json({
      got_header: !!rawHeader,
      got_query:  !!rawQuery,
      valid,
      user,
      db,
      search_path: sp.search_path,
      error: err
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// публичный FAQ (без tgAuth)
app.get('/api/faq', async (_, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT slug, title, md_text, tags
        FROM derma.content
       WHERE published = true
       ORDER BY id`);
    res.json(rows);
  } catch (e) {
    console.error('FAQ ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// список всех объявленных маршрутов (исправлено, без .stack)
app.get('/api/_routes', (req, res) => {
  const routes = [];
  (app._router?.stack || []).forEach(l => {
    if (!l?.route) return;
    const methods = Object.keys(l.route.methods || {}).map(m => m.toUpperCase()).join('|') || 'GET';
    const paths   = Array.isArray(l.route.path) ? l.route.path : [l.route.path];
    paths.forEach(p => routes.push(`${methods} ${p}`));
  });
  res.json(routes.sort());
});

// ====== protected routes ======
app.get('/api/progress', tgAuth, async (req, res) => {
  try {
    await ensureUser(req);
    const uid = await userIdByTg(req.tg);
    if (!uid) return res.status(400).json({ error: 'missing tg (or user not found)' });

    const { rows } = await pool.query(`
      SELECT plan_id, patient_id, cum_mg, weight_kg, cum_mg_per_kg,
             target_min_cum_mg_per_kg, target_opt_cum_mg_per_kg, target_max_cum_mg_per_kg,
             progress_to_opt, daily_dose_mg, days_left_estimate
        FROM derma.v_patient_progress
       WHERE patient_id = $1`, [uid]);

    if (!rows.length) return res.status(404).json({ error: 'no active plan' });

    const row   = rows[0];
    const modeQ = String(req.query.mode || 'opt');
    const perKg = ({ min: 120, opt: 135, max: 150 })[modeQ] ?? 135;

    const w = Number(row.weight_kg) || 0;
    const taken_mg = Number(row.cum_mg) || 0;
    const target_mg = w > 0 ? Math.round(perKg * w) : 0;
    const percent   = target_mg > 0 ? (100 * taken_mg / target_mg) : 0;

    res.json({ ...row, mode: modeQ, target_mg, taken_mg, percent });
  } catch (e) {
    console.error('PROGRESS ERROR:', e);
    res.status(500).json({ error: e.message || 'server error' });
  }
});
// последние отметки (GET)
app.get('/api/dose', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    if (!uid) return res.status(400).json({ error: 'missing tg (or user not found)' });

    const limit = Math.min(Number(req.query.limit || 14), 90);
    const { rows } = await pool.query(
      `SELECT date, mg_taken
         FROM derma.dose_logs
        WHERE patient_id=$1
        ORDER BY date DESC
        LIMIT $2`,
      [uid, limit]
    );
    res.json(rows);
  } catch (e) {
    console.error('DOSE LIST ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// сохранить отметку (POST)
app.post('/api/dose', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    if (!uid) return res.status(400).json({ error: 'missing tg (or user not found)' });

    const mg = Number(req.body?.mg);
    if (!Number.isFinite(mg) || mg < 0) return res.status(400).json({ error: 'bad mg' });

    const d = req.body?.date || new Date().toISOString().slice(0,10);
    await pool.query(
      `INSERT INTO derma.dose_logs(patient_id,date,mg_taken)
       VALUES ($1,$2,$3)
       ON CONFLICT (patient_id,date) DO UPDATE SET mg_taken=EXCLUDED.mg_taken`,
      [uid, d, mg]
    );
    res.json({ ok: true, date: d, mg });
  } catch (e) {
    console.error('DOSE POST ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});


// === New endpoints for updated front ===

// Aliases for intakes (совместимость со старым фронтом)
app.get('/api/intakes', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    if (!uid) return res.status(400).json({ error: 'missing tg' });

    const limit = Math.min(Number(req.query.limit || 14), 90);
    const { rows } = await pool.query(
      `SELECT date, mg_taken AS mg
         FROM derma.dose_logs
        WHERE patient_id=$1
        ORDER BY date DESC
        LIMIT $2`,
      [uid, limit]
    );
    res.json(rows);
  } catch (e) {
    console.error('INTAKES LIST ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// Безопасная вставка (принимаем date = 'YYYY-MM-DD' или iso; upsert по дате)
app.post('/api/intakes', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    if (!uid) return res.status(401).json({ error: 'unauthorized' });

    const mg = Number(req.body?.mg);
    if (!Number.isFinite(mg) || mg <= 0) return res.status(400).json({ error: 'mg>0 required' });

    // поддерживаем и {date:'YYYY-MM-DD'}, и {iso:'...'}
    let d = String(req.body?.date || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) {
      // если прилетело iso, приведём к 'YYYY-MM-DD'
      const iso = String(req.body?.iso || '');
      const dt = new Date(iso || Date.now());
      d = isNaN(dt.getTime()) ? new Date().toISOString().slice(0,10) : dt.toISOString().slice(0,10);
    }

    await pool.query(
      `INSERT INTO derma.dose_logs (patient_id, date, mg_taken)
       VALUES ($1,$2,$3)
       ON CONFLICT (patient_id, date) DO UPDATE
         SET mg_taken = EXCLUDED.mg_taken`,
      [uid, d, mg]
    );

    res.json({ ok: true, date: d, mg });
  } catch (e) {
    console.error('INTAKES POST ERROR:', e);
    res.status(500).json({ error: e.message || 'INTAKES_INSERT_FAILED' });
  }
});

// Persist user's selected dose mode (optional)
app.post('/api/dose-mode', tgAuth, async (req, res) => {
  try {
    const uid  = await userIdByTg(req.tg);
    const mode = (req.body?.mode || 'opt');
    if (!['min','opt','max'].includes(mode)) return res.status(400).json({ error:'bad mode' });

    let persisted = false;
    try {
      await pool.query('UPDATE derma.users SET dose_mode = $2 WHERE id = $1', [uid, mode]);
      persisted = true;
    } catch (_) { /* column may not exist - fine */ }

    res.json({ ok: true, persisted });
  } catch (e) {
    console.error('DOSE-MODE ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// Reset only intakes and progress-related settings (keep profile)
app.post('/api/reset', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    if (!uid) return res.status(400).json({ error: 'missing tg' });

    const del = await pool.query('DELETE FROM derma.dose_logs WHERE patient_id=$1', [uid]);

    // Also try to wipe reminder-related rows if such table(s) exist.
    let removedRem = 0;
    try {
      const r1 = await pool.query('DELETE FROM derma.reminders WHERE patient_id=$1', [uid]);
      removedRem += r1.rowCount || 0;
    } catch(_){ /* table may not exist - ignore */ }
    try {
      const r2 = await pool.query('DELETE FROM derma.reminders_local WHERE patient_id=$1', [uid]);
      removedRem += r2.rowCount || 0;
    } catch(_){ /* table may not exist - ignore */ }

    res.json({ ok: true, removed: del.rowCount, removed_reminders: removedRem });
  } catch (e) {
    console.error('RESET ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// === /New endpoints ===
// GET /api/me
app.get('/api/me', tgAuth, async (req, res) => {
  try {
    // УЖЕ аутентифицированы и ensureUser ВЫЗВАН в tgAuth → тут только читаем
    const uid = await userIdByTg(req.tg || req.tgUser?.id);
    if (!uid) return res.status(401).json({ error: 'unauthorized' });

    const { rows } = await pool.query(
      `select id, tg_id, full_name, sex, birth_date, weight_kg, height_cm, tz,
              accepted_terms_at, allergies, terms_version, is_doctor
         from derma.users
        where id = $1`,
      [uid]
    );
    const me = rows[0] || {};
    me.fresh_user = !!req.isFreshUser;   // ← значение, выставленное в tgAuth при первой вставке
    return res.json(me);
  } catch (e) {
    console.error('ME GET ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/me
app.post('/api/me', tgAuth, async (req, res) => {
  try {
    // Никаких повторных ensureUser — берём текущего пользователя из tg
    const uid = await userIdByTg(req.tg || req.tgUser?.id);
    if (!uid) return res.status(401).json({ error: 'unauthorized' });

    const { weight_kg, height_cm, sex, birth_date, full_name, tz, accepted, allergies, terms_version } = req.body || {};

    await pool.query(
      `update derma.users set
         weight_kg = coalesce($1, weight_kg),
         height_cm = coalesce($2, height_cm),
         sex       = coalesce($3, sex),
         birth_date= coalesce($4, birth_date),
         full_name = coalesce($5, full_name),
         tz        = coalesce($6, tz),
         accepted_terms_at = case when $7::boolean is true
                                  then coalesce(accepted_terms_at, now())
                                  else accepted_terms_at end,
         allergies = coalesce($8::text[], allergies),
         terms_version = greatest(coalesce($9::int, terms_version), terms_version),
         updated_at= now()
       where id = $10`,
      [weight_kg, height_cm, sex, birth_date, full_name, tz, accepted, allergies, terms_version, uid]
    );

    const { rows } = await pool.query(
      `select id, tg_id, full_name, sex, birth_date, weight_kg, height_cm, tz,
              accepted_terms_at, allergies, terms_version
         from derma.users
        where id = $1`,
      [uid]
    );

    const me = rows[0] || {};
    me.fresh_user = !!req.isFreshUser;
    return res.json(me);
  } catch (e) {
    console.error('ME POST ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});
// ===== DOCTOR: code + attach API =====
app.post('/api/doctor/code', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const uid = await userIdByTg(req.tg || req.tgUser?.id);
    if (!uid) return res.status(401).json({ error: 'unauthorized' });

    const { profile = {}, code: passedCode, settings = {} } = req.body || {};
    // нормализуем код
    let code = String(passedCode || '')
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, '')
      .slice(0, 5);

    // если кода нет — сгенерим
    if (!/^[A-Z0-9]{5}$/.test(code)) {
      const ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      code = Array.from({ length: 5 }, () => ABC[Math.floor(Math.random() * ABC.length)]).join('');
    }

    await pool.query('BEGIN');

    // 1) снимаем активность со старого кода врача
    await pool.query(
      'UPDATE doctor_codes SET active=false, revoked_at=now() WHERE doctor_id=$1 AND active',
      [uid]
    );

    // 2) если этот код активен у КОГО-ТО — конфликт 409
    const clash = await pool.query('SELECT 1 FROM doctor_codes WHERE code=$1 AND active', [code]);
    if (clash.rowCount) {
      await pool.query('ROLLBACK');
      return res.status(409).json({ error: 'code already taken' });
    }

    // 3) активируем новый
    await pool.query(
      'INSERT INTO doctor_codes(doctor_id, code, active) VALUES ($1,$2,true)',
      [uid, code]
    );

    // 4) апсерт профиля
    const prof = {
      specialty:   profile.specialty ?? null,
      city:        profile.city ?? null,
      clinic:      profile.clinic ?? null,
      tg:          (profile.tg ?? profile.tg_handle ?? null)?.replace(/^@/,'') || null,
      contact:     profile.contact ?? profile.contact_text ?? null,
      avatar_url:  profile.avatarUrl ?? profile.avatar_url ?? null,
      accepting:   settings.accepting === true,
      auto_accept: settings.autoAccept === true,
    };

    await pool.query(`
      INSERT INTO doctor_profiles
        (user_id, specialty, city, clinic, tg_handle, contact_text, avatar_url, accepting, auto_accept)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT (user_id) DO UPDATE SET
        specialty    = COALESCE(EXCLUDED.specialty,    doctor_profiles.specialty),
        city         = COALESCE(EXCLUDED.city,         doctor_profiles.city),
        clinic       = COALESCE(EXCLUDED.clinic,       doctor_profiles.clinic),
        tg_handle    = COALESCE(EXCLUDED.tg_handle,    doctor_profiles.tg_handle),
        contact_text = COALESCE(EXCLUDED.contact_text, doctor_profiles.contact_text),
        avatar_url   = COALESCE(EXCLUDED.avatar_url,   doctor_profiles.avatar_url),
        accepting    = EXCLUDED.accepting,
        auto_accept  = EXCLUDED.auto_accept,
        updated_at   = now()
    `, [uid, prof.specialty, prof.city, prof.clinic, prof.tg, prof.contact, prof.avatar_url, prof.accepting, prof.auto_accept]);

    // 5) помечаем, что это врач + сохраняем ФИО
    await pool.query('UPDATE users SET is_doctor=true WHERE id=$1', [uid]);
    if (profile.name) {
      await pool.query('UPDATE users SET full_name=$2 WHERE id=$1', [uid, String(profile.name).slice(0,180)]);
    }

    await pool.query('COMMIT');
    res.json({ ok: true, code });
  } catch (e) {
    try { await pool.query('ROLLBACK'); } catch(_) {}
    console.error('DOCTOR CODE ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/doctor/me', tgAuth, async (req, res) => {
  try{
    await pool.query('SET search_path = derma, public');
    const uid = await userIdByTg(req.tg || req.tgUser?.id);

    const u  = await pool.query('SELECT is_doctor, full_name FROM derma.users WHERE id=$1',[uid]);
    const dc = await pool.query('SELECT code FROM derma.doctor_codes WHERE doctor_id=$1 AND active',[uid]);
    const dp = await pool.query(`
      SELECT specialty, city, clinic, tg_handle, contact_text, avatar_url, accepting, auto_accept
        FROM derma.doctor_profiles WHERE user_id=$1`, [uid]);

    const profRow = dp.rows[0] || {};
    const profile = {
      name:       u.rows?.[0]?.full_name || null,
      specialty:  profRow.specialty ?? null,
      clinic:     profRow.clinic ?? null,
      city:       profRow.city ?? null,
      tg:         profRow.tg_handle ?? null,
      contact:    profRow.contact_text ?? null,
      avatar_url: profRow.avatar_url ?? null,
      accepting:  profRow.accepting ?? null,
      auto_accept:profRow.auto_accept ?? null,
    };

    res.json({
      is_doctor: !!u.rows?.[0]?.is_doctor,
      code:      dc.rows?.[0]?.code || null,
      profile
    });
  }catch(e){
    console.error('DOCTOR ME ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});


app.get('/api/doctor/validate', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const code = String(req.query.code || '').toUpperCase();
    if (!/^[A-Z0-9]{5}$/.test(code)) return res.status(400).json({ error: 'bad code' });

    const { rows } = await pool.query(`
      SELECT u.id AS doctor_id,
       COALESCE(u.full_name,'Врач') AS name,
       dp.clinic, dp.city,
       COALESCE(
         dp.avatar_url,
         NULLIF(u.tg_photo_url,''),
         CASE WHEN NULLIF(u.tg_username,'') IS NOT NULL
              THEN 'https://unavatar.io/telegram/' || u.tg_username
              ELSE NULL
         END
       ) AS avatar_url
        FROM derma.doctor_codes dc
        JOIN derma.users u ON u.id = dc.doctor_id
        LEFT JOIN derma.doctor_profiles dp ON dp.user_id = u.id
       WHERE dc.code = $1 AND dc.active`, [code]);

    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true, doctor: rows[0], code });
  } catch (e) {
    console.error('DOCTOR VALIDATE ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// === PATIENTS LIST (active attachments only) ===
app.get('/api/doctor/patients', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const did = await userIdByTg(req.tg || req.tgUser?.id);

    // активные связи (unbound_at IS NULL); берём самую свежую по bound_at
    const base = await pool.query(`
      SELECT DISTINCT ON (p.id)
             p.id AS patient_id,
             COALESCE(NULLIF(p.full_name,''), NULLIF(p.tg_username,''), 'Пациент') AS patient_name,
             p.weight_kg,
             p.sex,
             p.photo_url,
             pd.bound_at
        FROM patient_doctors pd
        JOIN users p ON p.id = pd.patient_id
       WHERE pd.doctor_id = $1
         AND pd.unbound_at IS NULL
       ORDER BY p.id, pd.bound_at DESC
    `, [did]);

    if (!base.rowCount) return res.json([]);

    const ids = base.rows.map(r => r.patient_id);

    // дозировки: среднее за 7 дней и кумулятив
    const doses = await pool.query(`
      SELECT patient_id,
             AVG(CASE WHEN date >= CURRENT_DATE - INTERVAL '6 day'
                      THEN mg_taken END)::numeric AS avg7,
             SUM(mg_taken)::numeric AS total_mg
        FROM dose_logs
       WHERE patient_id = ANY($1)
       GROUP BY patient_id
    `, [ids]);
    const doseMap = new Map(doses.rows.map(r => [r.patient_id, r]));

    // последние анализы ALT/AST/TG/CHOL
    const labs = await pool.query(`
      WITH latest AS (
        SELECT DISTINCT ON (lr.patient_id, lt.code)
               lr.patient_id AS user_id,
               lt.code       AS lab_code,
               lr.value_num  AS value,
               lr.units_txt  AS unit,
               lr.date       AS measured_at,
               lr.status     AS status
          FROM lab_results lr
          JOIN lab_types   lt ON lt.id = lr.lab_type_id
         WHERE lr.patient_id = ANY($1)
           AND lt.code IN ('ALT','AST','TG','CHOL')
         ORDER BY lr.patient_id, lt.code, lr.date DESC, lr.id DESC
      )
      SELECT user_id,
             jsonb_object_agg(
               lab_code,
               jsonb_build_object(
                 'value', value,
                 'unit',  unit,
                 'date',  to_char(measured_at,'YYYY-MM-DD'),
                 'status', COALESCE(status,'g')
               )
             ) AS labs
        FROM latest
       GROUP BY user_id
    `, [ids]);
    const labsMap = new Map(labs.rows.map(r => [r.user_id, r.labs]));

    // сборка под фронт (нужен progress_pct)
    const out = base.rows.map(r => {
      const d = doseMap.get(r.patient_id) || {};
      const w = Number(r.weight_kg) || 0;
      const goal = w * 135; // дефолтная цель
      const total = Number(d.total_mg || 0);
      const progress_pct = goal > 0 ? Math.min(100, Math.round(total / goal * 100)) : 0;

      return {
        patient_id:   r.patient_id,
        patient_name: r.patient_name,
        weight_kg:    r.weight_kg,
        sex:          r.sex,
        photo_url:    r.photo_url,
        avg7:         Number(d.avg7 || 0),
        total_mg:     total,
        progress_pct,
        // last_report — можно взять max(date) из dose_logs, если нужно:
        last_report:  null,
        labs:         labsMap.get(r.patient_id) || {}
      };
    });

    res.json(out);
  } catch (e) {
    console.error('DOCTOR PATIENTS ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});



// ВРАЧ: дневной срез по пациенту
// GET /api/doctor/patient/:pid/day?date=YYYY-MM-DD
app.get('/api/doctor/patient/:pid/day', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');

    const did  = await userIdByTg(req.tg || req.tgUser?.id);
    const pid  = Number(req.params.pid);
    const ds   = (req.query.date || new Date().toISOString().slice(0,10));

    // доступ врача к пациенту
    const ok = await pool.query(
      `select 1 from patient_doctors
        where doctor_id=$1 and patient_id=$2 and unbound_at is null`,
      [did, pid]
    );
    if (!ok.rowCount) return res.status(403).json({ error:'forbidden' });

    // параллельные запросы под твою схему
    const [pat, diary, dose, photos, prog] = await Promise.all([
      pool.query(`
        select u.id,
               coalesce(nullif(u.full_name,''), nullif(u.tg_username,''), 'Пациент') as name,
               coalesce(nullif(u.photo_url,''), nullif(u.tg_photo_url,''))           as avatar_url,
               u.weight_kg, u.sex,
               p.start_date
          from derma.users u
          left join derma.plans p on p.patient_id = u.id
         where u.id = $1
         limit 1`, [pid]),

      pool.query(`
        select
          feeling_score              as mood,
          side_effects               as side_effects,
          comment                    as note
        from derma.diary
        where patient_id=$1 and at_date=$2::date
        order by id desc
        limit 1`, [pid, ds]).catch(()=>({rows:[]})),

      pool.query(`
        select coalesce(sum(mg_taken),0)::numeric as mg
          from derma.dose_logs
         where patient_id=$1 and date=$2::date`, [pid, ds]).catch(()=>({rows:[{mg:0}]})),

      pool.query(`
        select id, url,
               coalesce(meta->>'kind','face') as kind,
               at_date                         as taken_at
          from derma.photos
         where patient_id=$1 and at_date=$2::date
         order by id desc`, [pid, ds]).catch(()=>({rows:[]})),

      pool.query(`
        select daily_dose_mg, cum_mg, weight_kg,
               target_opt_cum_mg_per_kg as target_mg_per_kg
          from derma.v_patient_progress
         where patient_id=$1
         limit 1`, [pid]).catch(()=>({rows:[]}))
    ]);

    const p = pat.rows?.[0] || {};
    const pr = prog.rows?.[0] || {};

    res.json({
      date: ds,
      patient: {
        id: p.id, name: p.name, avatar_url: p.avatar_url,
        weight_kg: p.weight_kg, sex: p.sex
      },
      course: { start_date: p.start_date || null },
      dose: {
        current_mg: Number(dose.rows?.[0]?.mg || 0),
        plan_mg: Number(pr.daily_dose_mg || 0),
        cumulative_mg: Number(pr.cum_mg || 0),
        weight_kg: Number(pr.weight_kg || p.weight_kg || 0),
        target_mg_per_kg: Number(pr.target_mg_per_kg || 135)
      },
      diary: diary.rows?.[0] || null,
      photos: photos.rows.map(r => ({ id:r.id, url:r.url, kind:r.kind, taken_at:r.taken_at }))
    });
  } catch (e) {
    console.error('DOCTOR DAY SNAPSHOT ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});


// ВРАЧ: пагинация по дням (лента)
/// GET /api/doctor/patient/:pid/timeline?start=YYYY-MM-DD&days=14
app.get('/api/doctor/patient/:pid/timeline', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const did  = await userIdByTg(req.tg || req.tgUser?.id);
    const pid  = Number(req.params.pid);
    const days = Math.min(Math.max(parseInt(req.query.days||'14',10), 1), 60);
    const start = req.query.start ? new Date(req.query.start) : new Date();
    const end = new Date(start); end.setDate(end.getDate() - (days-1));
    const s0 = end.toISOString().slice(0,10);
    const s1 = start.toISOString().slice(0,10);

    const ok = await pool.query(
      `select 1 from patient_doctors where doctor_id=$1 and patient_id=$2 and unbound_at is null`,
      [did, pid]
    );
    if (!ok.rowCount) return res.status(403).json({ error:'forbidden' });

    // generate_series по дням и влеваем туда наличие записей/фото
    const q = await pool.query(`
      with d as (
        select generate_series($2::date, $3::date, interval '1 day')::date as day
      ),
      diary as (
        select at_date::date as day, 1 as has_diary
          from derma.diary
         where patient_id=$1 and at_date between $2::date and $3::date
         group by 1
      ),
      shot as (
        select at_date::date as day, count(*) as photos
          from derma.photos
         where patient_id=$1
           and at_date between $2::date and $3::date
           and coalesce(meta->>'kind','face') in ('face','body')
         group by 1
      ),
      dose as (
        select date as day, coalesce(sum(mg_taken),0)::numeric as mg
          from dose_logs
         where patient_id=$1 and date between $2::date and $3::date
         group by 1
      )
      select d.day,
             coalesce(dose.mg,0)::numeric     as dose_mg,
             coalesce(shot.photos,0)::int     as photos_count,
             coalesce(diary.has_diary,0)::int as has_diary
        from d
        left join dose  on dose.day  = d.day
        left join shot  on shot.day  = d.day
        left join diary on diary.day = d.day
       order by d.day desc
    `, [pid, s0, s1]).catch(()=>({ rows:[] }));

    res.json(q.rows);
  } catch (e) {
    console.error('DOCTOR TIMELINE ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});
app.post('/api/doctor/attach', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const pid  = await userIdByTg(req.tg || req.tgUser?.id);
    const code = String(req.body?.code || '').toUpperCase();
    if (!/^[A-Z0-9]{5}$/.test(code)) return res.status(400).json({ error: 'bad code' });

    const r = await pool.query('SELECT doctor_id FROM derma.doctor_codes WHERE code=$1 AND active', [code]);
    if (!r.rowCount) return res.status(404).json({ error: 'code not found' });

    const did = r.rows[0].doctor_id;
    await pool.query('UPDATE derma.patient_doctors SET unbound_at=now() WHERE patient_id=$1 AND unbound_at IS NULL', [pid]);
    await pool.query(`
  INSERT INTO derma.patient_doctors (patient_id, doctor_id, status, bound_at, unbound_at)
  VALUES ($1,$2,'accepted', now(), NULL)
  ON CONFLICT (patient_id, doctor_id)
  DO UPDATE SET
    status='accepted',
    bound_at = COALESCE(patient_doctors.bound_at, EXCLUDED.bound_at),
    unbound_at = NULL
`, [pid, did]);

    const { rows } = await pool.query(`
      SELECT u.id AS doctor_id,
       COALESCE(u.full_name,'Врач') AS name,
       dp.clinic, dp.city,
       COALESCE(
         dp.avatar_url,
         NULLIF(u.tg_photo_url,''),
         CASE WHEN NULLIF(u.tg_username,'') IS NOT NULL
              THEN 'https://unavatar.io/telegram/' || u.tg_username
              ELSE NULL
         END
       ) AS avatar_url
        FROM derma.users u
        LEFT JOIN derma.doctor_profiles dp ON dp.user_id=u.id
       WHERE u.id=$1`, [did]);

    res.json({ ok: true, code, doctor: rows[0] });
  } catch (e) {
    console.error('DOCTOR ATTACH ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/doctor/attached', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const pid = await userIdByTg(req.tg || req.tgUser?.id);

    const { rows } = await pool.query(`
      SELECT u.id AS doctor_id,
       COALESCE(u.full_name,'Врач') AS name,
       dp.clinic, dp.city,
       COALESCE(
         dp.avatar_url,
         NULLIF(u.tg_photo_url,''),
         CASE WHEN NULLIF(u.tg_username,'') IS NOT NULL
              THEN 'https://unavatar.io/telegram/' || u.tg_username
              ELSE NULL
         END
       ) AS avatar_url
        FROM derma.patient_doctors pd
        JOIN derma.users u ON u.id = pd.doctor_id
        LEFT JOIN derma.doctor_profiles dp ON dp.user_id = u.id
        LEFT JOIN derma.doctor_codes dc ON dc.doctor_id = u.id AND dc.active
       WHERE pd.patient_id=$1 AND pd.unbound_at IS NULL
       LIMIT 1`, [pid]);

    if (!rows.length) return res.json(null);
    res.json({ ok: true, code: rows[0].code || null, doctor: rows[0] });
  } catch (e) {
    console.error('DOCTOR ATTACHED ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});
// ===== DOCTOR REQUESTS FLOW =====
// Пациент создаёт заявку по коду врача
app.post('/api/doctor/request', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const pid  = await userIdByTg(req.tg || req.tgUser?.id);
    const code = String(req.body?.code || '').toUpperCase();
    if (!/^[A-Z0-9]{5}$/.test(code)) return res.status(400).json({ error:'bad code' });

    // Находим врача по коду
    const rCode = await pool.query(`
      SELECT u.id AS doctor_id,
       COALESCE(u.full_name,'Врач') AS name,
       dp.clinic, dp.city,
       COALESCE(
         dp.avatar_url,
         NULLIF(u.tg_photo_url,''),
         CASE WHEN NULLIF(u.tg_username,'') IS NOT NULL
              THEN 'https://unavatar.io/telegram/' || u.tg_username
              ELSE NULL
         END
       ) AS avatar_url
        FROM derma.doctor_codes dc
        JOIN derma.users u ON u.id = dc.doctor_id
        LEFT JOIN derma.doctor_profiles dp ON dp.user_id = u.id
       WHERE dc.code=$1 AND dc.active`, [code]);

    if (!rCode.rowCount) return res.status(404).json({ error:'code not found' });

    const doc = rCode.rows[0];
    const did = doc.doctor_id;

    // Одна «pending» заявка на пациента
    const rPending = await pool.query(
      `SELECT id, status FROM derma.doctor_requests
        WHERE patient_id=$1 AND status='pending'`,
      [pid]
    );
    if (!rPending.rowCount) {
      await pool.query(
        `INSERT INTO derma.doctor_requests(patient_id, doctor_id, status)
         VALUES ($1,$2,'pending')`, [pid, did]
      );
    } else {
      // если уже была «pending» на другого врача — можно отменить или перекинуть, но для простоты просто сообщим
      const old = rPending.rows[0];
      if (old && did) {
        await pool.query(`UPDATE derma.doctor_requests SET doctor_id=$2 WHERE id=$1`, [old.id, did]);
      }
    }

    // Автопринятие?
    // Автопринятие
if (doc.auto_accept) {
  await pool.query('BEGIN');

  // (на всякий случай) пометить возможную pending-заявку принятой
  await pool.query(
    `update doctor_requests
        set status='accepted', decided_at=now()
      where patient_id=$1 and doctor_id=$2 and status='pending'`,
    [pid, did]
  );

  await pool.query(`update patient_doctors
                       set unbound_at=now()
                     where patient_id=$1 and unbound_at is null`,
    [pid]);

  await pool.query(`
    insert into patient_doctors (patient_id, doctor_id, status, bound_at, unbound_at)
    values ($1,$2,'accepted', now(), null)
    on conflict (patient_id, doctor_id)
    do update set
      status='accepted',
      bound_at = coalesce(patient_doctors.bound_at, excluded.bound_at),
      unbound_at = null
  `, [pid, did]);

  await pool.query('COMMIT');
  return res.json({ ok:true, auto:true, status:'accepted' });
}

    // Иначе — «ожидание»
    return res.status(202).json({
      ok: true,
      status: 'pending',
      doctor: { id: did, name: doc.name, clinic: doc.clinic, city: doc.city, avatar_url: doc.avatar_url }
    });
  } catch (e) {
    try { await pool.query('ROLLBACK'); } catch(_) {}
    console.error('DOCTOR REQUEST POST ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// Пациент получает статус своей заявки
app.get('/api/doctor/request', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const pid = await userIdByTg(req.tg || req.tgUser?.id);

    // 1) есть принятый врач?
    const acc = await pool.query(`
      SELECT u.id AS doctor_id, COALESCE(u.full_name,'Врач') AS name,
             dp.clinic, dp.city, dp.avatar_url
        FROM derma.patient_doctors pd
        JOIN derma.users u ON u.id=pd.doctor_id
        LEFT JOIN derma.doctor_profiles dp ON dp.user_id=u.id
       WHERE pd.patient_id=$1 AND pd.unbound_at IS NULL
       LIMIT 1`, [pid]);
    if (acc.rowCount) {
      const d = acc.rows[0];
      return res.json({ ok:true, status:'accepted',
        doctor:{ id:d.doctor_id, name:d.name, clinic:d.clinic, city:d.city, avatar_url:d.avatar_url }});
    }

    // 2) иначе проверяем «pending»
    const pend = await pool.query(`
      SELECT dr.id, dr.status, u.id AS doctor_id, COALESCE(u.full_name,'Врач') AS name,
             dp.clinic, dp.city, dp.avatar_url
        FROM derma.doctor_requests dr
        JOIN derma.users u ON u.id=dr.doctor_id
        LEFT JOIN derma.doctor_profiles dp ON dp.user_id=u.id
       WHERE dr.patient_id=$1
       ORDER BY dr.created_at DESC
       LIMIT 1`, [pid]);

    if (!pend.rowCount) return res.json({ ok:true, status:'none' });

    const r = pend.rows[0];
    return res.json({ ok:true, status:r.status,
      doctor:{ id:r.doctor_id, name:r.name, clinic:r.clinic, city:r.city, avatar_url:r.avatar_url },
      request_id: r.id
    });
  } catch (e) {
    console.error('DOCTOR REQUEST GET ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// Отмена пациентом «pending»-заявки
app.delete('/api/doctor/request', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const pid = await userIdByTg(req.tg || req.tgUser?.id);
    await pool.query(
      `UPDATE derma.doctor_requests
          SET status='cancelled', decided_at=now()
        WHERE patient_id=$1 AND status='pending'`, [pid]
    );
    res.json({ ok:true });
  } catch (e) {
    console.error('DOCTOR REQUEST DELETE ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// === REQUESTS LIST (pending) ===
app.get('/api/doctor/requests', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const did = await userIdByTg(req.tg || req.tgUser?.id);

    const { rows } = await pool.query(
      `SELECT dr.id,
              dr.created_at,
              p.id AS patient_id,
              COALESCE(NULLIF(p.full_name,''), NULLIF(p.tg_username,''), 'Пациент') AS patient_name
         FROM doctor_requests dr
         JOIN users p ON p.id = dr.patient_id
        WHERE dr.doctor_id = $1
          AND dr.status = 'pending'
        ORDER BY dr.created_at ASC`,
      [did]
    );
    res.json(rows);
  } catch (e) {
    console.error('DOCTOR REQUESTS LIST ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// === ACCEPT REQUEST ===
app.post('/api/doctor/requests/:id/accept', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');

    const did = await userIdByTg(req.tg || req.tgUser?.id);
    const id  = Number(req.params.id);

    await pool.query('BEGIN');

    // помечаем заявку принятой и берём пациента
    const r = await pool.query(
      `UPDATE doctor_requests
          SET status='accepted', decided_at = now()
        WHERE id=$1 AND doctor_id=$2 AND status='pending'
        RETURNING patient_id`,
      [id, did]
    );
    if (!r.rowCount) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'not found or already decided' });
    }
    const pid = r.rows[0].patient_id;

    // закрываем предыдущую активную связь (если была)
    await pool.query(
      `UPDATE patient_doctors
          SET unbound_at = now()
        WHERE patient_id = $1 AND unbound_at IS NULL`,
      [pid]
    );

    // создаём новую активную связь (PK (patient_id,bound_at), активность = unbound_at IS NULL)
    await pool.query(
      `INSERT INTO patient_doctors (patient_id, doctor_id, bound_at, unbound_at)
       VALUES ($1, $2, now(), NULL)`,
      [pid, did]
    );

    await pool.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    try { await pool.query('ROLLBACK'); } catch(_) {}
    console.error('DOCTOR REQUEST ACCEPT ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// Отклонить заявку (врач)
app.post('/api/doctor/requests/:id/reject', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const did = await userIdByTg(req.tg || req.tgUser?.id);
    const id  = Number(req.params.id);

    const r = await pool.query(
      `UPDATE derma.doctor_requests
          SET status='rejected', decided_at=now()
        WHERE id=$1 AND doctor_id=$2 AND status='pending'`,
      [id, did]
    );
    if (!r.rowCount) return res.status(404).json({ error:'not found' });

    res.json({ ok:true });
  } catch (e) {
    console.error('DOCTOR REQUEST REJECT ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});


app.delete('/api/doctor/attach', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const pid = await userIdByTg(req.tg || req.tgUser?.id);
    await pool.query('UPDATE derma.patient_doctors SET unbound_at=now() WHERE patient_id=$1 AND unbound_at IS NULL', [pid]);
    res.json({ ok: true });
  } catch (e) {
    console.error('DOCTOR DETACH ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});



// план курса
app.get('/api/plan', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    const r = await pool.query(
      'SELECT patient_id, drug, capsule_mg, start_date FROM derma.plans WHERE patient_id=$1',
      [uid]
    );
    res.json(r.rows[0] || null);
  } catch (e) { console.error('PLAN GET ERROR:', e); res.status(500).json({ error: e.message }); }
});

// === PLAN: SAVE ===
app.post('/api/plan', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');

    const { drug, capsule_mg, start_date } = req.body || {};
    // drug обязателен; допускаем roaccutane/aknekutan/other
    if (!['roaccutane','aknekutan','other'].includes(drug || '')) {
      return res.status(400).json({ error:'bad drug' });
    }

    // capsule_mg теперь опционален
    let cap = null;
    if (capsule_mg !== undefined && capsule_mg !== null && String(capsule_mg) !== '') {
      cap = Number(capsule_mg);
      const allowed = drug === 'roaccutane' ? [10,20]
                    : drug === 'aknekutan'  ? [8,16]
                    : [];
      if (allowed.length && !allowed.includes(cap)) {
        return res.status(400).json({ error:'bad capsule_mg' });
      }
    }

    const patientId = await userIdByTg(req.tg || req.tgUser?.id);
    if (!patientId) return res.status(400).json({ error:'no user' });

    // ⬇️ ВАЖНО: используем patient_id (НЕ user_id) и не требуем created_at/updated_at
    const sql = `
      INSERT INTO derma.plans (patient_id, drug, capsule_mg, start_date)
      VALUES ($1,$2,$3,$4)
      ON CONFLICT (patient_id) DO UPDATE
        SET drug        = EXCLUDED.drug,
            capsule_mg  = EXCLUDED.capsule_mg,
            start_date  = EXCLUDED.start_date
      RETURNING patient_id, drug, capsule_mg, start_date
    `;
    const { rows } = await pool.query(sql, [patientId, drug, cap, start_date || null]);
    return res.json(rows[0]);
  } catch (e) {
    console.error('PLAN POST ERROR:', e);
    return res.status(500).json({ error:'server' });
  }
});



// анализы
function labStatus(code, value, sex = 'O') {
  if (value == null || Number.isNaN(+value)) return 'pending';
  const v = +value;
  switch (code) {
    case 'ALT': return v <= (sex === 'M' ? 40 : 31) ? 'ok' : 'attention';
    case 'AST': return v <= (sex === 'M' ? 40 : 31) ? 'ok' : 'attention';
    case 'TG':  return v < 1.7 ? 'ok' : 'attention';
    case 'HCG': return 'pending';
    default:    return 'pending';
  }
}

app.get('/api/labs', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    const { rows } = await pool.query(
      `SELECT lr.id, lt.code, lt.name, lr.date, lr.value_num, lr.units_txt, lr.status
         FROM derma.lab_results lr
         JOIN derma.lab_types lt ON lt.id = lr.lab_type_id
        WHERE lr.patient_id = $1
        ORDER BY lr.date DESC, lr.id DESC
        LIMIT 50`,
      [uid]
    );
    res.json(rows);
  } catch (e) { console.error('LABS GET ERROR:', e); res.status(500).json({ error: e.message }); }
});
// === GET дневника (гидратация)
app.get('/api/diary/day', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const uid = await userIdByTg(req.tg || req.tgUser?.id);
    if (!uid) return res.status(401).json({ error: 'unauthorized' });

    const ds = String(req.query.date || new Date().toISOString().slice(0,10)).slice(0,10);

    const { rows } = await pool.query(`
      select at_date::date as date, feeling_score, side_effects, comment
        from diary
       where patient_id=$1 and at_date=$2::date
       order by id desc
       limit 1`, [uid, ds]);

    const photos = await pool.query(`
      select id, url, coalesce(meta->>'kind','face') as kind, at_date
        from photos
       where patient_id=$1 and at_date=$2::date
       order by id desc
    `, [uid, ds]);

    res.json({ date: ds, diary: rows[0] || null, photos: photos.rows });
  } catch (e) {
    console.error('DIARY GET ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// === UPSERT дневника
app.post('/api/diary/day', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tgUser?.id || req.tg);
    if (!uid) return res.status(401).json({ error: 'unauthorized' });

    const dateISO  = String(req.body?.date || '').slice(0, 10);
    const score    = Number(req.body?.feeling_score || 0);
    const effects  = req.body?.side_effects || {};
    const comment  = String(req.body?.comment || '');

    await pool.query('SET search_path = derma, public');

    const sql = `
      WITH upd AS (
        UPDATE diary
           SET feeling_score = $3,
               side_effects  = COALESCE($4::jsonb, '{}'::jsonb),
               comment       = $5
         WHERE patient_id = $1 AND at_date = $2::date
         RETURNING id
      )
      INSERT INTO diary (patient_id, at_date, feeling_score, side_effects, comment)
      SELECT $1, $2::date, $3, COALESCE($4::jsonb, '{}'::jsonb), $5
      WHERE NOT EXISTS (SELECT 1 FROM upd)
      RETURNING id;
    `;
    await pool.query(sql, [uid, dateISO, score, effects, comment]);
    res.json({ ok: true });
  } catch (err) {
    console.error('DIARY UPSERT ERROR', err);
    res.status(500).json({ error: 'server_error', details: String(err.message || err) });
  }
});


// === UPSERT фото дня (по patient_id + date + kind)
app.post('/api/diary/photo', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg || req.tgUser?.id);
    if (!uid) return res.status(401).json({ error:'unauthorized' });

    const ds   = String(req.body?.date || new Date().toISOString().slice(0,10)).slice(0,10);
    let kind   = String(req.body?.kind || 'face').toLowerCase();
    if (!['face','body'].includes(kind)) kind = 'face';

    const url  = String(req.body?.data_url || req.body?.url || '').trim();
    if (!url) return res.status(400).json({ error: 'url_or_data_url_required' });

    const meta = (req.body?.meta && typeof req.body.meta === 'object') ? req.body.meta : {};
    meta.kind  = kind;

    const { rows } = await pool.query(
      `INSERT INTO derma.photos (patient_id, at_date, kind, url, meta)
       VALUES ($1, $2::date, $3, $4, $5::jsonb)
       ON CONFLICT (patient_id, at_date, kind)
       DO UPDATE SET url  = EXCLUDED.url,
                     meta = EXCLUDED.meta
       RETURNING id`,
      [uid, ds, kind, url, meta]
    );

    res.json({ ok: true, id: rows[0]?.id, date: ds, kind });
  } catch (e) {
    console.error('PHOTO UPSERT ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});



app.post('/api/labs', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    const { code, date, value_num, units_txt } = req.body || {};
    if (!code || !date) return res.status(400).json({ error: 'code and date required' });

    const lt = await pool.query('SELECT id FROM derma.lab_types WHERE code = $1', [code]);
    if (!lt.rowCount) return res.status(400).json({ error: 'unknown lab code' });

    const u = await pool.query('SELECT sex FROM derma.users WHERE id=$1', [uid]);
    const sex = u.rows[0]?.sex || 'O';
    const status = labStatus(code, Number(value_num), sex);

    const ins = await pool.query(
      `INSERT INTO derma.lab_results (patient_id, lab_type_id, date, value_num, units_txt, status)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [uid, lt.rows[0].id, date, (value_num ?? null), (units_txt ?? null), status]
    );
    res.json({ ok: true, id: ins.rows[0].id, status });
  } catch (e) { console.error('LABS POST ERROR:', e); res.status(500).json({ error: e.message }); }
});
app.get('/api/summary', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    if (!uid) return res.status(401).json({ error: 'unauthorized' });

    const q = await pool.query(`
      WITH s AS (
        SELECT u.weight_kg,
               COALESCE(SUM(dl.mg_taken),0)::numeric AS cum_mg,
               COALESCE(SUM(dl.mg_taken) FILTER (WHERE dl.date >= current_date-6),0)::numeric/7.0  AS avg7,
               COALESCE(SUM(dl.mg_taken) FILTER (WHERE dl.date >= current_date-13),0)::numeric/14.0 AS avg14
        FROM derma.users u
        LEFT JOIN derma.dose_logs dl ON dl.patient_id = u.id
        WHERE u.id=$1
        GROUP BY u.id
      )
      SELECT
        weight_kg,
        cum_mg::int,
        CASE WHEN weight_kg>0 THEN cum_mg/weight_kg ELSE NULL END AS cum_mg_per_kg,
        avg7, avg14,
        120::int AS t_min,
        135::int AS t_opt,
        150::int AS t_max,
        GREATEST((135*weight_kg - cum_mg), 0) AS remain_opt_mg,
        CASE
          WHEN avg14>0 AND (135*weight_kg - cum_mg) > 0
          THEN CEIL((135*weight_kg - cum_mg)/avg14)::int
        END AS days_opt
      FROM s
    `,[uid]);

    const d = q.rows[0] || {};
    const eta_opt_date = d.days_opt
      ? new Date(Date.now() + d.days_opt*86400000).toISOString().slice(0,10)
      : null;

    res.json({ ...d, eta_opt_date });
  } catch (e) {
    console.error('SUMMARY ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});
// ====== health ======
app.get('/api/_health', async (req, res) => {
  try {
    // проверим, что БД доступна
    await pool.query('select 1');
    res.json({ ok: true, db: true, t: Date.now() });
  } catch (e) {
    res.status(500).json({ ok: false, db: false, error: String(e) });
  }
});
// === Перехват старых путей на новые файлы (ДОЛЖНО идти до static) ===
app.get(['/main', '/plan', '/profile'], (req, res) => {
  const q = req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : '';
  const map = {
    '/main': '/main.html',
    '/plan': '/plan.html',
    '/profile': '/profile.html',
  };
  res.redirect(302, map[req.path] + q);
});

// Дополнительно: если где-то есть /faq без .html
app.get('/faq', (req, res) => {
  const q = req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : '';
  res.redirect(302, '/faq.html' + q);
});

// ====== static ======                // если выше не было require('path')

// (1) Ставим CSP, который НЕ блокирует inline-скрипты и data:/blob: картинки
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:",
      // было: "script-src  'self' 'unsafe-inline' 'unsafe-eval' blob:",
      "script-src  'self' 'unsafe-inline' 'unsafe-eval' blob: https://telegram.org https://*.telegram.org",
      "style-src   'self' 'unsafe-inline' data: https://fonts.googleapis.com",
      "img-src     'self' data: blob: https: http: https://unavatar.io https://*.unavatar.io https://telegram.org https://*.telegram.org https://t.me https://*.t.me",
      "media-src   'self' data: blob:",
      "font-src    'self' data: https://fonts.gstatic.com",
      // было: "connect-src 'self' https: http: data: blob:"
      "connect-src 'self' https: http: data: blob: https://telegram.org https://*.telegram.org"
    ].join('; ')
  );
  next();
});

// (2) Вырубаем агрессивный кеш статики на время отладки
const staticRoot = path.join(__dirname, 'webapp');
const staticOpts = { etag: false, lastModified: false, cacheControl: true, maxAge: 0 };

app.use(express.static(staticRoot, staticOpts));                       // /css, /js, /img, /index.html
// Алиасы для удобных путей без /dark/

const pagesDir = path.join(__dirname, 'webapp', 'dark');

// ДОБАВЬ ЭТО:
app.get(['/faq', '/faq.html'], (req, res) =>
  res.sendFile(path.join(pagesDir, 'faq.html'))
);
app.get(['/reset', '/reset.html'], (req, res) =>
  res.sendFile(path.join(pagesDir, 'reset.html'))
);
app.get(['/', '/main', '/main.html'], (req, res) =>
  res.sendFile(path.join(pagesDir, 'main.html'))
);

app.get(['/profile', '/profile.html'], (req, res) =>
  res.sendFile(path.join(pagesDir, 'profile.html'))
);
app.get(['/plan', '/plan.html'], (req, res) =>
  res.sendFile(path.join(pagesDir, 'plan.html'))
);

app.get(['/myprofile', '/myprofile.html'], (req, res) =>
  res.sendFile(path.join(pagesDir, 'myprofile.html'))
);
app.use('/img', express.static(path.join(staticRoot, 'img'), staticOpts));
app.use('/img', express.static(path.join(staticRoot, 'dark', 'img'), staticOpts));
// дальше как было:
app.get(['/calendar', '/calendar.html'], (req, res) =>
  res.sendFile(path.join(pagesDir, 'calendar.html'))
);
app.get(['/diary', '/diary.html'], (req, res) =>
  res.sendFile(path.join(pagesDir, 'diary.html'))
);

app.get(['/labs', '/labs.html'], (req, res) =>
  res.sendFile(path.join(pagesDir, 'labs.html'))
);
app.use('/dark',  express.static(path.join(staticRoot, 'dark'), staticOpts));
app.use('/light', express.static(path.join(staticRoot, 'light'), staticOpts));

app.get('/', (_req, res) => res.sendFile(path.join(staticRoot, 'index.html')));
// === REMINDERS v2 ============================================================
// Хранилища настроек (в памяти процесса)
const reminders = Object.create(null);      // ежедневное напоминание о приёме
const stockCfg  = Object.create(null);      // "мало капсул"

// Периоды
const TICK_MS            = Number(process.env.TICK_MS || 60_000);      // частота проверки (по умолчанию 1 мин)
const REPEAT_MS_DEFAULT  = Number(process.env.REM_MS  || 3*60*60*1000); // повтор через (по умолчанию 3 часа)

// Сохранение настроек ежедневного напоминания (тумблер/время/повтор в минутах)
app.post('/api/reminder', tgAuth, async (req, res) => {
  const tgId = req.tg || req.tgUser?.id;
  if (!tgId) return res.status(401).json({ ok:false, error: 'unauthorized' });

  const { enabled, time, repeat_min } = req.body || {};
  reminders[tgId] = {
    ...(reminders[tgId] || {}),
    enabled: !!enabled,
    time: String(time || '09:00').slice(0,5), // HH:MM
    // если repeat_min прислали — используем его, иначе дефолт из REPEAT_MS_DEFAULT
    repeat_min: Number.isFinite(+repeat_min) && +repeat_min > 0 ? +repeat_min : undefined,
    _date: null, _sentToday: false, _lastMs: 0
  };
  res.json({ ok:true, data: reminders[tgId] });
});

// Дев-эндпойнт: мгновенно прислать себе тестовое уведомление в TG
app.post('/api/dev/remind-now', tgAuth, async (req, res) => {
  try {
    const tgId = req.tg || req.tgUser?.id || req.body?.tg;
    if (!tgId) return res.status(401).json({ ok:false, error: 'unauthorized' });
    await sendReminder(tgId, '✅ Тест напоминания: всё работает!');
    res.json({ ok: true });
  } catch (e) {
    console.error('TEST-NOTIFY ERROR:', e);
    res.status(500).json({ ok:false, error:String(e) });
  }
});

// Сохранение настроек для "мало капсул" (из WebApp)
app.post('/api/reminder/stock', tgAuth, async (req, res) => {
  const tgId = req.tg || req.tgUser?.id;
  if (!tgId) return res.status(401).json({ error: 'unauthorized' });

  const { enabled, time, threshold } = req.body || {};
  stockCfg[tgId] = {
    ...(stockCfg[tgId] || {}),
    enabled: !!enabled,
    time: String(time || '09:00').slice(0,5),
    threshold: Number.isFinite(+threshold) ? +threshold : 10,
    _date: null, _sent: false
  };
  res.json({ ok: true, data: stockCfg[tgId] });
});

// ---- вспомогательные
const userTzCache = new Map();
async function getUserTzByTg(tgId) {
  if (userTzCache.has(tgId)) return userTzCache.get(tgId);
  await pool.query('SET search_path = derma, public');
  const r = await pool.query('SELECT tz FROM derma.users WHERE tg_id=$1::bigint',[Number(tgId)]);
  const tz = r.rows[0]?.tz || 'Europe/Moscow';
  userTzCache.set(tgId, tz);
  return tz;
}

function nowParts(tz) {
  const p = new Intl.DateTimeFormat('en-GB',{
    timeZone:tz,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false
  }).formatToParts(new Date());
  const g = t => p.find(x => x.type===t)?.value;
  return { date: `${g('year')}-${g('month')}-${g('day')}`, time: `${g('hour')}:${g('minute')}` };
}

async function hasTakenToday(tgId, tz) {
  await pool.query('SET search_path = derma, public');
  const q = await pool.query(
    `SELECT 1
       FROM derma.dose_logs dl
       JOIN derma.users u ON u.id = dl.patient_id
      WHERE u.tg_id = $1::bigint
        AND dl.date = (now() AT TIME ZONE $2)::date
      LIMIT 1`,
    [Number(tgId), tz]
  );
  return !!q.rowCount;
}

// приблизительный расчёт оставшихся капсул по данным прогресса
async function getCapsulesLeft(tgId) {
  await pool.query('SET search_path = derma, public');
  const q = await pool.query(`
    SELECT vp.days_left_estimate::numeric AS days_left,
           COALESCE(vp.daily_dose_mg,0)::numeric AS daily_mg,
           COALESCE(p.capsule_mg,0)::numeric     AS cap_mg
      FROM derma.v_patient_progress vp
      JOIN derma.users u ON u.id = vp.patient_id
      LEFT JOIN derma.plans p ON p.patient_id = u.id
     WHERE u.tg_id = $1::bigint
     LIMIT 1`,
     [Number(tgId)]
  );
  if (!q.rowCount) return null;
  const r = q.rows[0];
  if (!r.cap_mg || !r.daily_mg || !r.days_left) return null;
  const mgLeft   = Number(r.days_left) * Number(r.daily_mg);
  const capsLeft = Math.max(0, Math.ceil(mgLeft / Number(r.cap_mg)));
  return capsLeft;
}

// основной тикер для приёма (учитывает per-user repeat_min)
async function tickDoseReminders() {
  for (const [tgId, cfg] of Object.entries(reminders)) {
    if (!cfg?.enabled || !cfg.time) continue;

    const tz = await getUserTzByTg(tgId);
    const { date, time } = nowParts(tz);

    // новый день → сброс флагов
    if (cfg._date !== date) { cfg._date = date; cfg._sentToday = false; cfg._lastMs = 0; }

    // если уже отметили — не напоминаем
    if (await hasTakenToday(tgId, tz)) continue;

    const repeatMs = (Number.isFinite(+cfg.repeat_min) && +cfg.repeat_min > 0)
      ? +cfg.repeat_min * 60_000
      : REPEAT_MS_DEFAULT;

    const dueFirst  = !cfg._sentToday && time >= cfg.time;
    const dueRepeat =  cfg._sentToday && (!cfg._lastMs || Date.now() - cfg._lastMs >= repeatMs);

    if (dueFirst || dueRepeat) {
      await sendReminder(
        tgId,
        'Пора принять препарат 💊\nЕсли уже выпили — отметьте приём в трекере.'
      );
      cfg._sentToday = true;
      cfg._lastMs    = Date.now();
    }
  }
}

// тикер для “мало капсул”: строго 1 раз в день в своё время
async function tickStockReminders() {
  for (const [tgId, cfg] of Object.entries(stockCfg)) {
    if (!cfg?.enabled || !cfg.time) continue;

    const tz = await getUserTzByTg(tgId);
    const { date, time } = nowParts(tz);

    if (cfg._date !== date) { cfg._date = date; cfg._sent = false; }

    if (!cfg._sent && time >= cfg.time) {
      const left = await getCapsulesLeft(tgId);
      if (left != null && left <= (cfg.threshold ?? 10)) {
        await sendReminder(tgId, `⚠️ Осталось ${left} капсул. Пора закупить лекарство.`);
      }
      cfg._sent = true;
    }
  }
}

// общий таймер
setInterval(() => {
  Promise.all([ tickDoseReminders(), tickStockReminders() ])
    .catch(e => console.error('reminders tick error', e));
}, TICK_MS);

console.log('[BOOT] TICK_MS=', TICK_MS, 'REM_MS(default)=', REPEAT_MS_DEFAULT);

// ==== SET TELEGRAM WEBHOOK ON BOOT ====
if (!isPolling) {
  (async () => {
    try {
      const base = (process.env.WEBAPP_URL || WEBAPP_URL || '').replace(/\/+$/,'');
      await bot.deleteWebHook({ drop_pending_updates: true }).catch(() => {});
      if (base) {
        await bot.setWebHook(`${base}/tg/webhook`);
        const me = await bot.getMe();
        console.log('Webhook set for @' + me.username);
      } else {
        console.warn('WEBAPP_URL is empty -> webhook not set');
      }
    } catch (e) {
      console.error('Webhook setup failed:', e?.message || e);
    }
  })();
} else {
  console.log('Bot started in POLLING mode');
}

// === START EXPRESS SERVER ===
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('Server listening on port', PORT);
});