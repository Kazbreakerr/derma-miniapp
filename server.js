// ====== imports / setup ======
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

const app = express();
app.use(express.json());
app.use(cors({
  origin: true,
  credentials: true,
  allowedHeaders: ['Content-Type', 'X-Telegram-InitData', 'tgwebappdata']
  
}));



// ====== DB pool ======
const dsn = process.env.DATABASE_URL;
if (!dsn) throw new Error('DATABASE_URL is empty');

const pool = new Pool({
  connectionString: dsn,
  ssl: { rejectUnauthorized: false },
});

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
async function tgAuth(req, res, next) {
  try {
    const initData = req.get('X-Telegram-InitData')
                     || req.query.tgWebAppData
                     || req.query.initData
                     || '';

    let tgUser = null;

    if (initData) {
      try {
        const { user } = parseAndVerifyInitData(initData);
        if (user?.id) tgUser = user;
      } catch (e) {
        if (process.env.ALLOW_UNVERIFIED_INIT === '1') {
          try {
            const sp = new URLSearchParams(initData);
            const u = sp.get('user') ? JSON.parse(sp.get('user')) : null;
            if (u?.id) {
              tgUser = u;
              console.warn('WARN: using unverified initData');
            }
          } catch {}
        }
        if (!tgUser) throw e;
      }
    }

    // dev ?tg=... допускаем, если нет валидного initData
    if (!tgUser) {
      const devTg = req.query.tg;
      if (devTg && /^\d+$/.test(String(devTg))) {
        tgUser = { id: Number(devTg), first_name: 'Dev', last_name: 'User', username: 'dev' };
      }
    }

    if (!tgUser?.id) return res.status(401).json({ error: 'BOT_INVALID' });

    // сохраним «кто пришёл»
    req.tg = Number(tgUser.id);
    req.tgUser = tgUser;

    // ⬅️ КЛЮЧЕВОЕ: гарантированно апсертим пользователя
    await ensureUser(req);

    return next();
  } catch (e) {
    console.error('AUTH ERROR:', e?.message || e);
    return res.status(401).json({ error: 'bad initData' });
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
app.get('/api/state/next/index', tgAuth, async (req, res) => {
  try {
       // для тестов: /index.html?forceSplash=1 всегда показывает splash+   if (String(req.query.forceSplash) === '1') {+     return res.json({ ok: true, page: '/dark/splash-video.html' });
  
    const firstTime = !!req.isFreshUser;           // ← уже есть в твоём tgAuth
    const page = firstTime ? '/dark/splash-video.html'
                           : '/dark/welcome-rt.html';
    res.json({ ok: true, page });
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
    const consented  = !!u.rows[0]?.accepted_terms_at;
    const hasProfile = u.rows[0]?.weight_kg != null;        // профиль считаем заполненным, если есть вес
    const p = await pool.query(
      'SELECT 1 FROM derma.plans WHERE patient_id=$1',
      [uid]
    );
    const hasPlan = !!p.rows[0];

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
    if (l && l.route && l.route.path) {
      const methods = Object.keys(l.route.methods || {}).join('|').toUpperCase() || 'GET';
      routes.push(`${methods} ${l.route.path}`);
    }
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

// Aliases for intakes
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

app.post('/api/intakes', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    if (!uid) return res.status(400).json({ error: 'missing tg' });

    const mg = Number(req.body?.mg);
    if (!Number.isFinite(mg) || mg < 0) return res.status(400).json({ error: 'bad mg' });

    const d = req.body?.date || new Date().toISOString().slice(0,10);
    await pool.query(
      `INSERT INTO derma.dose_logs(patient_id,date,mg_taken)
       VALUES ($1,$2,$3)
       ON CONFLICT (patient_id,date) DO UPDATE SET mg_taken=EXCLUDED.mg_taken`,
      [uid, d, mg]
    );
    res.status(201).json({ ok: true, date: d, mg });
  } catch (e) {
    console.error('INTAKES POST ERROR:', e);
    res.status(500).json({ error: e.message });
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
    const uid  = await userIdByTg(req.tg || req.tgUser?.id);
    const code = String(req.body?.code || '').toUpperCase();
    if (!/^[A-Z0-9]{5}$/.test(code)) return res.status(400).json({ error: 'bad code' });

    // код не должен конфликтовать с активными
    const taken = await pool.query('SELECT 1 FROM derma.doctor_codes WHERE code=$1 AND active', [code]);
    if (taken.rowCount) return res.status(409).json({ error: 'code taken' });

    // деактивируем старый код этого врача (если был)
    await pool.query('UPDATE derma.doctor_codes SET active=false, revoked_at=now() WHERE doctor_id=$1 AND active', [uid]);
    await pool.query('INSERT INTO derma.doctor_codes(code, doctor_id, active) VALUES ($1,$2,true)', [code, uid]);

    // профиль/настройки
    const p   = req.body?.profile  || {};
    const s   = req.body?.settings || {};
    const ava = req.body?.avatarUrl || null;
    await pool.query(`
      INSERT INTO derma.doctor_profiles(user_id, specialty, city, clinic, tg_handle, contact_text, avatar_url, accepting, auto_accept)
      VALUES ($1,$2,$3,$4,$5,$6,$7, COALESCE($8,true), COALESCE($9,false))
      ON CONFLICT (user_id) DO UPDATE SET
        specialty    = COALESCE(EXCLUDED.specialty, doctor_profiles.specialty),
        city         = COALESCE(EXCLUDED.city,      doctor_profiles.city),
        clinic       = COALESCE(EXCLUDED.clinic,    doctor_profiles.clinic),
        tg_handle    = COALESCE(EXCLUDED.tg_handle, doctor_profiles.tg_handle),
        contact_text = COALESCE(EXCLUDED.contact_text, doctor_profiles.contact_text),
        avatar_url   = COALESCE(EXCLUDED.avatar_url,   doctor_profiles.avatar_url),
        accepting    = EXCLUDED.accepting,
        auto_accept  = EXCLUDED.auto_accept,
        updated_at   = now()
    `, [uid, p.specialty||null, p.city||null, p.clinic||null, p.tg||null, p.contact||null, ava, s.accepting===true, s.autoAccept===true]);

    await pool.query('UPDATE derma.users SET is_doctor = true WHERE id=$1', [uid]);

    res.json({ ok: true, code });
  } catch (e) {
    console.error('DOCTOR CODE ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/doctor/me', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const uid = await userIdByTg(req.tg || req.tgUser?.id);

    const { rows: c } = await pool.query(
      'SELECT code FROM derma.doctor_codes WHERE doctor_id=$1 AND active', [uid]);
    const { rows: p } = await pool.query(
      `SELECT specialty, city, clinic, tg_handle, contact_text, avatar_url, accepting, auto_accept
         FROM derma.doctor_profiles WHERE user_id=$1`, [uid]);

    res.json({ code: c[0]?.code || null, profile: p[0] || null });
  } catch (e) {
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
             dp.clinic, dp.city, dp.avatar_url
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
    await pool.query('INSERT INTO derma.patient_doctors(patient_id, doctor_id) VALUES ($1,$2)', [pid, did]);

    const { rows } = await pool.query(`
      SELECT u.id AS doctor_id,
             COALESCE(u.full_name,'Врач') AS name,
             dp.clinic, dp.city, dp.avatar_url
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
      SELECT dc.code,
             u.id AS doctor_id,
             COALESCE(u.full_name,'Врач') AS name,
             dp.clinic, dp.city, dp.avatar_url
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
      SELECT dc.doctor_id,
             COALESCE(u.full_name,'Врач') AS name,
             dp.clinic, dp.city, dp.avatar_url,
             COALESCE(dp.auto_accept,false) AS auto_accept
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
    if (doc.auto_accept) {
      await pool.query('BEGIN');
      // помечаем заявку «accepted»
      await pool.query(
        `UPDATE derma.doctor_requests
            SET status='accepted', decided_at=now()
          WHERE patient_id=$1 AND doctor_id=$2 AND status='pending'`,
        [pid, did]
      );
      // открепляем прошлых
      await pool.query('UPDATE derma.patient_doctors SET unbound_at=now() WHERE patient_id=$1 AND unbound_at IS NULL', [pid]);
      // крепим текущего
      await pool.query('INSERT INTO derma.patient_doctors(patient_id, doctor_id) VALUES ($1,$2)', [pid, did]);
      await pool.query('COMMIT');

      return res.json({
        ok: true,
        status: 'accepted',
        doctor: { id: did, name: doc.name, clinic: doc.clinic, city: doc.city, avatar_url: doc.avatar_url }
      });
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

// Список «pending»-заявок для врача
app.get('/api/doctor/requests', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const did = await userIdByTg(req.tg || req.tgUser?.id);

    // проверим, что это «врач»
    const u = await pool.query('SELECT is_doctor FROM derma.users WHERE id=$1', [did]);
    if (!u.rowCount || !u.rows[0].is_doctor) return res.status(403).json({ error:'not a doctor' });

    const { rows } = await pool.query(`
      SELECT dr.id, dr.created_at,
             p.id AS patient_id, COALESCE(p.full_name,'Пациент') AS patient_name
        FROM derma.doctor_requests dr
        JOIN derma.users p ON p.id=dr.patient_id
       WHERE dr.doctor_id=$1 AND dr.status='pending'
       ORDER BY dr.created_at ASC`, [did]);

    res.json(rows);
  } catch (e) {
    console.error('DOCTOR REQUESTS LIST ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// Подтвердить заявку (врач)
app.post('/api/doctor/requests/:id/accept', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const did = await userIdByTg(req.tg || req.tgUser?.id);
    const id  = Number(req.params.id);

    await pool.query('BEGIN');
    const r = await pool.query(
      `UPDATE derma.doctor_requests
          SET status='accepted', decided_at=now()
        WHERE id=$1 AND doctor_id=$2 AND status='pending'
        RETURNING patient_id`, [id, did]);
    if (!r.rowCount) { await pool.query('ROLLBACK'); return res.status(404).json({ error:'not found' }); }

    const pid = r.rows[0].patient_id;
    await pool.query('UPDATE derma.patient_doctors SET unbound_at=now() WHERE patient_id=$1 AND unbound_at IS NULL', [pid]);
    await pool.query('INSERT INTO derma.patient_doctors(patient_id, doctor_id) VALUES ($1,$2)', [pid, did]);
    await pool.query('COMMIT');

    res.json({ ok:true });
  } catch (e) {
    try { await pool.query('ROLLBACK'); } catch(_){}
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

// ===== DOCTOR: code + me (минимально для кабинета) =====
app.post('/api/doctor/code', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const uid  = await userIdByTg(req.tg || req.tgUser?.id);
    const code = String(req.body?.code || '').toUpperCase();
    if (!/^[A-Z0-9]{5}$/.test(code)) return res.status(400).json({ error: 'bad code' });

    // деактивируем прежний код и записываем новый
    await pool.query('UPDATE derma.doctor_codes SET active=false, revoked_at=now() WHERE doctor_id=$1 AND active', [uid]);
    await pool.query('INSERT INTO derma.doctor_codes(code, doctor_id, active) VALUES ($1,$2,true) ON CONFLICT (code) DO UPDATE SET doctor_id=EXCLUDED.doctor_id, active=true, revoked_at=NULL', [code, uid]);

    res.json({ ok: true, code });
  } catch (e) {
    console.error('DOCTOR CODE ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/doctor/me', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const uid = await userIdByTg(req.tg || req.tgUser?.id);
    const { rows } = await pool.query('SELECT code FROM derma.doctor_codes WHERE doctor_id=$1 AND active', [uid]);
    res.json({ code: rows[0]?.code || null, profile: null });
  } catch (e) {
    console.error('DOCTOR ME ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});


// ====== static ======
const staticRoot = path.join(__dirname, 'webapp'); // serve files from /webapp
app.use(express.static(staticRoot));                // /css, /js, /img, /index.html
app.use('/dark',  express.static(path.join(staticRoot, 'dark')));
app.use('/light', express.static(path.join(staticRoot, 'light')));
app.get('/', (_, res) => res.sendFile(path.join(staticRoot, 'index.html')));
// === REMINDERS v2 ============================================================
const reminders = Object.create(null);      // приём препарата
const stockCfg  = Object.create(null);      // напоминание "мало капсул"

// Сохранение настроек для приёма (из WebApp)
app.post('/api/reminder', tgAuth, async (req, res) => {
  const tgId = req.tg || req.tgUser?.id;
  if (!tgId) return res.status(401).json({ error: 'unauthorized' });

  const { enabled, time } = req.body || {};
  reminders[tgId] = {
    ...(reminders[tgId] || {}),
    enabled: !!enabled,
    time: String(time || '20:30').slice(0,5),
    _date: null, _sentToday: false, _lastMs: 0
  };
  res.json({ ok: true, data: reminders[tgId] });
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
  const p = new Intl.DateTimeFormat('en-GB',{timeZone:tz,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).formatToParts(new Date());
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

// основной тикер для приёма
async function tickDoseReminders() {
  const REPEAT_MS = Number(process.env.REM_MS || (60*1000)); // дефолт 3 часа
  for (const [tgId, cfg] of Object.entries(reminders)) {
    if (!cfg?.enabled || !cfg.time) continue;

    const tz = await getUserTzByTg(tgId);
    const { date, time } = nowParts(tz);

    // новый день → сброс флагов
    if (cfg._date !== date) { cfg._date = date; cfg._sentToday = false; cfg._lastMs = 0; }

    // если уже отметили — не напоминаем
    if (await hasTakenToday(tgId, tz)) continue;

    const dueFirst  = !cfg._sentToday && time >= cfg.time;
    const dueRepeat =  cfg._sentToday && (!cfg._lastMs || Date.now() - cfg._lastMs >= REPEAT_MS);

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

// общий тикер раз в минуту
setInterval(() => {
  Promise.all([ tickDoseReminders(), tickStockReminders() ])
    .catch(e => console.error('reminders tick error', e));
}, 60 * 1000);


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