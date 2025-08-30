// ====== imports / setup ======
require('dotenv').config();
process.on('uncaughtException', err => console.error('UNCAUGHT', err));
process.on('unhandledRejection', err => console.error('UNHANDLED', err));
const { bot, WEBAPP_URL } = require('./bot'); // импорт один раз
const isPolling = !process.env.WEBAPP_URL;    // локально — polling, на Render — webhook
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
              accepted_terms_at, allergies, terms_version
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
    '/main': '/main-dark.html',
    '/plan': '/plan-dark.html',
    '/profile': '/profile-dark.html',
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
const staticDir = path.join(__dirname, 'webapp');
app.use(express.static(staticDir));
app.get('/', (_, res) => res.sendFile(path.join(staticDir, 'index.html')));

// ==== START HTTP SERVER ====
const port = process.env.PORT || 3000;
const host = process.env.HOST || '0.0.0.0';
app.listen(port, host, () => {
  console.log(`API listening on ${host}:${port}`);
});

// Telegram webhook endpoint (ОДИН раз)
app.post('/tg/webhook', (req, res) => {
  try { bot.processUpdate(req.body); } 
  catch (e) { console.error('webhook handler error:', e); }
  res.sendStatus(200);
});

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