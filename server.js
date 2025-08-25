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

// DEV-дружественная аутентификация: либо initData, либо ?tg=...
function tgAuth(req, res, next) {
  const initData = req.get('X-Telegram-InitData')
               || req.query.tgWebAppData
               || req.query.initData
               || '';
  if (!initData) {
    const tg = req.query.tg;
    if (tg) { req.tg = Number(tg); return next(); }
    return res.status(401).json({ error: 'no initData' });
  }
  try {
    const { user } = parseAndVerifyInitData(initData);
    req.tg = user?.id;
    req.tgUser = user;
    next();
  } catch (e) {
    // временный DEV-фолбек (включается, если ALLOW_UNVERIFIED_INIT=1 в окружении)
    if (process.env.ALLOW_UNVERIFIED_INIT === '1') {
      try {
        const sp = new URLSearchParams(initData);
        const user = sp.get('user') ? JSON.parse(sp.get('user')) : null;
        req.tg = user?.id; req.tgUser = user;
        console.warn('WARN: using unverified initData');
        return next();
      } catch {}
    }
    console.error('AUTH ERROR:', e.message);
    res.status(401).json({ error: 'bad initData' });
  }
}

// ====== helpers ======
async function userIdByTg(tg) {
  if (!tg) return null;
  const r = await pool.query('SELECT id FROM derma.users WHERE tg_id=$1', [tg]);
  return r.rows[0]?.id || null;
}
async function ensureUser(req) {
  try {
    // 1) Достаём tg_id из заголовка initData (Telegram) или ?tg (DEV)
    let tgId = null, fullName = null, username = null;

    const initDataRaw = req.get('X-Telegram-InitData')
                   || req.query.tgWebAppData
                   || req.query.initData
                   || '';
    if (initDataRaw) {
      const p = new URLSearchParams(initDataRaw);
      const userStr = p.get('user');
      if (userStr) {
        const u = JSON.parse(userStr);
        tgId = Number(u.id);
        username = u.username || null;
        fullName = [u.first_name, u.last_name].filter(Boolean).join(' ') || null;
      }
    }

    if (!tgId) {
      const q = req.query?.tg ?? req.body?.tg;
      if (q) tgId = Number(q);
    }

    if (!tgId || Number.isNaN(tgId)) {
      // нет initData и нет ?tg — неавторизован
      return null;
    }

    // 2) Заводим/обновляем пользователя
    const { rows } = await pool.query(
      `insert into derma.users (tg_id, full_name)
 values ($1::bigint, $2)
 on conflict (tg_id) do update
   set full_name = coalesce(EXCLUDED.full_name, derma.users.full_name),
       updated_at = now()
 returning *`,
[tgId, fullName]
    );
    return rows[0] || null;
  } catch (e) {
    console.error('ensureUser error:', e);
    return null;
  }
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
    res.json(rows[0]);
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

// GET /api/me
app.get('/api/me', async (req, res) => {
  try {
    const u = await ensureUser(req);
    if (!u) return res.status(401).json({ error: 'unauthorized' });

    const { rows } = await pool.query(
  `select id, tg_id, full_name, sex, birth_date, weight_kg, height_cm, tz,
          accepted_terms_at, allergies, terms_version
     from derma.users
    where id = $1`,
  [u.id]
);
    res.json(rows[0] || {});
  } catch (e) {
    console.error('ME GET ERROR:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/me
app.post('/api/me', async (req, res) => {
  try {
    const u = await ensureUser(req);
    if (!u) return res.status(401).json({ error: 'unauthorized' });

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
  [weight_kg, height_cm, sex, birth_date, full_name, tz, accepted, allergies, terms_version, u.id]
);

    const { rows } = await pool.query(
  `select id, tg_id, full_name, sex, birth_date, weight_kg, height_cm, tz,
          accepted_terms_at, allergies, terms_version
     from derma.users
    where id = $1`,
  [u.id]
);
    res.json(rows[0]);
  } catch (e) {
    console.error('ME POST ERROR:', e);
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

app.post('/api/plan', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    const { drug, capsule_mg, start_date } = req.body || {};
    const d = (drug || '').toLowerCase();
    if (!['roaccutane','aknekutan'].includes(d)) return res.status(400).json({ error: 'bad drug' });
    const mg = Number(capsule_mg);
    const okMg = (d === 'roaccutane') ? [10,20] : [8,16];
    if (!okMg.includes(mg)) return res.status(400).json({ error: 'bad capsule_mg' });

    await pool.query(
      `INSERT INTO derma.plans (patient_id, drug, capsule_mg, start_date)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (patient_id)
         DO UPDATE SET drug=EXCLUDED.drug, capsule_mg=EXCLUDED.capsule_mg, start_date=EXCLUDED.start_date, updated_at=NOW()`,
      [uid, d, mg, start_date || null]
    );
    const r = await pool.query('SELECT patient_id, drug, capsule_mg, start_date FROM derma.plans WHERE patient_id=$1', [uid]);
    res.json(r.rows[0]);
  } catch (e) { console.error('PLAN POST ERROR:', e); res.status(500).json({ error: e.message }); }
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