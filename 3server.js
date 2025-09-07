// server.js — компактный, но полный

require('dotenv').config();
process.on('uncaughtException', e => console.error('UNCAUGHT', e));
process.on('unhandledRejection', e => console.error('UNHANDLED', e));

const path    = require('path');
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const pg      = require('pg');
pg.defaults.ssl = true;
const { Pool } = pg;

// --- (опционально) Telegram bot; в dev без него будет мок --- //
let bot = null, WEBAPP_URL = process.env.WEBAPP_URL || '';
try {
  ({ bot, WEBAPP_URL = WEBAPP_URL } = require('./bot'));
} catch {
  bot = {
    getMe: async () => ({ username: 'dev-bot', id: 0 }),
    setWebHook: async () => {},
    deleteWebHook: async () => {},
    sendMessage: async () => {}
  };
}

const app  = express();
const PORT = process.env.PORT || 3000;

// === базовые мидлвары ===
app.use(express.json());
app.use(cors({
  origin: true,
  credentials: true,
  allowedHeaders: ['Content-Type','X-Telegram-InitData','x-telegram-initdata','tgwebappdata']
}));

// === БД ===
const dsn = process.env.DATABASE_URL;
if (!dsn) throw new Error('DATABASE_URL is empty');
const pool = new Pool({ connectionString: dsn, ssl: { rejectUnauthorized: false } });

// === CSP, чтобы НЕ ломать inline-JS, data: и blob: ===
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:",
    "script-src  'self' 'unsafe-inline' 'unsafe-eval' blob:",
    "style-src   'self' 'unsafe-inline' data:",
    "img-src     'self' data: blob:",
    "media-src   'self' data: blob:",
    "font-src    'self' data:",
    "connect-src 'self' https: http: data: blob:"
  ].join('; '));
  next();
});

// === статика без агрессивного кэша (важно для dev) ===
const staticRoot = path.join(__dirname, 'webapp');
const staticOpts = { etag: false, lastModified: false, cacheControl: true, maxAge: 0 };
app.use(express.static(staticRoot, staticOpts));
app.use('/dark',  express.static(path.join(staticRoot, 'dark'), staticOpts));
app.use('/light', express.static(path.join(staticRoot, 'light'), staticOpts));
app.get('/', (_req, res) => res.sendFile(path.join(staticRoot, 'index.html')));

// удобные редиректы без .html
app.get(['/main', '/plan', '/profile'], (req, res) => {
  const q = req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : '';
  res.redirect(302, { '/main': '/main.html', '/plan': '/plan.html', '/profile': '/profile.html' }[req.path] + q);
});
app.get('/faq', (req, res) => {
  const q = req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : '';
  res.redirect(302, '/faq.html' + q);
});

// === Telegram WebApp initData проверка + dev-режим ?tg=... ===
const BOT_TOKEN = process.env.BOT_TOKEN || (bot?.telegram?.token ?? '');
function parseAndVerifyInitData(initData) {
  const sp = new URLSearchParams(initData);
  const hash = sp.get('hash');
  sp.delete('hash');
  const entries = [];
  sp.forEach((v, k) => entries.push(`${k}=${v}`));
  entries.sort();
  const dataCheckString = entries.join('\n');

  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const sign   = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');

  if (!hash || sign !== hash) throw new Error('bad initData hash');

  const authDateMs = Number(sp.get('auth_date') || '0') * 1000;
  if (!authDateMs || Date.now() - authDateMs > 24 * 60 * 60 * 1000) throw new Error('stale initData');

  const user = sp.get('user') ? JSON.parse(sp.get('user')) : null;
  return { user };
}

async function userIdByTg(tgId) {
  if (!tgId) return null;
  await pool.query('SET search_path = derma, public');
  const { rows } = await pool.query('SELECT id FROM derma.users WHERE tg_id = $1::bigint', [Number(tgId)]);
  return rows[0]?.id || null;
}

async function tgAuth(req, res, next) {
  try {
    let tgId = null;

    // 1) заголовок Telegram WebApp
    const raw = req.get('X-Telegram-InitData') || req.get('x-telegram-initdata') || '';
    if (raw) {
      try { tgId = JSON.parse(new URLSearchParams(raw).get('user')).id; } catch {}
      if (tgId) {
        // валидируем хэш
        parseAndVerifyInitData(raw);
      }
    }

    // 2) Dev: ?tg=123
    if (!tgId && /^\d+$/.test(String(req.query.tg || ''))) tgId = Number(req.query.tg);

    if (!tgId) return res.status(401).json({ error: 'BOT_INVALID' });

    await pool.query('SET search_path = derma, public');
    const ins = await pool.query(
      `INSERT INTO derma.users(tg_id) VALUES ($1) ON CONFLICT (tg_id) DO NOTHING RETURNING id`,
      [tgId]
    );
    req.isFreshUser = ins.rowCount > 0;
    req.tg = tgId;
    next();
  } catch (e) {
    console.error('tgAuth error', e);
    res.status(401).json({ error: 'BOT_INVALID' });
  }
}

// === HEALTH/DEBUG ===
app.get('/api/health', (_, res) => res.json({ ok: true }));
app.get('/api/_health', async (_req, res) => {
  try { await pool.query('select 1'); res.json({ ok: true, db: true, t: Date.now() }); }
  catch (e) { res.status(500).json({ ok: false, db: false, error: String(e) }); }
});
app.get('/api/_bot', async (_req, res) => {
  try { const me = await bot.getMe(); res.json({ ok: true, username: me.username, id: me.id }); }
  catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});
app.get('/api/_routes', (req, res) => {
  const routes = [];
  (app._router?.stack || []).forEach(l => {
    if (l?.route?.path) routes.push(`${Object.keys(l.route.methods||{}).join('|').toUpperCase()||'GET'} ${l.route.path}`);
  });
  res.json(routes.sort());
});
app.get('/api/debug', async (req, res) => {
  try {
    const rawHeader = req.get('X-Telegram-InitData') || '';
    const rawQuery  = req.query.tgWebAppData || req.query.initData || '';
    let valid = false, user = null, err = null;
    try { const parsed = parseAndVerifyInitData(rawHeader || rawQuery); valid = !!parsed?.user?.id; user = parsed?.user || null; }
    catch (e) { err = String(e.message || e); }
    const { rows: [db] } = await pool.query(`SELECT current_database() AS db, current_user AS "user"`);
    const { rows: [sp] } = await pool.query(`SHOW search_path`);
    res.json({ got_header: !!rawHeader, got_query: !!rawQuery, valid, user, db, search_path: sp.search_path, error: err });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// === роутинг первого запуска / ре-энтри ===
async function decideDoctorState(uid) {
  await pool.query('SET search_path = derma, public');
  const u   = await pool.query('SELECT is_doctor FROM derma.users WHERE id=$1', [uid]);
  let isDoc = !!u.rows[0]?.is_doctor;
  const code = await pool.query('SELECT code FROM derma.doctor_codes WHERE doctor_id=$1 AND active', [uid]);
  const prof = await pool.query('SELECT 1 FROM derma.doctor_profiles WHERE user_id=$1', [uid]);
  const hasDoctorAssets = !!(code.rows[0]?.code || prof.rows[0]);
  if (!isDoc && hasDoctorAssets) isDoc = true;
  return { isDoctor: isDoc, onbDone: hasDoctorAssets };
}

app.get('/api/state/next/index', tgAuth, async (req, res) => {
  try {
    if (String(req.query.forceSplash) === '1') return res.json({ ok: true, page: '/dark/splash-video.html' });
    if (req.isFreshUser) return res.json({ ok: true, page: '/dark/splash-video.html' });
    const uid = await userIdByTg(req.tg);
    let page = '/dark/main.html';
    if (uid) {
      const { isDoctor, onbDone } = await decideDoctorState(uid);
      if (isDoctor) page = onbDone ? '/dark/doctor-cabinet-mint-rose.html' : '/dark/doctor-onboarding-mint-rose.html';
    }
    res.json({ ok: true, page });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/state/next/welcome', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const uid = await userIdByTg(req.tg);
    if (!uid) return res.status(401).json({ ok: false, error: 'unauthorized' });

    const { isDoctor, onbDone } = await decideDoctorState(uid);
    if (isDoctor) {
      return res.json({ ok: true, role: 'doctor', page: onbDone ? '/dark/doctor-cabinet-mint-rose.html' : '/dark/doctor-onboarding-mint-rose.html' });
    }

    const u  = await pool.query(`SELECT accepted_terms_at, weight_kg FROM derma.users WHERE id = $1`, [uid]);
    const p  = await pool.query('SELECT 1 FROM derma.plans WHERE patient_id=$1', [uid]);
    const consented  = !!u.rows[0]?.accepted_terms_at;
    const hasProfile = (Number(u.rows[0]?.weight_kg) || 0) > 0;
    const hasPlan    = !!p.rows[0];

    const page = !consented ? '/dark/warnings.html'
               : !hasProfile ? '/dark/profile.html'
               : !hasPlan   ? '/dark/plan.html'
               :              '/dark/main.html';

    res.json({ ok: true, role: 'patient', page });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// === профиль / согласие ===
app.get('/api/me', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    const { rows } = await pool.query(
      `select id, tg_id, full_name, sex, birth_date, weight_kg, height_cm, tz,
              accepted_terms_at, allergies, terms_version, is_doctor
         from derma.users where id=$1`, [uid]
    );
    const me = rows[0] || {};
    me.fresh_user = !!req.isFreshUser;
    res.json(me);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/me', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    const { weight_kg, height_cm, sex, birth_date, full_name, tz, accepted, allergies, terms_version } = req.body || {};
    await pool.query(
      `update derma.users set
         weight_kg = coalesce($1, weight_kg),
         height_cm = coalesce($2, height_cm),
         sex       = coalesce($3, sex),
         birth_date= coalesce($4, birth_date),
         full_name = coalesce($5, full_name),
         tz        = coalesce($6, tz),
         accepted_terms_at = case when $7::boolean is true then coalesce(accepted_terms_at, now()) else accepted_terms_at end,
         allergies = coalesce($8::text[], allergies),
         terms_version = greatest(coalesce($9::int, terms_version), terms_version),
         updated_at = now()
       where id = $10`,
      [weight_kg, height_cm, sex, birth_date, full_name, tz, accepted, allergies, terms_version, uid]
    );
    const { rows } = await pool.query(
      `select id, tg_id, full_name, sex, birth_date, weight_kg, height_cm, tz,
              accepted_terms_at, allergies, terms_version
         from derma.users where id=$1`, [uid]
    );
    const me = rows[0] || {};
    me.fresh_user = !!req.isFreshUser;
    res.json(me);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// === план курса ===
app.get('/api/plan', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    const r = await pool.query('SELECT patient_id, drug, capsule_mg, start_date FROM derma.plans WHERE patient_id=$1', [uid]);
    res.json(r.rows[0] || null);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/plan', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const { drug, capsule_mg, start_date } = req.body || {};
    if (!['roaccutane','aknekutan','other'].includes(drug || '')) return res.status(400).json({ error:'bad drug' });

    let cap = null;
    if (capsule_mg !== undefined && capsule_mg !== null && String(capsule_mg) !== '') {
      cap = Number(capsule_mg);
      const allowed = drug === 'roaccutane' ? [10,20] : drug === 'aknekutan' ? [8,16] : [];
      if (allowed.length && !allowed.includes(cap)) return res.status(400).json({ error:'bad capsule_mg' });
    }

    const patientId = await userIdByTg(req.tg);
    const sql = `
      INSERT INTO derma.plans (patient_id, drug, capsule_mg, start_date)
      VALUES ($1,$2,$3,$4)
      ON CONFLICT (patient_id) DO UPDATE
        SET drug=EXCLUDED.drug, capsule_mg=EXCLUDED.capsule_mg, start_date=EXCLUDED.start_date
      RETURNING patient_id, drug, capsule_mg, start_date
    `;
    const { rows } = await pool.query(sql, [patientId, drug, cap, start_date || null]);
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error:'server' }); }
});

// === приёмы (dose/intakes) ===
app.get('/api/intakes', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
    const limit = Math.min(Number(req.query.limit || 14), 90);
    const { rows } = await pool.query(
      `SELECT date, mg_taken AS mg
         FROM derma.dose_logs
        WHERE patient_id=$1
        ORDER BY date DESC
        LIMIT $2`, [uid, limit]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/intakes', tgAuth, async (req, res) => {
  try {
    const uid = await userIdByTg(req.tg);
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// === анализы ===
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
        LIMIT 50`, [uid]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// === врач (onboarding/cabinet) — код/профиль/прикрепления/заявки ===
app.post('/api/doctor/code', tgAuth, async (req, res) => {
  try{
    await pool.query('SET search_path = derma, public');
    const uid = await userIdByTg(req.tg);
    const { profile = {}, code: passedCode, settings = {} } = req.body || {};
    let code = String(passedCode||'').trim().toUpperCase();
    if (!/^[A-Z0-9]{5}$/.test(code)) {
      const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      code = Array.from({length:5},()=>alphabet[Math.floor(Math.random()*alphabet.length)]).join('');
    }

    await pool.query('BEGIN');
    await pool.query(`
      INSERT INTO derma.doctor_codes(doctor_id, code, active)
      VALUES ($1,$2,true)
      ON CONFLICT (doctor_id) DO UPDATE
        SET code=EXCLUDED.code, active=true, revoked_at=NULL
    `,[uid, code]);

    const prof = {
      specialty:    profile.specialty ?? null,
      clinic:       profile.clinic ?? null,
      city:         profile.city ?? null,
      tg:           profile.tg ?? profile.tg_handle ?? null,
      contact:      profile.contact ?? profile.contact_text ?? null,
      avatar_url:   profile.avatarUrl ?? profile.avatar_url ?? null,
      accepting:    settings.accepting === true,
      auto_accept:  settings.autoAccept === true,
    };
    await pool.query(`
      INSERT INTO derma.doctor_profiles(user_id, specialty, city, clinic, tg_handle, contact_text, avatar_url, accepting, auto_accept)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT (user_id) DO UPDATE
        SET specialty=COALESCE(EXCLUDED.specialty,doctor_profiles.specialty),
            city=COALESCE(EXCLUDED.city,doctor_profiles.city),
            clinic=COALESCE(EXCLUDED.clinic,doctor_profiles.clinic),
            tg_handle=COALESCE(EXCLUDED.tg_handle,doctor_profiles.tg_handle),
            contact_text=COALESCE(EXCLUDED.contact_text,doctor_profiles.contact_text),
            avatar_url=COALESCE(EXCLUDED.avatar_url,doctor_profiles.avatar_url),
            accepting=EXCLUDED.accepting,
            auto_accept=EXCLUDED.auto_accept,
            updated_at=now()
    `,[uid, prof.specialty, prof.city, prof.clinic, prof.tg, prof.contact, prof.avatar_url, prof.accepting, prof.auto_accept]);

    await pool.query('UPDATE derma.users SET is_doctor = true WHERE id=$1', [uid]);
    if (profile.name) await pool.query('UPDATE derma.users SET full_name=$2 WHERE id=$1', [uid, String(profile.name).slice(0,180)]);
    await pool.query('COMMIT');

    res.json({ ok:true, code });
  }catch(e){
    try{ await pool.query('ROLLBACK'); }catch(_){}
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/doctor/me', tgAuth, async (req, res) => {
  try{
    await pool.query('SET search_path = derma, public');
    const uid = await userIdByTg(req.tg);
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
    res.json({ is_doctor: !!u.rows?.[0]?.is_doctor, code: dc.rows?.[0]?.code || null, profile });
  }catch(e){ res.status(500).json({ error: e.message }); }
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/doctor/attach', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const pid  = await userIdByTg(req.tg);
    const code = String(req.body?.code || '').toUpperCase();
    if (!/^[A-Z0-9]{5}$/.test(code)) return res.status(400).json({ error: 'bad code' });
    const r = await pool.query('SELECT doctor_id FROM derma.doctor_codes WHERE code=$1 AND active', [code]);
    if (!r.rowCount) return res.status(404).json({ error: 'code not found' });
    const did = r.rows[0].doctor_id;
    await pool.query('UPDATE derma.patient_doctors SET unbound_at=now() WHERE patient_id=$1 AND unbound_at IS NULL', [pid]);
    await pool.query('INSERT INTO derma.patient_doctors(patient_id, doctor_id) VALUES ($1,$2)', [pid, did]);
    const { rows } = await pool.query(`
      SELECT u.id AS doctor_id, COALESCE(u.full_name,'Врач') AS name,
             dp.clinic, dp.city, dp.avatar_url
        FROM derma.users u
        LEFT JOIN derma.doctor_profiles dp ON dp.user_id=u.id
       WHERE u.id=$1`, [did]);
    res.json({ ok: true, code, doctor: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/doctor/attached', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const pid = await userIdByTg(req.tg);
    const { rows } = await pool.query(`
      SELECT dc.code, u.id AS doctor_id, COALESCE(u.full_name,'Врач') AS name,
             dp.clinic, dp.city, dp.avatar_url
        FROM derma.patient_doctors pd
        JOIN derma.users u ON u.id = pd.doctor_id
        LEFT JOIN derma.doctor_profiles dp ON dp.user_id = u.id
        LEFT JOIN derma.doctor_codes dc ON dc.doctor_id = u.id AND dc.active
       WHERE pd.patient_id=$1 AND pd.unbound_at IS NULL
       LIMIT 1`, [pid]);
    if (!rows.length) return res.json(null);
    res.json({ ok: true, code: rows[0].code || null, doctor: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/doctor/requests', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const did = await userIdByTg(req.tg);
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/doctor/requests/:id/accept', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const did = await userIdByTg(req.tg);
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
  } catch (e) { try{ await pool.query('ROLLBACK'); }catch{} res.status(500).json({ error: e.message }); }
});

app.post('/api/doctor/requests/:id/reject', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const did = await userIdByTg(req.tg);
    const id  = Number(req.params.id);
    const r = await pool.query(
      `UPDATE derma.doctor_requests
          SET status='rejected', decided_at=now()
        WHERE id=$1 AND doctor_id=$2 AND status='pending'`,
      [id, did]
    );
    if (!r.rowCount) return res.status(404).json({ error:'not found' });
    res.json({ ok:true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/doctor/attach', tgAuth, async (req, res) => {
  try {
    await pool.query('SET search_path = derma, public');
    const pid = await userIdByTg(req.tg);
    await pool.query('UPDATE derma.patient_doctors SET unbound_at=now() WHERE patient_id=$1 AND unbound_at IS NULL', [pid]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// === напоминалки (локальные настройки) — простая in-memory реализация ===
const reminders = Object.create(null); // приём
const stockCfg  = Object.create(null); // «мало капсул»

app.post('/api/reminder', tgAuth, async (req, res) => {
  const tgId = req.tg;
  const { enabled, time } = req.body || {};
  reminders[tgId] = { ...(reminders[tgId]||{}), enabled: !!enabled, time: String(time || '20:30').slice(0,5), _date:null, _sentToday:false, _lastMs:0 };
  res.json({ ok: true, data: reminders[tgId] });
});
app.post('/api/reminder/stock', tgAuth, async (req, res) => {
  const tgId = req.tg;
  const { enabled, time, threshold } = req.body || {};
  stockCfg[tgId] = { ...(stockCfg[tgId]||{}), enabled: !!enabled, time: String(time || '09:00').slice(0,5), threshold: Number.isFinite(+threshold) ? +threshold : 10, _date:null, _sent:false };
  res.json({ ok: true, data: stockCfg[tgId] });
});

// (тикеры можно упростить или отключить в dev)
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
  } catch (e) { console.error('Ошибка отправки напоминания:', e?.response?.body || e); }
}
// (для локального dev можно не запускать периодику)
if (process.env.ENABLE_REMINDERS === '1') {
  setInterval(() => {
    Promise.all([]).catch(e => console.error('reminders tick error', e));
  }, 60_000);
}

// === старт сервера ===
app.listen(PORT, () => {
  console.log('Server listening on', PORT);
});
