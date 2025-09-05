// worker.js
require('dotenv').config();
const { Pool } = require('pg');
const { bot, WEBAPP_URL } = require('./bot'); // тот же bot.js, что и в server.js

// --- DB pool ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// --- helpers ---
function appUrlFor(tgId) {
  const base = (process.env.WEBAPP_URL || WEBAPP_URL || '').replace(/\/+$/, '');
  return `${base}/main?tg=${tgId}`;
}

async function sendReminder(tgId, text) {
  try {
    await bot.sendMessage(tgId, text, {
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [{ text: 'Отметить приём 💊', web_app: { url: appUrlFor(tgId) } }],
          [{ text: 'Открыть в браузере', url: appUrlFor(tgId) }],
        ],
      },
    });
  } catch (e) {
    console.error('Ошибка отправки напоминания:', e?.response?.body || e);
  }
}

// --- кеш таймзон ---
const userTzCache = new Map();
async function getUserTzByTg(tgId) {
  if (userTzCache.has(tgId)) return userTzCache.get(tgId);
  await pool.query('SET search_path = derma, public');
  const r = await pool.query('SELECT tz FROM derma.users WHERE tg_id=$1::bigint', [Number(tgId)]);
  const tz = r.rows[0]?.tz || 'Europe/Moscow';
  userTzCache.set(tgId, tz);
  return tz;
}

function nowParts(tz) {
  const p = new Intl.DateTimeFormat('en-GB', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).formatToParts(new Date());
  const g = t => p.find(x => x.type === t)?.value;
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

// --- напоминания ---
const reminders = Object.create(null);   // 💊 приём
const stockCfg  = Object.create(null);   // ⚠️ мало капсул

// тикер приёма
async function tickDoseReminders() {
  const REPEAT_MS = Number(process.env.REM_MS || (3 * 60 * 60 * 1000)); // дефолт: 3ч
  const { rows } = await pool.query('SELECT tg_id FROM derma.users WHERE tg_id IS NOT NULL');

  for (const u of rows) {
    const tgId = u.tg_id;
    if (!reminders[tgId]) {
      // дефолт — 20:30
      reminders[tgId] = { enabled: true, time: '20:30', _date: null, _sentToday: false, _lastMs: 0 };
    }
    const cfg = reminders[tgId];
    if (!cfg.enabled) continue;

    const tz = await getUserTzByTg(tgId);
    const { date, time } = nowParts(tz);
    if (cfg._date !== date) { cfg._date = date; cfg._sentToday = false; cfg._lastMs = 0; }

    if (await hasTakenToday(tgId, tz)) continue;

    const dueFirst  = !cfg._sentToday && time >= cfg.time;
    const dueRepeat = cfg._sentToday && (!cfg._lastMs || Date.now() - cfg._lastMs >= REPEAT_MS);

    if (dueFirst || dueRepeat) {
      await sendReminder(tgId, 'Пора принять препарат 💊\nЕсли уже выпили — отметьте приём в трекере.');
      cfg._sentToday = true;
      cfg._lastMs = Date.now();
    }
  }
}

// тикер капсул
async function tickStockReminders() {
  const { rows } = await pool.query('SELECT tg_id FROM derma.users WHERE tg_id IS NOT NULL');
  for (const u of rows) {
    const tgId = u.tg_id;
    if (!stockCfg[tgId]) {
      stockCfg[tgId] = { enabled: true, time: '09:00', threshold: 10, _date: null, _sent: false };
    }
    const cfg = stockCfg[tgId];
    if (!cfg.enabled) continue;

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

// --- запуск ---
setInterval(() => {
  Promise.all([ tickDoseReminders(), tickStockReminders() ])
    .catch(e => console.error('reminders tick error', e));
}, 60 * 1000);

console.log('Worker запущен:', new Date().toISOString());
