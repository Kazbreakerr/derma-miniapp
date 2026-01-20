require('dotenv').config();
const TelegramBot = require('node-telegram-bot-api');

const BOT_TOKEN = String(process.env.BOT_TOKEN || '').trim();
const WEBAPP_URL = String(process.env.WEBAPP_URL || '').trim() || 'https://derma-miniapp.onrender.com';
if (!BOT_TOKEN) throw new Error('BOT_TOKEN is empty');

// На Render у тебя обычно webhook, локально — polling.
// Текущая логика "polling если нет WEBAPP_URL" — неверная (WEBAPP_URL у тебя как раз должен быть всегда).
const usePolling = !process.env.TELEGRAM_WEBHOOK && !process.env.RENDER && !process.env.RENDER_SERVICE_ID;
const bot = new TelegramBot(BOT_TOKEN, { polling: usePolling });

function baseUrl() {
  return WEBAPP_URL.replace(/\/+$/, '');
}

function appUrl(q = {}) {
  const u = new URL(baseUrl() + '/');
  Object.entries(q).forEach(([k, v]) => {
    if (v !== undefined && v !== null && String(v).length) u.searchParams.set(k, String(v));
  });
  return u.toString();
}

function mainKeyboard() {
  return {
    keyboard: [
      [{ text: '🚀 Открыть Retiora' }],
      [{ text: '✅ Сегодня' }, { text: '📅 Календарь' }],
      [{ text: '❓ FAQ' }, { text: '🆘 Поддержка' }],
    ],
    resize_keyboard: true,
    persistent: true,
  };
}

function openAppInline(tab) {
  // tab — это просто маркер, чтобы в будущем ты могла сделать ?tab=today и открывать нужный экран.
  // Сейчас даже если ты не используешь tab — оно не мешает, query протащится дальше.
  const url = appUrl(tab ? { tab } : {});
  return {
    inline_keyboard: [[
      { text: '🚀 Открыть приложение', web_app: { url } },
      { text: '🌐 Открыть в браузере', url },
    ]],
  };
}

// ===== Commands =====
bot.onText(/\/start(?:\s+(.+))?/, (msg, match) => {
  const ref = match && match[1] ? String(match[1]) : '';
  const chatId = msg.chat.id;

  const text =
`Привет! Я Retiora — трекер ретиноидов/изотретиноина.

Я помогу быстро открыть приложение, перейти к нужным разделам и найти ответы в FAQ.

Нажми кнопку ниже 👇`;

  bot.sendMessage(chatId, text, {
    reply_markup: openAppInline(ref ? 'from_start' : undefined),
  }).then(() => {
    bot.sendMessage(chatId, 'Меню:', { reply_markup: mainKeyboard() });
  }).catch(() => {});
});

bot.onText(/\/app/, (msg) => {
  bot.sendMessage(msg.chat.id, 'Открываю Retiora:', {
    reply_markup: openAppInline('today'),
  });
});

bot.onText(/\/help/, (msg) => {
  bot.sendMessage(msg.chat.id,
`Что я умею:
• Открыть Retiora
• Быстро перейти к «Сегодня» и календарю
• Дать FAQ и контакты поддержки

Основная работа (дозы/календарь/дневник/врач) — внутри приложения.`,
  { reply_markup: openAppInline() });
});

bot.onText(/\/faq/, (msg) => {
  bot.sendMessage(msg.chat.id,
`FAQ:
1) Пропуск дозы — обычно не удваивают без указаний врача.
2) Сухость — уход + защита губ/кожи.
3) Анализы — сдавать по плану врача.

Хочешь — сделаю FAQ «кнопками по темам» прямо в боте.`,
  { reply_markup: openAppInline('faq') });
});

bot.onText(/\/support/, (msg) => {
  bot.sendMessage(msg.chat.id,
`Поддержка:
Пришли, пожалуйста:
• что не работает
• шаги воспроизведения
• скрин/видео
• устройство и версия iOS/Android

И мы разберёмся быстрее.`,
  {
    reply_markup: {
      inline_keyboard: [
        // замени на свой контакт/чат
        [{ text: '📩 Написать в поддержку', url: 'https://t.me/your_support' }],
        [{ text: '🚀 Открыть Retiora', web_app: { url: appUrl({ tab: 'today' }) } }],
      ],
    },
  });
});

// ===== Menu кнопки (текстовые) =====
bot.on('message', (msg) => {
  const chatId = msg.chat.id;
  const t = String(msg.text || '').trim();

  if (t === '🚀 Открыть Retiora') {
    return bot.sendMessage(chatId, 'Открываю:', { reply_markup: openAppInline('today') });
  }
  if (t === '✅ Сегодня') {
    return bot.sendMessage(chatId, 'Сегодня:', { reply_markup: openAppInline('today') });
  }
  if (t === '📅 Календарь') {
    return bot.sendMessage(chatId, 'Календарь:', { reply_markup: openAppInline('calendar') });
  }
  if (t === '❓ FAQ') {
    return bot.sendMessage(chatId, 'FAQ:', { reply_markup: openAppInline('faq') });
  }
  if (t === '🆘 Поддержка') {
    return bot.sendMessage(chatId, 'Поддержка:', { reply_markup: { inline_keyboard: [[{ text: '📩 Написать', url: 'https://t.me/your_support' }]] } });
  }
});

bot.on('web_app_data', (msg) => {
  console.log('web_app_data from', msg.from?.id, msg.web_app_data?.data);
});

module.exports = { bot, WEBAPP_URL };
