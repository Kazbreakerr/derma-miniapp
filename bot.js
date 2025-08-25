require('dotenv').config();
const TelegramBot = require('node-telegram-bot-api');



const BOT_TOKEN = process.env.BOT_TOKEN;
const WEBAPP_URL = process.env.WEBAPP_URL || '';
if (!BOT_TOKEN) throw new Error('BOT_TOKEN is empty');

// БЕЗ polling — дальше работаем через вебхук
const usePolling = !process.env.WEBAPP_URL;  
const bot = new TelegramBot(BOT_TOKEN, { polling: false });

// /start — кнопка открытия мини-аппа
bot.onText(/\/start(?:\s+(.+))?/, (msg, match) => {
  const ref = match && match[1] ? match[1] : '';
  bot.sendMessage(msg.chat.id, 'Откройте Derma Mini-App:', {
    reply_markup: {
      inline_keyboard: [[
        { text: 'Открыть мини-апп', web_app: { url: WEBAPP_URL + (ref ? ('?ref=' + encodeURIComponent(ref)) : '') } }
      ]]
    }
  });
});

// Если фронт шлёт данные через Telegram.WebApp.sendData
bot.on('web_app_data', (msg) => {
  console.log('web_app_data from', msg.from?.id, msg.web_app_data?.data);
});

module.exports = { bot, WEBAPP_URL };