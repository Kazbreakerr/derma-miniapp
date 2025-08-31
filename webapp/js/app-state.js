/* js/app-state.js
   Единое хранилище для приложения RoaccutaneTracker.
   Ключи localStorage:
     - rt.settings   → { theme, telegram:{chatId}, doctor:{code,linked}, consent:{doctorViewDiary} }
     - rt.reminders  → [{id:'main', time:'HH:MM', enabled:true}]
     - rt.profile    → { allergies: [] }
     - rt.diary.v2   → (как есть сейчас у тебя)
*/

(() => {
  const NS = 'rt';
  const KEYS = {
    settings: `${NS}.settings`,
    reminders: `${NS}.reminders`,
    profile: `${NS}.profile`,
    diaryV2: `${NS}.diary.v2`,
  };

  // Значения по умолчанию — бережные (ничего не ломают)
  const DEFAULTS = {
    [KEYS.settings]: {
      theme: 'dark',
      telegram: { chatId: null },
      doctor: { code: null, linked: false },
      consent: { doctorViewDiary: false },
    },
    [KEYS.reminders]: [
      { id: 'main', time: '20:30', enabled: false },
    ],
    [KEYS.profile]: {
      allergies: [],
      avatar: null,
    },
    // diary.v2 не трогаем — у каждого своя структура; если нет — создадим пустую
    [KEYS.diaryV2]: null,
  };

  // --- utils ---
  const safeParse = (s, fb = null) => {
    try { return JSON.parse(s); } catch { return fb; }
  };
  const clone = v => (v == null ? v : JSON.parse(JSON.stringify(v)));

  function readRaw(key) {
    const raw = localStorage.getItem(key);
    return safeParse(raw, null);
  }

  function writeRaw(key, value) {
    const prev = readRaw(key);
    localStorage.setItem(key, JSON.stringify(value));
    // Событие изменения внутри этой вкладки
    window.dispatchEvent(new CustomEvent('rt:changed', {
      detail: { key, value: clone(value), prev: clone(prev), local: true },
    }));
  }

  // Инициализация (дефолты + миграции)
  function ensureDefaults() {
    for (const key of Object.values(KEYS)) {
      const cur = readRaw(key);
      if (cur === null) {
        writeRaw(key, DEFAULTS[key]);
      }
    }
  }

  // Простая миграция: если найдём старый ключ rt.diary — сохраним как rt.diary.v2
  function migrate() {
    const old = readRaw(`${NS}.diary`);
    if (old && !readRaw(KEYS.diaryV2)) {
      writeRaw(KEYS.diaryV2, old);
    }
  }

  // Публичные API
  function get(keyName) {
    const key = KEYS[keyName] || keyName; // можно передавать и полный ключ
    const val = readRaw(key);
    if (val === null && DEFAULTS[key] !== undefined) {
      writeRaw(key, DEFAULTS[key]);
      return clone(DEFAULTS[key]);
    }
    return clone(val);
  }

  function set(keyName, value) {
    const key = KEYS[keyName] || keyName;
    writeRaw(key, value);
    return clone(value);
  }

  // Обновление по функции
  function update(keyName, updater) {
    const cur = get(keyName);
    const next = updater(clone(cur));
    set(keyName, next);
    return clone(next);
  }

  // Патч (неглубокий merge объектов)
  function patch(keyName, partial) {
    return update(keyName, cur => Object.assign({}, cur || {}, partial));
  }

  // Подписка на изменения конкретного ключа
  function subscribe(keyName, handler) {
    const key = KEYS[keyName] || keyName;

    const onCustom = (e) => {
      if (e.detail && e.detail.key === key) handler(e.detail);
    };
    const onStorage = (e) => {
      if (e.key === key) {
        handler({
          key,
          value: safeParse(e.newValue),
          prev: safeParse(e.oldValue),
          local: false,
        });
      }
    };
    window.addEventListener('rt:changed', onCustom);
    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener('rt:changed', onCustom);
      window.removeEventListener('storage', onStorage);
    };
  }

  // Удобные хелперы для напоминаний
  function getMainReminder() {
    const list = get('reminders') || [];
    return list.find(r => r.id === 'main') || { id:'main', time:'20:30', enabled:false };
  }
  function setMainReminder({ time, enabled }) {
    update('reminders', list => {
      const arr = Array.isArray(list) ? list.slice() : [];
      const idx = arr.findIndex(r => r.id === 'main');
      const next = { id:'main', time: time ?? '20:30', enabled: enabled ?? true };
      if (idx === -1) arr.push(next); else arr[idx] = Object.assign({}, arr[idx], next);
      return arr;
    });
  }

  // Мини-хелпер темы (без UI — просто запись + дата-атрибут)
  function applyTheme(theme) {
    const t = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = t;
    patch('settings', { theme: t });
  }

  // Запуск
  ensureDefaults();
  migrate();

  // Экспорт
  window.AppState = {
    KEYS,
    get, set, update, patch, subscribe,
    reminders: { getMain: getMainReminder, setMain: setMainReminder },
    applyTheme,
  };
})();
