<script>
// js/theme-router.js
window.ThemeRouter = (function () {
  const KEY = 'rt.settings';

  function getSettings() {
    try { return JSON.parse(localStorage.getItem(KEY) || '{}'); }
    catch { return {}; }
  }
  function setTheme(theme) {
    try {
      const s = getSettings();
      s.theme = theme;
      localStorage.setItem(KEY, JSON.stringify(s));
    } catch {}
    try { AppState.applyTheme(theme); } catch { document.documentElement.dataset.theme = theme; }
  }

  // Жёсткая тема страницы + авто-redirect на парную при несовпадении
  function hardTheme(pageTheme, counterpartHref) {
    const saved = getSettings().theme || pageTheme;
    // мгновенная отрисовка до загрузки CSS
    document.documentElement.dataset.theme = saved;
    if (saved !== pageTheme) {
      const qs = location.search || '';
      location.replace(counterpartHref + qs);
      return 'redirected';
    }
    // зафиксируем выбранную тему как актуальную
    setTheme(pageTheme);
    return 'ok';
  }

  // Привязка к переключателям темы на странице
  function bindSwitchers(counterpartHref) {
    document.querySelectorAll('[data-role="theme-switch"]').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        const cur = (document.documentElement.dataset.theme === 'dark') ? 'dark' : 'light';
        const next = cur === 'dark' ? 'light' : 'dark';
        setTheme(next);
        const qs = location.search || '';
        location.replace(counterpartHref + qs);
      });
    });
  }

  return { hardTheme, bindSwitchers, setTheme };
})();
</script>
