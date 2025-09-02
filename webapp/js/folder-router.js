// /js/folder-router.js
const F = (() => {
  // Если сервер отдает /webapp как корень сайта, BASE='/' — оставить.
  // Если отдаешь иначе, поставь свой префикс, например '/webapp/'
  const BASE = '/';

  const allowed = new Set([
    // базовый онбординг
    'splash-video.html','welcome-rt.html','warnings.html','profile.html','plan.html','main.html','reset.html',
    // твои страницы
    'labs.html','calendar.html','faq.html','diary.html','myprofile.html',
    // при необходимости добавь doctor*.html и т.п.
  ]);

  function themeFromPath(path = location.pathname) {
    return path.includes('/light/') ? 'light' : 'dark';
  }
  function otherTheme(t = themeFromPath()) { return t === 'light' ? 'dark' : 'light'; }
  function folder(t = themeFromPath()) { return `${BASE}${t}/`; }

  function pageName(path = location.pathname) {
    const p = path.split('/').pop();
    return p || 'index.html';
  }

  function href(page, t) {
    return folder(t ?? themeFromPath()) + page;
  }

  function nextUrl(next, t = themeFromPath()) {
    try {
      const url = new URL(next, location.href);
      const file = url.pathname.split('/').pop();
      if (!allowed.has(file)) return href('welcome-rt.html', t);
      return href(file + url.search + url.hash, t);
    } catch {
      const file = (next || '').split('?')[0];
      return allowed.has(file) ? href(next, t) : href('welcome-rt.html', t);
    }
  }

  function switchTheme(toTheme) {
    const current = pageName();
    location.href = href(current + location.search + location.hash,
                         toTheme ?? otherTheme());
  }

  function goto(page) { location.href = href(page); }

  // Автопривязка ссылок и кнопок
  function initLinks() {
    document.querySelectorAll('a[data-page]').forEach(a => {
      const file = a.dataset.page.endsWith('.html') ? a.dataset.page : `${a.dataset.page}.html`;
      a.setAttribute('href', href(file));
    });
    document.querySelectorAll('[data-switch-theme]').forEach(btn => {
      btn.addEventListener('click', () => switchTheme());
    });
  }

  // Редирект из корня (index.html)
  function rootRedirect() {
    const last = localStorage.getItem('rt.lastTheme') || 'dark';
    location.replace(href('splash-video.html?next=welcome-rt.html', last));
  }

  return { href, nextUrl, goto, switchTheme, initLinks, themeFromPath, otherTheme, rootRedirect };
})();
