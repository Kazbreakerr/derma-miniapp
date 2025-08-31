// js/partials.js
(function(){
  async function inject(host){
    const url = host.getAttribute('data-include');
    if(!url) return;
    try{
      const res  = await fetch(url, { cache: 'no-cache' });
      const html = await res.text();
      host.innerHTML = html;
      host.removeAttribute('data-include');

      // Подсветка активной ссылки в нижней навигации
      const navRoot = host.querySelector('[data-bottom-nav]');
      if (navRoot) {
        const cur = location.pathname.split('/').pop().toLowerCase();
        navRoot.querySelectorAll('a[href]').forEach(a=>{
          const file = a.getAttribute('href').split('/').pop().toLowerCase();
          if (file === cur) {
            a.classList.add('active');
            a.setAttribute('aria-current','page');
          }
        });
      }

      // Проставляем версию внутри вставленного фрагмента
      const ver = (window.RT_VERSION || '0.5');
      host.querySelectorAll('[data-rt-version]').forEach(s => s.textContent = ver);
    }catch(err){
      console.error('Include failed:', url, err);
    }
  }

  async function loadPartials(){
    const nodes = document.querySelectorAll('[data-include]');
    for (const n of nodes) await inject(n);
    // На всякий — проставим версию и вне партиалов
    const ver = (window.RT_VERSION || '0.5');
    document.querySelectorAll('[data-rt-version]').forEach(s => s.textContent = ver);
  }

  // Экспорт
  window.loadPartials = loadPartials;
})();
