/* RT Tabbar injector + auto active + auto spacer height */
(function(){
  function addTgParamToLinks(root){
    try{
      const sp = new URLSearchParams(location.search);
      const tg = sp.get('tg');
      if(!tg) return;

      root.querySelectorAll('a.nav-item[href]').forEach(a=>{
        const raw = a.getAttribute('href') || '';
        const parts = raw.split('#');
        const baseAndQs = parts[0];
        const hash = parts[1] ? ('#' + parts[1]) : '';

        const [path, qs] = baseAndQs.split('?');
        const q = new URLSearchParams(qs || '');
        if(!q.get('tg')) q.set('tg', tg);

        const qstr = q.toString();
        a.setAttribute('href', path + (qstr ? ('?' + qstr) : '') + hash);
      });
    }catch(_){}
  }

  function setActive(root){
    const here = (location.pathname.split('/').pop() || '').toLowerCase();
    if(!here) return;

    root.querySelectorAll('a.nav-item[href]').forEach(a=>{
      const href = (a.getAttribute('href') || '').split('#')[0].split('?')[0].toLowerCase();
      if(href && href.endsWith(here)) a.classList.add('active');
    });
  }

  function fitSpacer(root){
    const navEl = root.querySelector('.navbar');
    const spacer = root.querySelector('.page-bottom-spacer');
    if(!navEl || !spacer) return;

    function calc(){
      const h = Math.ceil(navEl.getBoundingClientRect().height);
      spacer.style.setProperty('--nav-h', h + 'px');
    }

    calc();
    window.addEventListener('resize', calc);
    window.addEventListener('orientationchange', calc);
    if('ResizeObserver' in window){
      new ResizeObserver(calc).observe(navEl);
    }
  }

  async function inject(){
    // mount point (recommended): <div id="rtTabbarMount"></div>
    const mount = document.getElementById('rtTabbarMount') || document.body;

    // prevent duplicates
    if(document.querySelector('.navbar')) return;

    try{
      const res = await fetch('rt_tabbar.html', { cache: 'no-store' });
      const html = await res.text();

      const wrap = document.createElement('div');
      wrap.innerHTML = html.trim();

      // append all nodes to mount
      while(wrap.firstChild){
        mount.appendChild(wrap.firstChild);
      }

      // setup
      addTgParamToLinks(mount);
      setActive(mount);
      fitSpacer(mount);
    }catch(e){
      // if fetch is blocked for any reason, fail silently
      console.warn('RT Tabbar: cannot load rt_tabbar.html', e);
    }
  }

  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', inject);
  }else{
    inject();
  }
})();
