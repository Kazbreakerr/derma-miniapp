// ============ Lazy images + bg loader ============
// usage:
// <img class="lazy" width="800" height="450" data-src="img/pic.jpg" alt="">
// <div class="lazy-bg skeleton skeleton--panel" data-bg-src="img/bg.png" style="--sk-ratio:4/3"></div>

(function(){
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));

  const settings = {
    root: null,
    rootMargin: '300px 0px',   // подгружать заранее
    threshold: 0.01
  };

  const io = ('IntersectionObserver' in window)
    ? new IntersectionObserver(onIntersect, settings)
    : null;

  function onIntersect(entries){
    for (const e of entries){
      if (e.isIntersecting){
        loadElement(e.target);
        io.unobserve(e.target);
      }
    }
  }

  function observe(elem){
    if (!elem) return;
    if (io) io.observe(elem);
    else loadElement(elem); // фолбэк
  }

  function loadElement(el){
    if (el.classList.contains('lazy-bg')) return loadBg(el);
    if (el.tagName === 'IMG') return loadImg(el);
    // поддержка picture
    if (el.tagName === 'PICTURE'){
      const img = el.querySelector('img');
      return loadImg(img);
    }
  }

  function markLoaded(el){
    el.classList.add('is-loaded');
    // снять skeleton у ближайшего контейнера
    const sk = el.closest('.skeleton');
    if (sk) sk.classList.add('is-done');
    sk?.setAttribute('aria-busy','false');
  }

  // <img data-src / data-srcset / data-sizes>
  function loadImg(img){
    if (!img) return;
    try { img.decoding = 'async'; } catch(_){}
    img.loading = img.getAttribute('loading') || 'lazy';

    const src    = img.dataset.src;
    const srcset = img.dataset.srcset;
    const sizes  = img.dataset.sizes;

    if (srcset) img.srcset = srcset;
    if (sizes)  img.sizes  = sizes;
    if (src)    img.src    = src;

    if (img.complete && img.naturalWidth) {
      markLoaded(img);
    } else {
      img.addEventListener('load', ()=>markLoaded(img), { once:true });
      img.addEventListener('error', ()=>markLoaded(img), { once:true });
    }
  }

  // <div class="lazy-bg" data-bg-src="...">
  function loadBg(box){
    const url = box.dataset.bgSrc;
    if (!url) return markLoaded(box);

    // пока грузится — помечаем skeleton занятым
    box.setAttribute('aria-busy','true');

    const tmp = new Image();
    try { tmp.decoding = 'async'; } catch(_){}
    tmp.onload = () => {
      box.style.backgroundImage = `url("${url}")`;
      box.style.backgroundSize = box.dataset.bgSize || 'cover';
      box.style.backgroundPosition = box.dataset.bgPos || 'center';
      markLoaded(box);
    };
    tmp.onerror = () => markLoaded(box);
    tmp.src = url;
  }

  function refresh(){
    $$('.lazy, .lazy-bg').forEach(el => observe(el));
  }

  // API для динамической подмены bg
  function swapBg(el, url){
    if (url) el.dataset.bgSrc = url;
    el.classList.remove('is-loaded');
    el.closest('.skeleton')?.classList.remove('is-done');
    observe(el);
  }

  // Автозапуск
  window.addEventListener('DOMContentLoaded', refresh);

  // Экспорт
  window.LazyImg = { refresh, observe, swapBg };
})();
