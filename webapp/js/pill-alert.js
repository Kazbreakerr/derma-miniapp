(function(){
  const SPOTS = document.querySelectorAll('[data-pill-spot]');
  if (!SPOTS.length) return;

  function todayISO(){
    const d = new Date();
    d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
    return d.toISOString().slice(0,10);
  }

  // Определяем, выпита ли сегодняшняя доза
  function getTodayMg(){
    const iso = todayISO();

    // 1) быстрый путь из main (если уже был открыт)
    try{
      const tIso = localStorage.getItem('derma_today_iso');
      if (tIso === iso){
        const mg = Number(localStorage.getItem('derma_today_mg') || 0);
        if (mg > 0) return mg;
      }
    }catch(_){}

    // 2) читаем дневник (v1)
    try{
      const diary = JSON.parse(localStorage.getItem('rt.diary.v1') || '{}');
      const rec = diary[iso];
      if (rec){
        if (rec.miss === true || rec.taken === false) return 0;
        const mg = Number(rec.dose ?? rec.mg ?? 0);
        return mg || 0;
      }
    }catch(_){}

    // 3) ничего не нашли — считаем, что не выпито
    return 0;
  }

  function render(){
    const mg = getTodayMg();
    SPOTS.forEach(spot => {
      let badge = spot.querySelector('.pill-alert');
      if (mg > 0){                // выпито — убираем
        if (badge) badge.remove();
        return;
      }
      if (!badge){                // не выпито — показываем
        badge = document.createElement('span');
        badge.className = 'pill-alert';
        badge.textContent = 'препарат';
        badge.title = 'Сегодня доза не отмечена';
        spot.appendChild(badge);
      }
    });
  }

  render();

  // Обновляться, если что-то поменяли в другом экране
  window.addEventListener('storage', (e)=>{
    if (['rt.diary.v1','derma_today_mg','derma_today_iso'].includes(e.key)) render();
  });

  // На всякий случай оставим ручной триггер
  window.renderPillAlert = render;
})();
