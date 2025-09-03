/* Глобальный индикатор «препарат» для всех страниц */
(function(){
  const todayISO = () => {
    const d = new Date();
    d.setHours(0,0,0,0);
    return new Date(d.getTime() - d.getTimezoneOffset()*60000).toISOString().slice(0,10);
  };
  const diaryV1 = () => { try{ return JSON.parse(localStorage.getItem('rt.diary.v1')||'{}'); }catch(_){ return {}; } };

  function needsAlert(){
    const iso = todayISO();
    const rec = diaryV1()[iso] || null;

    // отмеченный пропуск считаем "не надо напоминать"
    const explicitlyMissed = !!(rec && (rec.miss === true || rec.taken === false)); // как в календаре
    if (explicitlyMissed) return false;

    // 1) дневник v1 (dose|mg)
    let mg = rec ? Number(rec.dose ?? rec.mg ?? 0) : 0;

    // 2) резерв — слепок, который главная уже пишет в LS
    // derma_today_iso/derma_today_mg выставляются на main в applyDiaryToMain
    if (!mg) {
      const lsIso = localStorage.getItem('derma_today_iso') || '';
      const lsMg  = Number(localStorage.getItem('derma_today_mg') || 0);
      if (lsIso.slice(0,10) === iso) mg = lsMg;
    }
    return mg <= 0;
  }

  function renderAll(){
    document.querySelectorAll('[data-pill-spot]').forEach(spot=>{
      spot.querySelectorAll('.pill-alert').forEach(n=>n.remove());
      if (!needsAlert()) return;
      const b = document.createElement('span');
      b.className = 'pill-alert';
      b.textContent = 'препарат';
      b.setAttribute('role','status');
      b.setAttribute('aria-label','Сегодняшняя доза ещё не принята');
      spot.appendChild(b);
    });
  }

  // Перерисовываем, когда дневник/слепок меняются (в т.ч. из другой вкладки)
  window.addEventListener('storage', (e)=>{
    if (['rt.diary.v1','rt.diary.v2','derma_today_iso','derma_today_mg'].includes(e.key)) renderAll();
  });
  document.addEventListener('visibilitychange', ()=>{ if(!document.hidden) renderAll(); });

  // Экспорт при необходимости
  window.pillAlert = { render: renderAll };
  renderAll();
})();
