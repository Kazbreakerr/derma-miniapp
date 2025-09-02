// /js/gates.js
const Gates = (() => {
  const K = { consent: 'rt.consent' }; // {derma:true, profile:true, plan:true}

  function readJSON(k, def={}) { try { return JSON.parse(localStorage.getItem(k)) || def; } catch { return def; } }
  function consent() { return readJSON(K.consent, {}); }

  function afterWelcome() {
    const c = consent();
    if (!c.derma)   return F.href('warnings.html');
    if (!c.profile) return F.href('profile.html');
    if (!c.plan)    return F.href('plan.html');
    return F.href('main.html');
  }

  return { consent, afterWelcome };
})();
