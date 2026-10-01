/* Read-only overview. Navigation stays on the current host; no cross-origin fetch. */
'use strict';
(() => {
  const names = {'main': 'Main', 'dev-1': 'Dev 1', 'dev-2': 'Dev 2'};
  const ports = {'main': 8501, 'dev-1': 8502, 'dev-2': 8503};
  const states = {idle: 'Disponible', running: 'En cours', waiting: 'En attente du labo',
    stopping: 'Arrêt en cours', deploying: 'Déploiement du scénario', teardown: 'Nettoyage',
    unavailable: 'Indisponible'};
  const cards = new Map();
  let pending = false;
  let lastCurrent = null;

  function render(data) {
    const section = document.getElementById('shared-activity');
    if (!data.enabled) { section.hidden = true; return; }
    section.hidden = false;
    lastCurrent = data.current;
    for (const id of Object.keys(names)) {
      const activity = data.instances.find(item => item.instance === id) || {state: 'unavailable'};
      let card = cards.get(id);
      if (!card) {
        card = document.createElement('a');
        card.className = 'activity-card';
        card.innerHTML = '<div class="activity-card-title"><strong></strong><span class="activity-current"></span></div>' +
          '<div class="activity-state"></div><div class="activity-detail"></div>';
        document.getElementById('activity-instances').appendChild(card);
        cards.set(id, card);
      }
      const current = id === data.current;
      const url = new URL('/', window.location.href);
      url.port = ports[id];
      if (current) { card.removeAttribute('href'); card.setAttribute('aria-current', 'page'); }
      else { card.href = url.href; card.removeAttribute('aria-current'); }
      const state = Object.hasOwn(states, activity.state) ? activity.state : 'unavailable';
      card.dataset.state = state;
      card.querySelector('strong').textContent = names[id];
      card.querySelector('.activity-current').textContent = current ? 'Vous êtes ici' : 'Ouvrir →';
      card.querySelector('.activity-state').textContent = states[state];
      const details = [];
      if (!['idle', 'unavailable'].includes(state)) {
        details.push(activity.scenario_id ? (/^\d+[a-z]?$/.test(activity.scenario_id) ? `Scénario S${activity.scenario_id}` : activity.scenario_id) : 'Audit réseau');
        if (activity.model) details.push(activity.model);
        if (state === 'running' && activity.phase > 0) details.push(`Phase ${activity.phase}`);
      }
      const detail = card.querySelector('.activity-detail');
      detail.textContent = details.join(' · ') || (state === 'idle' ? 'Aucune exécution active' : 'État impossible à vérifier');
      detail.title = detail.textContent;
    }
    const missing = data.instances.some(item => item.state === 'unavailable');
    document.getElementById('activity-freshness').textContent = missing
      ? 'Vue partielle · actualisation toutes les 5 s' : 'Actualisation toutes les 5 s';
  }

  async function refresh() {
    if (pending || document.hidden) return;
    pending = true;
    try {
      const response = await fetch('/api/activity', {cache: 'no-store', signal: AbortSignal.timeout(4000)});
      if (!response.ok) throw new Error('Activity unavailable');
      const data = await response.json();
      if (!Array.isArray(data.instances)) throw new Error('Invalid activity');
      render(data);
    } catch (_) {
      if (lastCurrent) render({enabled: true, current: lastCurrent,
        instances: Object.keys(names).map(instance => ({instance, state: 'unavailable'}))});
      else document.getElementById('shared-activity').hidden = false;
      document.getElementById('activity-freshness').textContent = 'Activité indisponible · nouvelle tentative automatique';
    } finally { pending = false; }
  }
  document.addEventListener('DOMContentLoaded', refresh);
  document.addEventListener('visibilitychange', refresh);
  setInterval(refresh, 5000);
})();
