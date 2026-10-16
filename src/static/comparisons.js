/* One controlled pair, using the existing rules/LLM comparator. */
'use strict';
const ComparisonUI = (() => {
  const state = {ready:false, loading:false, options:null, selected:null, running:false,
    starting:false, polling:false, request:0, pageRequest:0, offset:0, limit:10,
    activeComparison:null, stopping:false, waiting:false};
  const el = id => document.getElementById(id);
  const esc = value => escapeHtml(String(value ?? ''));
  const measured = value => typeof value === 'number' && Number.isFinite(value);
  const labels = {pending:'En attente',running:'En cours',completed:'Terminée',failed:'Échec',
    stopped:'Arrêtée',partial:'Nettoyage incomplet',incomplete:'Non comparable',budget_exceeded:'Limite atteinte'};
  const statusLabel = value => labels[value] || 'État indisponible';
  const date = value => value && Number.isFinite(Date.parse(value)) ? new Intl.DateTimeFormat('fr-BE',
    {timeZone:'Europe/Brussels',dateStyle:'short',timeStyle:'short'}).format(new Date(value)) : 'Date indisponible';

  function number(value, kind='count') {
    if (!measured(value)) return '—';
    if (kind === 'percent') return `${(value * 100).toFixed(1)} %`;
    if (kind === 'money') return `$${value.toFixed(4)}`;
    if (kind === 'duration') {
      const seconds=Math.round(Math.abs(value));
      return `${value<0?'-':''}${Math.floor(seconds/60)} min ${seconds%60} s`;
    }
    return String(value);
  }

  function error(message) {
    el('comparison-error').textContent = message || '';
    el('comparison-error').hidden = !message;
  }

  function lock() {
    const busy = state.running || state.starting;
    el('comparison-form').querySelectorAll('input,select,button').forEach(item => {item.disabled=busy;});
    el('comparison-launch').disabled = busy || !state.options?.runtime?.available || !el('comparison-model').value;
    el('comparison-stop').hidden = !state.running || state.activeComparison !== state.selected;
    el('comparison-stop').disabled = state.stopping;
  }

  function reason(text) {
    const arm = text.startsWith('rules:') ? 'Règles : ' : text.startsWith('llm:') ? 'Agent LLM : ' : 'Paire : ';
    const value = text.replace(/^(rules|llm|pair):\s*/, '');
    const known = {'missing run':'audit non exécuté ou introuvable',
      'incomplete run, evidence or usage':'audit, preuves ou mesures incomplets',
      'incomplete analysis':'analyse incomplète',
      'missing evaluable stage artifacts':'résultats d’analyse ou de vérification insuffisants',
      'mutable knowledge configuration':'configuration des connaissances non figée',
      'incompatible evidence/process metrics':'contrats de preuve ou de mesure incompatibles',
      'unexpected model consumption':'consommation modèle inattendue'};
    if (known[value]) return arm + known[value];
    if (value.startsWith('incompatible ')) return arm + 'conditions différentes (' + value.slice(13) + ')';
    return arm + value;
  }

  function render(data) {
    el('comparison-detail').hidden = false;
    el('comparison-detail-heading').textContent = `S${data.scenario.id} · ${data.scenario.name}`;
    const duration = measured(data.config.max_duration_s)
      ? `${data.config.max_duration_s} secondes maximum par audit` : 'sans plafond de durée';
    const cost = measured(data.config.max_cost_usd)
      ? `${number(data.config.max_cost_usd,'money')} maximum par audit` : 'sans plafond de coût';
    el('comparison-context').textContent = `${date(data.started_at)} · ${data.public_environment?.target_network || 'Réseau enregistré dans l’inventaire'} · ${data.config.model} · ${data.order.map(p=>p==='rules'?'Règles':'Agent LLM').join(' puis ')} · ${data.config.max_tool_calls} appels maximum par audit · ${duration} · ${cost}`;
    const result = data.comparison;
    const finished = !['running','pending'].includes(data.status);
    el('comparison-results').hidden = !finished;
    el('comparison-outcome').textContent = (state.stopping && state.activeComparison===data.id
      ? 'Arrêt demandé. Attente de la fin des opérations en cours et du nettoyage. ' : state.waiting && state.activeComparison===data.id ? 'En attente du laboratoire partagé. ' : '') + `${statusLabel(data.status)}. ` + (result ? result.comparable
      ? 'Paire comparable selon les contrôles du protocole. L’écart est celui de cet essai uniquement.'
      : 'Paire non comparable : aucun écart ni classement n’est calculé.'
      : finished ? (data.error || 'Aucun résultat de comparaison disponible.') : 'Préparation et audits en cours. Les résultats seront évalués après la fin des deux audits.');
    const metrics = [
      ['Failles confirmées correctes','confirmed.true_positives'],
      ['Confirmations incorrectes','confirmed.false_positives'],
      ['Failles attendues manquées','confirmed.false_negatives'],
      ['Précision des confirmations','confirmed.precision','percent'],
      ['Rappel des confirmations','confirmed.recall','percent'],
      ['F1 des confirmations','confirmed.f1','percent'],
      ['Spécificité des contrôles sains','specificity','percent'],
      ['Appels d’outils','total_tool_calls'],['Erreurs d’outils','total_tool_errors'],
      ['Temps des audits','wall_clock_duration_s','duration'],['Coût LLM déclaré','total_cost_usd','money'],
      ['Tokens du modèle','total_tokens'],
    ];
    const cells = metrics.map(([title,key,kind]) => {
      const left = result?.arms?.rules?.metrics?.[key], right = result?.arms?.llm?.metrics?.[key];
      const delta = result?.comparable ? result.delta_llm_minus_rules?.[key] : null;
      const difference = !measured(delta) ? '—' : kind === 'percent'
        ? `${delta>0?'+':''}${(delta*100).toFixed(1)} points` : `${delta>0?'+':''}${number(delta,kind)}`;
      return `<tr><th scope="row">${esc(title)}</th><td>${number(left,kind)}</td><td>${number(right,kind)}</td><td>${difference}</td></tr>`;
    }).join('');
    const issues = result?.incomparability_reasons || [];
    const preflights = Object.entries(data.preflights || {}).map(([policy,item]) => `<li>${policy==='rules'?'Règles':'Agent LLM'} : précontrôle ${item.status==='valid'?'valide dans le périmètre vérifié':'invalide'} (${esc(date(item.checked_at))}).</li>`).join('');
    el('comparison-results').innerHTML = (data.error ? `<p class="procedure-error">${esc(data.error)}</p>` : '')
      + (issues.length ? `<ul class="comparison-reasons">${issues.map(issue=>`<li>${esc(reason(issue))}</li>`).join('')}</ul>` : '')
      + `<div class="procedure-table-scroll"><table class="procedure-table comparison-results"><thead><tr><th>Mesure</th><th>Règles</th><th>Agent LLM</th><th>Écart LLM − règles</th></tr></thead><tbody>${cells}</tbody></table></div>`
      + '<p class="procedure-help">— : mesure absente ou non définie. Pour un contrôle sans faille, le F1 reste non défini ; lire la spécificité. Le temps concerne les audits, hors préparation et nettoyage. Les coûts déclarés ou estimés concernent l’usage LLM, hors infrastructure et travail humain.</p>'
      + `<p class="procedure-help">${esc(data.environment_scope)}</p>${preflights ? `<ul class="procedure-help">${preflights}</ul>` : ''}`
      + '<p class="procedure-help">Une seule paire ne démontre pas une supériorité générale. Les preuves et les propriétés attendues nécessitent une revue indépendante.</p>'
      + `<div class="comparison-actions">${Object.entries(data.arms).filter(([,id])=>id).map(([policy,id])=>`<button type="button" class="procedure-secondary" data-comparison-run="${esc(id)}">Résultats ${policy==='rules'?'des règles':'du modèle'}</button>`).join('')}<a class="procedure-permalink" href="/api/comparisons/${encodeURIComponent(data.id)}/download">Exporter le résultat JSON</a><a class="procedure-permalink" href="#comparison/${encodeURIComponent(data.id)}">Lien vers cette comparaison</a></div>`;
    el('comparison-results').querySelectorAll('[data-comparison-run]').forEach(button=>button.addEventListener('click',()=>{switchView('main'); viewRun(button.dataset.comparisonRun);}));
    el('comparison-steps').innerHTML = data.steps.map(step=>`<li data-status="${esc(step.status)}"><span class="procedure-step-mark" aria-hidden="true"></span><div><strong>${esc(step.label)}</strong></div><span class="procedure-step-status">${esc(statusLabel(step.status))}</span></li>`).join('');
    el('comparison-steps-panel').open = !finished;
  }

  async function showPair(identifier, focus=false) {
    state.selected = identifier;
    const request = ++state.request;
    const data = await fetchJSON(`/api/comparisons/${encodeURIComponent(identifier)}`);
    if (request !== state.request || state.selected !== identifier) return;
    if (!data) {error('Résultat indisponible. Actualisez pour réessayer.');return;}
    render(data);
    lock();
    window.history.replaceState(null,'',`#comparison/${encodeURIComponent(identifier)}`);
    if (focus) {el('comparison-detail').scrollIntoView({block:'start'});el('comparison-detail-heading').focus({preventScroll:true});}
  }

  async function history() {
    const request = ++state.pageRequest;
    const data = await fetchJSON(`/api/comparisons?offset=${state.offset}&limit=${state.limit}`);
    if (request !== state.pageRequest) return;
    if (!Array.isArray(data?.items)) {el('comparison-history-message').textContent='Historique indisponible. Actualisez pour réessayer.';return;}
    el('comparison-history-message').textContent=data.total?'':'Aucune comparaison enregistrée. Choisissez un scénario et un modèle pour préparer la première paire.';
    el('comparison-rows').innerHTML=data.items.map(item=>`<tr><td><strong>S${esc(item.scenario.id)} · ${esc(item.scenario.name)}</strong><span>${esc(date(item.started_at))}</span></td><td>${esc(item.config.model)}</td><td>${esc(statusLabel(item.status))}</td><td>${item.comparable===true?'Comparable':item.comparable===false?'Non comparable':'En attente'}</td><td><button class="procedure-secondary" type="button" data-pair="${esc(item.id)}">Consulter</button></td></tr>`).join('');
    el('comparison-rows').querySelectorAll('[data-pair]').forEach(button=>button.addEventListener('click',()=>showPair(button.dataset.pair,true)));
    el('comparison-page').textContent=data.total?`${data.offset+1}–${data.offset+data.items.length} sur ${data.total}`:'0 résultat';
    el('comparison-prev').disabled=state.offset===0;
    el('comparison-next').disabled=state.offset+state.limit>=data.total;
  }

  async function sync() {
    if (state.polling) return;
    state.polling=true;
    try {
      const status=await fetchJSON('/api/pipeline/status');
      if (!status) {error('Connexion au suivi interrompue. Nouvelle vérification à la prochaine actualisation.');return;}
      state.running=Boolean(status.running || status.teardown_running);
      state.activeComparison=status.running && status.runner_kind==='comparison' ? status.comparison_id : null;
      state.stopping=Boolean(status.stopping);
      state.waiting=Boolean(status.lab_waiting);
      lock();
      if (status.running && status.runner_kind==='comparison' && status.comparison_id && !state.selected) state.selected=status.comparison_id;
      if (state.selected) await showPair(state.selected);
      await history();
    } finally {state.polling=false;}
  }

  async function open() {
    if (state.loading) return;
    state.loading=true;
    let focusRoute=false;
    try {
      if (!state.ready) {
        const [options,models]=await Promise.all([fetchJSON('/api/comparisons/options'),fetchJSON('/api/models')]);
        if (!options || !Array.isArray(models?.models)) throw new Error('Configuration de comparaison indisponible. Actualisez pour réessayer.');
        state.options=options;
        el('comparison-scenario').innerHTML='<option value="">Choisir un scénario…</option>'+options.scenarios.map(item=>`<option value="${esc(item.id)}">S${esc(item.id)} · ${esc(item.name)}</option>`).join('');
        const available=models.models.filter(item=>item.available!==false);
        el('comparison-model').innerHTML='<option value="">Choisir un modèle…</option>'+available.map((item,i)=>`<option value="${i}" data-provider="${esc(item.provider)}" data-model="${esc(item.id)}">${esc(item.label || item.id)}</option>`).join('');
        el('comparison-runtime').textContent=options.runtime.reason || '';
        el('comparison-runtime').hidden=options.runtime.available;
        if (options.runtime.available && !available.length) {
          el('comparison-runtime').textContent='Aucun modèle disponible. Configurez un modèle et son fournisseur dans « Modèles ».';
          el('comparison-runtime').hidden=false;
        }
        state.ready=true;
        const route=window.location.hash.match(/^#comparison\/([0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}_[a-f0-9]{12})$/);
        if (route) {state.selected=route[1];focusRoute=true;}
      }
      await sync();
      if (focusRoute && !el('comparison-detail').hidden) {
        el('comparison-detail').scrollIntoView({block:'start'});el('comparison-detail-heading').focus({preventScroll:true});
      }
    } catch (exception) {error(exception.message);}
    finally {state.loading=false;lock();}
  }

  async function launch(event) {
    event.preventDefault();
    if (state.starting || state.running) return;
    error('');
    const selected=el('comparison-model').selectedOptions[0];
    const body={runner_kind:'comparison',scenario_id:el('comparison-scenario').value,
      provider:selected?.dataset.provider,model:selected?.dataset.model,
      max_tool_calls:Number(el('comparison-calls').value),max_duration_s:null,
      max_cost_usd:null,comparison_order:el('comparison-order').value};
    if (!body.scenario_id || !body.provider || !body.model) {error('Choisissez un scénario et un modèle.');return;}
    state.starting=true;lock();
    try {
      const response=await adminFetch('/api/pipeline/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      const data=await response.json();
      if (!response.ok) throw new Error(_formatErrDetail(data.detail || 'Lancement refusé.'));
      state.selected=data.comparison_id;state.activeComparison=data.comparison_id;state.running=true;
      document.getElementById('btn-start').disabled=true;
      lockRunnerChoice(true);startSSE();
      await showPair(data.comparison_id,true);await history();
    } catch (exception) {error(exception.message);}
    finally {state.starting=false;lock();}
  }

  document.addEventListener('DOMContentLoaded',()=>{
    el('comparison-form').addEventListener('submit',launch);
    el('comparison-model').addEventListener('change',lock);
    el('comparison-scenario').addEventListener('change',()=>{
      const item=state.options?.scenarios.find(s=>s.id===el('comparison-scenario').value);
      el('comparison-target').textContent=item?`${item.target_network} · ${item.devices} équipements TCP prévus ; disponibilité contrôlée avant chaque audit.`:'';
    });
    el('comparison-refresh').addEventListener('click',async()=>{state.ready=false;await open();});
    el('comparison-prev').addEventListener('click',()=>{state.offset=Math.max(0,state.offset-state.limit);history();});
    el('comparison-next').addEventListener('click',()=>{state.offset+=state.limit;history();});
    el('comparison-stop').addEventListener('click',async()=>{
      if (state.activeComparison!==state.selected) return;
      const response=await adminFetch('/api/pipeline/stop',{method:'POST'});
      if (!response.ok) {error('Arrêt refusé. Une session administrateur valide est nécessaire.');return;}
      el('comparison-outcome').textContent='Arrêt demandé. Attente de la fin des opérations en cours et du nettoyage.';
      state.stopping=true;lock();
    });
    setInterval(()=>{if(state.ready && !document.hidden && !el('comparison-view').hidden)sync();},4000);
  });
  return {open,showPair,render,number,reason};
})();
