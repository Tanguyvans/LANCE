/* Guided operations using the existing runner, evidence and cancellation APIs. */
'use strict';
const ProcedureUI = (() => {
  const state = {catalogue: [], selected: null, steps: [], runId: null, liveId: null,
    running: false, starting: false, loading: false, request: 0, ready: false, status: 'pending',
    viewingHistory: false, syncing: false, controlStatus: null, section: 'results',
    pageOffset: 0, pageLimit: 10, pageRequest: 0, filterProcedure: '', filterTarget: '',
    includeDiagnostics: false};
  const byId = id => document.getElementById(id);
  const esc = value => escapeHtml(String(value ?? ''));
  const labels = {pending: 'En attente', waiting: 'Attente du laboratoire', running: 'En cours',
    completed: 'Terminé', done: 'Terminé', partial: 'Partiel', failed: 'Échec', stopped: 'Arrêté',
    budget_exceeded: 'Limite atteinte', skipped: 'Non exécuté', stopping: 'Arrêt demandé',
    incomplete: 'Incomplet', not_run: 'Non exécuté', confirmed: 'Confirmé par les preuves',
    not_confirmed: 'Non confirmé', error: 'Erreur de contrôle', not_targeted: 'Non ciblé',
    up: 'Répond aux sondes', observed: 'Observé', not_observed: 'Fin non observée'};
  const label = value => labels[value] || 'État indisponible';
  const list = value => Array.isArray(value) ? value : [];
  const measured = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
  const coverageLabels = {collected:'Collecte terminée', checked:'Phases de contrôle terminées',
    partial:'Collecte ou contrôles incomplets', running:'Observations intermédiaires',
    unavailable:'Données indisponibles', diagnostic:'Diagnostic hors ligne'};

  function formatDuration(value) {
    if (!measured(value)) return '—';
    const seconds = Math.round(value);
    if (seconds < 60) return `${seconds} s`;
    return `${Math.floor(seconds / 60)} min ${String(seconds % 60).padStart(2, '0')} s`;
  }

  function formatDate(value, fallback) {
    if (value && Number.isFinite(Date.parse(value))) return new Intl.DateTimeFormat('fr-BE',
      {timeZone:'Europe/Brussels',day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}).format(new Date(value));
    return fallback;
  }

  function setSection(section) {
    if (section === 'launch' && (state.running || state.starting)) return;
    if (section === 'launch') {
      if (state.viewingHistory || byId('procedure-form').hidden) select(state.selected?.id);
      clearRoute();
    }
    state.section = section;
    byId('procedure-overview').hidden = section !== 'results';
    byId('procedure-launcher').hidden = section !== 'launch';
    byId('comparison-view').hidden = section !== 'comparison';
    byId('procedure-detail').hidden = section !== 'results' || !state.runId;
    ['results','launch','comparison'].forEach(name => byId(`procedure-tab-${name}`).setAttribute('aria-selected', String(name === section)));
    if (section === 'comparison' && typeof ComparisonUI !== 'undefined') ComparisonUI.open();
  }

  function clearRoute() {
    if (typeof window !== 'undefined' && window.location.hash.startsWith('#automation/'))
      window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }

  function showDetail(scroll = false) {
    setSection('results');
    byId('procedure-detail').hidden = false;
    byId('procedure-progress-details').open = state.running;
    byId('procedure-close-detail').hidden = state.running;
    if (scroll) { byId('procedure-detail').scrollIntoView({block:'start'}); byId('procedure-record-description').focus({preventScroll:true}); }
  }

  function observations(item) {
    const data = item.observations;
    if (!data) return item.diagnostic ? 'Diagnostic de l’application' : item.available ? 'Constats et preuves' : 'Résultats indisponibles';
    const hosts = `${data.hosts} hôte${data.hosts === 1 ? '' : 's'}`;
    return item.procedure.id === 'discovery-v1' ? hosts : `${hosts} · ${data.services} service${data.services === 1 ? '' : 's'} TCP`;
  }

  function renderOverview(data) {
    const items = list(data.items);
    byId('procedure-run-rows').innerHTML = items.map(item => `<tr data-run="${esc(item.id)}"><td><strong>${esc(item.procedure.title)}</strong><span>${esc(formatDate(item.started_at,item.id))}${item.procedure.version ? ` · v${esc(item.procedure.version)}` : ' · version non enregistrée'}</span></td><td>${esc(item.target || (item.diagnostic ? 'Sans réseau' : 'Cible non enregistrée'))}<span>${item.scenario ? 'Scénario enregistré' : item.diagnostic ? 'Diagnostic' : 'Scénario non enregistré'}</span></td><td><strong>${esc(observations(item))}</strong><span>${esc(coverageLabels[item.coverage] || coverageLabels.unavailable)}</span>${measured(item.tool_errors) ? `<span>${item.tool_errors} erreur${item.tool_errors === 1 ? '' : 's'} d’outil</span>` : ''}</td><td>${item.evaluation.status === 'not_applicable' ? 'Sans objet' : 'Non évaluée'}</td><td class="procedure-mono">${formatDuration(item.duration_s)}${item.duration_scope === 'tools' ? '<span>Outils uniquement</span>' : ''}</td><td class="procedure-mono">${measured(item.tool_calls) ? item.tool_calls : '—'}</td><td><span class="procedure-outcome" data-status="${esc(item.status)}">${esc(label(item.status))}</span></td><td><button type="button" class="procedure-secondary" data-procedure-run="${esc(item.id)}">Consulter</button></td></tr>`).join('');
    byId('procedure-run-rows').querySelectorAll('[data-procedure-run]').forEach(button => button.addEventListener('click', () => showRun(button.dataset.procedureRun)));
    byId('procedure-overview-empty').hidden = items.length > 0;
    byId('procedure-page-info').textContent = data.total ? `${data.offset + 1}–${data.offset + items.length} sur ${data.total}` : '0 résultat';
    byId('procedure-prev').disabled = data.offset === 0;
    byId('procedure-next').disabled = data.offset + data.limit >= data.total;
    byId('procedure-filter').innerHTML = '<option value="">Toutes les procédures</option>' + list(data.procedures).map(id => `<option value="${esc(id)}">${esc(state.catalogue.find(item => item.id === id)?.title || id)}</option>`).join('');
    byId('procedure-filter').value = state.filterProcedure;
    byId('procedure-target-filter').innerHTML = '<option value="">Toutes les cibles</option>' + list(data.targets).map(target => `<option value="${esc(target)}">${esc(target)}</option>`).join('');
    byId('procedure-target-filter').value = state.filterTarget;
  }

  function renderSummary(item) {
    if (!item) { byId('procedure-run-summary').innerHTML = '<p class="procedure-empty">Mesures d’exécution indisponibles.</p>'; return; }
    const metrics = [[item.duration_scope === 'tools' ? 'Durée des outils' : 'Durée totale', formatDuration(item.duration_s)],
      ['Appels d’outils', measured(item.tool_calls) ? item.tool_calls : '—'],
      ['Erreurs d’outils', measured(item.tool_errors) ? item.tool_errors : '—']];
    if (item.observations) metrics.push(['Hôtes observés',item.observations.hosts]);
    if (item.observations && item.procedure.id === 'service-inventory-v1') metrics.push(['Services TCP observés',item.observations.services]);
    const reason = item.evaluation.reason === 'offline_diagnostic' ? 'Ce diagnostic vérifie l’application sans accès réseau.'
      : item.evaluation.reason === 'scenario_not_recorded' ? 'Cette exécution cible un réseau direct. Aucun scénario ni résultat attendu n’a été enregistré pour calculer un score.'
      : 'Le scénario est enregistré. La comparaison aux résultats attendus et les scores de détection ne sont pas encore calculés pour cette procédure.';
    byId('procedure-run-summary').innerHTML = `<div class="procedure-measures">${metrics.map(([title,value]) => `<div><span>${esc(title)}</span><strong>${esc(value)}</strong></div>`).join('')}</div><p class="procedure-evaluation"><strong>Évaluation par scénario : ${item.evaluation.status === 'not_applicable' ? 'sans objet' : 'non évaluée'}.</strong> ${esc(reason)}</p>`;
  }

  function message(text, error = false) {
    const element = byId('procedure-form-error');
    element.textContent = text || ''; element.hidden = !text;
    element.classList.toggle('procedure-error', error);
    const notice = byId('procedure-catalogue-message');
    notice.textContent = text || ''; notice.hidden = !text;
  }

  function card(procedure) {
    const missing = procedure.availability?.available === false;
    const selected = !state.viewingHistory && state.selected?.id === procedure.id;
    return `<button type="button" class="procedure-card ${selected ? 'selected' : ''}" data-procedure="${esc(procedure.id)}" aria-pressed="${selected}">
      <span class="procedure-card-category">${esc(procedure.category)}${missing ? ' · outil absent' : ''}</span>
      <strong>${esc(procedure.title)}</strong><span>${esc(procedure.summary)}</span>
      <span class="procedure-card-footer">${procedure.target_kind === 'scenario' ? 'Scénario du laboratoire' : procedure.target_kind === 'network' ? 'Réseau autorisé' : 'Sans réseau'}<span aria-hidden="true">→</span></span></button>`;
  }

  function renderCatalogue() {
    byId('procedure-catalogue').innerHTML = state.catalogue.filter(item => !item.diagnostic).map(card).join('');
    byId('procedure-diagnostics').innerHTML = state.catalogue.filter(item => item.diagnostic).map(card).join('');
    document.querySelectorAll('[data-procedure]').forEach(button => {
      button.disabled = state.running || state.starting;
      button.addEventListener('click', () => select(button.dataset.procedure));
    });
  }

  function renderSteps() {
    const explanations = {
      predeployment_cleanup: 'Suppression des scénarios précédents avant le déploiement.',
      predeployment_cleanup_failed: 'Le nettoyage préalable a échoué ; des machines des scénarios précédents peuvent rester présentes.',
    };
    byId('procedure-steps').innerHTML = state.steps.map(step => `<li data-status="${esc(step.status || 'pending')}"><span class="procedure-step-mark" aria-hidden="true"></span><div><strong>${esc(step.label || step.id)}</strong>${step.target ? `<span>${esc(step.target)}</span>` : ''}${explanations[step.reason] ? `<span>${esc(explanations[step.reason])}</span>` : ''}</div><span class="procedure-step-status">${esc(label(step.status || 'pending'))}</span></li>`).join('');
  }

  function setStatus(status, activity) {
    if (state.running && !state.viewingHistory && state.controlStatus === 'stopping') {
      status = 'stopping';
      activity = 'Arrêt demandé. Les opérations en cours et le nettoyage doivent encore se terminer.';
    } else if (state.running && !state.viewingHistory && state.controlStatus === 'waiting') {
      status = 'waiting'; activity = 'En attente de la réservation du laboratoire.';
    }
    state.status = status || 'pending';
    byId('procedure-status').textContent = label(state.status);
    byId('procedure-status').dataset.status = state.status;
    if (activity) byId('procedure-activity').textContent = activity;
  }

  function lockForm() {
    const locked = state.running || state.starting;
    byId('procedure-tab-launch').disabled = locked;
    byId('procedure-form').querySelectorAll('input, select, button').forEach(input => { input.disabled = locked; });
    const missing = state.selected?.availability?.available === false;
    byId('procedure-launch').disabled = locked || missing || !state.selected;
    document.querySelectorAll('[data-procedure]').forEach(button => { button.disabled = locked; });
    byId('procedure-stop').hidden = !state.running;
    byId('procedure-dashboard').hidden = !state.runId;
  }

  function select(identifier) {
    if (state.running || state.starting) return;
    const procedure = state.catalogue.find(item => item.id === identifier);
    if (!procedure) return;
    state.selected = procedure; state.runId = null; state.viewingHistory = false;
    byId('procedure-detail').hidden = true;
    state.steps = list(procedure.steps).map(step => ({...step, status: 'pending'}));
    ++state.request;
    renderCatalogue(); renderSteps(); message(''); setStatus('pending', 'Les étapes s’actualiseront au lancement.');
    byId('procedure-form').hidden = false;
    byId('procedure-description').innerHTML = `<div class="procedure-description-top"><span class="procedure-card-category">${esc(procedure.category)}</span><span class="procedure-version">Version ${esc(procedure.version)}</span></div><h3>${esc(procedure.title)}</h3><p>${esc(procedure.summary)}</p><dl class="procedure-description-list"><div><dt>Vous obtenez</dt><dd>${esc(procedure.outputs)}</dd></div><div><dt>Couverture</dt><dd>${esc(procedure.scope)}</dd></div>${procedure.ports ? `<div><dt>Ports TCP inspectés</dt><dd class="procedure-mono">${esc(procedure.ports)}</dd></div>` : ''}</dl>`;
    byId('procedure-network-field').hidden = procedure.target_kind !== 'network';
    byId('procedure-network').required = procedure.target_kind === 'network';
    byId('procedure-scenario-field').hidden = procedure.target_kind !== 'scenario';
    byId('procedure-scenario').required = procedure.target_kind === 'scenario';
    byId('procedure-offline-field').hidden = procedure.target_kind !== 'none';
    byId('procedure-effects').textContent = procedure.effects;
    byId('procedure-duration').value = procedure.defaults.max_duration_s ?? '';
    byId('procedure-duration-label').textContent = procedure.runner_kind === 'rules' ? 'Temps maximal des contrôles (secondes)' : 'Temps maximal (secondes)';
    byId('procedure-duration-help').textContent = procedure.runner_kind === 'rules'
      ? 'Cette limite couvre l’analyse et la vérification. L’attente du laboratoire, le déploiement et le nettoyage peuvent prolonger la durée totale.'
      : procedure.target_kind === 'network' ? 'Cette limite comprend l’attente du laboratoire et les sondes réseau.' : 'Cette limite couvre le diagnostic hors ligne.';
    byId('procedure-calls').value = procedure.defaults.max_tool_calls || '';
    byId('procedure-calls').max = procedure.runner_kind === 'rules' ? '2000' : '100';
    byId('procedure-calls-field').hidden = procedure.target_kind === 'none';
    byId('procedure-launch-summary').textContent = procedure.target_kind === 'none' ? 'Sans modèle · sans réseau' : 'Sans modèle · observations et traces conservées';
    byId('procedure-launch').textContent = procedure.target_kind === 'scenario' ? 'Lancer l’audit automatique' : procedure.target_kind === 'none' ? 'Lancer le diagnostic' : 'Lancer la procédure';
    byId('procedure-results').innerHTML = '<p class="procedure-empty">Les résultats de cette procédure apparaîtront ici après son lancement.</p>';
    if (procedure.availability?.available === false) message(`Outils absents du contrôleur : ${list(procedure.availability.missing_dependencies).join(', ')}. Installez-les sur le contrôleur pour lancer cette procédure.`, true);
    lockForm();
  }

  function buildRequest(procedure, values) {
    const body = {runner_kind: procedure.runner_kind};
    if (procedure.script_id) body.script_id = procedure.script_id;
    if (procedure.target_kind === 'network') {
      if (!values.network || !values.network.includes('/')) throw new Error('Indiquez le réseau IPv4 autorisé au format CIDR.');
      body.target_network = values.network;
    }
    if (procedure.target_kind === 'scenario') {
      if (!values.scenario) throw new Error('Choisissez un scénario public déployable.');
      body.scenario_id = values.scenario; body.auto_teardown = values.cleanup;
    }
    // Empty fields mean no ceiling; only the rules audit accepts them.
    const empty = value => value === '' || value === null || value === undefined;
    if (!empty(values.duration)) {
      const duration = Number(values.duration);
      if (!Number.isSafeInteger(duration) || duration < 1 || duration > 3600) throw new Error('Le temps maximal doit être compris entre 1 et 3 600 secondes.');
      body.max_duration_s = duration;
    } else if (procedure.runner_kind !== 'rules') {
      throw new Error('Le temps maximal doit être compris entre 1 et 3 600 secondes.');
    }
    if (procedure.target_kind !== 'none') {
      const max = procedure.runner_kind === 'rules' ? 2000 : 100;
      if (!empty(values.calls)) {
        const calls = Number(values.calls);
        if (!Number.isSafeInteger(calls) || calls < 1 || calls > max) throw new Error(`Le nombre d’appels doit être compris entre 1 et ${max}.`);
        body.max_tool_calls = calls;
      } else if (procedure.runner_kind !== 'rules') {
        throw new Error(`Le nombre d’appels doit être compris entre 1 et ${max}.`);
      }
    }
    return body;
  }

  async function launch(event) {
    event.preventDefault();
    if (!state.selected || state.running || state.starting) return;
    message('');
    let body;
    try {
      body = buildRequest(state.selected, {network: byId('procedure-network').value.trim(), scenario: byId('procedure-scenario').value,
        cleanup: byId('procedure-cleanup').checked, duration: byId('procedure-duration').value.trim(), calls: byId('procedure-calls').value.trim()});
    } catch (error) { message(error.message, true); return; }
    state.starting = true; lockForm();
    try {
      const response = await adminFetch('/api/pipeline/start', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(_formatErrDetail(data.detail || `HTTP ${response.status}`));
      state.runId = null; state.liveId = null; state.running = true; state.controlStatus = null;
      byId('procedure-record-description').textContent = `${state.selected.title} — démarrage`;
      byId('procedure-run-summary').innerHTML = '';
      showDetail(true);
      state.steps = list(state.selected.steps).map(step => ({...step, status: 'pending'}));
      renderSteps(); setStatus('running', 'Lancement accepté. Préparation de l’exécution…');
      byId('procedure-results').innerHTML = '<p class="procedure-empty">Collecte des observations en cours…</p>';
      clearLog(); setRunnerView(body.runner_kind);
      if (body.script_id) byId('sel-script').value = body.script_id;
      byId('btn-start').disabled = true; byId('btn-stop').style.display = 'block'; lockRunnerChoice(true);
      startSSE();
    } catch (error) { message(error.message || 'Le lancement a échoué.', true); }
    finally { state.starting = false; lockForm(); }
  }

  function renderInventory(results) {
    const hosts = list(results.hosts);
    const rows = hosts.flatMap(host => {
      const services = list(host.services);
      const inspected = list(results.steps).some(step => step.id === `host-${host.ip}` && step.status === 'completed');
      const empty = results.script_id === 'discovery-v1' ? 'Services non inspectés' : inspected ? 'Aucun port ouvert observé' : 'Inspection non effectuée';
      return (services.length ? services : [null]).map(service => `<tr><td class="procedure-mono">${esc(host.ip)}</td><td class="procedure-mono">${service ? esc(`${service.port}/${service.protocol || 'tcp'}`) : '—'}</td><td>${service ? esc(service.service || service.name || 'inconnu') : empty}</td><td>${service ? esc(service.detail || service.version || service.product || '—') : esc(label(host.status))}</td></tr>`);
    }).join('');
    const coverage = results.coverage || {};
    const reasons = {host_limit: 'La limite de 16 équipements inspectés a été atteinte.', observation_limit: 'La limite de conservation des observations a été atteinte.',
      unconfirmed_host_state: 'Certains hôtes ne sont pas attestés actifs.', unusable_host_reports: 'Certaines réponses ne désignent pas une adresse exploitable dans le réseau autorisé.',
      unreadable_observation: 'Une observation est illisible.', observation_unavailable_before_truncation: 'Une sortie tronquée ne permet pas de reconstituer toutes les observations.',
      scan_incomplete: 'Au moins une sonde ne s’est pas terminée correctement.', stopped: 'L’exécution a été arrêtée.', budget_exceeded: 'Une limite d’exécution a été atteinte.', failed: 'L’exécution a échoué.'};
    const notes = list(coverage.incomplete_reasons).filter(reason => reason !== 'partial').map(reason => reasons[reason] || 'Une partie de la collecte est incomplète.');
    if (coverage.raw_output_truncated) notes.push('Les extraits texte sont raccourcis ; les observations structurées conservées figurent dans ce tableau.');
    const partial = coverage.partial === true || coverage.complete === false || coverage.observations_truncated || coverage.host_limit_reached;
    return `<div class="procedure-result-heading"><strong>${hosts.length} hôte${hosts.length > 1 ? 's' : ''} affiché${hosts.length > 1 ? 's' : ''}</strong><span>${esc(label(results.status))}</span></div>
      ${partial ? '<p class="procedure-notice">Couverture partielle : certaines observations ou inspections n’ont pas pu être terminées. Consultez les détails et les traces.</p>' : ''}
      ${notes.length ? `<ul class="procedure-help">${notes.map(note => `<li>${esc(note)}</li>`).join('')}</ul>` : ''}
      ${hosts.length ? `<div class="procedure-table-scroll"><table class="procedure-table"><thead><tr><th scope="col">Équipement</th><th scope="col">Port</th><th scope="col">Service</th><th scope="col">Version / état</th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="procedure-empty">Aucun hôte observé dans les résultats disponibles. Cela ne garantit pas l’absence d’équipements sur le réseau.</p>'}
      ${list(results.errors).length ? `<ul class="procedure-error">${results.errors.map(error => `<li>${esc(typeof error === 'string' ? error : error.message || error.error || error.kind || JSON.stringify(error))}</li>`).join('')}</ul>` : ''}
      <p class="procedure-help">Ces observations décrivent les réponses obtenues. Elles ne constituent pas une confirmation de vulnérabilité.</p>`;
  }

  function renderAudit(audit) {
    const devices = list(audit.devices);
    const rows = devices.flatMap(device => (list(device.findings).length ? device.findings : [null]).map(finding => {
      const verdict = finding?.verification || 'not_run';
      const coverage = `Analyse : ${label(device.analysis_status)}. Vérification : ${label(device.verification_status)}.`;
      const diagnostics = `${Number(device.scanner_error_count) || 0} erreur(s) de scan · ${Number(device.verification_error_count) || 0} erreur(s) de vérification`;
      const errors = list(finding?.execution_errors).map(error => error.reason || error.kind || 'Erreur de contrôle').join(' ; ');
      return `<tr><td>${esc(device.device_id)}<span class="procedure-cell-detail procedure-mono">${esc(device.device_ip)}</span></td><td>${esc(coverage)}<span class="procedure-cell-detail">${esc(diagnostics)}</span></td><td>${finding ? esc(finding.type) : 'Aucun constat disponible'}</td><td><span class="procedure-verdict" data-verdict="${esc(verdict)}">${esc(label(verdict))}</span></td><td>${esc(finding?.evidence || finding?.details || 'Aucun constat ne permet de conclure sur l’ensemble des contrôles.')}${errors ? `<span class="procedure-cell-detail">${esc(errors)}</span>` : ''}</td></tr>`;
    })).join('');
    return devices.length ? `<div class="procedure-table-scroll"><table class="procedure-table"><thead><tr><th scope="col">Équipement</th><th scope="col">Couverture</th><th scope="col">Constat</th><th scope="col">Vérification</th><th scope="col">Observation / preuve</th></tr></thead><tbody>${rows}</tbody></table></div><p class="procedure-help">Une confirmation vient des traces d’exécution vérifiées. Une absence de constat ne garantit pas l’absence de vulnérabilité.</p>` : '<p class="procedure-empty">Aucun résultat par équipement disponible à ce stade. Consultez les étapes de préparation et les éventuelles erreurs.</p>';
  }

  function renderResults(data) {
    const results = data?.results || {};
    const progress = data?.progress || results;
    if (Array.isArray(progress.steps)) { state.steps = progress.steps; renderSteps(); }
    const status = progress.status || data?.status || results.status || data?.audit?.run_status;
    if (status) setStatus(status, state.viewingHistory ? 'Exécution enregistrée. Les étapes et les observations ci-dessous proviennent de son dossier.' : undefined);
    const identity = data?.procedure || results.procedure || progress.procedure;
    if (identity || state.viewingHistory) {
      const known = state.catalogue.some(item => item.id === identity?.id);
      byId('procedure-record-description').innerHTML = `<span>${state.running ? 'Exécution en cours' : 'Exécution enregistrée'} · ${identity?.version ? `Version ${esc(identity.version)}` : 'Version non enregistrée'}</span><h3>${esc(identity?.title || 'Procédure automatisée')}</h3><span class="procedure-mono">${esc(state.runId)}</span>${known && !state.running ? '<button type="button" class="procedure-secondary" id="procedure-prepare-new">Relancer cette procédure</button>' : ''}<a class="procedure-permalink" href="#automation/${encodeURIComponent(state.runId || '')}">Lien vers cette exécution</a>`;
      byId('procedure-prepare-new')?.addEventListener('click', () => { select(identity.id); setSection('launch'); });
    }
    if (!data?.available) {
      const reason = data?.reason === 'procedure_results_not_recorded' ? 'Cette ancienne exécution ne possède pas de résultats structurés. Son résumé reste disponible dans le dashboard.' : data?.reason;
      byId('procedure-results').innerHTML = `<p class="procedure-empty">${esc(reason || 'Aucun résultat structuré disponible pour cette exécution.')}</p>`;
      return;
    }
    const content = data.kind === 'audit' ? renderAudit(data.audit || {}) : data.kind === 'diagnostic'
      ? `<p class="procedure-diagnostic-result">${results.status === 'completed' ? 'Le lancement et l’enregistrement du diagnostic ont réussi.' : esc(label(results.status))}</p><p class="procedure-help">Diagnostic hors ligne : aucun scan réseau ni résultat de sécurité.</p>`
      : renderInventory(results);
    const identityHtml = identity ? `<p class="procedure-result-identity"><strong>${esc(identity.title)}</strong><span>${identity.version ? `Version ${esc(identity.version)} enregistrée` : 'Version historique non enregistrée'}</span></p>` : '';
    byId('procedure-results').innerHTML = identityHtml + content + (state.runId ? `<div class="procedure-evidence-actions"><button type="button" class="procedure-secondary" data-procedure-file="tool_calls.jsonl">Voir les traces d’outils</button><button type="button" class="procedure-secondary" data-procedure-file="run_summary.md">Lire le résumé</button><span class="procedure-help procedure-mono">${esc(state.runId)}</span></div>` : '');
    byId('procedure-results').querySelectorAll('[data-procedure-file]').forEach(button => {
      if (data.kind === 'diagnostic' && button.dataset.procedureFile === 'tool_calls.jsonl') button.hidden = true;
      button.addEventListener('click', () => viewFile(state.runId, button.dataset.procedureFile));
    });
  }

  async function loadResults(runId) {
    const request = ++state.request;
    let data;
    try {
      const [response, summary] = await Promise.all([fetch(`/api/runs/${encodeURIComponent(runId)}/procedure-results`), fetchJSON(`/api/procedures/runs/${encodeURIComponent(runId)}`)]);
      data = await response.json();
      if (!response.ok) data = {available: false, reason: `Résultats indisponibles : ${_formatErrDetail(data.detail || `HTTP ${response.status}`)}`};
      if (request === state.request && state.runId === runId) renderSummary(summary);
    } catch (_) { data = {available: false, reason: 'Connexion aux résultats impossible. Actualisez pour réessayer.'}; }
    if (request !== state.request || state.runId !== runId) return;
    if (data) renderResults(data);
  }

  async function showRun(runId) {
    if (state.running) {
      if (state.liveId !== runId) message('Une procédure est en cours. Son suivi reste affiché jusqu’à sa fin.', true);
      else { await sync(); showDetail(true); }
      return;
    }
    state.runId = runId; state.viewingHistory = true; state.steps = []; renderSteps(); renderCatalogue();
    showDetail();
    byId('procedure-form').hidden = true; byId('procedure-dashboard').hidden = false;
    byId('procedure-record-description').textContent = 'Lecture de l’exécution enregistrée…';
    byId('procedure-run-summary').innerHTML = '';
    byId('procedure-results').innerHTML = '<p class="procedure-empty">Chargement des observations…</p>';
    setStatus('pending', 'Lecture des observations enregistrées…');
    await loadResults(runId);
    if (state.runId === runId) {
      showDetail(true);
      if (typeof window !== 'undefined') window.history.replaceState(null,'',`#automation/${encodeURIComponent(runId)}`);
    }
  }

  async function history() {
    const request = ++state.pageRequest;
    const query = `offset=${state.pageOffset}&limit=${state.pageLimit}&include_diagnostics=${state.includeDiagnostics}&procedure_id=${encodeURIComponent(state.filterProcedure)}&target=${encodeURIComponent(state.filterTarget)}`;
    const data = await fetchJSON(`/api/procedures/runs?${query}`);
    if (request !== state.pageRequest) return;
    byId('procedure-overview-error').hidden = Array.isArray(data?.items);
    if (!Array.isArray(data?.items)) {
      byId('procedure-overview-error').textContent = 'Impossible de charger les exécutions. Cliquez sur Actualiser pour réessayer.';
      byId('procedure-run-rows').innerHTML = ''; byId('procedure-page-info').textContent = 'Indisponible';
      byId('procedure-prev').disabled = true; byId('procedure-next').disabled = true;
      return;
    }
    renderOverview(data);
  }

  async function scenarios() {
    const data = await fetchJSON('/api/scenarios');
    const options = list(data?.scenarios).filter(item => !isSealedScenario(item) && item.deployment_supported !== false);
    byId('procedure-scenario').innerHTML = '<option value="">Choisir un scénario public…</option>' + options.map(item => `<option value="${esc(item.id)}">${esc(item.exported ? item.name : `S${item.id} · ${item.name}`)}</option>`).join('');
  }

  async function sync() {
    if (!state.ready || state.starting || state.syncing) return;
    state.syncing = true;
    try {
    const status = await fetchJSON('/api/pipeline/status');
    if (!status) {
      if (state.running) byId('procedure-activity').textContent = 'Connexion interrompue. Vérification de l’état à la prochaine actualisation…';
      return;
    }
    const automation = ['rules', 'scripted'].includes(status.runner_kind);
    if (status.running && automation && status.run_dir) {
      const id = status.run_dir.split('/').pop();
      if (!state.running) {
        const run = status.runner_kind === 'scripted' ? await fetchJSON(`/api/runs/${encodeURIComponent(id)}`) : null;
        const procedure = status.runner_kind === 'rules' ? 'rules-audit-v1' : run?.script_id;
        if (procedure && (state.viewingHistory || state.selected?.id !== procedure)) select(procedure);
      }
      state.running = true; state.viewingHistory = false; state.liveId = id; state.runId = id;
      showDetail();
      state.controlStatus = status.stopping ? 'stopping' : status.lab_waiting ? 'waiting' : null;
      setStatus(status.stopping ? 'stopping' : status.lab_waiting ? 'waiting' : 'running', status.stopping ? 'Arrêt demandé. Les opérations en cours et le nettoyage doivent encore se terminer.' : status.lab_waiting ? 'En attente de la réservation du laboratoire.' : 'Exécution en cours. Les observations restent intermédiaires.');
      await loadResults(id);
    } else if (!status.running && state.running) {
      state.running = false;
      byId('procedure-close-detail').hidden = false;
      setStatus(status.run_status || 'failed');
      if (state.liveId) await loadResults(state.liveId);
      byId('procedure-activity').textContent = 'Exécution terminée. Les observations et les traces disponibles sont présentées ci-dessous.';
      await history();
    }
    lockForm();
    } finally { state.syncing = false; }
  }

  function onEvent(event) {
    const id = typeof event.run_dir === 'string' ? event.run_dir.split('/').pop() : null;
    if (id && (event.runner_kind === 'rules' || event.runner_kind === 'scripted')) {
      if (state.liveId && state.liveId !== id && state.running) return;
      state.liveId = id;
      if (state.running || ['runner_started', 'pipeline_start'].includes(event.type)) state.runId = id;
    }
    if (!state.running || (id && state.liveId && id !== state.liveId)) return;
    if (['lab_waiting', 'lab_acquired'].includes(event.type)) {
      if (state.controlStatus !== 'stopping') state.controlStatus = event.type === 'lab_waiting' ? 'waiting' : null;
      setStatus(event.type === 'lab_waiting' ? 'waiting' : 'running');
    }
    if (event.type === 'procedure_step') {
      const existing = state.steps.find(step => step.id === event.step_id);
      if (existing) Object.assign(existing, {status: event.status, target: event.target, label: event.label || existing.label});
      else state.steps.push({id: event.step_id, label: event.label, status: event.status, target: event.target});
      renderSteps(); setStatus(state.status, `${event.label || 'Étape'} · ${label(event.status)}`);
    }
    if (event.type === 'procedure_results' && event.results) renderResults({available: true, kind: event.results.script_id === 'smoke-v1' ? 'diagnostic' : 'inventory', results: event.results});
    if (event.type === 'procedure_progress' && event.progress) {
      state.steps = list(event.progress.steps); renderSteps();
      setStatus(event.progress.status);
    }
    if (['deploy_start', 'deploy_done', 'phase_done', 'phase_start', 'teardown_done', 'procedure_progress'].includes(event.type) && state.runId) loadResults(state.runId);
    if (['runner_done', 'pipeline_done'].includes(event.type) && id === state.liveId) {
      state.running = false; setStatus(event.status || 'failed', 'Exécution terminée. Les observations et les traces disponibles sont présentées ci-dessous.');
      byId('procedure-close-detail').hidden = false;
      lockForm(); loadResults(id); history();
    }
  }

  async function open() {
    if (state.loading) return;
    if (state.ready) { await sync(); await history(); return; }
    state.loading = true;
    try {
      const data = await fetchJSON('/api/procedures');
      if (!Array.isArray(data?.procedures)) throw new Error('Catalogue indisponible. Actualisez pour réessayer.');
      state.catalogue = data.procedures; state.ready = true;
      select(state.catalogue.find(item => !item.diagnostic)?.id);
      setSection(state.section);
      byId('procedure-catalogue-message').hidden = true;
      await Promise.all([scenarios(), history()]); await sync();
      if (typeof window !== 'undefined' && !state.running) {
        const route = window.location.hash.match(/^#automation\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})$/);
        if (route) await showRun(route[1]);
        if (/^#comparison\/[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}_[a-f0-9]{12}$/.test(window.location.hash)) setSection('comparison');
      }
    } catch (error) {
      byId('procedure-catalogue-message').textContent = error.message;
      byId('procedure-catalogue-message').hidden = false;
    } finally { state.loading = false; }
  }

  document.addEventListener('DOMContentLoaded', () => {
    ['results','launch','comparison'].forEach(section => byId(`procedure-tab-${section}`).addEventListener('click', () => {
      if (section !== 'comparison' && typeof window !== 'undefined' && window.location.hash.startsWith('#comparison/'))
        window.history.replaceState(null,'',window.location.pathname + window.location.search);
      setSection(section);
    }));
    byId('procedure-close-detail').addEventListener('click', () => { if (state.running) return; state.runId = null; state.viewingHistory = false; ++state.request; byId('procedure-detail').hidden = true; clearRoute(); });
    for (const [id,key] of [['procedure-filter','filterProcedure'],['procedure-target-filter','filterTarget'],['procedure-include-diagnostics','includeDiagnostics']]) {
      byId(id).addEventListener('change', () => { state[key] = key === 'includeDiagnostics' ? byId(id).checked : byId(id).value; state.pageOffset = 0; history(); });
    }
    byId('procedure-prev').addEventListener('click', () => { state.pageOffset = Math.max(0,state.pageOffset - state.pageLimit); history(); });
    byId('procedure-next').addEventListener('click', () => { state.pageOffset += state.pageLimit; history(); });
    byId('procedure-form').addEventListener('submit', launch);
    byId('procedure-refresh').addEventListener('click', async () => {
      if (state.running || state.starting) { await sync(); return; }
      state.ready = false; await open();
    });
    byId('procedure-stop').addEventListener('click', async () => {
      try {
        const response = await adminFetch('/api/pipeline/stop', {method: 'POST'});
        if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(_formatErrDetail(data.detail || 'Arrêt refusé.')); }
        state.controlStatus = 'stopping';
        setStatus('stopping', 'Arrêt demandé. Attente de la fin des opérations en cours et du nettoyage.');
      } catch (error) { message(error.message, true); }
    });
    byId('procedure-dashboard').addEventListener('click', () => { switchView('main'); if (state.runId) viewRun(state.runId); });
    setInterval(() => { if (!document.hidden && state.ready && (state.running || !byId('procedures-view').hidden)) sync(); }, 4000);
  });
  return {open, onEvent, buildRequest, renderInventory, renderAudit, showRun, renderOverview, renderSummary, setSection};
})();
