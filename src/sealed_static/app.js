'use strict';

const POLL_INTERVAL_MS = 5000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROVIDER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const STATUSES = Object.freeze({
  queued: ['En file', 'La suite complète attend son exécution.', 'active'],
  running: ['En cours', 'La suite complète est en cours.', 'active'],
  complete: ['Terminée', 'Le résultat global signé est disponible.', 'complete'],
  failed: ['Échec', 'La suite a échoué sans exposer de détail interne.', 'failed'],
  cancelled: ['Annulée', 'La suite complète a été annulée.', 'cancelled'],
  expired: ['Expirée', 'La fenêtre d’évaluation a expiré.', 'failed'],
});
const TERMINAL = new Set(['complete', 'failed', 'cancelled', 'expired']);
const METRICS = Object.freeze([
  ['overall_score', 'Score global', 'ratio', true],
  ['precision', 'Précision', 'ratio', false],
  ['recall', 'Recall', 'ratio', false],
  ['f1', 'F1', 'ratio', false],
  ['exploitation_coverage', 'Couverture exploitation', 'ratio', false],
  ['path_coverage', 'Couverture chemins', 'ratio', false],
  ['cost_usd', 'Coût total', 'usd', false],
]);

let launchToken = '';
let suiteId = '';
let active = false;
let pollTimer = null;
let pollInFlight = false;

class ApiError extends Error {
  constructor(status) {
    super('sealed request failed');
    this.status = status;
  }
}

function byId(id) {
  return document.getElementById(id);
}

function setStatus(badge, message, state) {
  byId('result-card').dataset.state = state;
  byId('status-badge').textContent = badge;
  byId('status-text').textContent = message;
}

function clearMetrics() {
  byId('metrics').replaceChildren();
  byId('metrics').hidden = true;
}

function renderMetrics(values) {
  const container = byId('metrics');
  container.replaceChildren();
  if (!values || typeof values !== 'object' || Array.isArray(values)) {
    container.hidden = true;
    return;
  }
  for (const [key, labelText, kind, primary] of METRICS) {
    const raw = values[key];
    if (typeof raw !== 'number' || !Number.isFinite(raw)) continue;
    if (kind === 'ratio' && (raw < 0 || raw > 1)) continue;
    if (kind === 'usd' && raw < 0) continue;
    const item = document.createElement('div');
    item.className = primary ? 'metric primary' : 'metric';
    const label = document.createElement('span');
    label.textContent = labelText;
    const value = document.createElement('strong');
    value.textContent = kind === 'usd' ? `$${raw.toFixed(4)}` : `${(raw * 100).toFixed(1)}%`;
    item.append(label, value);
    container.appendChild(item);
  }
  container.hidden = container.childElementCount === 0;
}

function renderIdentity(payload) {
  const container = byId('identity');
  container.replaceChildren();
  const runner = payload?.runner;
  const fields = [
    ['Benchmark', payload?.benchmark_version],
    ['Modèle signé', runner?.model],
    ['Provider signé', runner?.provider],
    ['Commit runner', runner?.git_commit],
    ['Image runner', runner?.runner_image_digest],
    ['Digest modèle', runner?.model_digest],
    ['Effacement', payload?.deletion_attestation?.status === 'deleted' ? 'attesté' : null],
  ];
  for (const [labelText, raw] of fields) {
    if (typeof raw !== 'string' || !raw) continue;
    const label = document.createElement('dt');
    label.textContent = labelText;
    const value = document.createElement('dd');
    value.textContent = raw;
    container.append(label, value);
  }
  container.hidden = container.childElementCount === 0;
}

function renderPayload(payload, fallback) {
  const rawStatus = typeof payload?.status === 'string' ? payload.status.trim().toLowerCase() : '';
  const status = Object.hasOwn(STATUSES, rawStatus) ? rawStatus : fallback;
  const [badge, message, state] = STATUSES[status];
  setStatus(badge, message, state);
  renderIdentity(payload);
  if (status === 'complete') renderMetrics(payload.metrics);
  else clearMetrics();
  return status;
}

function genericError(status) {
  if (status === 401 || status === 403) return ['Accès refusé', 'Le token est invalide ou expiré.'];
  if (status === 400) return ['Requête refusée', 'Le modèle, le provider ou l’identifiant n’est pas autorisé.'];
  if (status === 409) return ['Conflit', 'Une campagne incompatible est déjà active.'];
  if (status === 429) return ['Quota atteint', 'La limite de campagnes a été atteinte.'];
  if (status === 502 || status === 503) return ['Indisponible', 'Le service privé est momentanément indisponible.'];
  return ['Échec', 'La requête a échoué sans exposer de détail interne.'];
}

function renderError(error) {
  const [badge, message] = genericError(error instanceof ApiError ? error.status : 0);
  setStatus(badge, message, 'failed');
  renderIdentity(null);
  clearMetrics();
}

async function request(method, path, body = null) {
  if (!launchToken) throw new ApiError(401);
  const headers = {
    'Accept': 'application/json',
    'X-Sealed-Launch-Token': launchToken,
  };
  if (body !== null) headers['Content-Type'] = 'application/json';
  let response;
  try {
    response = await fetch(`/api/sealed${path}`, {
      method,
      headers,
      body: body === null ? undefined : JSON.stringify(body),
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
  } catch (_) {
    throw new ApiError(0);
  }
  if (!response.ok) throw new ApiError(response.status);
  const type = response.headers.get('content-type') || '';
  if (!type.includes('application/json')) throw new ApiError(502);
  try {
    return await response.json();
  } catch (_) {
    throw new ApiError(502);
  }
}

function updateControls() {
  byId('launch').disabled = active;
  byId('model').disabled = active;
  byId('provider').disabled = active;
  byId('cancel').hidden = !active || !suiteId;
  byId('resume-suite-id').disabled = active;
}

function showReference() {
  const reference = byId('suite-reference');
  reference.textContent = suiteId ? `Identifiant opaque : ${suiteId}` : '';
  reference.hidden = !suiteId;
  if (suiteId) byId('resume-suite-id').value = suiteId;
}

function clearPoll() {
  if (pollTimer !== null) clearTimeout(pollTimer);
  pollTimer = null;
}

function schedulePoll(delay = POLL_INTERVAL_MS) {
  clearPoll();
  if (active && suiteId && launchToken) pollTimer = setTimeout(pollSuite, delay);
}

function finish() {
  clearPoll();
  active = false;
  pollInFlight = false;
  launchToken = '';
  byId('token').value = '';
  updateControls();
}

function takeToken() {
  const token = byId('token').value.trim();
  if (!token) throw new ApiError(401);
  launchToken = token;
  byId('token').value = '';
}

async function launchSuite(event) {
  event.preventDefault();
  if (active) return;
  suiteId = '';
  showReference();
  renderIdentity(null);
  clearMetrics();
  const model = byId('model').value.trim();
  const provider = byId('provider').value.trim();
  if (!model || model.length > 256 || /[\x00-\x1f\x7f]/.test(model) || !PROVIDER_RE.test(provider)) {
    renderError(new ApiError(400));
    return;
  }
  try {
    takeToken();
    active = true;
    updateControls();
    showReference();
    setStatus('Démarrage', 'Création de la campagne complète.', 'active');
    const payload = await request('POST', '/suites', {model, provider});
    const returnedId = typeof payload?.suite_id === 'string' ? payload.suite_id.toLowerCase() : '';
    if (!UUID_RE.test(returnedId)) throw new ApiError(502);
    suiteId = returnedId;
    showReference();
    const status = renderPayload(payload, 'queued');
    if (TERMINAL.has(status)) finish();
    else schedulePoll(1000);
  } catch (error) {
    renderError(error);
    finish();
  }
}

async function resumeSuite(event) {
  event.preventDefault();
  if (active) return;
  const candidate = byId('resume-suite-id').value.trim().toLowerCase();
  if (!UUID_RE.test(candidate)) {
    renderError(new ApiError(400));
    return;
  }
  try {
    takeToken();
    suiteId = candidate;
    active = true;
    updateControls();
    showReference();
    await pollSuite();
  } catch (error) {
    renderError(error);
    finish();
  }
}

async function pollSuite() {
  if (!active || !suiteId || !launchToken || pollInFlight) return;
  pollInFlight = true;
  let again = false;
  try {
    const payload = await request('GET', `/suites/${encodeURIComponent(suiteId)}`);
    const status = renderPayload(payload, 'running');
    if (TERMINAL.has(status)) finish();
    else again = true;
  } catch (error) {
    renderError(error);
    const code = error instanceof ApiError ? error.status : 0;
    if ([400, 401, 403, 404, 410].includes(code)) finish();
    else again = true;
  } finally {
    pollInFlight = false;
    if (again) schedulePoll();
  }
}

async function cancelSuite() {
  if (!active || !suiteId || !launchToken) return;
  if (!window.confirm('Annuler toute la campagne scellée ?')) return;
  clearPoll();
  setStatus('Annulation', 'La suppression de la campagne a été demandée.', 'cancelled');
  try {
    await request('DELETE', `/suites/${encodeURIComponent(suiteId)}`);
    schedulePoll(1000);
  } catch (error) {
    renderError(error);
    const code = error instanceof ApiError ? error.status : 0;
    if ([400, 401, 403, 404, 410].includes(code)) finish();
    else schedulePoll();
  }
}

byId('launch-form').addEventListener('submit', launchSuite);
byId('resume-form').addEventListener('submit', resumeSuite);
byId('cancel').addEventListener('click', cancelSuite);
window.addEventListener('pagehide', () => {
  launchToken = '';
  suiteId = '';
  active = false;
  clearPoll();
  byId('token').value = '';
});
updateControls();
