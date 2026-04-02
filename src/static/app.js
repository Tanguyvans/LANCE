/* NATO Smart City IoT — Pentest Orchestrator frontend */
'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let cy = null;           // Cytoscape instance
let eventSource = null;  // SSE connection
let activeRunId = null;  // run being viewed in detail panel
let nodeVulns = {};      // { nodeId: [{id,type,severity,service,details,cve_ids}] }
let nodeHosts = {};      // { ip: {hostname, ports, os} } from nmap

const PHASE_NAMES = {1:'Graph',2:'Recon',3:'Vuln',4:'Exploit',5:'Report'};

function _cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

const SEV_COLOR = {
  CRITICAL: _cssVar('--sev-critical-fg') || '#ff6b6b',
  HIGH:     _cssVar('--sev-high-fg')     || '#f0883e',
  MEDIUM:   _cssVar('--sev-medium-fg')   || '#d29922',
  LOW:      _cssVar('--sev-low-fg')      || '#3fb950',
  INFO:     _cssVar('--sev-info-fg')     || '#58a6ff',
};

const TYPE_COLOR = {
  router:   '#e74c3c',
  switch:   '#95a5a6',
  gateway:  '#e67e22',
  sensor:   '#2ecc71',
  compute:  '#3498db',
  camera:   '#9b59b6',
  ap:       '#1abc9c',
  external: '#7f8c8d',
};

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Resize handles ─────────────────────────────────────────────────────────
function initResizeHandles() {
  const root = document.documentElement;

  function makeDraggable(handleId, cssVar, cursor, getSize, minPx, maxPx) {
    const handle = document.getElementById(handleId);
    if (!handle) return;
    let dragging = false;

    handle.addEventListener('mousedown', e => {
      dragging = true;
      handle.classList.add('dragging');
      document.body.style.cursor = cursor;
      document.body.style.userSelect = 'none';
      e.preventDefault();
    });

    let _rafPending = false;
    document.addEventListener('mousemove', e => {
      if (!dragging) return;
      if (_rafPending) return;
      _rafPending = true;
      requestAnimationFrame(() => {
        const newSize = Math.min(maxPx, Math.max(minPx, getSize(e)));
        root.style.setProperty(cssVar, newSize + 'px');
        _rafPending = false;
      });
    });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove('dragging');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    });
  }

  makeDraggable(
    'resize-sidebar', '--sidebar-w', 'col-resize',
    e => e.clientX,
    160, 420
  );

  makeDraggable(
    'resize-detail', '--detail-w', 'col-resize',
    e => document.documentElement.clientWidth - e.clientX,
    180, 480
  );

  makeDraggable(
    'resize-log', '--log-h', 'row-resize',
    e => document.documentElement.clientHeight - e.clientY,
    60, 400
  );
}

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('sel-scenario').addEventListener('change', function () {
    loadTopology(this.value ? parseInt(this.value) : null);
  });
  document.getElementById('btn-start').addEventListener('click', startRun);
  document.getElementById('btn-stop').addEventListener('click', stopRun);
  document.getElementById('log-clear').addEventListener('click', clearLog);
  document.getElementById('modal-close').addEventListener('click', () => closeModal());
  document.getElementById('modal-overlay').addEventListener('click', closeModal);
  document.getElementById('compare-close').addEventListener('click', () => closeCompare());
  document.getElementById('compare-overlay').addEventListener('click', closeCompare);
  document.getElementById('btn-compare').addEventListener('click', openCompare);

  // View nav (Dashboard / Benchmark)
  document.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  // Detail tabs
  document.getElementById('detail-tabs').addEventListener('click', e => {
    const tab = e.target.closest('.detail-tab');
    if (tab) switchDetailTab(tab.dataset.tab);
  });

  // Benchmark controls
  document.getElementById('bm-refresh').addEventListener('click', loadBenchmark);
  document.getElementById('bm-filter-scenario').addEventListener('change', renderBenchmarkTable);

  initResizeHandles();

  await loadTopology();
  await loadRuns();
  pollStatus();
});

// ── Cytoscape graph ────────────────────────────────────────────────────────
const CY_LAYOUT = {
  name:            'cose',
  animate:         false,
  nodeRepulsion:   8000,
  idealEdgeLength: 120,
  padding:         30,
};

function _updateTopologyTable(nodes) {
  const tbody = document.getElementById('topology-tbody');
  if (!tbody) return;
  tbody.innerHTML = nodes.map(n => {
    const vulns = nodeVulns[n.id] || [];
    const order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
    const worst = order.find(s => vulns.some(v => v.severity === s)) || 'OK';
    return `<tr>
      <td>${escapeHtml(n.id)}</td>
      <td>${escapeHtml(n.ip || '—')}</td>
      <td>${escapeHtml(n.type || '—')}</td>
      <td>${escapeHtml(worst)}</td>
    </tr>`;
  }).join('');
}

async function loadTopology(scenarioId = null) {
  const url = scenarioId ? `/api/topology?scenario=${scenarioId}` : '/api/topology';
  const cyDiv = document.getElementById('cy');
  const loading = document.getElementById('cy-loading');

  if (!cy && loading) loading.style.display = 'flex';

  const data = await fetchJSON(url);

  if (loading) loading.style.display = 'none';

  if (!data) {
    cyDiv.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--muted);font-size:13px">Impossible de charger la topologie</div>';
    return;
  }

  nodeVulns = {};
  nodeHosts = {};

  const elements = [
    ...data.nodes.map(n => ({
      group: 'nodes',
      data: { ...n, _origColor: n.color },
    })),
    ...data.edges.map(e => ({
      group: 'edges',
      data: { ...e },
    })),
  ];

  if (cy) {
    cy.elements().remove();
    cy.add(elements);
    cy.layout(CY_LAYOUT).run();
  } else {
    cy = cytoscape({
      container: cyDiv,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color':  'data(color)',
            'label':             'data(label)',
            'color':             '#e6edf3',
            'font-size':         '10px',
            'text-valign':       'bottom',
            'text-halign':       'center',
            'text-margin-y':     '4px',
            'width':             '36px',
            'height':            '36px',
            'border-width':      '2px',
            'border-color':      'rgba(255,255,255,.1)',
            'text-outline-width': '2px',
            'text-outline-color': '#0d1117',
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#1f6feb',
            'border-width': '3px',
          },
        },
        {
          selector: 'edge',
          style: {
            'line-color':           'data(color)',
            'target-arrow-color':   'data(color)',
            'target-arrow-shape':   'triangle',
            'curve-style':          'bezier',
            'width':                2,
            'arrow-scale':          0.8,
            'opacity':              0.7,
          },
        },
      ],
      layout: CY_LAYOUT,
    });

    cy.on('tap', 'node', evt => showNodeDetail(evt.target.data()));
    cy.on('tap', evt => { if (evt.target === cy) hideDetail(); });
  }

  buildLegend(data.nodes);
  _updateTopologyTable(data.nodes);
}

function buildLegend(nodes) {
  const types = [...new Set(nodes.map(n => n.type))];
  const legend = document.getElementById('graph-legend');
  legend.innerHTML = types.map(t =>
    `<div class="legend-item">
       <div class="legend-dot" style="background:${TYPE_COLOR[t] || '#888'}"></div>
       ${escapeHtml(t)}
     </div>`
  ).join('');
}

function colorNodeBySeverity(nodeId, severity) {
  const node = cy.getElementById(nodeId);
  if (!node.length) {
    // Try to find by IP
    const match = cy.nodes().filter(n => n.data('ip') === nodeId);
    if (!match.length) return;
    match.forEach(n => _setNodeColor(n, severity));
    return;
  }
  _setNodeColor(node, severity);
}

function _setNodeColor(node, severity) {
  const color = SEV_COLOR[severity] || SEV_COLOR['INFO'];
  node.style('background-color', color);
  node.style('border-color', color);
  node.style('border-width', '3px');
}

function resetNodeColors() {
  cy.nodes().forEach(n => {
    n.style('background-color', n.data('_origColor') || n.data('color'));
    n.style('border-color', 'rgba(255,255,255,.1)');
    n.style('border-width', '2px');
  });
}

// ── Detail panel ───────────────────────────────────────────────────────────
function showNodeDetail(data) {
  document.getElementById('detail-placeholder').style.display = 'none';
  const el = document.getElementById('detail-content');
  el.style.display = 'block';
  document.getElementById('detail-node-view').hidden = false;
  document.getElementById('detail-run-view').hidden = true;

  const vulns = nodeVulns[data.id] || [];
  const hostInfo = nodeHosts[data.ip] || null;

  const sevSummary = vulns.length
    ? Object.entries(
        vulns.reduce((acc, v) => { acc[v.severity] = (acc[v.severity]||0)+1; return acc; }, {})
      ).map(([s,c]) => `<span class="sev ${s}">${s}:${c}</span>`).join(' ')
    : '<span style="color:var(--muted)">Aucune vulnérabilité détectée</span>';

  const services = data.services?.length
    ? data.services.map(s => `<span class="service-tag">${s}</span>`).join('')
    : '<span style="color:var(--muted)">—</span>';

  const ports = hostInfo?.ports?.length
    ? hostInfo.ports.map(p => `<span class="service-tag">${p}</span>`).join('')
    : null;

  const vulnHtml = vulns.map(v => `
    <div class="vuln-item">
      <span class="sev ${escapeHtml(v.severity)}">${escapeHtml(v.severity)}</span>
      <strong>${escapeHtml(v.type)}</strong> — ${escapeHtml(v.service || '')}${v.port ? ':'+escapeHtml(String(v.port)) : ''}
      <div style="color:var(--muted);margin-top:3px;font-size:10px">${escapeHtml(v.details || '')}</div>
      ${v.cve_ids?.length ? `<div style="color:#58a6ff;font-size:10px;margin-top:2px">${v.cve_ids.map(escapeHtml).join(', ')}</div>` : ''}
    </div>
  `).join('');

  document.getElementById('detail-node-view').innerHTML = `
    <h2>
      <span style="background:${escapeHtml(data.color||'#3498db')};border-radius:4px;padding:2px 6px;font-size:11px">${escapeHtml(data.type||'node')}</span>
      ${escapeHtml(data.id)}
    </h2>
    <div class="detail-row"><span class="detail-key">IP</span><span class="detail-val">${escapeHtml(data.ip||'—')}</span></div>
    ${hostInfo?.hostname ? `<div class="detail-row"><span class="detail-key">Hostname</span><span class="detail-val">${escapeHtml(hostInfo.hostname)}</span></div>` : ''}
    ${hostInfo?.os ? `<div class="detail-row"><span class="detail-key">OS</span><span class="detail-val">${escapeHtml(hostInfo.os)}</span></div>` : ''}

    <div class="detail-section">
      <h3>Services (YAML)</h3>
      ${services}
    </div>

    ${ports ? `<div class="detail-section"><h3>Ports détectés (nmap)</h3>${ports}</div>` : ''}

    <div class="detail-section">
      <h3>Vulnérabilités (${vulns.length})</h3>
      ${sevSummary}
      <div style="margin-top:8px">${vulnHtml || ''}</div>
    </div>
  `;
}

function hideDetail() {
  document.getElementById('detail-placeholder').style.display = '';
  document.getElementById('detail-content').style.display = 'none';
}

// ── Pipeline ───────────────────────────────────────────────────────────────
async function startRun() {
  const model    = document.getElementById('sel-model').value;
  const scenario = document.getElementById('sel-scenario').value || null;
  const teardown = document.getElementById('cb-teardown').checked;
  const phases   = [...document.querySelectorAll('.phase-cb:checked')].map(c => parseInt(c.value));

  // Reset graph colors and state
  resetNodeColors();
  nodeVulns = {};
  nodeHosts = {};
  setCost(0);
  clearPhasePills();

  // Load correct topology
  await loadTopology(scenario ? parseInt(scenario) : null);

  const budgetRaw = document.getElementById('inp-budget').value;
  const maxCost = budgetRaw ? parseFloat(budgetRaw) : null;

  const body = {
    model,
    provider: 'openrouter',
    scenario_id: scenario ? parseInt(scenario) : null,
    phases: phases.length < 5 ? phases : null,
    auto_teardown: teardown,
    max_cost_usd: maxCost,
  };

  const res = await fetch('/api/pipeline/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.json();
    addLog({type:'error', message: err.detail || 'Erreur démarrage pipeline'});
    return;
  }

  document.getElementById('btn-start').disabled = true;
  document.getElementById('btn-stop').style.display = 'block';

  startSSE();
}

async function stopRun() {
  await fetch('/api/pipeline/stop', { method: 'POST' }).catch(() => {});
  if (eventSource) { eventSource.close(); eventSource = null; }
  document.getElementById('btn-start').disabled = false;
  document.getElementById('btn-stop').style.display = 'none';
  addLog({type:'error', message:"Run interrompu par l'utilisateur"});
}

function startSSE() {
  if (eventSource) eventSource.close();

  eventSource = new EventSource('/api/pipeline/stream');

  eventSource.onmessage = (e) => {
    try { handleEvent(JSON.parse(e.data)); }
    catch(e) { console.warn('SSE parse error', e); }
  };

  eventSource.onerror = () => {
    addLog({type:'error', message:'Connexion SSE perdue'});
    eventSource.close();
    eventSource = null;
    document.getElementById('btn-start').disabled = false;
    document.getElementById('btn-stop').style.display = 'none';
    loadRuns();
  };
}

function handleEvent(ev) {
  const t = ev.type;
  addLog(ev);

  if (t === 'phase_start') {
    setPhasePill(ev.phase, 'running');
  }

  else if (t === 'phase_done') {
    setPhasePill(ev.phase, ev.status === 'completed' ? 'done' : 'failed');
    setCost(ev.cumulative_cost_usd || 0);
  }

  else if (t === 'pipeline_done') {
    setCost(ev.total_cost_usd || 0);
    document.getElementById('btn-start').disabled = false;
    document.getElementById('btn-stop').style.display = 'none';
    if (eventSource) { eventSource.close(); eventSource = null; }
    loadRuns();
  }

  else if (t === 'error') {
    document.getElementById('btn-start').disabled = false;
    document.getElementById('btn-stop').style.display = 'none';
    if (eventSource) { eventSource.close(); eventSource = null; }
    loadRuns();
  }

  else if (t === 'tool_result' && ev.name === 'nmap_scan') {
    const parsed = parseNmapResult(ev.result || '');
    Object.entries(parsed).forEach(([ip, info]) => {
      nodeHosts[ip] = info;
      // Find node by IP and mark as scanned
      if (cy) {
        cy.nodes().forEach(n => {
          if (n.data('ip') === ip) {
            n.style('border-color', '#58a6ff');
            n.style('border-width', '2px');
          }
        });
      }
    });
  }

  // Vuln sub-agent done — extract vulns from deliverable name pattern
  else if (t === 'phase_done' && ev.phase === 3) {
    // Fetch vuln analysis deliverable to color nodes
    fetchVulnResults(ev.run_dir);
  }
}

async function fetchVulnResults(runIdOrDir) {
  if (!runIdOrDir) return;
  const runId = runIdOrDir.includes('/') ? runIdOrDir.split('/').pop() : runIdOrDir;
  try {
    const data = await fetchJSON(`/api/runs/${runId}/03_vuln_analysis.json`);
    if (!data || !data.content) return;

    const content = data.content;
    const queue = Array.isArray(content) ? content : (content.vulnerabilities || []);

    queue.forEach(vuln => {
      const nodeId = vuln.device_id;
      if (!nodeVulns[nodeId]) nodeVulns[nodeId] = [];
      nodeVulns[nodeId].push(vuln);
    });

    // Color nodes by worst severity
    Object.entries(nodeVulns).forEach(([nodeId, vulns]) => {
      const order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
      const worst = order.find(s => vulns.some(v => v.severity === s));
      if (worst) colorNodeBySeverity(nodeId, worst);
    });

    // Refresh accessible table with updated severity states
    if (cy) _updateTopologyTable(cy.nodes().map(n => n.data()));
  } catch(e) { console.warn('fetchVulnResults failed', e); }
}

// ── Run history ────────────────────────────────────────────────────────────
const RUNS_PER_PAGE = 15;
let _allRuns = [];
let _runsShown = RUNS_PER_PAGE;
const _compareSet = new Set(); // max 2 run IDs

function toggleCompare(runId) {
  if (_compareSet.has(runId)) {
    _compareSet.delete(runId);
  } else {
    if (_compareSet.size >= 2) {
      const oldest = _compareSet.values().next().value;
      _compareSet.delete(oldest);
      const oldEl = document.querySelector(`.run-item[data-id="${CSS.escape(oldest)}"]`);
      if (oldEl) {
        oldEl.classList.remove('compare-active');
        oldEl.querySelector('.run-compare')?.classList.remove('active');
      }
    }
    _compareSet.add(runId);
  }
  const el = document.querySelector(`.run-item[data-id="${CSS.escape(runId)}"]`);
  if (el) {
    const inCompare = _compareSet.has(runId);
    el.classList.toggle('compare-active', inCompare);
    el.querySelector('.run-compare')?.classList.toggle('active', inCompare);
  }
  _updateCompareButton();
}

function _updateCompareButton() {
  const btn = document.getElementById('btn-compare');
  if (btn) btn.style.display = _compareSet.size === 2 ? 'block' : 'none';
}

async function openCompare() {
  const ids = [..._compareSet];
  if (ids.length < 2) return;
  const [idA, idB] = ids;

  document.getElementById('compare-body').innerHTML =
    '<div style="padding:20px;color:var(--muted)">Chargement…</div>';
  document.getElementById('compare-overlay').classList.add('open');

  const [runA, runB, scoreA, scoreB] = await Promise.all([
    fetchJSON(`/api/runs/${encodeURIComponent(idA)}`),
    fetchJSON(`/api/runs/${encodeURIComponent(idB)}`),
    fetchJSON(`/api/runs/${encodeURIComponent(idA)}/score`),
    fetchJSON(`/api/runs/${encodeURIComponent(idB)}/score`),
  ]);

  const pct = v => (v != null ? (v * 100).toFixed(1) + '%' : '—');

  const colHtml = (run, score, id) => {
    const label = id.replace(/_/g, ' ');
    if (!run) return `
      <div class="compare-col-header">${escapeHtml(label)}</div>
      <div class="compare-col-body" style="color:var(--red)">Erreur chargement</div>`;
    const scoreSection = score?.recall != null ? `
      <div class="detail-section">
        <h3>Score benchmark</h3>
        <div class="detail-row"><span class="detail-key">Recall</span><span class="detail-val">${pct(score.recall)}</span></div>
        <div class="detail-row"><span class="detail-key">Precision</span><span class="detail-val">${pct(score.precision)}</span></div>
        <div class="detail-row"><span class="detail-key">F1</span><span class="detail-val">${pct(score.f1_score)}</span></div>
        <div class="detail-row"><span class="detail-key">Score pondéré</span><span class="detail-val">${score.weighted_score} / ${score.max_weighted_score}</span></div>
        <div class="detail-row"><span class="detail-key">Faux positifs</span><span class="detail-val">${score.false_positives} FP</span></div>
      </div>` : '';
    return `
      <div class="compare-col-header">${escapeHtml(label)}</div>
      <div class="compare-col-body">
        <div class="detail-row"><span class="detail-key">Scénario</span><span class="detail-val">${escapeHtml(run.scenario || 'Lab physique')}</span></div>
        <div class="detail-row"><span class="detail-key">Coût</span><span class="detail-val">${run.cost != null ? '$'+run.cost.toFixed(4) : '—'}</span></div>
        <div class="detail-row"><span class="detail-key">Statut</span><span class="detail-val"><span class="run-badge ${escapeHtml(run.status)}">${escapeHtml(run.status)}</span></span></div>
        ${scoreSection}
        <div class="detail-section">
          <h3>Fichiers (${run.files.length})</h3>
          ${run.files.map(f => `<div style="font-size:11px;padding:2px 0;color:var(--muted)">${escapeHtml(f)}</div>`).join('')}
        </div>
      </div>`;
  };

  document.getElementById('compare-body').innerHTML = `
    <div class="compare-cols">
      <div>${colHtml(runA, scoreA, idA)}</div>
      <div>${colHtml(runB, scoreB, idB)}</div>
    </div>`;
}

function closeCompare(e) {
  if (e && e.target !== document.getElementById('compare-overlay')) return;
  document.getElementById('compare-overlay').classList.remove('open');
}

function _renderRunItem(r) {
  const ts  = r.id.replace('_', ' ').replace(/_/g, ':');
  const scn = r.scenario ? `<span>${escapeHtml(r.scenario)}</span>` : '';
  const cost = r.cost != null ? `<span>$${r.cost.toFixed(4)}</span>` : '';
  const eid = escapeHtml(r.id);
  const inCmp = _compareSet.has(r.id);
  return `
    <div class="run-item ${r.id === activeRunId ? 'active' : ''} ${inCmp ? 'compare-active' : ''}" data-id="${eid}"
      onclick="viewRun('${eid}')"
      role="button" tabindex="0"
      onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();viewRun('${eid}')}">
      <div class="run-item-header">
        <span class="run-id">${escapeHtml(ts)}</span>
        <span class="run-badge ${escapeHtml(r.status)}">${escapeHtml(r.status)}</span>
      </div>
      <div class="run-meta">
        ${scn} ${cost}
        <button class="run-compare ${inCmp ? 'active' : ''}" onclick="event.stopPropagation(); toggleCompare('${eid}')" title="Ajouter à la comparaison">⊕</button>
        <button class="run-download" onclick="event.stopPropagation(); downloadRun('${eid}')">⬇ zip</button>
      </div>
    </div>
  `;
}

function _renderRunList() {
  const list = document.getElementById('run-list');
  const visible = _allRuns.slice(0, _runsShown);
  let html = visible.map(_renderRunItem).join('');
  if (_allRuns.length > _runsShown) {
    html += `<div style="padding:8px 12px;border-top:1px solid var(--border)">
      <button class="run-download" style="width:100%;text-align:center" onclick="_showMoreRuns()">
        Voir plus (${_allRuns.length - _runsShown} restants)
      </button>
    </div>`;
  }
  list.innerHTML = html;
}

function _showMoreRuns() {
  const list = document.getElementById('run-list');
  // Remove the "show more" footer before appending
  const footer = list.lastElementChild;
  if (footer) list.removeChild(footer);

  const prev = _runsShown;
  _runsShown += RUNS_PER_PAGE;
  _allRuns.slice(prev, _runsShown).forEach(r => {
    list.insertAdjacentHTML('beforeend', _renderRunItem(r));
  });

  if (_allRuns.length > _runsShown) {
    list.insertAdjacentHTML('beforeend', `<div style="padding:8px 12px;border-top:1px solid var(--border)">
      <button class="run-download" style="width:100%;text-align:center" onclick="_showMoreRuns()">
        Voir plus (${_allRuns.length - _runsShown} restants)
      </button>
    </div>`);
  }
}

async function loadRuns() {
  const runs = await fetchJSON('/api/runs');
  const list = document.getElementById('run-list');
  if (runs === null) {
    list.innerHTML = '<div style="padding:12px;color:var(--red,#ff6b6b);font-size:11px">Serveur inaccessible</div>';
    return;
  }
  if (runs.length === 0) {
    list.innerHTML = '<div style="padding:12px;color:var(--muted);font-size:11px">Aucun run</div>';
    return;
  }
  _allRuns = runs;
  _runsShown = RUNS_PER_PAGE;
  _renderRunList();
}

async function viewRun(runId) {
  activeRunId = runId;

  // Highlight active run
  document.querySelectorAll('.run-item').forEach(el => {
    el.classList.toggle('active', el.dataset.id === runId);
  });

  const run = await fetchJSON(`/api/runs/${runId}`);
  if (!run) return;

  // Switch graph to this run's topology
  const scenarioId = run.scenario ? parseInt(run.scenario.replace('S', '')) : null;
  resetNodeColors();
  nodeVulns = {};
  nodeHosts = {};
  await loadTopology(scenarioId);

  // Sync dropdown
  document.getElementById('sel-scenario').value = scenarioId !== null ? String(scenarioId) : '';

  // Show run view in detail panel
  document.getElementById('detail-placeholder').style.display = 'none';
  document.getElementById('detail-content').style.display = 'block';
  document.getElementById('detail-node-view').hidden = true;
  document.getElementById('detail-run-view').hidden = false;

  // Title
  const label = runId.replace(/_/g, ' ');
  document.getElementById('detail-run-title').textContent = label;

  // Ensure Info tab is active
  switchDetailTab('info');

  const eRunId = escapeHtml(runId);
  const pct = v => (v != null ? (v * 100).toFixed(1) + '%' : '—');

  // ── Info panel ────────────────────────────────────────────────────────────
  let scoreHtml = '';
  if (run.scenario && run.files.includes('03_vuln_analysis.json')) {
    const score = await fetchJSON(`/api/runs/${eRunId}/score`);
    if (score && score.recall != null) {
      scoreHtml = `
        <div class="detail-section">
          <h3>Score benchmark</h3>
          <div class="detail-row"><span class="detail-key">Recall</span><span class="detail-val">${pct(score.recall)}</span></div>
          <div class="detail-row"><span class="detail-key">Precision</span><span class="detail-val">${pct(score.precision)}</span></div>
          <div class="detail-row"><span class="detail-key">F1</span><span class="detail-val">${pct(score.f1_score)}</span></div>
          <div class="detail-row"><span class="detail-key">Score pondéré</span><span class="detail-val">${score.weighted_score} / ${score.max_weighted_score}</span></div>
          <div class="detail-row"><span class="detail-key">Faux positifs</span><span class="detail-val">${score.false_positives} FP</span></div>
        </div>`;
    }
  }

  document.getElementById('detail-panel-info').innerHTML = `
    <div class="detail-row"><span class="detail-key">Scénario</span><span class="detail-val">${escapeHtml(run.scenario || 'Lab physique')}</span></div>
    <div class="detail-row"><span class="detail-key">Coût</span><span class="detail-val">${run.cost != null ? '$'+run.cost.toFixed(4) : '—'}</span></div>
    <div class="detail-row"><span class="detail-key">Statut</span><span class="detail-val"><span class="run-badge ${escapeHtml(run.status)}">${escapeHtml(run.status)}</span></span></div>
    <div class="detail-row"><span class="detail-key">Fichiers</span><span class="detail-val">${run.files.length}</span></div>
    ${scoreHtml}
  `;

  // ── Fichiers panel ────────────────────────────────────────────────────────
  const fileHtml = run.files.map(f => {
    const ef = escapeHtml(f);
    return `
    <div class="file-item"
      onclick="viewFile('${eRunId}', '${ef}')"
      role="button" tabindex="0"
      onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();viewFile('${eRunId}','${ef}')}">
      <span>${ef}</span>
      <span style="color:var(--muted)">→</span>
    </div>`;
  }).join('');
  document.getElementById('detail-panel-files').innerHTML = `<div class="file-list">${fileHtml}</div>`;

  // ── Rapport panel ─────────────────────────────────────────────────────────
  const reportPanel = document.getElementById('detail-panel-report');
  if (run.files.includes('05_report.md')) {
    reportPanel.innerHTML = '<div style="color:var(--muted);font-size:11px;padding:4px 0">Chargement du rapport…</div>';
    const data = await fetchJSON(`/api/runs/${eRunId}/05_report.md`);
    if (data && data.content) {
      reportPanel.innerHTML = `<div class="md-render">${renderMarkdown(data.content)}</div>`;
    } else {
      reportPanel.innerHTML = '<div style="color:var(--muted);font-size:11px">Rapport non disponible</div>';
    }
  } else {
    reportPanel.innerHTML = '<div style="color:var(--muted);font-size:11px;padding:4px 0">Rapport (phase 5) non généré pour ce run.</div>';
  }

  // Load vuln data to color graph nodes
  if (run.files.includes('03_vuln_analysis.json')) {
    await fetchVulnResults(runId);
  }
}

function switchDetailTab(tab) {
  document.querySelectorAll('.detail-tab').forEach(btn => {
    const active = btn.dataset.tab === tab;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  document.querySelectorAll('.detail-panel').forEach(panel => {
    panel.hidden = panel.id !== `detail-panel-${tab}`;
  });
}

async function viewFile(runId, filename) {
  const data = await fetchJSON(`/api/runs/${runId}/${filename}`);
  if (!data) return;

  document.getElementById('modal-title').textContent = filename;
  const body = document.getElementById('modal-body');

  if (data.type === 'json') {
    body.textContent = JSON.stringify(data.content, null, 2);
  } else {
    body.textContent = data.content;
  }

  const overlay = document.getElementById('modal-overlay');
  overlay._prevFocus = document.activeElement;
  overlay.classList.add('open');
  document.getElementById('modal-close').focus();
}

async function downloadRun(runId) {
  window.location.href = `/api/runs/${runId}/download/zip`;
}

// ── Markdown renderer ──────────────────────────────────────────────────────

function renderMarkdown(md) {
  // Extract fenced code blocks first to avoid processing their contents
  const parts = [];
  const CODE_RE = /```(\w*)\n?([\s\S]*?)```/g;
  let last = 0, m;
  while ((m = CODE_RE.exec(md)) !== null) {
    if (m.index > last) parts.push({ type: 'text', src: md.slice(last, m.index) });
    parts.push({ type: 'code', lang: m[1], src: m[2].trimEnd() });
    last = m.index + m[0].length;
  }
  if (last < md.length) parts.push({ type: 'text', src: md.slice(last) });

  return parts.map(p => {
    if (p.type === 'code') {
      return `<pre class="md-pre"><code class="md-code">${escapeHtml(p.src)}</code></pre>`;
    }
    return _renderMdBlock(p.src);
  }).join('');
}

function _renderMdBlock(text) {
  const lines = text.split('\n');
  let html = '';
  let listTag = null;
  let tableRows = [];
  let inTable = false;

  const flushList = () => {
    if (listTag) { html += `</${listTag}>`; listTag = null; }
  };
  const flushTable = () => {
    if (!inTable) return;
    inTable = false;
    const rows = tableRows.filter(r => r !== null);
    if (!rows.length) { tableRows = []; return; }
    const header = rows[0];
    const body = rows.slice(1);
    html += '<table class="md-table"><thead><tr>';
    header.forEach(c => html += `<th>${_renderInline(c.trim())}</th>`);
    html += '</tr></thead><tbody>';
    body.forEach(row => {
      html += '<tr>';
      row.forEach(c => html += `<td>${_renderInline(c.trim())}</td>`);
      html += '</tr>';
    });
    html += '</tbody></table>';
    tableRows = [];
  };

  for (const line of lines) {
    // Table row
    if (/^\|/.test(line)) {
      flushList();
      inTable = true;
      const cols = line.replace(/^\||\|$/g, '').split('|');
      // Separator row (e.g. |---|---|)
      if (/^[\s|:\-]+$/.test(line)) { tableRows.push(null); }
      else tableRows.push(cols);
      continue;
    }
    if (inTable) flushTable();

    // Heading
    const hm = line.match(/^(#{1,4}) (.+)/);
    if (hm) {
      flushList();
      const lvl = hm[1].length;
      html += `<h${lvl} class="md-h${lvl}">${_renderInline(hm[2])}</h${lvl}>`;
      continue;
    }

    // HR
    if (/^---+\s*$/.test(line)) { flushList(); html += '<hr class="md-hr">'; continue; }

    // Blockquote
    if (/^> /.test(line)) {
      flushList();
      html += `<blockquote class="md-blockquote">${_renderInline(line.slice(2))}</blockquote>`;
      continue;
    }

    // Unordered list
    const ulm = line.match(/^[-*] (.+)/);
    if (ulm) {
      if (listTag !== 'ul') { flushList(); html += '<ul class="md-ul">'; listTag = 'ul'; }
      html += `<li>${_renderInline(ulm[1])}</li>`;
      continue;
    }

    // Ordered list
    const olm = line.match(/^\d+\. (.+)/);
    if (olm) {
      if (listTag !== 'ol') { flushList(); html += '<ol class="md-ol">'; listTag = 'ol'; }
      html += `<li>${_renderInline(olm[1])}</li>`;
      continue;
    }

    // Empty line — flush structures, add spacing
    if (!line.trim()) { flushList(); html += '<br>'; continue; }

    flushList();
    html += `<p class="md-p">${_renderInline(line)}</p>`;
  }

  flushList();
  flushTable();
  return html;
}

function _renderInline(text) {
  let t = escapeHtml(text);
  t = t.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  t = t.replace(/__(.*?)__/g, '<strong>$1</strong>');
  t = t.replace(/\*(.*?)\*/g, '<em>$1</em>');
  t = t.replace(/_(.*?)_/g, '<em>$1</em>');
  t = t.replace(/`(.*?)`/g, '<code class="md-code-inline">$1</code>');
  return t;
}

// ── View switching (Dashboard / Benchmark) ─────────────────────────────────

let _bmData = null; // cached benchmark data

function switchView(view) {
  const isMain = view === 'main';
  const mainEl = document.getElementById('main');
  mainEl.style.display = isMain ? 'flex' : 'none';
  document.getElementById('benchmark-view').hidden = isMain;
  // Log panel belongs to the dashboard only
  document.getElementById('resize-log').style.display = isMain ? '' : 'none';
  document.getElementById('log-wrap').style.display = isMain ? '' : 'none';

  document.querySelectorAll('.view-btn').forEach(btn => {
    const active = btn.dataset.view === view;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
  });

  if (!isMain && !_bmData) loadBenchmark();
}

// ── Benchmark ──────────────────────────────────────────────────────────────

async function loadBenchmark() {
  document.getElementById('bm-table').hidden = true;
  document.getElementById('bm-empty').hidden = true;
  document.getElementById('bm-body').insertAdjacentHTML('afterbegin',
    '<div id="bm-loading" style="padding:32px;text-align:center;color:var(--muted);font-size:13px">Chargement…</div>');

  _bmData = await fetchJSON('/api/runs/benchmark');

  const loading = document.getElementById('bm-loading');
  if (loading) loading.remove();

  if (!_bmData || !_bmData.length) {
    document.getElementById('bm-empty').hidden = false;
    return;
  }
  document.getElementById('bm-table').hidden = false;
  renderBenchmarkTable();
}

function renderBenchmarkTable() {
  const filter = document.getElementById('bm-filter-scenario').value;
  const rows = (_bmData || []).filter(r => !filter || r.scenario === filter);

  const pct = v => v != null ? (v * 100).toFixed(0) + '%' : '—';
  const barColor = v => {
    if (v == null) return 'var(--muted)';
    if (v >= 0.75) return 'var(--green)';
    if (v >= 0.5)  return 'var(--orange)';
    return 'var(--red)';
  };

  const tbody = document.getElementById('bm-tbody');
  tbody.innerHTML = rows.map(r => {
    const s = r.score;
    const f1 = s?.f1_score;
    const barW = f1 != null ? Math.round(f1 * 100) : 0;
    const noScore = `<span class="bm-no-score">—</span>`;
    const modelShort = r.model ? escapeHtml(r.model.split('/').pop()) : '—';
    return `<tr>
      <td class="bm-run-id" onclick="switchView('main');viewRun('${escapeHtml(r.id)}')">${escapeHtml(r.id.replace(/_/g, ' '))}</td>
      <td><span class="run-badge done">${escapeHtml(r.scenario)}</span></td>
      <td style="font-size:11px;color:var(--muted)">${modelShort}</td>
      <td><span class="run-badge ${escapeHtml(r.status)}">${escapeHtml(r.status)}</span></td>
      <td>${r.cost != null ? '$'+r.cost.toFixed(4) : '—'}</td>
      <td>${s ? pct(s.recall) : noScore}</td>
      <td>${s ? pct(s.precision) : noScore}</td>
      <td>${s ? pct(f1) : noScore}</td>
      <td>${s ? `${s.weighted_score}/${s.max_weighted_score}` : noScore}</td>
      <td>
        <div class="bm-bar-wrap" title="${f1 != null ? pct(f1)+' F1' : 'pas de score'}">
          <div class="bm-bar" style="width:${barW}%;background:${barColor(f1)}"></div>
        </div>
      </td>
    </tr>`;
  }).join('');
}

// ── Modal ──────────────────────────────────────────────────────────────────
function closeModal(e) {
  if (e && e.target !== document.getElementById('modal-overlay')) return;
  const overlay = document.getElementById('modal-overlay');
  overlay.classList.remove('open');
  if (overlay._prevFocus) { overlay._prevFocus.focus(); overlay._prevFocus = null; }
}

document.addEventListener('keydown', e => {
  const overlay = document.getElementById('modal-overlay');
  if (!overlay.classList.contains('open')) return;

  if (e.key === 'Escape') {
    const cOverlay = document.getElementById('compare-overlay');
    if (cOverlay.classList.contains('open')) { closeCompare(); return; }
    closeModal();
    return;
  }

  if (e.key === 'Tab') {
    const focusable = overlay.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey) {
      if (document.activeElement === first) { e.preventDefault(); last.focus(); }
    } else {
      if (document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }
});

// ── Phase pills ────────────────────────────────────────────────────────────
function setPhasePill(phase, status) {
  const pill = document.querySelector(`.phase-pill[data-phase="${phase}"]`);
  if (!pill) return;
  pill.className = `phase-pill ${status}`;
  pill.setAttribute('aria-label', `Phase ${phase} ${PHASE_NAMES[phase] || ''}: ${status}`);
}

function clearPhasePills() {
  document.querySelectorAll('.phase-pill').forEach(p => p.className = 'phase-pill');
}

// ── Cost ───────────────────────────────────────────────────────────────────
function setCost(val) {
  document.getElementById('cost-val').textContent = '$' + (val || 0).toFixed(4);
}

// ── Event log ──────────────────────────────────────────────────────────────
const MAX_LOG = 300;

function addLog(ev) {
  const log = document.getElementById('log');
  const t = ev.type || 'info';

  let text = '';
  if (t === 'phase_start')   text = `▶ Phase ${ev.phase} — ${PHASE_NAMES[ev.phase] || ''}`;
  else if (t === 'phase_done') text = `✓ Phase ${ev.phase} done (${ev.status}) — $${(ev.cost_usd||0).toFixed(4)}`;
  else if (t === 'pipeline_start') text = `Pipeline démarré — ${ev.device_count} devices, ${ev.cve_count} CVEs`;
  else if (t === 'pipeline_done')  text = `Pipeline terminé — Total: $${(ev.total_cost_usd||0).toFixed(4)}`;
  else if (t === 'tool_call')  text = `→ ${ev.name}(${_truncate(JSON.stringify(ev.args||{}), 80)})`;
  else if (t === 'tool_result') text = `← ${ev.name}: ${_truncate(String(ev.result||''), 120)}`;
  else if (t === 'text_chunk') text = ev.text ? _truncate(ev.text, 200) : null;
  else if (t === 'error')      text = `✗ ${ev.message || 'Erreur inconnue'}`;
  else if (t === 'deploy_start')   text = `Déploiement scénario S${ev.scenario_id}…`;
  else if (t === 'deploy_done')    text = `Scénario S${ev.scenario_id} ${ev.success ? 'déployé' : 'ÉCHEC'}`;
  else if (t === 'inject_start')   text = `Injection vulns…`;
  else if (t === 'inject_done')    text = `Vulns injectées ${ev.success ? '✓' : '✗'}`;
  else if (t === 'teardown_start') text = `Teardown scénario S${ev.scenario_id}…`;
  else if (t === 'teardown_done')  text = `Teardown terminé`;

  if (!text) return;

  const line = document.createElement('div');
  line.className = `log-line ${t}`;
  line.textContent = text;
  log.appendChild(line);

  // Trim old lines
  while (log.children.length > MAX_LOG) log.removeChild(log.firstChild);
  log.scrollTop = log.scrollHeight;
}

function clearLog() {
  document.getElementById('log').innerHTML = '';
}

// ── Nmap parser ────────────────────────────────────────────────────────────
function parseNmapResult(raw) {
  try {
    const parsed = JSON.parse(raw);
    if (parsed && parsed.stdout) raw = parsed.stdout;
  } catch(e) { console.warn('parseNmapResult JSON parse failed', e); }

  const hosts = {};
  let currentIp = null;

  for (const line of raw.split('\n')) {
    const ipMatch = line.match(/Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?/);
    if (ipMatch) {
      currentIp = ipMatch[2];
      hosts[currentIp] = {hostname: ipMatch[1] || '', ports: [], os: ''};
      continue;
    }
    if (!currentIp) continue;
    const portMatch = line.trim().match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
    if (portMatch) {
      const label = `${portMatch[1]}/${portMatch[2]} ${portMatch[3]}${portMatch[4] ? ' ('+portMatch[4].trim().slice(0,40)+')' : ''}`;
      hosts[currentIp].ports.push(label);
    }
    const osMatch = line.match(/OS details?: (.+)/);
    if (osMatch) hosts[currentIp].os = osMatch[1].trim();
  }
  return hosts;
}

// ── Status polling (catch up after page reload) ────────────────────────────
async function pollStatus() {
  const status = await fetchJSON('/api/pipeline/status');
  if (!status) return;
  setCost(status.cost);
  if (status.running) {
    document.getElementById('btn-start').disabled = true;
    document.getElementById('btn-stop').style.display = 'block';
    startSSE();
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────
async function fetchJSON(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    return await res.json();
  } catch(_) {
    return null;
  }
}

function _truncate(str, n) {
  return str.length > n ? str.slice(0, n) + '…' : str;
}
