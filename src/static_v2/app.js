'use strict';

// ── State ──────────────────────────────────────────────────────────────────
const state = {
  scenario: null,
  model: null,
  running: false,
  currentRun: null,
  layers: new Set(['network']),
  nodes: {},          // id → node data
  vulns: {},          // ip → [{type, severity, status}]
  compromised: [],    // ips compromised by intrusion
  hopEdges: [],       // intrusion hop pairs
  allScenarios: [],   // loaded from API
  sse: null,
};

// ── Severity config ────────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { color: '#ff1744', glow: 30, order: 0 },
  HIGH:     { color: '#ff6d00', glow: 20, order: 1 },
  MEDIUM:   { color: '#ffd600', glow: 12, order: 2 },
  LOW:      { color: '#69f0ae', glow: 8,  order: 3 },
  INFO:     { color: '#40c4ff', glow: 6,  order: 4 },
  SAFE:     { color: '#00d4ff', glow: 6,  order: 5 },
};

// Role → base color (used when no vuln severity)
const ROLE_COLOR = {
  router:         '#2979ff',
  gateway:        '#2979ff',
  switch:         '#448aff',
  ap:             '#40c4ff',
  server:         '#00bcd4',
  compute:        '#00bcd4',
  mqtt_broker:    '#ff6d00',
  mqtt_broker_v2: '#ff6d00',
  web_server:     '#00bcd4',
  ssh_server:     '#00bcd4',
  db_server:      '#e040fb',
  plc:            '#ff1744',
  historian:      '#e040fb',
  nodered_server: '#ff9100',
  snmp_server:    '#00bcd4',
  coap_server:    '#00bcd4',
  camera:         '#ff6d00',
  camera_server:  '#ff6d00',
  sensor:         '#69f0ae',
  iot_gateway:    '#2979ff',
  external:       '#546e7a',
};

// Role → node size (width/height)
const ROLE_SIZE = {
  router: 60, gateway: 60, switch: 55, ap: 50,
  external: 46,
  plc: 58, historian: 58, db_server: 58,
};
function nodeSize(role) { return ROLE_SIZE[role] || 52; }

// ── Cytoscape init ─────────────────────────────────────────────────────────
const cy = cytoscape({
  container: document.getElementById('cy'),
  style: buildCyStyle(),
  layout: { name: 'preset' },
  userZoomingEnabled: true,
  userPanningEnabled: true,
  boxSelectionEnabled: false,
  autoungrabify: false,
});

function buildCyStyle() {
  return [
    {
      selector: 'node',
      style: {
        'background-color': '#071628',
        'border-color': 'data(baseColor)',
        'border-width': 2,
        'color': '#c8e4f8',
        'label': 'data(label)',
        'font-family': 'Space Mono, monospace',
        'font-size': 10,
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 8,
        'text-wrap': 'wrap',
        'text-max-width': '120px',
        'text-background-color': 'rgba(5,10,20,0.85)',
        'text-background-opacity': 1,
        'text-background-padding': '3px',
        'text-background-shape': 'roundrectangle',
        'shadow-blur': 18,
        'shadow-color': 'data(baseColor)',
        'shadow-opacity': 0.55,
        'shadow-offset-x': 0,
        'shadow-offset-y': 0,
        'width': 'data(sz)',
        'height': 'data(sz)',
        'shape': 'ellipse',
      }
    },
    {
      selector: 'node[sev = "CRITICAL"]',
      style: {
        'border-color': '#ff1744',
        'shadow-color': '#ff1744',
        'shadow-opacity': 0.95,
        'shadow-blur': 45,
        'border-width': 3.5,
        'background-color': '#1a0510',
      }
    },
    {
      selector: 'node[sev = "HIGH"]',
      style: {
        'border-color': '#ff6d00',
        'shadow-color': '#ff6d00',
        'shadow-opacity': 0.85,
        'shadow-blur': 32,
        'border-width': 3,
        'background-color': '#1a0e05',
      }
    },
    {
      selector: 'node[sev = "MEDIUM"]',
      style: {
        'border-color': '#ffd600',
        'shadow-color': '#ffd600',
        'shadow-opacity': 0.65,
        'shadow-blur': 22,
        'border-width': 2.5,
        'background-color': '#131000',
      }
    },
    {
      selector: 'node[sev = "LOW"]',
      style: {
        'border-color': '#69f0ae',
        'shadow-color': '#69f0ae',
        'shadow-opacity': 0.5,
        'shadow-blur': 16,
      }
    },
    {
      selector: 'node.compromised',
      style: {
        'border-color': '#d500f9',
        'shadow-color': '#d500f9',
        'shadow-opacity': 1,
        'shadow-blur': 45,
        'border-width': 3,
      }
    },
    {
      selector: 'node.selected',
      style: {
        'border-width': 3,
        'shadow-opacity': 1,
        'shadow-blur': 50,
      }
    },
    {
      selector: 'node[type = "external"]',
      style: {
        'shape': 'diamond',
        'background-color': '#080e18',
        'border-color': '#546e7a',
        'border-style': 'dashed',
        'shadow-color': '#546e7a',
        'shadow-blur': 8,
        'shadow-opacity': 0.4,
      }
    },
    {
      selector: 'edge',
      style: {
        'line-color': 'rgba(0, 180, 255, 0.25)',
        'width': 1.8,
        'curve-style': 'bezier',
        'target-arrow-shape': 'none',
      }
    },
    {
      selector: 'edge[protocol = "lorawan"], edge[protocol = "zigbee"]',
      style: {
        'line-style': 'dashed',
        'line-dash-pattern': [4, 4],
        'line-color': 'rgba(105, 240, 174, 0.2)',
      }
    },
    {
      selector: 'edge[protocol = "mqtt"]',
      style: {
        'line-color': 'rgba(255, 109, 0, 0.25)',
      }
    },
    {
      selector: 'edge[protocol = "wan"]',
      style: {
        'line-style': 'dashed',
        'line-color': 'rgba(255, 23, 68, 0.3)',
        'width': 2,
      }
    },
    {
      selector: 'edge.attack-path',
      style: {
        'line-color': '#ff1744',
        'width': 2.5,
        'line-style': 'dashed',
        'line-dash-pattern': [6, 4],
        'opacity': 0.8,
        'target-arrow-shape': 'triangle',
        'target-arrow-color': '#ff1744',
        'arrow-scale': 1.2,
      }
    },
    {
      selector: 'edge.intrusion-hop',
      style: {
        'line-color': '#d500f9',
        'width': 3,
        'opacity': 0.9,
        'target-arrow-shape': 'triangle',
        'target-arrow-color': '#d500f9',
        'arrow-scale': 1.4,
        'shadow-blur': 15,
        'shadow-color': '#d500f9',
        'shadow-opacity': 0.6,
      }
    },
    {
      selector: 'edge.hidden',
      style: { 'opacity': 0, 'events': 'no' }
    },
    {
      selector: 'node.hidden',
      style: { 'opacity': 0.15 }
    },
  ];
}

// ── Topology loading ───────────────────────────────────────────────────────
async function loadTopology() {
  const url = state.scenario
    ? `/api/topology?scenario=${state.scenario}`
    : '/api/topology';
  const data = await fetchJSON(url);
  cy.elements().remove();
  state.nodes = {};
  state.vulns = {};
  state.compromised = [];

  const elements = [];

  for (const n of (data.nodes || [])) {
    state.nodes[n.id] = n;
    const role = n.role || n.type || 'server';
    const sev = topSeverity(n.id);
    const baseColor = ROLE_COLOR[role] || '#00d4ff';
    const sz = nodeSize(role);
    // Label: device name (id without prefix) + IP
    const shortId = n.id.replace(/^s\d+-/, '').replace(/_/g, '-');
    const labelName = (shortId !== n.ip && shortId !== n.id) ? shortId : (role !== 'server' ? role : n.id);
    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        label: `${labelName}\n${n.ip || ''}`,
        ip: n.ip,
        role,
        os: n.os,
        sev,
        type: n.type,
        services: n.services || [],
        cve_count: n.cve_count || 0,
        baseColor,
        sz,
      },
    });
  }

  for (const e of (data.edges || [])) {
    elements.push({
      group: 'edges',
      data: {
        id: `${e.source}-${e.target}`,
        source: e.source,
        target: e.target,
        protocol: e.protocol || 'ethernet',
      },
    });
  }

  cy.add(elements);
  applyLayout();
  applyLayers();
  updateMetric('metricDevices', data.nodes?.length ?? '—');
  const vulns = data.nodes?.reduce((acc, n) => acc + (n.data?.vuln_count || 0), 0);
  if (vulns) updateMetric('metricVulns', vulns);
}

function applyLayout() {
  const n = cy.nodes().length;
  if (n === 0) return;

  const layout = cy.layout({
    name: 'breadthfirst',
    animate: true,
    animationDuration: 900,
    fit: true,
    padding: 60,
    directed: true,
    spacingFactor: 1.8,
    circle: false,
    grid: false,
    avoidOverlap: true,
    maximal: false,
  });
  layout.run();
}

function topSeverity(nodeId) {
  const node = state.nodes[nodeId];
  if (!node) return 'SAFE';
  const ip = node.ip;
  const vulns = state.vulns[ip] || [];
  if (vulns.length === 0) return 'SAFE';
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  for (const sev of order) {
    if (vulns.some(v => v.severity === sev)) return sev;
  }
  return 'SAFE';
}

function updateNodeSeverities() {
  cy.nodes().forEach(node => {
    const sev = topSeverity(node.id());
    node.data('sev', sev);
  });
}

// ── Layer system ───────────────────────────────────────────────────────────
function applyLayers() {
  const layers = state.layers;

  cy.nodes().forEach(n => {
    n.removeClass('hidden');
    const showLabel = layers.has('services');
    if (showLabel) {
      const services = n.data('services') || [];
      const ports = services.map(s => s.port).filter(Boolean).join(', ');
      n.data('label', `${n.data('ip') || n.id()}\n${ports}`);
    } else {
      n.data('label', n.data('ip') || n.id());
    }
  });

  cy.edges().forEach(e => {
    e.removeClass('hidden attack-path intrusion-hop');
  });

  if (layers.has('paths')) {
    cy.edges().addClass('attack-path');
  }
  if (layers.has('infiltration')) {
    cy.edges().forEach(e => {
      const pair = `${e.data('source')}-${e.data('target')}`;
      if (state.hopEdges.includes(pair)) {
        e.removeClass('attack-path');
        e.addClass('intrusion-hop');
      }
    });
    state.compromised.forEach(ip => {
      const node = cy.nodes().filter(n => n.data('ip') === ip);
      node.addClass('compromised');
    });
  } else {
    cy.nodes().removeClass('compromised');
  }

  if (!layers.has('network')) {
    cy.edges().addClass('hidden');
  }
}

// ── Event log ──────────────────────────────────────────────────────────────
function log(msg, type = 'info') {
  const entries = document.getElementById('logEntries');
  const line = document.createElement('div');
  line.className = `log-line ${type}`;
  const now = new Date();
  const t = `${now.getHours().toString().padStart(2,'0')}:${now.getMinutes().toString().padStart(2,'0')}:${now.getSeconds().toString().padStart(2,'0')}`;
  line.innerHTML = `<span class="log-time">${t}</span><span class="log-msg">${escHtml(msg)}</span>`;
  entries.prepend(line);
  while (entries.children.length > 200) entries.lastChild.remove();
}

// ── Phase progress bar ─────────────────────────────────────────────────────
const PHASES = ['Graph', 'Recon', 'Vuln', 'Exploit', 'Intrusion', 'Report'];

function initPhaseBar() {
  const steps = document.getElementById('phaseSteps');
  steps.innerHTML = '';
  PHASES.forEach((p, i) => {
    const div = document.createElement('div');
    div.className = 'phase-step';
    div.title = p;
    div.id = `phase-step-${i}`;
    steps.appendChild(div);
  });
}

function setPhase(phaseNum, status = 'active') {
  PHASES.forEach((_, i) => {
    const el = document.getElementById(`phase-step-${i}`);
    if (!el) return;
    el.className = 'phase-step';
    if (i < phaseNum) el.classList.add('done');
    else if (i === phaseNum) el.classList.add(status);
  });
  const label = document.getElementById('phaseLabel');
  label.textContent = phaseNum < PHASES.length ? PHASES[phaseNum] : 'Done';
}

// ── SSE connection ─────────────────────────────────────────────────────────
function connectSSE() {
  if (state.sse) { state.sse.close(); state.sse = null; }
  const es = new EventSource('/api/pipeline/stream');
  state.sse = es;

  es.onmessage = e => {
    let ev;
    try { ev = JSON.parse(e.data); } catch { return; }
    handleEvent(ev);
  };

  es.onerror = () => {
    setTimeout(connectSSE, 3000);
  };
}

function handleEvent(ev) {
  const t = ev.type;

  if (t === 'pipeline_start') {
    setRunning(true);
    updateMetric('metricDevices', ev.device_count ?? '—');
    setPhase(0, 'active');
    log(`Pipeline started — ${ev.device_count} devices, ${ev.cve_count} CVEs`, 'phase');
  }

  else if (t === 'pipeline_done') {
    setRunning(false);
    setPhase(PHASES.length - 1, 'done');
    updateMetric('metricCost', `$${(ev.total_cost_usd || 0).toFixed(3)}`);
    log('Pipeline done', 'success');
    loadRuns();
  }

  else if (t === 'phase_start') {
    const idx = phaseIndex(ev.phase);
    if (idx >= 0) setPhase(idx, 'active');
    document.getElementById('phaseLabel').textContent = ev.label || ev.phase;
    log(`▶ Phase ${ev.phase} — ${ev.label || ''}`, 'phase');
  }

  else if (t === 'phase_done') {
    const idx = phaseIndex(ev.phase);
    if (idx >= 0) setPhase(idx, 'done');
    const cost = ev.cost_usd ? ` $${ev.cost_usd.toFixed(3)}` : '';
    log(`✓ Phase ${ev.phase} done${cost}`, 'success');
  }

  else if (t === 'device_start') {
    log(`  Analyzing ${ev.device_id} (${ev.ip})`, 'info');
  }

  else if (t === 'device_done') {
    const vulns = ev.vuln_count || 0;
    if (vulns > 0) {
      const ip = ev.ip;
      if (!state.vulns[ip]) state.vulns[ip] = [];
      (ev.vulns || []).forEach(v => state.vulns[ip].push(v));
      updateNodeSeverities();
      updateMetric('metricVulns', totalVulns());
    }
    log(`  ${ev.device_id}: ${vulns} vulns`, vulns > 0 ? 'warn' : 'info');
  }

  else if (t === 'exploit_start') {
    log(`  Exploiting ${ev.vuln_type} on ${ev.device_id}`, 'exploit');
  }

  else if (t === 'exploit_done') {
    const ok = ev.status === 'CONFIRMED';
    log(`  ${ok ? '✓' : '✗'} ${ev.vuln_type} ${ev.device_id} — ${ev.status}`, ok ? 'success' : 'warn');
  }

  else if (t === 'intrusion_compromised') {
    const ip = ev.device_ip;
    if (ip && !state.compromised.includes(ip)) state.compromised.push(ip);
    const node = cy.nodes().filter(n => n.data('ip') === ip);
    if (node.length) node.addClass('compromised');
    log(`  Compromised: ${ev.device_id} (${ip}) via ${ev.access_method || '?'}`, 'intrusion');
  }

  else if (t === 'intrusion_hop') {
    const from = ev.from_ip;
    const to = ev.to_ip;
    if (from && to) {
      const fromNode = cy.nodes().filter(n => n.data('ip') === from);
      const toNode   = cy.nodes().filter(n => n.data('ip') === to);
      if (fromNode.length && toNode.length) {
        const edgeId = `hop-${from}-${to}`;
        if (!cy.getElementById(edgeId).length) {
          cy.add({ group: 'edges', data: { id: edgeId, source: fromNode.id(), target: toNode.id() } });
        }
        cy.getElementById(edgeId).addClass('intrusion-hop');
        state.hopEdges.push(`${fromNode.id()}-${toNode.id()}`);
      }
    }
    log(`  Hop: ${from} → ${to} via ${ev.method || '?'}`, 'intrusion');
  }

  else if (t === 'intrusion_done') {
    const cj = (ev.crown_jewels_reached || []).join(', ') || 'none';
    log(`Infiltration done — ${ev.devices_compromised || 0} compromised, ${ev.credentials_harvested || 0} creds, crown jewels: ${cj}`, 'intrusion');
    updateMetric('metricVulns', totalVulns());
  }

  else if (t === 'tool_result') {
    if (ev.tool === 'nmap_scan' && ev.ip) {
      if (!cy.getElementById(ev.ip).length) {
        cy.add({ group: 'nodes', data: { id: ev.ip, label: ev.ip, ip: ev.ip, sev: 'SAFE', type: 'server' } });
        cy.layout({ name: 'cose', animate: true, animationDuration: 600, fit: false, randomize: false }).run();
      }
    }
  }

  else if (t === 'error') {
    setRunning(false);
    log(`✗ ${ev.message}`, 'error');
    setStatusDot('error');
  }

  else if (t === 'deploy_start') {
    log(`Deploying scenario ${ev.scenario_id}...`, 'info');
  }
  else if (t === 'deploy_done') {
    log(`Scenario deployed ${ev.success ? '✓' : '✗'}`, ev.success ? 'success' : 'error');
    if (ev.success) loadTopology();
  }
  else if (t === 'inject_start') log('Injecting vulns...', 'info');
  else if (t === 'inject_done') log('Vulns injected ✓', 'success');

  else if (t === 'teardown_done') {
    log(`Teardown S${ev.scenario_id} ${ev.success ? 'done ✓' : 'failed ✗'}`, ev.success ? 'success' : 'error');
    if (ev.success) loadTopology();
  }

  else if (t === 'batch_start') {
    log(`Batch started — ${ev.total} scenarios: ${ev.ids.join(', ')}`, 'phase');
  }
  else if (t === 'batch_scenario_start') {
    log(`[${ev.index + 1}/${ev.total}] Starting S${ev.scenario_id}...`, 'phase');
  }
  else if (t === 'batch_scenario_done') {
    const r = ev.result || {};
    const score = r.score != null ? ` score=${r.score.toFixed(1)}` : '';
    log(`[${ev.index + 1}/${ev.total}] S${ev.scenario_id} done${score}`, 'success');
  }
  else if (t === 'batch_done') {
    setRunning(false);
    log('Batch complete', 'success');
    loadRuns();
  }
}

function phaseIndex(phase) {
  const map = { 1: 0, '1': 0, 2: 1, '2': 1, 3: 2, '3': 2, 4: 3, '4': 3, 5: 4, '5': 4, 6: 5, '6': 5 };
  return map[phase] ?? -1;
}

// ── UI state helpers ───────────────────────────────────────────────────────
function setRunning(running) {
  state.running = running;
  document.getElementById('btnRun').disabled = running;
  document.getElementById('btnStop').disabled = !running;
  document.getElementById('btnBatch').disabled = running;
  setStatusDot(running ? 'running' : 'done');
}

function setStatusDot(status) {
  const dot = document.getElementById('statusDot');
  dot.className = `status-dot ${status}`;
}

function updateMetric(id, val) {
  const el = document.getElementById(id);
  if (!el) return;
  el.querySelector('.m-val').textContent = val;
}

function totalVulns() {
  return Object.values(state.vulns).reduce((s, arr) => s + arr.length, 0);
}

// ── Node click — right panel ───────────────────────────────────────────────
cy.on('tap', 'node', e => {
  const node = e.target;
  cy.nodes().removeClass('selected');
  node.addClass('selected');
  showNodeDetail(node);
});

cy.on('tap', e => {
  if (e.target === cy) {
    cy.nodes().removeClass('selected');
    closeRightPanel();
  }
});

function showNodeDetail(node) {
  const data = node.data();
  const ip = data.ip || node.id();
  const vulns = state.vulns[ip] || [];
  const rp = document.getElementById('rightPanel');
  const rpTitle = document.getElementById('rpTitle');
  const rpContent = document.getElementById('rpContent');

  rpTitle.textContent = data.role ? `${data.role.toUpperCase()} — ${ip}` : ip;

  const sevCounts = {};
  vulns.forEach(v => { sevCounts[v.severity] = (sevCounts[v.severity] || 0) + 1; });

  const compromised = state.compromised.includes(ip);

  rpContent.innerHTML = `
    <div class="rp-field">
      <div class="rp-label">IP Address</div>
      <div class="rp-value">${escHtml(ip)}</div>
    </div>
    <div class="rp-field">
      <div class="rp-label">Role</div>
      <div class="rp-value">${escHtml(data.role || data.type || '—')}</div>
    </div>
    <div class="rp-field">
      <div class="rp-label">OS</div>
      <div class="rp-value">${escHtml(data.os || '—')}</div>
    </div>
    ${data.cve_count ? `<div class="rp-field"><div class="rp-label">CVEs</div><div class="rp-value">${data.cve_count}</div></div>` : ''}
    ${compromised ? `<div class="rp-field"><div class="rp-value" style="color:#d500f9">⚠ COMPROMISED</div></div>` : ''}
    ${data.services && data.services.length ? `
    <div class="rp-field">
      <div class="rp-label">Services</div>
      <div class="rp-value">${data.services.map(s =>
        `<span class="vuln-badge INFO">${s.port}/${s.protocol || 'tcp'} ${escHtml(s.name || '')}</span>`
      ).join('')}</div>
    </div>` : ''}
    <div class="rp-field">
      <div class="rp-label">Vulnerabilities (${vulns.length})</div>
      <div class="severity-bar">
        ${vulns.length === 0 ? '<span style="color:var(--text-dim);font-size:11px">None detected</span>' :
          vulns.map(v => `<span class="vuln-badge ${v.severity || 'INFO'}">${escHtml(v.type || v.vuln_type || '?')}</span>`).join('')
        }
      </div>
    </div>
  `;

  rp.classList.remove('hidden');
}

function closeRightPanel() {
  document.getElementById('rightPanel').classList.add('hidden');
}

document.getElementById('rpClose').addEventListener('click', () => {
  cy.nodes().removeClass('selected');
  closeRightPanel();
});

// ── Layer toggles ──────────────────────────────────────────────────────────
document.querySelectorAll('.layer-item').forEach(item => {
  item.addEventListener('click', () => {
    const layer = item.dataset.layer;
    if (state.layers.has(layer)) {
      state.layers.delete(layer);
      item.classList.remove('active');
    } else {
      state.layers.add(layer);
      item.classList.add('active');
    }
    applyLayers();
  });
});

// ── Scenario selector (dynamic) ────────────────────────────────────────────
function bindScenarioBtn(btn) {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.s-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.scenario = btn.dataset.s || null;
    state.vulns = {};
    state.compromised = [];
    state.hopEdges = [];
    loadTopology();
  });
}

async function loadScenarios() {
  const data = await fetchJSON('/api/scenarios');
  const scenarios = (data.scenarios || []).slice().sort((a, b) => {
    // Sort numerically when possible, then alphabetically
    const na = parseInt(a.id), nb = parseInt(b.id);
    if (!isNaN(na) && !isNaN(nb)) return na - nb;
    if (!isNaN(na)) return -1;
    if (!isNaN(nb)) return 1;
    return String(a.id).localeCompare(String(b.id));
  });
  state.allScenarios = scenarios;

  const grid = document.getElementById('scenarioBtns');
  bindScenarioBtn(grid.querySelector('.s-btn[data-s=""]'));

  for (const s of scenarios) {
    const btn = document.createElement('button');
    btn.className = 's-btn';
    btn.dataset.s = s.id;
    btn.title = s.name || `Scenario ${s.id}`;
    btn.textContent = `S${s.id}`;
    grid.appendChild(btn);
    bindScenarioBtn(btn);
  }
}

// ── Run controls ───────────────────────────────────────────────────────────
document.getElementById('btnRun').addEventListener('click', async () => {
  const body = { provider: 'openrouter', model: state.model };
  if (state.scenario) body.scenario_id = String(state.scenario);
  const r = await fetchJSON('/api/pipeline/start', { method: 'POST', body: JSON.stringify(body) });
  if (r.status !== 'started') log(`Start failed: ${r.detail || JSON.stringify(r)}`, 'error');
});

document.getElementById('btnStop').addEventListener('click', async () => {
  await fetchJSON('/api/pipeline/stop', { method: 'POST' });
  log('Stop requested', 'warn');
});

document.getElementById('btnTeardown').addEventListener('click', async () => {
  if (!state.scenario) { log('No scenario selected', 'warn'); return; }
  const res = await fetchJSON('/api/pipeline/teardown', { method: 'POST', body: JSON.stringify({ scenario_id: String(state.scenario) }) });
  if (res.error) { log(`Teardown request failed (${res.error})`, 'error'); return; }
  log(`Teardown S${state.scenario} requested...`, 'warn');
});

// ── Batch modal ────────────────────────────────────────────────────────────
const batchSelected = new Set();

document.getElementById('btnBatch').addEventListener('click', () => {
  const grid = document.getElementById('batchGrid');
  grid.innerHTML = '';
  const scenarios = state.allScenarios || [];
  for (const s of scenarios) {
    const btn = document.createElement('button');
    btn.className = 'batch-btn' + (batchSelected.has(s.id) ? ' selected' : '');
    btn.textContent = `S${s.id}`;
    btn.title = s.name || '';
    btn.addEventListener('click', () => {
      if (batchSelected.has(s.id)) { batchSelected.delete(s.id); btn.classList.remove('selected'); }
      else { batchSelected.add(s.id); btn.classList.add('selected'); }
    });
    grid.appendChild(btn);
  }
  document.getElementById('batchModal').classList.remove('hidden');
});

document.getElementById('btnBatchClose').addEventListener('click', () => {
  document.getElementById('batchModal').classList.add('hidden');
});

document.getElementById('btnBatchRun').addEventListener('click', async () => {
  if (batchSelected.size === 0) { log('Select at least one scenario', 'warn'); return; }
  const ids = [...batchSelected].sort();
  const body = { batch_ids: ids.map(String), provider: 'openrouter', model: state.model };
  document.getElementById('batchModal').classList.add('hidden');
  await fetchJSON('/api/pipeline/batch', { method: 'POST', body: JSON.stringify(body) });
});

// ── Model selector ─────────────────────────────────────────────────────────
const FALLBACK_MODELS = [
  { id: 'google/gemini-2.5-flash-preview', label: 'Gemini 2.5 Flash' },
  { id: 'anthropic/claude-sonnet-4-6', label: 'Claude Sonnet 4.6' },
  { id: 'openai/gpt-4o', label: 'GPT-4o' },
];

async function loadModels() {
  const data = await fetchJSON('/api/models');
  const models = (data.models && data.models.length) ? data.models : FALLBACK_MODELS;
  const sel = document.getElementById('modelSelect');
  sel.innerHTML = '';
  models.forEach(m => {
    const opt = document.createElement('option');
    opt.value = m.id;
    opt.textContent = m.label || m.id;
    sel.appendChild(opt);
  });
  state.model = sel.value;
  sel.addEventListener('change', () => { state.model = sel.value; });
}

// ── Runs list ──────────────────────────────────────────────────────────────
async function loadRuns() {
  const data = await fetchJSON('/api/runs');
  const list = document.getElementById('runsList');
  list.innerHTML = '';
  (data.runs || []).slice(0, 15).forEach(r => {
    const el = document.createElement('div');
    el.className = 'run-entry' + (r.id === state.currentRun ? ' active' : '');
    el.textContent = r.id;
    el.addEventListener('click', () => selectRun(r.id));
    list.appendChild(el);
  });
}

async function selectRun(runId) {
  state.currentRun = runId;
  document.querySelectorAll('.run-entry').forEach(el => {
    el.classList.toggle('active', el.textContent === runId);
  });
}

// ── Fetch helper ───────────────────────────────────────────────────────────
async function fetchJSON(url, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  try {
    const r = await fetch(url, { ...opts, headers });
    return r.ok ? r.json() : { error: r.status };
  } catch (e) {
    return { error: e.message };
  }
}

function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Init ───────────────────────────────────────────────────────────────────
async function init() {
  try {
    initPhaseBar();
    connectSSE();
    await Promise.all([loadModels(), loadRuns(), loadScenarios()]);
    await loadTopology();
    log('Monitor online', 'success');
  } catch(e) {
    log(`Init error: ${e.message}`, 'error');
  }
}

// Clear log button
document.getElementById('btnClearLog').addEventListener('click', () => {
  document.getElementById('logEntries').innerHTML = '';
});

init();
