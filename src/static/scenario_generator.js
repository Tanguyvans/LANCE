'use strict';

const _scenarioLab = {
  blueprints: [],
  variants: [],
  selected: null,
  loading: null,
  graph: null,
  builder: {
    topologies: [],
    catalog: null,
    selectedNodes: new Set(),
    findings: new Map(),
    loading: null,
  },
};

function _scenarioLabSeed() {
  return Math.floor(Math.random() * 2147483647);
}

function _setScenarioLabStatus(message, type = 'info') {
  const status = document.getElementById('sl-status');
  status.textContent = message;
  status.dataset.type = type;
}

async function _scenarioLabRequest(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {'Content-Type': 'application/json', ...(options.headers || {})},
  });
  let payload = {};
  try { payload = await response.json(); } catch (_) { payload = {}; }
  if (!response.ok) {
    throw new Error(_formatErrDetail(payload.detail || `HTTP ${response.status}`));
  }
  return payload;
}

function _scenarioLabOptions(select, operations) {
  select.innerHTML = '';
  for (const operation of operations || []) {
    const option = document.createElement('option');
    option.value = operation.id;
    option.textContent = operation.label;
    select.appendChild(option);
  }
}

function _scenarioLabBlueprint() {
  const id = document.getElementById('sl-blueprint').value;
  return _scenarioLab.blueprints.find(item => item.id === id) || null;
}

function _refreshScenarioLabOperations() {
  _scenarioLabOptions(
    document.getElementById('sl-operation'),
    _scenarioLabBlueprint()?.operations || [],
  );
}

function _renderScenarioLabVariants() {
  const container = document.getElementById('sl-variants');
  container.innerHTML = '';
  if (!_scenarioLab.variants.length) {
    container.innerHTML = '<div class="sl-empty">Aucune variante générée.</div>';
    return;
  }
  for (const variant of _scenarioLab.variants) {
    const button = document.createElement('button');
    button.className = 'sl-variant' + (
      _scenarioLab.selected?.id === variant.id ? ' active' : ''
    );
    button.innerHTML = `
      <strong>${escapeHtml(variant.id)}</strong>
      <span>${variant.exported ? 'Exporté · ' : ''}${escapeHtml(variant.operation)} · ${variant.vulnerability_count} failles · ${variant.control_count} contrôles</span>
    `;
    button.addEventListener('click', () => selectScenarioLabVariant(variant.id));
    container.appendChild(button);
  }
}

function _renderScenarioLabDetails(variant) {
  const container = document.getElementById('sl-details');
  const mutate = document.getElementById('sl-mutate');
  const exportButton = document.getElementById('sl-export');
  const deleteButton = document.getElementById('sl-delete-export');
  const deleteVariantButton = document.getElementById('sl-delete-variant');
  const summary = _scenarioLab.variants.find(item => item.id === variant?.id);
  const exported = Boolean(summary?.exported);
  if (!variant) {
    exportButton.disabled = true;
    deleteButton.hidden = true;
    deleteButton.disabled = true;
    deleteVariantButton.disabled = true;
    container.innerHTML = '<div class="sl-empty">Sélectionnez ou générez une variante.</div>';
    mutate.disabled = true;
    document.getElementById('sl-mutation-operation').innerHTML = '';
    return;
  }
  exportButton.disabled = exported;
  exportButton.hidden = exported;
  deleteButton.hidden = !exported;
  deleteButton.disabled = !exported;
  deleteVariantButton.disabled = false;

  mutate.disabled = false;
  _scenarioLabOptions(
    document.getElementById('sl-mutation-operation'),
    variant.allowed_operations,
  );
  const findings = variant.ground_truth.vulnerabilities.map(item => `
    <div class="sl-finding">
      <span class="severity">${escapeHtml(String(item.severity || '').toUpperCase())}</span>
      <span>${escapeHtml(item.title)}</span>
      <span class="device">${escapeHtml(item.device)}</span>
    </div>
  `).join('');
  container.innerHTML = `
    <div class="sl-stats">
      <div class="sl-stat"><strong>${variant.topology.service_count}</strong><span>Services</span></div>
      <div class="sl-stat"><strong>${variant.vulnerability_count}</strong><span>Failles</span></div>
      <div class="sl-stat"><strong>${variant.control_count}</strong><span>Contrôles</span></div>
      <div class="sl-stat"><strong>${variant.attack_path_count}</strong><span>Chemins</span></div>
    </div>
    <div class="sl-meta">
      ${escapeHtml(variant.id)}<br>
      source S${escapeHtml(variant.source_scenario_id)} · seed ${variant.seed} · ${escapeHtml(variant.operation)}<br>
      parent ${escapeHtml(variant.parent_variant_id || 'racine')} · ${escapeHtml(variant.deployment_status)}
    </div>
    <div>${findings || '<div class="sl-empty">Aucune faille injectée.</div>'}</div>
  `;
}

function _scenarioLabGraphStyle() {
  return [
    {
      selector: 'node',
      style: {
        'background-color': _cssVar('--node-compute'),
        'label': 'data(label)',
        'color': _cssVar('--text'),
        'font-size': '10px',
        'text-valign': 'bottom',
        'text-margin-y': '6px',
        'text-background-color': _cssVar('--bg'),
        'text-background-opacity': 0.75,
        'text-background-padding': '2px',
        'width': '34px',
        'height': '34px',
        'border-width': '2px',
        'border-color': 'rgba(255,255,255,.15)',
      },
    },
    {selector: 'node[type="router"]', style: {'background-color': _cssVar('--node-router')}},
    {selector: 'node[type="gateway"]', style: {'background-color': _cssVar('--node-gateway')}},
    {selector: 'node[type="sensor"]', style: {'background-color': _cssVar('--node-sensor')}},
    {selector: 'node[type="camera"]', style: {'background-color': _cssVar('--node-camera')}},
    {
      selector: 'node[vuln_count > 0]',
      style: {'border-color': _cssVar('--orange'), 'border-width': '4px'},
    },
    {
      selector: 'edge',
      style: {
        'line-color': _cssVar('--border'),
        'target-arrow-color': _cssVar('--border'),
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'width': 1.5,
        'opacity': 0.7,
      },
    },
  ];
}

async function _previewScenarioLabVariant(variant) {
  const data = await _scenarioLabRequest(
    '/api/scenario-generator/' + encodeURIComponent(variant.id) + '/topology',
  );
  const elements = [
    ...(data.nodes || []).map(node => ({group: 'nodes', data: node})),
    ...(data.edges || []).map(edge => ({group: 'edges', data: edge})),
  ];
  const container = document.getElementById('sl-cy');
  if (_scenarioLab.graph) {
    _scenarioLab.graph.destroy();
  }
  _scenarioLab.graph = cytoscape({
    container,
    elements,
    style: _scenarioLabGraphStyle(),
    layout: {
      name: 'cose',
      animate: false,
      nodeRepulsion: 11000,
      idealEdgeLength: 130,
      gravity: 0.8,
      padding: 45,
    },
  });
  document.getElementById('sl-preview-meta').textContent =
    `${variant.id} · ${data.nodes.length} nœuds · ${(data.subnets || []).join(', ')}`;
}

async function selectScenarioLabVariant(variantId) {
  try {
    _scenarioLab.selected = await _scenarioLabRequest(
      '/api/scenario-generator/' + encodeURIComponent(variantId),
    );
    _renderScenarioLabVariants();
    _renderScenarioLabDetails(_scenarioLab.selected);
    await _previewScenarioLabVariant(_scenarioLab.selected);
  } catch (error) {
    _setScenarioLabStatus(`Erreur : ${error.message}`, 'error');
    addLog({type: 'error', message: `Scenario Lab : ${error.message}`});
  }
}

function _setScenarioBuilderStatus(message, type = 'info') {
  const status = document.getElementById('sl-builder-status');
  if (!status) return;
  status.textContent = message;
  status.dataset.type = type;
}

function _builderFindingKey(nodeId, candidateId) {
  return String(nodeId) + '::' + String(candidateId);
}

function _builderNodeById(nodeId) {
  return (_scenarioLab.builder.catalog?.nodes || []).find(
    node => node.id === nodeId
  ) || null;
}

function _renderScenarioBuilderNodes() {
  const container = document.getElementById('sl-builder-nodes');
  const nodes = (_scenarioLab.builder.catalog?.nodes || []).filter(node => !node.router);
  if (!nodes.length) {
    container.innerHTML = '<div class="sl-empty">Aucun nœud disponible.</div>';
    return;
  }
  const router = (_scenarioLab.builder.catalog?.nodes || []).find(node => node.router);
  const routerLabel = router
    ? '<div class="sl-builder-node"><input type="checkbox" checked disabled><div><strong>Routeur inclus</strong><small>' +
      escapeHtml(router.name) + ' · ' + escapeHtml(router.ip || '') + '</small></div></div>'
    : '';
  container.innerHTML = routerLabel + nodes.map(node => {
    const checked = _scenarioLab.builder.selectedNodes.has(node.id) ? ' checked' : '';
    const services = (node.services || []).join(', ') || 'service non référencé';
    return '<label class="sl-builder-node"><input type="checkbox" data-builder-node="' +
      escapeHtml(node.id) + '"' + checked + '><div><strong>' +
      escapeHtml(node.name) + '</strong><small>' + escapeHtml(node.role) + ' · ' +
      escapeHtml(services) + ' · ' + node.candidate_count + ' failles compatibles</small></div></label>';
  }).join('');
  container.querySelectorAll('[data-builder-node]').forEach(input => {
    input.addEventListener('change', () => {
      const nodeId = input.dataset.builderNode;
      if (input.checked) {
        _scenarioLab.builder.selectedNodes.add(nodeId);
      } else {
        _scenarioLab.builder.selectedNodes.delete(nodeId);
        for (const key of _scenarioLab.builder.findings.keys()) {
          if (key.startsWith(nodeId + '::')) _scenarioLab.builder.findings.delete(key);
        }
      }
      _renderScenarioBuilderNodes();
      _renderScenarioBuilderCandidates();
      _renderScenarioBuilderSelection();
    });
  });
}

function _renderScenarioBuilderCandidates() {
  const container = document.getElementById('sl-builder-candidates');
  const selected = (_scenarioLab.builder.catalog?.nodes || []).filter(
    node => _scenarioLab.builder.selectedNodes.has(node.id)
  );
  if (!selected.length) {
    container.innerHTML = '<div class="sl-empty">Ajoutez un nœud pour afficher ses failles.</div>';
    return;
  }
  container.innerHTML = selected.map(node => {
    const heading = '<div class="sl-builder-group"><strong>' + escapeHtml(node.name) +
      '</strong><small>' + escapeHtml(node.role) + '</small></div>';
    const candidates = (node.candidates || []).map(candidate => {
      const key = _builderFindingKey(node.id, candidate.candidate_id);
      const chosen = _scenarioLab.builder.findings.has(key);
      return '<div class="sl-builder-candidate' + (chosen ? ' is-selected' : '') + '">' +
        '<div><strong>' + escapeHtml(candidate.title) + '</strong><small>' +
        escapeHtml(String(candidate.severity).toUpperCase()) + ' · ' +
        escapeHtml(candidate.category) + (candidate.scenario_scope?.length
          ? ' · scope historique : ' + escapeHtml(candidate.scenario_scope.join(', '))
          : '') + '</small></div><button type="button" data-builder-finding="' +
        escapeHtml(key) + '">' + (chosen ? 'Retirer' : 'Ajouter') + '</button></div>';
    }).join('');
    return heading + (candidates || '<div class="sl-empty">Aucune faille compatible avec ce nœud.</div>');
  }).join('');
  container.querySelectorAll('[data-builder-finding]').forEach(button => {
    button.addEventListener('click', () => {
      const key = button.dataset.builderFinding;
      const separator = key.indexOf('::');
      const nodeId = key.slice(0, separator);
      const candidateId = key.slice(separator + 2);
      const node = _builderNodeById(nodeId);
      const candidate = (node?.candidates || []).find(
        item => item.candidate_id === candidateId
      );
      if (!node || !candidate) return;
      if (_scenarioLab.builder.findings.has(key)) {
        _scenarioLab.builder.findings.delete(key);
      } else {
        _scenarioLab.builder.findings.set(key, {
          nodeId, candidateId, node, candidate,
        });
      }
      _renderScenarioBuilderCandidates();
      _renderScenarioBuilderSelection();
    });
  });
}

function _renderScenarioBuilderSelection() {
  const container = document.getElementById('sl-builder-selection');
  const selected = Array.from(_scenarioLab.builder.selectedNodes)
    .map(nodeId => _builderNodeById(nodeId))
    .filter(Boolean);
  const findings = Array.from(_scenarioLab.builder.findings.values());
  if (!selected.length && !findings.length) {
    container.innerHTML = '<div class="sl-empty">Aucun nœud sélectionné.</div>';
    return;
  }
  const nodes = selected.map(node =>
    '<div class="sl-builder-selected"><div><strong>' + escapeHtml(node.name) +
    '</strong><small>' + escapeHtml(node.role) + '</small></div><button type="button" data-builder-remove-node="' +
    escapeHtml(node.id) + '">Retirer</button></div>'
  ).join('');
  const selectedFindings = findings.map(item =>
    '<div class="sl-builder-selected"><div><span class="severity">' +
    escapeHtml(String(item.candidate.severity).toUpperCase()) + '</span> ' +
    escapeHtml(item.candidate.title) + '<small>' + escapeHtml(item.node.name) +
    '</small></div><button type="button" data-builder-remove-finding="' +
    escapeHtml(_builderFindingKey(item.nodeId, item.candidateId)) + '">Retirer</button></div>'
  ).join('');
  container.innerHTML = (nodes || '') + (selectedFindings || '');
  container.querySelectorAll('[data-builder-remove-node]').forEach(button => {
    button.addEventListener('click', () => {
      _scenarioLab.builder.selectedNodes.delete(button.dataset.builderRemoveNode);
      for (const key of _scenarioLab.builder.findings.keys()) {
        if (key.startsWith(button.dataset.builderRemoveNode + '::')) {
          _scenarioLab.builder.findings.delete(key);
        }
      }
      _renderScenarioBuilderNodes();
      _renderScenarioBuilderCandidates();
      _renderScenarioBuilderSelection();
    });
  });
  container.querySelectorAll('[data-builder-remove-finding]').forEach(button => {
    button.addEventListener('click', () => {
      _scenarioLab.builder.findings.delete(button.dataset.builderRemoveFinding);
      _renderScenarioBuilderCandidates();
      _renderScenarioBuilderSelection();
    });
  });
}

async function _loadScenarioBuilderCatalog(topologyId) {
  const data = await _scenarioLabRequest(
    '/api/scenario-generator/builder/catalog/' + encodeURIComponent(topologyId)
  );
  _scenarioLab.builder.catalog = data;
  _scenarioLab.builder.selectedNodes = new Set();
  _scenarioLab.builder.findings = new Map();
  _renderScenarioBuilderNodes();
  _renderScenarioBuilderCandidates();
  _renderScenarioBuilderSelection();
  _setScenarioBuilderStatus(
    data.topology.name + ' · sélectionnez les nœuds puis les failles compatibles'
  );
}

async function _loadScenarioBuilder() {
  const data = await _scenarioLabRequest('/api/scenario-generator/builder/topologies');
  _scenarioLab.builder.topologies = data.topologies || [];
  const select = document.getElementById('sl-builder-topology');
  const previous = select.value;
  select.innerHTML = _scenarioLab.builder.topologies.map(topology =>
    '<option value="' + escapeHtml(topology.id) + '">' +
    escapeHtml(topology.name) + ' · ' + topology.candidate_count + ' failles</option>'
  ).join('');
  const chosen = _scenarioLab.builder.topologies.some(item => item.id === previous)
    ? previous
    : _scenarioLab.builder.topologies[0]?.id;
  if (!chosen) {
    _setScenarioBuilderStatus('Aucune topologie disponible.', 'error');
    return;
  }
  select.value = chosen;
  await _loadScenarioBuilderCatalog(chosen);
}

async function _composeScenarioBuilder() {
  const button = document.getElementById('sl-builder-compose');
  const topologyId = document.getElementById('sl-builder-topology').value;
  button.disabled = true;
  _setScenarioBuilderStatus('Composition et validation…');
  try {
    const result = await _scenarioLabRequest('/api/scenario-generator/builder/compose', {
      method: 'POST',
      body: JSON.stringify({
        topology_id: topologyId,
        selected_nodes: Array.from(_scenarioLab.builder.selectedNodes),
        findings: Array.from(_scenarioLab.builder.findings.values()).map(item => ({
          node_id: item.nodeId,
          candidate_id: item.candidateId,
        })),
        name: document.getElementById('sl-builder-name').value,
        seed: Number(document.getElementById('sl-builder-seed').value) || 0,
        execution_profile: document.getElementById('sl-builder-execution').value,
      }),
    });
    await Promise.all([_loadScenarioLab(), loadScenariosConfig()]);
    await selectScenarioLabVariant(result.id);
    _setScenarioBuilderStatus(result.id + ' créé et validé.', 'success');
    addLog({type: 'info', message: 'Scénario manuel créé : ' + result.id});
  } catch (error) {
    _setScenarioBuilderStatus('Composition impossible : ' + error.message, 'error');
    addLog({type: 'error', message: 'Scenario Lab : ' + error.message});
  } finally {
    button.disabled = false;
  }
}

async function _randomScenarioBuilder() {
  const button = document.getElementById('sl-builder-random');
  button.disabled = true;
  _setScenarioBuilderStatus('Génération aléatoire et validation…');
  const value = id => Number(document.getElementById(id).value) || 1;
  try {
    const result = await _scenarioLabRequest('/api/scenario-generator/builder/random', {
      method: 'POST',
      body: JSON.stringify({
        topology_id: document.getElementById('sl-builder-topology').value || null,
        seed: Number(document.getElementById('sl-builder-seed').value) || 0,
        min_nodes: value('sl-random-min-nodes'),
        max_nodes: value('sl-random-max-nodes'),
        min_vulnerabilities: value('sl-random-min-vulns'),
        max_vulnerabilities: value('sl-random-max-vulns'),
        execution_profile: document.getElementById('sl-builder-execution').value,
      }),
    });
    await Promise.all([_loadScenarioLab(), loadScenariosConfig()]);
    await selectScenarioLabVariant(result.id);
    _setScenarioBuilderStatus(result.id + ' généré avec des combinaisons compatibles.', 'success');
    addLog({type: 'info', message: 'Scénario aléatoire créé : ' + result.id});
  } catch (error) {
    _setScenarioBuilderStatus('Génération impossible : ' + error.message, 'error');
    addLog({type: 'error', message: 'Scenario Lab : ' + error.message});
  } finally {
    button.disabled = false;
  }
}

async function _loadScenarioLab() {
  const [blueprints, variants] = await Promise.all([
    _scenarioLabRequest('/api/scenario-generator/blueprints'),
    _scenarioLabRequest('/api/scenario-generator'),
  ]);
  _scenarioLab.blueprints = blueprints.blueprints || [];
  _scenarioLab.variants = variants.variants || [];

  const select = document.getElementById('sl-blueprint');
  const previous = select.value;
  select.innerHTML = '';
  for (const blueprint of _scenarioLab.blueprints) {
    const option = document.createElement('option');
    option.value = blueprint.id;
    option.textContent = `${blueprint.label} (S${blueprint.source_scenario_id})`;
    select.appendChild(option);
  }
  if (_scenarioLab.blueprints.some(item => item.id === previous)) {
    select.value = previous;
  }
  _refreshScenarioLabOperations();
  _renderScenarioLabVariants();
  _renderScenarioLabDetails(_scenarioLab.selected);
  await _loadScenarioBuilder();
  _setScenarioLabStatus(
    `${_scenarioLab.blueprints.length} blueprints · ${_scenarioLab.variants.length} variantes · ${_scenarioLab.variants.filter(item => item.exported).length} exports dashboard`,
  );
}

async function openScenarioLab() {
  if (!_scenarioLab.loading) {
    _scenarioLab.loading = _loadScenarioLab().catch(error => {
      _setScenarioLabStatus(`Erreur : ${error.message}`, 'error');
      addLog({type: 'error', message: `Scenario Lab : ${error.message}`});
    }).finally(() => {
      _scenarioLab.loading = null;
    });
  }
  await _scenarioLab.loading;
  requestAnimationFrame(() => {
    if (_scenarioLab.graph) {
      _scenarioLab.graph.resize();
      _scenarioLab.graph.fit(undefined, 45);
    }
  });
}

async function _generateScenarioLabVariant() {
  const button = document.getElementById('sl-generate');
  button.disabled = true;
  _setScenarioLabStatus('Génération en cours…');
  try {
    const generated = await _scenarioLabRequest('/api/scenario-generator', {
      method: 'POST',
      body: JSON.stringify({
        blueprint_id: document.getElementById('sl-blueprint').value,
        operation: document.getElementById('sl-operation').value,
        seed: Number(document.getElementById('sl-seed').value),
      }),
    });
    await _loadScenarioLab();
    await selectScenarioLabVariant(generated.id);
    _setScenarioLabStatus(`${generated.id} généré · prévisualisation uniquement`, 'success');
    addLog({type: 'info', message: `Scénario généré : ${generated.id}`});
  } catch (error) {
    _setScenarioLabStatus(`Génération impossible : ${error.message}`, 'error');
    addLog({type: 'error', message: `Génération impossible : ${error.message}`});
  } finally {
    button.disabled = false;
  }
}

async function _mutateScenarioLabVariant() {
  if (!_scenarioLab.selected) return;
  const button = document.getElementById('sl-mutate');
  button.disabled = true;
  _setScenarioLabStatus('Mutation en cours…');
  try {
    const generated = await _scenarioLabRequest(
      '/api/scenario-generator/' + encodeURIComponent(_scenarioLab.selected.id) + '/mutations',
      {
        method: 'POST',
        body: JSON.stringify({
          operation: document.getElementById('sl-mutation-operation').value,
          seed: Number(document.getElementById('sl-mutation-seed').value),
        }),
      },
    );
    await _loadScenarioLab();
    await selectScenarioLabVariant(generated.id);
    _setScenarioLabStatus(`${generated.id} créé depuis sa variante parente`, 'success');
    addLog({type: 'info', message: `Scénario muté : ${generated.id}`});
  } catch (error) {
    _setScenarioLabStatus(`Mutation impossible : ${error.message}`, 'error');
    addLog({type: 'error', message: `Mutation impossible : ${error.message}`});
  } finally {
    button.disabled = !_scenarioLab.selected;
  }
}


async function _exportScenarioLabVariant() {
  if (!_scenarioLab.selected) return;
  const variantId = _scenarioLab.selected.id;
  const button = document.getElementById('sl-export');
  button.disabled = true;
  _setScenarioLabStatus('Export vers le dashboard…');
  try {
    await _scenarioLabRequest(
      '/api/scenario-generator/' + encodeURIComponent(variantId) + '/export',
      {method: 'POST'},
    );
    await Promise.all([_loadScenarioLab(), loadScenariosConfig()]);
    await selectScenarioLabVariant(variantId);
    _setScenarioLabStatus(`${variantId} est disponible dans le dashboard`, 'success');
    addLog({type: 'info', message: `Scénario exporté vers le dashboard : ${variantId}`});
  } catch (error) {
    _setScenarioLabStatus(`Export impossible : ${error.message}`, 'error');
    addLog({type: 'error', message: `Export impossible : ${error.message}`});
  } finally {
    _renderScenarioLabDetails(_scenarioLab.selected);
  }
}

async function _deleteScenarioLabExport() {
  if (!_scenarioLab.selected) return;
  const variantId = _scenarioLab.selected.id;
  if (!window.confirm('Effacer cet export du dashboard ? La variante du Lab sera conservée.')) return;
  const button = document.getElementById('sl-delete-export');
  button.disabled = true;
  try {
    await _scenarioLabRequest(
      '/api/scenario-generator/' + encodeURIComponent(variantId) + '/export',
      {method: 'DELETE'},
    );
    await Promise.all([_loadScenarioLab(), loadScenariosConfig()]);
    await selectScenarioLabVariant(variantId);
    _setScenarioLabStatus(`${variantId} retiré du dashboard`, 'success');
    addLog({type: 'info', message: `Export retiré du dashboard : ${variantId}`});
  } catch (error) {
    _setScenarioLabStatus(`Suppression impossible : ${error.message}`, 'error');
    addLog({type: 'error', message: `Suppression impossible : ${error.message}`});
  } finally {
    _renderScenarioLabDetails(_scenarioLab.selected);
  }
}

async function _deleteScenarioLabVariant() {
  if (!_scenarioLab.selected) return;
  const variantId = _scenarioLab.selected.id;
  const summary = _scenarioLab.variants.find(item => item.id === variantId);
  const exportWarning = summary?.exported
    ? ' Son export sera également retiré du dashboard.'
    : '';
  if (!window.confirm(`Effacer définitivement ${variantId} du Scenario Lab ?${exportWarning}`)) return;

  const button = document.getElementById('sl-delete-variant');
  button.disabled = true;
  _setScenarioLabStatus(`Suppression de ${variantId}…`);
  try {
    const payload = await _scenarioLabRequest(
      '/api/scenario-generator/' + encodeURIComponent(variantId),
      {method: 'DELETE'},
    );
    _scenarioLab.selected = null;
    if (_scenarioLab.graph) {
      _scenarioLab.graph.destroy();
      _scenarioLab.graph = null;
    }
    document.getElementById('sl-preview-meta').textContent = 'Aucune variante sélectionnée';
    document.getElementById('sl-cy').innerHTML = '';
    await Promise.all([_loadScenarioLab(), loadScenariosConfig()]);
    if (payload.scenario?.export_deleted) await loadTopology(null);
    const suffix = payload.scenario?.export_deleted ? ' et retiré du dashboard' : '';
    _setScenarioLabStatus(`${variantId} supprimé du Scenario Lab${suffix}`, 'success');
    addLog({type: 'info', message: `Scénario généré supprimé : ${variantId}${suffix}`});
  } catch (error) {
    _setScenarioLabStatus(`Suppression impossible : ${error.message}`, 'error');
    addLog({type: 'error', message: `Suppression impossible : ${error.message}`});
  } finally {
    _renderScenarioLabDetails(_scenarioLab.selected);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('sl-builder-seed').value = _scenarioLabSeed();
  document.getElementById('sl-seed').value = _scenarioLabSeed();
  document.getElementById('sl-mutation-seed').value = _scenarioLabSeed();
  document.getElementById('sl-blueprint').addEventListener(
    'change',
    _refreshScenarioLabOperations,
  );
  document.getElementById('sl-generate').addEventListener(
    'click',
    _generateScenarioLabVariant,
  );
  document.getElementById('sl-mutate').addEventListener(
    'click',
    _mutateScenarioLabVariant,
  );
  document.getElementById('sl-export').addEventListener(
    'click',
    _exportScenarioLabVariant,
  );
  document.getElementById('sl-delete-export').addEventListener(
    'click',
    _deleteScenarioLabExport,
  );
  document.getElementById('sl-delete-variant').addEventListener(
    'click',
    _deleteScenarioLabVariant,
  );
  document.getElementById('sl-builder-topology').addEventListener('change', () => {
    _loadScenarioBuilderCatalog(document.getElementById('sl-builder-topology').value)
      .catch(error => _setScenarioBuilderStatus('Catalogue indisponible : ' + error.message, 'error'));
  });
  document.getElementById('sl-builder-compose').addEventListener(
    'click',
    _composeScenarioBuilder,
  );
  document.getElementById('sl-builder-random').addEventListener(
    'click',
    _randomScenarioBuilder,
  );
  document.getElementById('sl-fit').addEventListener('click', () => {
    if (_scenarioLab.graph) {
      _scenarioLab.graph.animate({
        fit: {padding: 45},
        duration: 300,
        easing: 'ease-out',
      });
    }
  });
});
