'use strict';

const scenarioLab = {
  blueprints: [],
  variants: [],
  selected: null,
};

function scenarioSeed() {
  return Math.floor(Math.random() * 2147483647);
}

async function scenarioGeneratorFetch(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  let payload = {};
  try { payload = await response.json(); } catch (_) { payload = {}; }
  if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
  return payload;
}

function setOperationOptions(select, operations) {
  select.innerHTML = '';
  for (const operation of operations || []) {
    const option = document.createElement('option');
    option.value = operation.id;
    option.textContent = operation.label;
    select.appendChild(option);
  }
}

function selectedBlueprint() {
  const id = document.getElementById('generatorBlueprint').value;
  return scenarioLab.blueprints.find(item => item.id === id) || null;
}

function refreshBlueprintOperations() {
  const blueprint = selectedBlueprint();
  setOperationOptions(
    document.getElementById('generatorOperation'),
    blueprint?.operations || [],
  );
}

function renderScenarioVariants() {
  const container = document.getElementById('generatorVariants');
  container.innerHTML = '';
  if (!scenarioLab.variants.length) {
    container.innerHTML = '<div class="generator-empty">NO GENERATED VARIANT</div>';
    return;
  }
  for (const variant of scenarioLab.variants) {
    const button = document.createElement('button');
    button.className = 'generator-variant' + (
      scenarioLab.selected?.id === variant.id ? ' active' : ''
    );
    button.innerHTML = `
      <strong>${escHtml(variant.id)}</strong>
      <span>${escHtml(variant.operation)} · ${variant.vulnerability_count} vulns · ${variant.control_count} controls</span>
    `;
    button.addEventListener('click', () => selectGeneratedScenario(variant.id));
    container.appendChild(button);
  }
}

function renderGeneratedDetails(variant) {
  const container = document.getElementById('generatorDetails');
  const mutate = document.getElementById('btnMutateScenario');
  const preview = document.getElementById('btnPreviewScenario');
  if (!variant) {
    container.innerHTML = '<div class="generator-empty">NO VARIANT SELECTED</div>';
    mutate.disabled = true;
    preview.disabled = true;
    return;
  }

  mutate.disabled = false;
  preview.disabled = false;
  setOperationOptions(
    document.getElementById('mutationOperation'),
    variant.allowed_operations,
  );
  const findings = variant.ground_truth.vulnerabilities.map(item => `
    <div class="generator-finding">
      <span class="severity">${escHtml(String(item.severity || '').toUpperCase())}</span>
      <span class="finding-title">${escHtml(item.title)}</span>
      <span class="finding-device">${escHtml(item.device)}</span>
    </div>
  `).join('');
  container.innerHTML = `
    <div class="generator-stats">
      <div class="generator-stat"><strong>${variant.topology.service_count}</strong><span>SERVICES</span></div>
      <div class="generator-stat"><strong>${variant.vulnerability_count}</strong><span>VULNS</span></div>
      <div class="generator-stat"><strong>${variant.control_count}</strong><span>CONTROLS</span></div>
      <div class="generator-stat"><strong>${variant.attack_path_count}</strong><span>PATHS</span></div>
    </div>
    <div class="generator-meta">
      ${escHtml(variant.id)}<br>
      source S${escHtml(variant.source_scenario_id)} · seed ${variant.seed} · ${escHtml(variant.operation)}<br>
      parent ${escHtml(variant.parent_variant_id || 'root')} · ${escHtml(variant.deployment_status)}
    </div>
    <div class="generator-findings">${findings}</div>
  `;
}

async function selectGeneratedScenario(variantId) {
  try {
    scenarioLab.selected = await scenarioGeneratorFetch(
      '/api/scenario-generator/' + encodeURIComponent(variantId),
    );
    renderScenarioVariants();
    renderGeneratedDetails(scenarioLab.selected);
  } catch (error) {
    log(`Generated scenario: ${error.message}`, 'error');
  }
}

async function loadScenarioLab() {
  const [blueprints, variants] = await Promise.all([
    scenarioGeneratorFetch('/api/scenario-generator/blueprints'),
    scenarioGeneratorFetch('/api/scenario-generator'),
  ]);
  scenarioLab.blueprints = blueprints.blueprints || [];
  scenarioLab.variants = variants.variants || [];

  const blueprintSelect = document.getElementById('generatorBlueprint');
  blueprintSelect.innerHTML = '';
  for (const blueprint of scenarioLab.blueprints) {
    const option = document.createElement('option');
    option.value = blueprint.id;
    option.textContent = `${blueprint.label} (S${blueprint.source_scenario_id})`;
    blueprintSelect.appendChild(option);
  }
  refreshBlueprintOperations();
  renderScenarioVariants();
  renderGeneratedDetails(scenarioLab.selected);
}

async function createGeneratedScenario() {
  const button = document.getElementById('btnGenerateScenario');
  button.disabled = true;
  try {
    const payload = {
      blueprint_id: document.getElementById('generatorBlueprint').value,
      operation: document.getElementById('generatorOperation').value,
      seed: Number(document.getElementById('generatorSeed').value),
    };
    const generated = await scenarioGeneratorFetch('/api/scenario-generator', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    await loadScenarioLab();
    await selectGeneratedScenario(generated.id);
    log(`Generated ${generated.id}`, 'success');
  } catch (error) {
    log(`Generation failed: ${error.message}`, 'error');
  } finally {
    button.disabled = false;
  }
}

async function mutateGeneratedScenario() {
  if (!scenarioLab.selected) return;
  const button = document.getElementById('btnMutateScenario');
  button.disabled = true;
  try {
    const payload = {
      operation: document.getElementById('mutationOperation').value,
      seed: Number(document.getElementById('mutationSeed').value),
    };
    const generated = await scenarioGeneratorFetch(
      '/api/scenario-generator/' + encodeURIComponent(scenarioLab.selected.id) + '/mutations',
      { method: 'POST', body: JSON.stringify(payload) },
    );
    await loadScenarioLab();
    await selectGeneratedScenario(generated.id);
    log(`Mutated ${generated.id}`, 'success');
  } catch (error) {
    log(`Mutation failed: ${error.message}`, 'error');
  } finally {
    button.disabled = !scenarioLab.selected;
  }
}

async function previewGeneratedScenario() {
  if (!scenarioLab.selected) return;
  const variantId = scenarioLab.selected.id;
  try {
    await scenarioGeneratorFetch(
      '/api/scenario-generator/' + encodeURIComponent(variantId) + '/export',
      {method: 'POST'},
    );
  } catch (error) {
    log(`Export failed: ${error.message}`, 'error');
    return;
  }
  state.generatedVariant = variantId;
  state.scenario = variantId;
  document.querySelectorAll('.s-btn').forEach(button => button.classList.remove('active'));
  document.getElementById('generatorModal').classList.add('hidden');
  document.getElementById('phaseLabel').textContent = 'GENERATED SCENARIO';
  await loadTopology();
  log(`Scenario ${state.generatedVariant} exported and ready to run`, 'success');
}

document.getElementById('btnGenerator').addEventListener('click', async () => {
  document.getElementById('generatorModal').classList.remove('hidden');
  document.getElementById('generatorSeed').value = scenarioSeed();
  document.getElementById('mutationSeed').value = scenarioSeed();
  try { await loadScenarioLab(); }
  catch (error) { log(`Scenario Lab: ${error.message}`, 'error'); }
});

document.getElementById('btnGeneratorClose').addEventListener('click', () => {
  document.getElementById('generatorModal').classList.add('hidden');
});
document.getElementById('generatorBlueprint').addEventListener('change', refreshBlueprintOperations);
document.getElementById('btnGenerateScenario').addEventListener('click', createGeneratedScenario);
document.getElementById('btnMutateScenario').addEventListener('click', mutateGeneratedScenario);
document.getElementById('btnPreviewScenario').addEventListener('click', previewGeneratedScenario);

if (window.location.hash === "#scenario-lab") {
  document.getElementById("btnGenerator").click();
}
