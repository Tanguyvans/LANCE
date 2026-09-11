"""Model choices use the registry without OpenRouter or Codex catalogs."""
from __future__ import annotations

import pytest
import json
from pathlib import Path
import shutil
import subprocess


@pytest.mark.parametrize("refresh", [False, True])
def test_selector_keeps_registry_models_and_excludes_removed_providers(tmp_path, monkeypatch, refresh):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "models.db"))
    monkeypatch.setenv("OPENROUTER_API_KEY", "configured")
    monkeypatch.setenv("MINIMAX_API_KEY", "configured")
    from src.api.routes import models
    from src.db import database as db

    def forbidden_catalog(*args, **kwargs):
        raise AssertionError("The selector must not query removed catalogs or pricing")

    monkeypatch.setattr("src.agent.codex_app_server.get_codex_catalog", forbidden_catalog)
    monkeypatch.setattr("src.agent.pricing._load_openrouter_catalog", forbidden_catalog)
    monkeypatch.setattr("src.agent.pricing._load_pricing", forbidden_catalog)
    db.init_db()
    for provider in ("local", "minimax", "openrouter", "codex"):
        db.upsert_provider(provider)
        db.upsert_model(
            f"{provider}-model", provider=provider, enabled=True,
            input_per_mtok=1.5, output_per_mtok=2.5,
        )
    db.upsert_model("disabled-local", provider="local", enabled=False)

    response = models.list_models(refresh=refresh)
    by_id = {model["id"]: model for model in response["models"]}
    assert set(by_id) == {"local-model", "minimax-model"}
    assert by_id["local-model"]["available"] is True
    assert by_id["local-model"]["input_per_mtok"] == 1.5
    assert by_id["local-model"]["output_per_mtok"] == 2.5
    assert by_id["minimax-model"]["subscription"] is True
    assert by_id["minimax-model"]["input_per_mtok"] is None
    assert response["providers"] == {
        "local": {"available": True, "model_count": 1},
        "minimax": {"available": True, "model_count": 1},
    }
    # Reducing launch choices does not delete historical configuration.
    assert db.get_model("openrouter-model") is not None
    assert db.get_model("codex-model") is not None


@pytest.mark.parametrize("registry_unavailable", [False, True])
def test_fallback_excludes_removed_providers_and_preserves_key_requirement(
    tmp_path, monkeypatch, registry_unavailable,
):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "models.db"))
    monkeypatch.delenv("MINIMAX_API_KEY", raising=False)
    from src.api.routes import models
    if registry_unavailable:
        def unavailable():
            raise OSError("database unavailable")
        monkeypatch.setattr("src.db.database.init_db", unavailable)

    response = models.list_models()
    assert response["models"]
    assert {model["provider"] for model in response["models"]} == {"minimax"}
    assert all(model["available"] is False for model in response["models"])


def test_excluded_registry_does_not_restore_fallback_choices(tmp_path, monkeypatch):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "models.db"))
    from src.api.routes import models
    from src.db import database as db
    db.init_db()
    db.upsert_provider("openrouter")
    db.upsert_model("router-model", provider="openrouter", enabled=True)
    assert models.list_models() == {"models": [], "providers": {}}


def test_dashboard_replaces_removed_saved_models_in_all_selectors():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js unavailable")
    source = (Path(__file__).resolve().parents[1] / "src/static/app.js").read_text()
    source = source[source.index("const MODEL_STORAGE_KEY"):source.index("async function loadScenariosConfig")]
    script = r'''
const vm = require('vm'), assert = require('assert');
class Element {
  constructor(tag = 'select') { this.tag = tag; this.children = []; this.dataset = {}; this._value = ''; }
  set innerHTML(value) { this.children = []; this._value = ''; }
  appendChild(child) { this.children.push(child); }
  get options() { return this.children.flatMap(child => child.tag === 'option' ? [child] : child.options); }
  get value() { return this.tag === 'option' ? this._value : this._value || this.options[0]?.value || ''; }
  set value(value) { this._value = value; }
  get selectedOptions() { return this.options.filter(option => option.value === this.value); }
}
(async () => {
  for (const removed of ['openrouter/auto', 'gpt-current']) {
    let stored = removed;
    const elements = Object.fromEntries(['sel-model', 'sel-judge-model', 'model-provider-status', 'btn-refresh-models']
      .map(id => [id, new Element()]));
    const phases = [new Element(), new Element(), new Element()];
    for (const select of [elements['sel-model'], elements['sel-judge-model'], ...phases]) select.value = removed;
    const requests = [];
    const context = {
      console,
      window: {localStorage: {getItem: () => stored, setItem: (key, value) => { stored = value; }}},
      document: {getElementById: id => elements[id], querySelectorAll: () => phases,
        createElement: tag => new Element(tag)},
      fetchJSON: async url => {
        requests.push(url);
        return {models: [
          {id: 'local-model', provider: 'local', label: 'Local', available: true, recommended: true},
          {id: 'MiniMax-M2.7', provider: 'minimax', label: 'MiniMax', available: false, subscription: true},
        ]};
      },
    };
    vm.createContext(context);
    vm.runInContext(__SOURCE__, context);
    await context.loadModels(true);
    assert.deepStrictEqual(requests, ['/api/models?refresh=true']);
    for (const select of [elements['sel-model'], elements['sel-judge-model'], ...phases]) {
      const options = select.options.filter(option => option.value);
      assert.deepStrictEqual(options.map(option => option.value), ['local-model', 'MiniMax-M2.7']);
      assert.strictEqual(options[0].dataset.provider, 'local');
      assert.strictEqual(options[1].disabled, true);
    }
    assert.strictEqual(elements['sel-model'].value, 'local-model');
    assert.strictEqual(elements['sel-judge-model'].value, 'local-model');
    assert(phases.every(select => select.value === ''));
    assert.strictEqual(stored, 'local-model');
    assert.strictEqual(elements['model-provider-status'].textContent, '1 modèle disponible sur 2');
  }
})().catch(error => { console.error(error); process.exit(1); });
'''
    result = subprocess.run(
        [node, "-"], input=script.replace("__SOURCE__", json.dumps(source)),
        text=True, capture_output=True, timeout=5,
    )
    assert result.returncode == 0, result.stdout + result.stderr
