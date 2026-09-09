"""Focused contract tests for provider mutation authentication."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from src.api.routes import providers


class FakeDB:
    def __init__(self):
        self.rows = {}
        self.write_count = 0

    def list_providers(self):
        return list(self.rows.values())

    def get_provider(self, name):
        return self.rows.get(name)

    def upsert_provider(self, *, name, base_url, api_key_env, default_model, kind):
        self.write_count += 1
        self.rows[name] = {
            "name": name,
            "base_url": base_url,
            "api_key_env": api_key_env,
            "default_model": default_model,
            "kind": kind,
        }


def _client(monkeypatch, *, reject_db=False):
    db = FakeDB()
    if reject_db:
        def _unexpected_db_access():
            raise AssertionError("database must not be touched before authentication")

        monkeypatch.setattr(providers, "_require_db", _unexpected_db_access)
    else:
        monkeypatch.setattr(providers, "_require_db", lambda: db)
    app = FastAPI()
    app.include_router(providers.router, prefix="/api/providers")
    return TestClient(app), db


def _provider_payload(name="local"):
    return {
        "name": name,
        "base_url": "http://localhost:11434/v1",
        "api_key_env": "LOCAL_API_KEY",
        "default_model": "local-model",
        "kind": "local",
    }


def test_missing_or_empty_server_token_fails_closed_without_db_write(monkeypatch):
    for configured in (None, "", "   "):
        client, db = _client(monkeypatch, reject_db=True)
        if configured is None:
            monkeypatch.delenv("LANCE_ADMIN_TOKEN", raising=False)
        else:
            monkeypatch.setenv("LANCE_ADMIN_TOKEN", configured)

        for method, path, payload in (
            ("post", "/api/providers", _provider_payload()),
            ("patch", "/api/providers/local", {"default_model": "updated-model"}),
        ):
            response = getattr(client, method)(path, json=payload)

            assert response.status_code == 503
            assert db.write_count == 0
            assert response.json()["detail"]["code"] == "admin_auth_not_configured"
            assert "LANCE_ADMIN_TOKEN" not in response.text


def test_missing_malformed_and_invalid_authorization_are_401_without_write(monkeypatch):
    monkeypatch.setenv("LANCE_ADMIN_TOKEN", "server-token-r16")
    for header in (None, "Basic server-token-r16", "Bearer", "Bearer other-token", "Bearer server-token-r16 extra"):
        client, db = _client(monkeypatch, reject_db=True)
        headers = {} if header is None else {"Authorization": header}

        response = client.post("/api/providers", json=_provider_payload(), headers=headers)

        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
        assert db.write_count == 0
        assert "server-token-r16" not in response.text

        response = client.patch(
            "/api/providers/local",
            json={"default_model": "updated-model"},
            headers=headers,
        )
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
        assert db.write_count == 0


def test_ambiguous_or_non_ascii_authorization_never_raises_500(monkeypatch):
    monkeypatch.setenv("LANCE_ADMIN_TOKEN", "server-token-r16")
    client, db = _client(monkeypatch, reject_db=True)

    ambiguous = client.post(
        "/api/providers",
        json=_provider_payload(),
        headers=[
            ("Authorization", "Bearer server-token-r16"),
            ("Authorization", "Bearer another-token"),
        ],
    )
    assert ambiguous.status_code == 401
    assert ambiguous.headers["www-authenticate"] == "Bearer"
    assert db.write_count == 0

    # Build a raw ASGI request so a non-ASCII/invalid header byte is tested at
    # the dependency boundary without relying on an HTTP client's encoding.
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/providers",
        "headers": [(b"authorization", b"Bearer \xff")],
    })
    from fastapi import HTTPException

    try:
        providers.require_admin_auth(request)
    except HTTPException as exc:
        assert exc.status_code == 401
        assert exc.headers["WWW-Authenticate"] == "Bearer"
    else:  # pragma: no cover - defensive assertion for the contract
        raise AssertionError("non-ASCII authorization unexpectedly accepted")


def test_valid_post_and_patch_are_authorized(monkeypatch):
    monkeypatch.setenv("LANCE_ADMIN_TOKEN", "server-token-r16")
    client, db = _client(monkeypatch)
    headers = {"Authorization": "Bearer server-token-r16"}

    created = client.post("/api/providers", json=_provider_payload(), headers=headers)
    updated = client.patch(
        "/api/providers/local",
        json={"default_model": "updated-model"},
        headers=headers,
    )

    assert created.status_code == 200
    assert updated.status_code == 200
    assert updated.json()["default_model"] == "updated-model"
    assert db.write_count == 2
    assert "server-token-r16" not in created.text + updated.text


def test_valid_auth_with_database_init_failure_is_db_503(monkeypatch):
    monkeypatch.setenv("LANCE_ADMIN_TOKEN", "server-token-r16")

    from src.db import database as db

    def fail_init_db():
        raise OSError("temporary database failure")

    monkeypatch.setattr(db, "init_db", fail_init_db)
    app = FastAPI()
    app.include_router(providers.router, prefix="/api/providers")

    response = TestClient(app).post(
        "/api/providers",
        json=_provider_payload(),
        headers={"Authorization": "Bearer server-token-r16"},
    )

    assert response.status_code == 503
    assert "Base de données indisponible" in response.json()["detail"]
    assert response.json()["detail"].find("admin_auth_not_configured") == -1
    assert "server-token-r16" not in response.text


def test_get_remains_public_and_body_validation_still_applies(monkeypatch):
    monkeypatch.delenv("LANCE_ADMIN_TOKEN", raising=False)
    client, db = _client(monkeypatch)

    read = client.get("/api/providers")
    assert read.status_code == 200
    assert read.json() == {"providers": []}
    # Body validation is exercised with a configured server token; it must not
    # result in a partial write.
    monkeypatch.setenv("LANCE_ADMIN_TOKEN", "any-configured-token")
    invalid = client.post(
        "/api/providers",
        json={"base_url": "http://localhost"},
        headers={"Authorization": "Bearer any-configured-token"},
    )
    assert invalid.status_code == 422
    assert db.write_count == 0


def test_js_provider_auth_boundary_with_real_api_send_and_fetch():
    """Exercise the manager's request boundary in Node's dependency-free VM."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js absent; skipping JavaScript behavior test")

    app_path = Path(__file__).parents[1] / "src" / "static" / "app.js"
    source = app_path.read_text(encoding="utf-8")
    start = source.index("const _mgr =")
    end = source.index("// Reload the registry", start)
    manager_source = source[start:end]
    script = f"""
const vm = require('vm');
const managerSource = {json.dumps(manager_source)};
const calls = [];
const sandbox = {{
  window: {{ location: {{ href: 'https://dashboard.test/app' }} }},
  URL,
  console,
  escapeHtml: value => String(value),
  _formatErrDetail: detail => typeof detail === 'string' ? detail : JSON.stringify(detail),
  fetch: async (url, options) => {{
    calls.push({{ url, options }});
    return {{ ok: false, status: 500, json: async () => ({{ detail: 'upstream leaked server-token-r16' }}) }};
  }},
}};
vm.createContext(sandbox);
vm.runInContext(managerSource + String.fromCharCode(10) + 'this.__r16 = {{ apiSend, _mgrProviderError, _mgr }};', sandbox);

function auth(call) {{ return call.options && call.options.headers && call.options.headers.Authorization; }}
function assert(condition, message) {{ if (!condition) throw new Error(message); }}

async function main() {{
  const cases = [
    ['POST', '/api/providers', true],
    ['PATCH', '/api/providers/nom', true],
    ['GET', '/api/providers', false],
    ['DELETE', '/api/providers/nom', false],
    ['POST', '/api/models', false],
    ['PATCH', '/api/providers-extra/nom', false],
    ['POST', 'https://other.test/api/providers', false],
    ['POST', '//other.test/api/providers', false],
    ['POST', 'http://dashboard.test/api/providers', false],
  ];
  for (const [method, url, expected] of cases) {{
    await sandbox.__r16.apiSend(method, url, {{}}, {{ adminToken: 'server-token-r16' }});
    const supplied = auth(calls[calls.length - 1]);
    assert(supplied === (expected ? 'Bearer server-token-r16' : undefined), method + ' ' + url + ' authorization mismatch');
  }}
  sandbox.__r16._mgr.adminToken = 'server-token-r16';
  const error = sandbox.__r16._mgrProviderError({{ status: 500, data: {{ detail: 'upstream leaked server-token-r16' }} }});
  assert(!error.includes('server-token-r16'), 'unexpected error leaked admin token');
  assert(error.includes('[clé masquée]'), 'unexpected error was not redacted');
  const auth503 = sandbox.__r16._mgrProviderError({{ status: 503, data: {{ detail: {{ code: 'admin_auth_not_configured', message: 'not configured' }} }} }});
  assert(auth503.includes('clé admin') && auth503.includes('serveur'), 'admin 503 was not explicit');
  const db503 = sandbox.__r16._mgrProviderError({{ status: 503, data: {{ detail: 'Base de données indisponible' }} }});
  assert(db503.includes('base SQLite') && !db503.includes('clé admin n’est pas configurée'), 'DB 503 was misclassified as auth');
}}

main().catch(error => {{ console.error(error.stack || error); process.exit(1); }});
"""
    result = subprocess.run(
        [node, "-e", script],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_js_manager_open_version_ignores_late_manager_callbacks():
    """Late manager responses cannot overwrite a later modal/session."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js absent; skipping JavaScript behavior test")

    app_path = Path(__file__).parents[1] / "src" / "static" / "app.js"
    source = app_path.read_text(encoding="utf-8")
    start = source.index("function closeModal(e)")
    reload_start = source.index("async function _mgrAfterChange", start)
    end = source.index("\n}\n", reload_start) + 3
    manager_source = source[start:end]
    script = f"""
const vm = require('vm');
const managerSource = {json.dumps(manager_source)};
const requests = [];
const state = {{ open: false, focusCount: 0 }};
const elements = {{
  overlay: {{ classList: {{
    contains: name => name === 'open' && state.open,
    add: () => {{ state.open = true; }},
    remove: () => {{ state.open = false; }},
  }} }},
  title: {{ textContent: '' }},
  body: {{ innerHTML: '' }},
  close: {{ focus: () => {{ state.focusCount += 1; }} }},
  compare: {{ classList: {{ contains: () => false }} }},
  admin: {{ value: '', listeners: [], addEventListener: (name, callback) => {{ if (name === 'input') elements.admin.listeners.push(callback); }} }},
  name: {{ value: 'new-provider' }},
  base: {{ value: 'http://localhost' }},
  defaultModel: {{ value: 'model' }},
  keyEnv: {{ value: 'LOCAL_API_KEY' }},
  kind: {{ value: 'local' }},
}};
const sandbox = {{
  window: {{ location: {{ href: 'https://dashboard.test/app' }} }},
  URL,
  console,
  confirm: () => true,
  resetScrollPosition: () => {{}},
  escapeHtml: value => String(value),
  _formatErrDetail: detail => typeof detail === 'string' ? detail : JSON.stringify(detail),
  loadModels: async () => {{ state.loadModelsCalls = (state.loadModelsCalls || 0) + 1; }},
  document: {{
    activeElement: null,
    addEventListener: () => {{}},
    getElementById: id => ({{
      'modal-overlay': elements.overlay,
      'modal-title': elements.title,
      'modal-body': elements.body,
      'modal-close': elements.close,
      'compare-overlay': elements.compare,
      'mgr-admin-token': elements.admin,
      'mgr-p-name': elements.name,
      'mgr-p-baseurl': elements.base,
      'mgr-p-default': elements.defaultModel,
      'mgr-p-keyenv': elements.keyEnv,
      'mgr-p-kind': elements.kind,
    }})[id] || null,
  }},
  fetch: (url, options) => new Promise(resolve => requests.push({{ url, options, resolve }})),
}};
vm.createContext(sandbox);
vm.runInContext(managerSource + String.fromCharCode(10) + 'this.__r16 = {{ closeModal, openModelsManager, _mgrAfterChange, _mgrPatchModel, _mgrOnSubmit, _renderManager, _mgr }};', sandbox);

function assert(condition, message) {{ if (!condition) throw new Error(message); }}
function response(data, ok = true, status = 200) {{ return {{ ok, status, json: async () => data }}; }}
async function tick() {{ await Promise.resolve(); await Promise.resolve(); }}

async function main() {{
  // Repro: first registry load resolves after close + a fresh opening.
  const firstOpen = sandbox.__r16.openModelsManager();
  await tick();
  assert(requests.length === 1, 'initial registry request missing');
  sandbox.__r16.closeModal();
  const secondOpen = sandbox.__r16.openModelsManager();
  await tick();
  assert(requests.length === 2, 'second registry request missing');
  requests[0].resolve(response({{ models: [], providers: [{{ name: 'stale-registry' }}] }}));
  await firstOpen;
  assert(!elements.body.innerHTML.includes('stale-registry'), 'stale registry overwrote new opening');
  requests[1].resolve(response({{ models: [], providers: [{{ name: 'fresh-registry' }}] }}));
  await secondOpen;
  assert(elements.body.innerHTML.includes('fresh-registry'), 'fresh registry did not render');

  // Repro: a model mutation resolves after the manager was closed.
  sandbox.__r16._mgr.msg = 'sentinel';
  const modelVersion = sandbox.__r16._mgr.openVersion;
  const lateModel = sandbox.__r16._mgrPatchModel('model', {{ enabled: false }}, modelVersion);
  await tick();
  sandbox.__r16.closeModal();
  requests[2].resolve(response({{ ok: true }}));
  await lateModel;
  assert(sandbox.__r16._mgr.msg === 'sentinel', 'late model callback changed manager state');

  // Repro: provider submit error resolves after close; no stale error/focus.
  const thirdOpen = sandbox.__r16.openModelsManager();
  await tick();
  requests[3].resolve(response({{ models: [], providers: [] }}));
  await thirdOpen;
  sandbox.__r16._mgr.msg = 'provider-sentinel';
  const providerVersion = sandbox.__r16._mgr.openVersion;
  elements.admin.value = 'server-token-r16';
  const submit = sandbox.__r16._mgrOnSubmit({{ target: {{ dataset: {{ form: 'provider' }} }}, preventDefault: () => {{}} }}, providerVersion);
  await tick();
  sandbox.__r16.closeModal();
  const focusBeforeLateProvider = state.focusCount;
  elements.admin.value = 'late-input-token';
  elements.admin.listeners[elements.admin.listeners.length - 1]();
  assert(sandbox.__r16._mgr.adminToken === '', 'late input callback changed credential state');
  requests[4].resolve(response({{ detail: 'unauthorized' }}, false, 401));
  await submit;
  assert(sandbox.__r16._mgr.msg === 'provider-sentinel', 'late provider error changed manager state');
  assert(state.focusCount === focusBeforeLateProvider, 'late provider error moved focus');

  // Repro: a successful provider POST resolves after close + reopen with a
  // fresh draft; it must not trigger a stale GET refresh or alter that draft.
  const staleSession = sandbox.__r16.openModelsManager();
  await tick();
  requests[5].resolve(response({{ models: [], providers: [] }}));
  await staleSession;
  const staleVersion = sandbox.__r16._mgr.openVersion;
  elements.name.value = 'stale-provider';
  elements.admin.value = 'stale-session-key';
  const staleSubmit = sandbox.__r16._mgrOnSubmit({{ target: {{ dataset: {{ form: 'provider' }} }}, preventDefault: () => {{}} }}, staleVersion);
  await tick();
  sandbox.__r16.closeModal();
  const freshSession = sandbox.__r16.openModelsManager();
  await tick();
  requests[7].resolve(response({{ models: [], providers: [] }}));
  await freshSession;
  const freshVersion = sandbox.__r16._mgr.openVersion;
  sandbox.__r16._mgr.editProvider = {{ name: 'new-draft' }};
  sandbox.__r16._mgr.adminToken = 'new-session-key';
  sandbox.__r16._renderManager(freshVersion);
  elements.body.innerHTML += 'NEW_DRAFT_MARKER';
  const focusBeforeStaleSuccess = state.focusCount;
  requests[6].resolve(response({{ name: 'stale-provider' }}));
  await staleSubmit;
  assert(sandbox.__r16._mgr.editProvider.name === 'new-draft', 'late provider success replaced new draft');
  assert(sandbox.__r16._mgr.adminToken === 'new-session-key', 'late provider success replaced new key');
  assert(elements.body.innerHTML.includes('NEW_DRAFT_MARKER'), 'late provider success replaced draft DOM');
  assert(requests.length === 8, 'late provider success triggered stale refresh');
  assert(state.focusCount === focusBeforeStaleSuccess, 'late provider success moved focus');

  // Repro: refresh started by a mutation resolves after a new close/open boundary.
  const fourthOpen = sandbox.__r16.openModelsManager();
  await tick();
  requests[8].resolve(response({{ models: [], providers: [{{ name: 'current' }}] }}));
  await fourthOpen;
  sandbox.__r16._mgr.providers = [{{ name: 'before-refresh' }}];
  const refreshVersion = sandbox.__r16._mgr.openVersion;
  const refresh = sandbox.__r16._mgrAfterChange(refreshVersion);
  await tick();
  sandbox.__r16.closeModal();
  requests[9].resolve(response({{ models: [], providers: [{{ name: 'stale-refresh' }}] }}));
  await refresh;
  assert(sandbox.__r16._mgr.providers[0].name === 'before-refresh', 'late refresh overwrote manager state');
  assert(!elements.body.innerHTML.includes('stale-refresh'), 'late refresh touched modal DOM');
  console.log('R16_MANAGER_VM_OK');
}}

main().catch(error => {{ console.error(error.stack || error); process.exit(1); }});
"""
    try:
        result = subprocess.run(
            [node, "-e", script],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"Node manager VM test timed out: {exc}")
    assert result.returncode == 0, result.stderr or result.stdout
    assert "R16_MANAGER_VM_OK" in result.stdout
