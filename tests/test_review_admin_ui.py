"""Browser request policy exercised without any network or persistent storage."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_admin_ui_only_sends_key_to_same_origin_mutations():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js required')
    source = (Path(__file__).parents[1] / 'src/static/app.js').read_text()
    helper = 'async function adminFetch' + source.split('async function adminFetch', 1)[1].split('\nasync function apiSend', 1)[0]
    cost = 'function setCost' + source.split('function setCost', 1)[1].split('// ── Event log', 1)[0]
    script = r'''
const assert = require('node:assert/strict');
const field = {value: 'test-key', focus() {this.focused = true;}};
const help = {textContent: ''}, details = {open: false}, badge = {};
global.document = {getElementById: id => ({'admin-action-token': field,
  'admin-action-help': help, 'admin-access': details, 'cost-val': badge})[id]};
global.window = {location: {href: 'https://dashboard.test/'}};
let request, status = 200, error = {};
global.fetch = async (url, options) => {
  request = {url, options};
  return {status, clone: () => ({json: async () => error})};
};
async function check() {
  for (const [url, method, allowed] of [
    ['/api/pipeline/start', 'POST', true], ['/api/models/1', 'DELETE', true],
    ['/api/providers/1', 'PATCH', true], ['/api/pipeline/status', 'GET', false],
    ['https://other.test/api/start', 'POST', false], ['/static/test', 'POST', false]
  ]) {
    await adminFetch(url, {method});
    assert.equal(request.options.headers.Authorization, allowed ? 'Bearer test-key' : undefined);
    if (allowed) assert.equal(request.options.redirect, 'error');
    await adminFetch(url, {method, headers: {'aUtHoRiZaTiOn': 'Bearer explicit'}});
    assert.equal(request.options.headers.Authorization, allowed ? 'Bearer explicit' : undefined);
    assert.equal(request.options.headers.aUtHoRiZaTiOn, undefined);
  }
  status = 401;
  await adminFetch('/api/pipeline/start', {method: 'POST'});
  assert.equal(details.open, true);
  assert.equal(field.focused, true);
  assert.match(help.textContent, /invalide/);
  status = 503; help.textContent = 'unchanged';
  await adminFetch('/api/pipeline/start', {method: 'POST'});
  assert.equal(help.textContent, 'unchanged');
  error = {detail: {code: 'admin_auth_not_configured'}};
  await adminFetch('/api/pipeline/start', {method: 'POST'});
  assert.match(help.textContent, /LANCE_ADMIN_TOKEN/);
  field.value = ''; status = 200;
  await adminFetch('/api/pipeline/start', {method: 'POST'});
  assert.equal(request.options.headers.Authorization, undefined);
  setCost(null); assert.equal(badge.textContent, 'Indisponible');
  setCost(0); assert.equal(badge.textContent, '$0.0000');
  setCost(1.25); assert.equal(badge.textContent, '$1.2500');
}
check().catch(e => {console.error(e); process.exit(1);});
'''
    result = subprocess.run([node, '-e', helper + cost + script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert 'localStorage' not in helper and 'sessionStorage' not in helper
