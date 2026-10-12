"""Independent extraction regression probes; only mocked local tool calls."""
import json
from unittest.mock import MagicMock
from src.agent.phases.analysis.supplemental import supplement_scans
import pytest
from src.agent.registry import AGENTS
from src.agent.cost_tracker import CostTracker
from src.agent.execution_profiles import resolve_execution_profile
from src.agent.phases.analysis.context import AnalysisContext, AnalysisServices


@pytest.fixture
def setup_phase(tmp_path):
    services = AnalysisServices(
        wrap_tool=lambda tool, **kwargs: tool,
        apply_tool_policy=lambda tools, _: tools,
        save_transaction=MagicMock(), model_callback=MagicMock(),
        discover_surface=MagicMock(), persist_findings=MagicMock(),
        promoted_deliverable=MagicMock(), recover_device=MagicMock(),
        validate_cves=MagicMock(), check_limits=MagicMock(),
        validate=MagicMock(),
    )
    context = AnalysisContext(
        run_dir=tmp_path, config=AGENTS['vuln_analysis'], provider=None,
        tracker=CostTracker(), profile=resolve_execution_profile('full'),
        services=services, variables={},
    )
    (tmp_path / '03_scans').mkdir(exist_ok=True)
    calls = []
    def http_request(**kwargs):
        calls.append(('http_request', kwargs))
        return json.dumps({'status_code': 200, 'body': json.dumps({'installed': True, 'marker': 'CITY-CONTROL-SECRET-S18'})})
    http_request.last_observation = lambda: {'evidence_ref': 'review-http'}
    def mtls_request(**kwargs):
        calls.append(('mtls_request', kwargs))
        return json.dumps({'status_code': 200, 'body': json.dumps({'device': 'device-a'})})
    mtls_request.last_observation = lambda: {'evidence_ref': 'review-mtls'}
    tools = [{'name': 'http_request', 'function': http_request}, {'name': 'mtls_request', 'function': mtls_request}]
    def run(surface, scans):
        errors = []
        supplement_scans(context, surface, scans, {tool['name']: tool['function'] for tool in tools}, errors)
        assert errors == []
        return calls
    return context, run



def test_mtls_reuses_only_observed_enrollment_bundle(setup_phase):
    context, run = setup_phase
    enrollment = {'id': 'enrollment', 'ip': '192.0.2.11', 'role': 'pki_enrollment_server'}
    mtls = {'id': 'api', 'ip': '192.0.2.12', 'role': 'pki_mtls_server'}
    bundle = {'certificate_pem': 'observed-cert', 'private_key_pem': 'observed-key'}
    scans = {'enrollment': {'scan_results': {'http': [{'tool': 'http_request', 'result': json.dumps({'status_code': 201, 'body': json.dumps(bundle)})}]}, 'findings': []}}
    calls = run([enrollment, mtls], scans)
    assert calls == [('mtls_request', {'url': 'https://192.0.2.12:8443/device/status', 'certificate_pem': 'observed-cert', 'private_key_pem': 'observed-key', 'method': 'GET'})]
    entry = scans['api']['scan_results']['pki_mtls'][0]
    assert entry['evidence_ref'] == 'review-mtls'
    assert 'private_key_pem' not in entry['kwargs']


def test_ota_preserves_metadata_rollback_restore_and_cross_device_order(setup_phase):
    context, run = setup_phase
    repo = {'id': 'repo', 'ip': '192.0.2.10', 'role': 'ota_repository'}
    a = {'id': 's17-device-a', 'ip': '192.0.2.11', 'role': 'ota_device'}
    b = {'id': 's17-device-b', 'ip': '192.0.2.12', 'role': 'ota_device'}
    old = {'version': '1', 'payload': 'old-observed', 'signature': 'sig-old-observed'}
    current = {'version': '2', 'payload': 'current-observed', 'signature': 'sig-current-observed'}
    scans = {'repo': {'scan_results': {'http': [{'tool': 'http_request', 'kwargs': {'url': 'http://192.0.2.10:8080/firmware'}, 'result': json.dumps({'status_code': 200, 'body': json.dumps({'artifacts': [old, current]})})}]}, 'findings': []}}
    calls = run([repo, a, b], scans)
    assert len(calls) == 4
    requests = [kwargs for tool, kwargs in calls]
    assert [json.loads(request['body'])['version'] for request in requests] == ['999', '1', '2', '2']
    assert [request['url'] for request in requests] == ['http://192.0.2.11:8080/install'] * 3 + ['http://192.0.2.12:8080/install']
    assert json.loads(requests[2]['body']) == current
    assert requests[3]['headers']['X-Benchmark-Cross-Device'] == 's17-device-a'
    assert all(request['follow_redirects'] is False for request in requests)


def test_ssrf_derivation_preserves_provenance_and_uses_observed_token(setup_phase):
    context, run = setup_phase
    web = {'id': 'web', 'ip': '192.0.2.10', 'role': 'cloud_web_server'}
    meta = {'id': 'meta', 'ip': '192.0.2.11', 'role': 'cloud_metadata_server'}
    control = {'id': 'control', 'ip': '192.0.2.12', 'role': 'cloud_control_plane'}
    credentials = json.dumps({'access_token': 'observed-token', 'scope': 'object-admin'})
    entry = {'tool': 'http_request', 'kwargs': {'url': 'http://192.0.2.10:8080/fetch'}, 'result': json.dumps({'status_code': 200, 'body': json.dumps({'body': credentials})}), 'evidence_ref': 'original-ssrf'}
    scans = {'web': {'scan_results': {'http': [entry]}, 'findings': []}}
    calls = run([web, meta, control], scans)
    assert len(calls) == 1
    assert calls[0][1]['url'] == 'http://192.0.2.12:8080/bucket/city-secrets'
    assert calls[0][1]['headers']['Authorization'] == 'Bearer observed-token'
    derived = scans['meta']['scan_results']['cloud_ssrf'][0]
    assert derived['derived_from_evidence_ref'] == 'original-ssrf'
    assert 'evidence_ref' not in derived
    assert scans['control']['scan_results']['cloud_ssrf'][0]['evidence_ref'] == 'review-http'


@pytest.mark.parametrize('scope,status,token', [('read-only', 200, 'observed'), ('object-admin', 401, 'observed'), ('object-admin', 200, '')])
def test_ssrf_no_control_request_without_positive_observation(setup_phase, scope, status, token):
    _, run = setup_phase
    devices = [{'id': 'web', 'ip': '192.0.2.10', 'role': 'cloud_web_server'}, {'id': 'meta', 'ip': '192.0.2.11', 'role': 'cloud_metadata_server'}, {'id': 'control', 'ip': '192.0.2.12', 'role': 'cloud_control_plane'}]
    entry = {'tool': 'http_request', 'kwargs': {'url': 'http://192.0.2.10:8080/fetch'}, 'result': json.dumps({'status_code': status, 'body': json.dumps({'body': json.dumps({'scope': scope, 'access_token': token})})})}
    scans = {'web': {'scan_results': {'http': [entry]}, 'findings': []}}
    assert run(devices, scans) == []
