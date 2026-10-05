"""Native scanner coverage must follow actual WebSocket and MQTT observations."""
import base64
import hashlib
import json

import pytest

from src.agent.scanner import extract_findings, scan_device

IP = '192.0.2.11'
KEY = 'MDEyMzQ1Njc4OWFiY2RlZg=='
ACCEPT = base64.b64encode(hashlib.sha1((KEY + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()


def _device(*, unknown_port=9001, unknown_protocol='tcp', reversed_order=False):
    services = [{'name': 'mqtt', 'port': 1883, 'protocol': 'tcp'},
                {'name': 'tor-orport?', 'port': unknown_port, 'protocol': unknown_protocol}]
    return {'id': 'broker', 'ip': IP, 'role': 'mqtt_broker',
            'services': list(reversed(services)) if reversed_order else services}


def _upgrade(**changes):
    return {'status_code': 101, 'headers': {'Upgrade': 'WebSocket', 'Connection': 'Upgrade',
            'Sec-WebSocket-Accept': ACCEPT}, 'final_url': f'http://{IP}:9001/',
            'redirect_chain': [], **changes}


def _receipt(args, **changes):
    return {'ok': True, 'success': True, 'status': 'success', 'return_code': 0,
            'timed_out': False, 'partial_timeout': False, 'error': None, 'output_truncated': False,
            'connack': {'received': True, 'reason_code': 0, 'accepted': True},
            'suback': {'received': True, 'mid': 7, 'reason_codes': [0], 'requested_qos': [0],
                       'granted_qos': [0], 'mid_matches_request': True, 'accepted': True},
            'subscribe_mid': 7, 'received_count': 1, 'requested_count': 1,
            'messages': [{'topic': 'sensors/temp', 'payload': '22.5', 'payload_b64': 'MjIuNQ==',
                          'payload_length': 4, 'raw_payload_complete': True, 'raw_topic_complete': True,
                          'qos': 0, 'retain': True, 'captured_at': '2026-10-05T12:00:00+00:00'}],
            'execution_attestation': {'output_format': 'mqtt-ws-json-v1', 'protocol': 'MQTTv311',
                'transport': 'websockets', 'ip': args['ip'], 'host': args['ip'], 'port': args['port'],
                'path': args['path'], 'topic': args['topic'], 'no_auth': True, 'auth': 'no_auth',
                'clean_session': True, 'reconnect_on_failure': False}, **changes}


def _scan(device=None, *, upgrade=None, native=None, missing_native=False):
    calls = []
    def ws(**kwargs):
        calls.append(kwargs)
        return json.dumps(native(kwargs) if native else _receipt(kwargs))
    tools = {'mqtt_listen': lambda **kwargs: json.dumps({'stdout': '', 'return_code': 0}),
             'nmap_scan': lambda **kwargs: json.dumps({'stdout': '9001/tcp open tor-orport?', 'return_code': 0}),
             'http_request': lambda **kwargs: json.dumps(_upgrade() if upgrade is None else upgrade)}
    if not missing_native: tools['mqtt_ws_listen'] = ws
    errors = []
    result = scan_device(device or _device(), tools, diagnostics=errors)
    return result, calls, errors


@pytest.mark.parametrize('reversed_order', [False, True])
def test_unknown_name_resolved_only_after_fresh_bound_native_exchange(reversed_order):
    device = _device(reversed_order=reversed_order)
    result, calls, errors = _scan(device)
    assert calls == [{'ip': IP, 'port': 9001, 'path': '/', 'topic': '#', 'count': 1, 'timeout': 5}]
    assert errors == []
    entry = next(e for e in result['mqtt'] if e['tool'] == 'mqtt_ws_listen')
    assert entry['resolved_services'] == [{'reported_name': 'tor-orport?', 'port': 9001,
        'protocol': 'tcp', 'identified_service': 'mqtt-ws', 'basis': 'bound_native_mqtt_ws_exchange'}]
    assert any(f['service'] == 'mqtt-ws' and f['exploitation_status'] == 'confirmed'
               for f in extract_findings(result, device))


@pytest.mark.parametrize('upgrade', [
    _upgrade(status_code=403), _upgrade(headers={}),
    _upgrade(headers={'Upgrade': 'WebSocket', 'Connection': 'Upgrade', 'Sec-WebSocket-Accept': 'wrong'}),
    _upgrade(headers={'Upgrade': 'Other', 'Connection': 'Upgrade', 'Sec-WebSocket-Accept': ACCEPT}),
    _upgrade(final_url=f'http://{IP}:9001/other'),
    _upgrade(redirect_chain=[f'http://{IP}:9001/elsewhere']),
    _upgrade(error='network failure'),
])
def test_no_native_probe_or_resolution_from_incomplete_upgrade(upgrade):
    _, calls, errors = _scan(upgrade=upgrade)
    assert calls == []
    assert errors == ['broker: no scanner rule for service tor-orport?']


@pytest.mark.parametrize('native', [
    lambda args: _receipt(args, messages=[], received_count=0),
    lambda args: _receipt(args, connack={'received': True, 'reason_code': 5, 'accepted': False},
                         status='auth_required', ok=False, success=False, return_code=5),
    lambda args: _receipt({**args, 'ip': '192.0.2.12'}),
    lambda args: _receipt({**args, 'path': '/other'}),
    lambda args: _receipt(args, error='connection failed'),
])
def test_no_resolution_without_complete_native_proof(native):
    result, calls, errors = _scan(native=native)
    assert len(calls) == 1
    assert errors == ['broker: no scanner rule for service tor-orport?']
    assert not any(e.get('resolved_services') for e in result['mqtt'])


@pytest.mark.parametrize('device', [_device(unknown_port=9002), _device(unknown_protocol='udp')])
def test_native_receipt_cannot_resolve_another_endpoint(device):
    _, calls, errors = _scan(device)
    assert len(calls) == 1
    assert errors == ['broker: no scanner rule for service tor-orport?']


def test_missing_native_tool_is_not_treated_as_covered():
    _, calls, errors = _scan(missing_native=True)
    assert not calls
    assert errors == ['broker: required tool mqtt_ws_listen unavailable',
                      'broker: no scanner rule for service tor-orport?']


def test_tool_exception_remains_recorded_and_unresolved():
    def fail(_):
        raise OSError('connection reset')
    result, calls, errors = _scan(native=fail)
    assert len(calls) == 1
    assert 'no scanner rule' in errors[0]
    entry = next(e for e in result['mqtt'] if e['tool'] == 'mqtt_ws_listen')
    assert json.loads(entry['result'])['return_code'] == -1
    assert not entry.get('resolved_services')


@pytest.mark.parametrize('mutate', [
    lambda e: e.update(evidence_phase=2),
    lambda e: e.update(authoritative=False),
    lambda e: e['kwargs'].update(follow_redirects=True),
    lambda e: e['kwargs'].update(url='http://192.0.2.12:9001/'),
    lambda e: e['kwargs']['headers'].update({'Sec-WebSocket-Version': '12'}),
    lambda e: e['kwargs']['headers'].update({'Sec-WebSocket-Key': 'not-base64'}),
    lambda e: e['kwargs']['headers'].update({'Sec-WebSocket-Key': 'eA=='}),
    lambda e: e['kwargs']['headers'].update({'Connection': 'close'}),
    lambda e: e['result']['headers'].update({'Connection': 'close'}),
    lambda e: e['result']['headers'].update({'Upgrade': 'unknown'}),
    lambda e: e['result']['headers'].update({'upgrade': 'WebSocket'}),
])
def test_followup_rejects_unbound_or_incomplete_handshake(mutate):
    from src.agent.scanner import _mqtt_ws_followup_request
    entry = {'tool': 'http_request', 'evidence_phase': 3, 'authoritative': True,
             'kwargs': {'url': f'http://{IP}:9001/', 'follow_redirects': False,
                        'headers': {'Upgrade': 'websocket', 'Connection': 'Upgrade',
                                    'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': KEY}},
             'result': _upgrade()}
    mutate(entry)
    assert _mqtt_ws_followup_request(entry, IP) is None


def test_unknown_service_without_known_mqtt_probe_is_not_renamed():
    device = _device()
    device['services'] = device['services'][1:]
    result, calls, errors = _scan(device)
    assert result == {}
    assert not calls
    assert errors == ['broker: no scanner rule for service tor-orport?']


def test_scanner_preserves_native_failure_as_phase_error(tmp_path, monkeypatch):
    from src.agent.scanner import run_scanner
    monkeypatch.setattr('src.agent.tools.tool_loader.filter_unavailable_tools', lambda tools: (tools, {}))
    native_failure = lambda **kwargs: json.dumps({'error': 'connection reset', 'status': 'error',
                                                 'return_code': 1, 'ok': False})
    tools = [{'name': name, 'function': fn} for name, fn in {
        'mqtt_listen': lambda **kwargs: json.dumps({'stdout': '', 'return_code': 0}),
        'nmap_scan': lambda **kwargs: json.dumps({'stdout': '9001/tcp open tor-orport?', 'return_code': 0}),
        'http_request': lambda **kwargs: json.dumps(_upgrade()),
        'mqtt_ws_listen': native_failure,
    }.items()]
    record = run_scanner(tmp_path, [_device()], tools=tools, max_workers=1)['broker']
    assert 'no scanner rule for service tor-orport?' in record['error']
    assert 'mqtt_ws_listen returned an error' in record['error']
    assert not any(f['service'] == 'mqtt-ws' and f['exploitation_status'] == 'confirmed'
                   for f in record['findings'])
