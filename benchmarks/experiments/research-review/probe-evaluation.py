"""Local read-only synthetic probes; run with Python 3.12 from repository root.

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3.12 benchmarks/experiments/research-review/probe-evaluation.py
No target, network, provider, benchmark run or repository write.
"""
import json
import tempfile
from pathlib import Path
from src.benchmark.funnel import evaluate_funnel
from src.agent.exploit_evidence import synthesize_exploit_result

v = {'id': 'same', 'device_ip': '192.0.2.1', 'type': 'data_exposure', 'service': 'http', 'port': 80, 'endpoint': '/x'}
with tempfile.TemporaryDirectory(prefix='lance-coverage-') as d:
    p = Path(d)
    (p / '03_vuln_analysis.json').write_text(json.dumps({'vulnerabilities': [v]}))
    (p / '04_exploitation.json').write_text(json.dumps({'tests': [
        {'vuln_id': 'same', 'status': 'TIMEOUT', 'verification_attempted': False},
        {'vuln_id': 'same', 'status': 'TIMEOUT', 'verification_attempted': False},
    ]}))
    result = evaluate_funnel(p, gt_count=1, filtered=[v], confirmations=[], match=lambda xs: {}, validate=lambda xs: set(), compatible=True, provenance_available=True)
    print('ambiguous_unattempted', json.dumps({k: result['diagnostics'][k] for k in ['verification', 'verification_population', 'verification_attempt_rate', 'orphan_tests']}))

v = {'id': 'v', 'device_ip': '192.0.2.1', 'type': 'insecure_update', 'service': 'http', 'port': 80, 'endpoint': '/update'}
r = {'tool': 'http_request', 'args': {'url': 'http://192.0.2.1/update', 'method': 'POST', 'body': '{"firmware":"known-good","signature":"valid-signed-image"}'}, 'result': {'status_code': 200, 'body': '{"message":"update accepted","signature_verified":true}', 'return_code': 0}}
print('signed_update', json.dumps(synthesize_exploit_result(v, [r])))
v['type'] = 'code_injection'
r['args']['body'] = '{"description":"show help"}'
r['result']['body'] = '{"help":"example command output: uid=1000(user)"}'
print('help_text_injection', json.dumps(synthesize_exploit_result(v, [r])))
