"""Read-only synthetic characterization of current context transformations.
Run from repository root with Python 3.12. No model or network calls.
Assertions document the 2026-09-29 behavior, not the desired fixed contract.
"""
import ast, json, runpy
from pathlib import Path
node = ast.parse(Path('src/agent/phases/analysis/compact.py').read_text())
cls = next(n for n in node.body if isinstance(n, ast.ClassDef))
f = next(n for n in cls.body if isinstance(n, ast.FunctionDef)
         and n.name == '_compact_phase3_scan_results')
f.decorator_list = []
ns = {'json': json}
exec(compile(ast.Module(body=[f], type_ignores=[]), '<compact-projection>', 'exec'), ns)
compact = ns[f.name]
scan = {'scan_results': {'http': [{'tool': 'http_get', 'kwargs': {'url': 'http://192.0.2.1'},
        'result': 'A'*2000 + 'MIDDLE_EVIDENCE' + 'Z'*2000}]}}
out = compact(scan)
assert 'MIDDLE_EVIDENCE' not in json.dumps(out)
assert out['_evidence_projection']['omitted_entries'] == 0
scan = {'scan_results': {str(i): [{'tool': 'http_get', 'kwargs': {'url': f'http://192.0.2.{i}'},
        'result': 'X'*1000}] for i in range(1, 21)}}
out = compact(scan)
assert len(out) - 1 == 6
assert out['_evidence_projection']['omitted_entries'] == 14
br = runpy.run_path('src/agent/phases/analysis/block_recovery.py')
log = []
for i in range(17):
    br['record_observation'](log, 'http_get', 'X'*1300 + f'TAIL_{i}',
                             kwargs={'url': f'http://192.0.2.{i}'})
assert len(log) == 16
assert all('TAIL_' not in x['result'] for x in log)
assert list(log[0]) == ['tool', 'args', 'result']
blocks = br['derive_blocks']({'id': 'fixture', 'services':
          [{'name': f's{i}', 'port': 1000+i} for i in range(20)]})
assert [len(b['services']) for b in blocks] == [2, 2, 2, 14]
memo = runpy.run_path('src/agent/core/memo.py')
assert not memo['_looks_unusable_model_memo']('L’analyse confirme que la vulnérabilité nécessite une')
assert not memo['_looks_unusable_model_memo']('This vulnerability is caused by an')
print("5 context probes reproduced: lost middle, omissions, observation truncation, block size, memo heuristic")
