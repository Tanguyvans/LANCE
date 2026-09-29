"""Static catalog inventory, not deployed coverage.
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3.12 benchmarks/experiments/research-review/inventory.py
"""
import collections
import hashlib
import json
from pathlib import Path
import yaml
from src.benchmark.strict_v3 import derive_matching_contract, forbidden_types_for_control

b = Path('benchmarks')
sidecar = yaml.safe_load((b / 'ground_truth/matching_contracts.yaml').read_text())
cat = yaml.safe_load((b / 'catalog.yaml').read_text())['scenarios']
rows, collisions = [], []
groups = {}
for c in cat:
    n, split = c['id'], c['split'].split('-')[0]
    path = b / f'ground_truth/{split}/scenario_{n}.yaml'
    assert sidecar['source_hashes'][n] == hashlib.sha256(path.read_bytes()).hexdigest()
    gt = yaml.safe_load(path.read_text())
    s = yaml.safe_load((b / f'scenarios/{split}/S{n}.yaml').read_text())
    vs = [{**sidecar['scenarios'][n].get(v['id'], {}), **v} for v in gt['vulnerabilities']]
    ctrl = gt.get('controls', [])
    rows.append(dict(scenario=n, split=split, difficulty=gt.get('difficulty'), services=len(gt['topology'].get('services', [])), vulns=len(vs), controls=len(ctrl), controls_type_evaluable=sum(bool(forbidden_types_for_control(x)) for x in ctrl), paths=len(gt.get('attack_paths', [])), network_depth_explicit=sum('network_pivot_depth' in v for v in vs), packs=s.get('packs', [])))
    gg = groups.setdefault(split, {k: collections.Counter() for k in ['category', 'services', 'difficulty', 'packs', 'network_depth', 'hop_depth']})
    gg['difficulty'][gt.get('difficulty')] += 1
    gg['packs'].update(s.get('packs', []))
    for v in vs:
        gg['category'][v.get('category')] += 1
        gg['services'].update(derive_matching_contract(v)['services'])
        gg['network_depth'][str(v.get('network_pivot_depth', 'unset'))] += 1
        gg['hop_depth'][str(v.get('hop_depth', 'unset'))] += 1
    for co in ctrl:
        for v in vs:
            overlap = set(forbidden_types_for_control(co)) & set(derive_matching_contract(v)['accepted_types'])
            if co['ip'] == v['ip'] and overlap:
                collisions.append(dict(scenario=n, control=co['id'], vulnerability=v['id'], types=sorted(overlap)))
print(json.dumps({'rows': rows, 'groups': groups, 'gt_control_collisions': collisions, 'totals': {k: sum(r[k] for r in rows) for k in ['services', 'vulns', 'controls', 'controls_type_evaluable', 'paths']}}, indent=2))
