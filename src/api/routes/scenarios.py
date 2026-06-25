"""Scenarios route — expose architectures, packs, and pre-configured scenarios."""
from __future__ import annotations

import re
from pathlib import Path

import yaml
from fastapi import APIRouter

router = APIRouter()

ROOT = Path(__file__).resolve().parents[3]
BENCHMARKS = ROOT / "benchmarks"


def _scenario_sort_key(s: dict) -> tuple:
    """Natural order: S1, S2, … S9, S10, S11 … (string sort puts S10 before S2).

    A trailing variant letter (e.g. '1h') sorts right after its base number.
    """
    m = re.match(r"S?(\d+)([a-z]*)", str(s.get("id", "")))
    return (int(m.group(1)), m.group(2)) if m else (9999, str(s.get("id", "")))


@router.get("")
def list_scenarios():
    """Return all available architectures, packs, and pre-configured scenarios."""

    # Architectures (topologies)
    architectures = []
    topo_dir = BENCHMARKS / "topologies"
    if topo_dir.exists():
        for f in sorted(topo_dir.glob("*.yaml")):
            data = yaml.safe_load(f.read_text())
            architectures.append({
                "id": data.get("id", f.stem),
                "name": data.get("name", f.stem),
                "description": data.get("description", ""),
                "services_count": len(data.get("services", [])),
                "roles": [s["role"] for s in data.get("services", [])],
            })

    # Packs (with individual vulns per role)
    packs = []
    packs_dir = BENCHMARKS / "packs" / "definitions"
    if packs_dir.exists():
        for f in sorted(packs_dir.glob("f*.yaml")):
            data = yaml.safe_load(f.read_text())
            vulns_by_role = data.get("vulnerabilities", {})
            total = sum(len(v) for v in vulns_by_role.values())

            # Flatten vulns with role info for the frontend
            vuln_list = []
            for role, role_vulns in vulns_by_role.items():
                for v in role_vulns:
                    vuln_list.append({
                        "role": role,
                        "title": v.get("title", ""),
                        "severity": v.get("severity", "medium"),
                        "category": v.get("category", ""),
                        "scenarios": v.get("scenarios"),  # null = all scenarios
                    })

            packs.append({
                "id": data.get("id", f.stem),
                "name": data.get("name", f.stem),
                "description": data.get("description", ""),
                "vuln_count": total,
                "roles": list(vulns_by_role.keys()),
                "vulns": vuln_list,
            })

    # Pre-configured scenarios
    scenarios = []
    scen_dir = BENCHMARKS / "scenarios"
    if scen_dir.exists():
        for f in sorted(scen_dir.glob("S*.yaml")):
            data = yaml.safe_load(f.read_text())
            scenarios.append({
                "id": data.get("scenario_id", f.stem),
                "name": data.get("name", ""),
                "difficulty": data.get("difficulty", "medium"),
                "posture": data.get("posture", "vulnerable"),
                "topology": data.get("topology", ""),
                "packs": data.get("packs", []),
            })
        scenarios.sort(key=_scenario_sort_key)

    return {
        "architectures": architectures,
        "packs": packs,
        "scenarios": scenarios,
    }
