"""Device / architecture / weakness axes of the scenario corpus.

Reads the public benchmark assets and the vocabulary in
benchmarks/taxonomy.yaml, then labels every scenario and every expected
vulnerability on three axes:

- device: the class of the service role (taxonomy ``roles``); protocols
  come from ``tool_registry.ROLE_SERVICES``, or from the taxonomy for the
  roles that registry does not describe;
- architecture: the *target* class declared for the topology (taxonomy
  ``architectures``) and the class *measured* from what the topology
  actually encodes (subnets, dual-homed relays, gateway-less services).
  A mismatch marks a scenario whose network does not implement its intent;
- weakness: the family of the ground-truth ``category``.

Nothing here writes to the catalogue, the scenarios, the topologies or the
ground truth. The versioned output is docs/benchmark/couverture-axes.md
(conformity table and coverage matrices), regenerated identically. The
detailed index, with a SHA-256 of every source, is written only on request.

Usage:
    python -m src.benchmark.taxonomy
    python -m src.benchmark.taxonomy --check
    python -m src.benchmark.taxonomy --json /tmp/axes.json
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from collections import Counter, deque
from pathlib import Path

import yaml

from src.benchmark.catalog import load_catalog
from src.benchmark.tool_registry import ROLE_SERVICES

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BENCHMARKS_ROOT = _REPO_ROOT / "benchmarks"
DEFAULT_MATRIX_OUTPUT = _REPO_ROOT / "docs" / "benchmark" / "couverture-axes.md"
TAXONOMY_SCHEMA_VERSION = 1

# Target class -> measured classes that implement it. Star and local-cloud
# have no structural signature of their own yet: a star needs leaves that
# are reachable only through the hub (gateway-like isolation), a local-cloud
# split needs at least two network segments.
CONFORMING_MEASUREMENTS: dict[str, frozenset[str]] = {
    "flat": frozenset({"flat"}),
    "segmented": frozenset({"segmented"}),
    "gateway": frozenset({"gateway"}),
    "multi_hop": frozenset({"multi_hop"}),
    "star": frozenset({"gateway"}),
    "local_cloud": frozenset({"segmented", "gateway", "multi_hop"}),
}
_SCENARIO_FILE_RE = re.compile(r"S([1-9]\d*)([a-z]*)\.yaml")


class TaxonomyError(ValueError):
    """Raised when the corpus uses a value the taxonomy does not classify."""


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(_REPO_ROOT).as_posix()
    except ValueError:
        return path.name


def _load_yaml(path: Path, sources: dict[str, str]) -> dict:
    raw = path.read_bytes()
    sources[_rel(path)] = hashlib.sha256(raw).hexdigest()
    return yaml.safe_load(raw) or {}


def load_taxonomy(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if data.get("schema_version") != TAXONOMY_SCHEMA_VERSION:
        raise TaxonomyError(f"{path}: unsupported schema_version {data.get('schema_version')!r}")
    classes = data.get("classes") or {}
    for axis in ("device", "architecture", "weakness"):
        if not isinstance(classes.get(axis), dict) or not classes[axis]:
            raise TaxonomyError(f"{path}: classes.{axis} must be a non-empty mapping")
    for role, entry in (data.get("roles") or {}).items():
        if entry.get("device") not in classes["device"]:
            raise TaxonomyError(f"role {role}: unknown device class {entry.get('device')!r}")
        if "protocols" in entry and role in ROLE_SERVICES:
            raise TaxonomyError(f"role {role}: protocols already defined by ROLE_SERVICES")
        if "protocols" not in entry and role not in ROLE_SERVICES:
            raise TaxonomyError(f"role {role}: no protocols in ROLE_SERVICES nor in the taxonomy")
    for topology, target in (data.get("architectures") or {}).items():
        if target not in classes["architecture"]:
            raise TaxonomyError(f"topology {topology}: unknown architecture class {target!r}")
        if target not in CONFORMING_MEASUREMENTS:
            raise TaxonomyError(f"architecture class {target!r} has no conformity rule")
    for category, family in (data.get("weaknesses") or {}).items():
        if family not in classes["weakness"]:
            raise TaxonomyError(f"category {category}: unknown weakness family {family!r}")
    return data


def role_protocols(role: str, taxonomy: dict) -> list[str]:
    if role in ROLE_SERVICES:
        return sorted({service["name"] for service in ROLE_SERVICES[role]})
    return sorted(taxonomy["roles"][role]["protocols"])


def _subnet(ip: str) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def measure_architecture(topology: dict) -> dict:
    """Measure the network structure a topology actually encodes.

    Segments are the /24 subnets of the router and services. A service with
    a ``secondary_ip`` bridges its two segments (a relay). The relay depth is
    the largest number of bridges between the router's segment and a service
    declared ``no_gateway`` (reachable only through relays).
    """
    services = topology.get("services") or []
    entry = _subnet(topology["router"]["ip"])
    segments = {entry}
    bridges: dict[str, set[str]] = {}
    for service in services:
        primary = _subnet(service["ip"])
        segments.add(primary)
        if service.get("secondary_ip"):
            secondary = _subnet(service["secondary_ip"])
            segments.add(secondary)
            bridges.setdefault(primary, set()).add(secondary)
            bridges.setdefault(secondary, set()).add(primary)
    distance = {entry: 0}
    queue = deque([entry])
    while queue:
        current = queue.popleft()
        for neighbour in sorted(bridges.get(current, ())):
            if neighbour not in distance:
                distance[neighbour] = distance[current] + 1
                queue.append(neighbour)
    isolated = [s for s in services if s.get("no_gateway")]
    relay_depth = max((distance.get(_subnet(s["ip"]), 0) for s in isolated), default=0)
    if len(segments) == 1:
        measured = "flat"
    elif relay_depth == 0:
        measured = "segmented"
    elif relay_depth == 1:
        measured = "gateway"
    else:
        measured = "multi_hop"
    return {
        "measured": measured,
        "segments": len(segments),
        "relays": sum(1 for s in services if s.get("secondary_ip")),
        "isolated_services": len(isolated),
        "relay_depth": relay_depth,
    }


def _scenario_files(benchmarks_root: Path) -> list[tuple[str, Path]]:
    found = []
    for group in ("dev", "test"):
        for path in (benchmarks_root / "scenarios" / group).glob("S*.yaml"):
            match = _SCENARIO_FILE_RE.fullmatch(path.name)
            if match:
                found.append((match.group(1) + match.group(2), path))
    return sorted(found, key=lambda item: (int(re.match(r"\d+", item[0]).group()), item[0]))


def build_index(benchmarks_root: Path = DEFAULT_BENCHMARKS_ROOT) -> dict:
    sources: dict[str, str] = {}
    taxonomy_path = benchmarks_root / "taxonomy.yaml"
    taxonomy = load_taxonomy(taxonomy_path)
    sources[_rel(taxonomy_path)] = hashlib.sha256(taxonomy_path.read_bytes()).hexdigest()
    catalog = load_catalog(benchmarks_root / "catalog.yaml")
    official = {descriptor.id: descriptor for descriptor in catalog.scenarios}
    roles, targets, families = taxonomy["roles"], taxonomy["architectures"], taxonomy["weaknesses"]
    missing: list[str] = []

    scenarios: list[dict] = []
    vulnerabilities: list[dict] = []
    for scenario_id, scenario_path in _scenario_files(benchmarks_root):
        scenario = _load_yaml(scenario_path, sources)
        topology_name = scenario.get("topology")
        topology_path = benchmarks_root / "topologies" / f"{topology_name}.yaml"
        if not topology_path.is_file():
            raise TaxonomyError(f"S{scenario_id}: topology file not found: {topology_path}")
        topology = _load_yaml(topology_path, sources)
        if topology_name not in targets:
            missing.append(f"topology {topology_name} (S{scenario_id})")
        service_roles = [service["role"] for service in topology.get("services") or []]
        missing += [f"role {role} (topology {topology_name})" for role in service_roles if role not in roles]
        gt_path = scenario_path.parents[2] / "ground_truth" / scenario_path.parent.name / f"scenario_{scenario_id}.yaml"
        ground_truth = _load_yaml(gt_path, sources) if gt_path.is_file() else {}
        if missing:
            continue

        architecture = measure_architecture(topology)
        target = targets[topology_name]
        architecture["target"] = target
        architecture["conforms"] = architecture["measured"] in CONFORMING_MEASUREMENTS[target]
        base_id = re.match(r"\d+", scenario_id).group()
        scenario_vulns = []
        for vuln in ground_truth.get("vulnerabilities") or []:
            role, category = vuln.get("role"), vuln.get("category")
            if role not in roles:
                missing.append(f"role {role} (S{scenario_id} {vuln.get('id')})")
                continue
            if category not in families:
                missing.append(f"category {category} (S{scenario_id} {vuln.get('id')})")
                continue
            scenario_vulns.append({
                "scenario_id": scenario_id,
                "vuln_id": vuln.get("id"),
                "role": role,
                "device": roles[role]["device"],
                "category": category,
                "weakness": families[category],
                "architecture_target": target,
                "architecture_measured": architecture["measured"],
            })
        vulnerabilities += scenario_vulns
        scenarios.append({
            "scenario_id": scenario_id,
            "official": scenario_id in official,
            "split": official[base_id].split if base_id in official else None,
            "label": official[scenario_id].label if scenario_id in official else scenario.get("name"),
            "topology": topology_name,
            "services": len(service_roles),
            "architecture": architecture,
            "devices": sorted({roles[role]["device"] for role in service_roles}),
            "protocols": sorted({p for role in service_roles for p in role_protocols(role, taxonomy)}),
            "weaknesses": sorted({v["weakness"] for v in scenario_vulns}),
            "vulnerabilities": len(scenario_vulns),
        })
    if missing:
        raise TaxonomyError("values not classified in benchmarks/taxonomy.yaml: "
                            + "; ".join(sorted(set(missing))))

    counted = [v for v in vulnerabilities if v["scenario_id"] in official]
    official_scenarios = [s for s in scenarios if s["official"]]
    return {
        "schema_version": TAXONOMY_SCHEMA_VERSION,
        "generated_by": "src.benchmark.taxonomy",
        "conformity_rules": {k: sorted(v) for k, v in CONFORMING_MEASUREMENTS.items()},
        "summary": {
            "official_scenarios": len(official_scenarios),
            "official_vulnerabilities": len(counted),
            "architecture_conforming": sum(s["architecture"]["conforms"] for s in official_scenarios),
            "by_architecture_target": dict(sorted(Counter(
                s["architecture"]["target"] for s in official_scenarios).items())),
            "by_architecture_measured": dict(sorted(Counter(
                s["architecture"]["measured"] for s in official_scenarios).items())),
            "by_device": dict(sorted(Counter(v["device"] for v in counted).items())),
            "by_weakness": dict(sorted(Counter(v["weakness"] for v in counted).items())),
        },
        "sources_sha256": dict(sorted(sources.items())),
        "scenarios": scenarios,
        "vulnerabilities": vulnerabilities,
    }


def _matrix(rows: list[str], cols: list[str], counts: Counter, row_title: str) -> list[str]:
    lines = [f"| {row_title} | " + " | ".join(cols) + " | Total |",
             "| --- | " + " | ".join("---:" for _ in cols) + " | ---: |"]
    for row in rows:
        cells = [str(counts[(row, col)]) if counts[(row, col)] else "·" for col in cols]
        lines.append(f"| {row} | " + " | ".join(cells) + f" | {sum(counts[(row, c)] for c in cols)} |")
    return lines


def render_markdown(index: dict, taxonomy: dict) -> str:
    classes = taxonomy["classes"]
    official = [s for s in index["scenarios"] if s["official"]]
    counted = [v for v in index["vulnerabilities"]
               if v["scenario_id"] in {s["scenario_id"] for s in official}]
    summary = index["summary"]
    lines = [
        "# Couverture du corpus par appareil, architecture et faille",
        "",
        "<!-- Fichier généré par `python -m src.benchmark.taxonomy` ; ne pas modifier à la main. -->",
        "",
        "Page générée depuis les assets publics et `benchmarks/taxonomy.yaml`. "
        "Les règles et limites sont décrites dans [la taxonomie](taxonomie.md). "
        f"Périmètre : les {summary['official_scenarios']} scénarios officiels du catalogue "
        f"et leurs {summary['official_vulnerabilities']} failles attendues ; S1h/S4h sont exclus des comptes.",
        "",
        "## Architecture visée et architecture mesurée",
        "",
        f"{summary['architecture_conforming']}/{summary['official_scenarios']} scénarios "
        "ont une topologie qui réalise l'architecture visée.",
        "",
        "| Scénario | Topologie | Visée | Mesurée | Segments | Profondeur de relais | Conforme |",
        "| --- | --- | --- | --- | ---: | ---: | :---: |",
    ]
    for s in official:
        a = s["architecture"]
        lines.append(f"| S{s['scenario_id']} | `{s['topology']}` | {a['target']} | {a['measured']} | "
                     f"{a['segments']} | {a['relay_depth']} | {'oui' if a['conforms'] else '**non**'} |")
    weaknesses = list(classes["weakness"])
    devices = [d for d in classes["device"]]
    architectures = list(classes["architecture"])
    lines += ["", "## Failles par appareil et famille de faille", "",
              "Nombre de failles attendues ; `·` signale une combinaison absente du corpus.", ""]
    lines += _matrix(devices, weaknesses, Counter((v["device"], v["weakness"]) for v in counted), "Appareil")
    lines += ["", "## Failles par architecture mesurée et famille de faille", ""]
    lines += _matrix(architectures, weaknesses,
                     Counter((v["architecture_measured"], v["weakness"]) for v in counted), "Architecture")
    lines += ["", "## Scénarios par architecture visée et mesurée", ""]
    lines += _matrix(architectures, architectures,
                     Counter((s["architecture"]["target"], s["architecture"]["measured"]) for s in official),
                     "Visée \\ mesurée")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--matrix-output", type=Path, default=DEFAULT_MATRIX_OUTPUT)
    parser.add_argument("--json", type=Path, default=None,
                        help="Also write the detailed per-scenario/per-vulnerability index here")
    parser.add_argument("--check", action="store_true",
                        help="Fail if the versioned coverage page differs from a fresh generation")
    args = parser.parse_args(argv)
    index = build_index()
    taxonomy = load_taxonomy(DEFAULT_BENCHMARKS_ROOT / "taxonomy.yaml")
    page = render_markdown(index, taxonomy)
    if args.check:
        path = args.matrix_output
        if not path.is_file() or path.read_text(encoding="utf-8") != page:
            print(f"stale: {_rel(path)} (run python -m src.benchmark.taxonomy)", file=sys.stderr)
            return 1
        return 0
    outputs = {args.matrix_output: page}
    if args.json is not None:
        outputs[args.json] = json.dumps(index, indent=2, ensure_ascii=False) + "\n"
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"Wrote {_rel(path)}")
    print(json.dumps(index["summary"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
