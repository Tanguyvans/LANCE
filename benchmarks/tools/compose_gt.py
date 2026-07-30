#!/usr/bin/env python3
"""Generate ground_truth/ YAML files from scenarios/ + topologies/ + packs/.

Usage:
    python3 benchmarks/tools/compose_gt.py                    # generate all
    python3 benchmarks/tools/compose_gt.py --scenario 1       # generate one
    python3 benchmarks/tools/compose_gt.py --validate         # compare vs existing
"""

import argparse
import re
import sys
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOPO_DIR = ROOT / "topologies"
PACKS_DIR = ROOT / "packs" / "definitions"
SCENARIOS_DIR = ROOT / "scenarios"
GT_DIR = ROOT / "ground_truth"

SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}

META_FIELDS = {"scenarios", "applies_to", "key"}


def load_topology(topo_id: str) -> dict:
    path = TOPO_DIR / f"{topo_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Topology not found: {path}")
    return yaml.safe_load(path.read_text())


def load_pack(pack_id: str) -> dict:
    path = PACKS_DIR / f"{pack_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Pack not found: {path}")
    return yaml.safe_load(path.read_text())


def _resolved_device_name(service: dict, scenario_id: str) -> str:
    return service["name_template"].format(sid=scenario_id)


def _slug(value: str) -> str:
    """Return a deterministic, YAML-friendly identifier fragment."""
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _stable_id(template: dict, device_name: str, fallback_index: int,
               prefix: str = "V") -> str:
    """Build a stable finding/control ID when a pack template exposes ``key``.

    Legacy packs do not contain keys and retain their historical V1/V2/... IDs.
    New packs must provide a key so IDs no longer depend on pack ordering.
    """
    key = template.get("key")
    if not key:
        return f"{prefix}{fallback_index}"
    return f"{key}@{_slug(device_name)}"


def _matches_selector(template: dict, service: dict, scenario_id: str) -> bool:
    """Return whether a pack entry applies to a concrete topology service.

    ``applies_to`` is deliberately small and declarative. Supported selectors:
    roles, profiles and devices. A selector list is an OR within its dimension;
    dimensions are combined with AND. Device selectors may use either the
    unresolved topology name_template or the concrete scenario device name.
    """
    legacy_scenarios = template.get("scenarios")
    if legacy_scenarios and scenario_id not in [str(s) for s in legacy_scenarios]:
        return False

    selector = template.get("applies_to") or {}
    if not isinstance(selector, dict):
        raise ValueError(f"applies_to must be a mapping, got {selector!r}")

    role = service.get("role")
    profile = service.get("security_profile", "vulnerable")
    device_name = _resolved_device_name(service, scenario_id)
    template_name = service.get("name_template", "")

    roles = selector.get("roles")
    profiles = selector.get("profiles")
    devices = selector.get("devices")

    if roles and role not in roles:
        return False
    if profiles and profile not in profiles:
        return False
    if devices and device_name not in devices and template_name not in devices:
        return False
    return True


def _materialize_template(template: dict, service: dict, scenario_id: str,
                          fallback_index: int, prefix: str = "V") -> dict:
    device_name = _resolved_device_name(service, scenario_id)
    ip = service["ip"]
    item = {
        "id": _stable_id(template, device_name, fallback_index, prefix=prefix),
        "device": device_name,
        "ip": ip,
        "role": service["role"],
    }
    if "security_profile" in service:
        item["security_profile"] = service["security_profile"]
    if template.get("key"):
        item["template_key"] = template["key"]

    for key, value in template.items():
        if key in META_FIELDS:
            continue
        if key == "indicators":
            item[key] = [str(indicator).replace("{ip}", ip) for indicator in value]
        elif key == "verification":
            item[key] = str(value).replace("{ip}", ip)
        else:
            item[key] = value
    return item


def _materialize_router_template(template: dict, topology: dict, scenario_id: str,
                                 fallback_index: int, prefix: str = "V") -> dict:
    router = topology.get("router", {})
    ip = router.get("ip", "192.168.100.1")
    service = {
        "name_template": router.get("name_template", "s{sid}-router"),
        "ip": ip,
        "role": "router",
        "security_profile": router.get("security_profile", "vulnerable"),
    }
    return _materialize_template(template, service, scenario_id, fallback_index, prefix)


def _first_difference(expected, actual, path: str = "$") -> str | None:
    """Describe the first structural difference between two YAML values."""
    if type(expected) is not type(actual):
        return f"{path}: type {type(expected).__name__} != {type(actual).__name__}"
    if isinstance(expected, dict):
        expected_keys = set(expected)
        actual_keys = set(actual)
        if expected_keys != actual_keys:
            missing = sorted(expected_keys - actual_keys)
            extra = sorted(actual_keys - expected_keys)
            return f"{path}: missing_keys={missing}, extra_keys={extra}"
        for key in expected:
            diff = _first_difference(expected[key], actual[key], f"{path}.{key}")
            if diff:
                return diff
        return None
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return f"{path}: length {len(expected)} != {len(actual)}"
        for index, (left, right) in enumerate(zip(expected, actual)):
            diff = _first_difference(left, right, f"{path}[{index}]")
            if diff:
                return diff
        return None
    if expected != actual:
        return f"{path}: {expected!r} != {actual!r}"
    return None


def compose_scenario(scenario_path: Path) -> dict:
    scenario = yaml.safe_load(scenario_path.read_text())
    sid = str(scenario["scenario_id"])
    topology = load_topology(scenario["topology"])

    vulns = []
    controls = []
    vuln_counter = 1
    control_counter = 1

    for pack_id in scenario.get("packs", []):
        pack = load_pack(pack_id)
        pack_vulns = pack.get("vulnerabilities", {})
        pack_controls = pack.get("controls", {})

        # Match pack vulns to topology services by role
        for svc in topology.get("services", []):
            role = svc["role"]
            for vuln_template in pack_vulns.get(role, []):
                if not _matches_selector(vuln_template, svc, sid):
                    continue
                vuln = _materialize_template(vuln_template, svc, sid, vuln_counter)
                vulns.append(vuln)
                vuln_counter += 1

            for control_template in pack_controls.get(role, []):
                if not _matches_selector(control_template, svc, sid):
                    continue
                control = _materialize_template(
                    control_template, svc, sid, control_counter, prefix="C"
                )
                controls.append(control)
                control_counter += 1

        # Router vulns
        if "router" in pack_vulns:
            router = topology.get("router", {})
            router_ip = router.get("ip", "192.168.100.1")

            for vuln_template in pack_vulns["router"]:
                router_service = {
                    "name_template": router.get("name_template", "s{sid}-router"),
                    "ip": router_ip,
                    "role": "router",
                    "security_profile": router.get("security_profile", "vulnerable"),
                }
                if not _matches_selector(vuln_template, router_service, sid):
                    continue
                vuln = _materialize_router_template(
                    vuln_template, topology, sid, vuln_counter
                )
                vulns.append(vuln)
                vuln_counter += 1

        if "router" in pack_controls:
            router = topology.get("router", {})
            router_service = {
                "name_template": router.get("name_template", "s{sid}-router"),
                "ip": router.get("ip", "192.168.100.1"),
                "role": "router",
                "security_profile": router.get("security_profile", "vulnerable"),
            }
            for control_template in pack_controls["router"]:
                if not _matches_selector(control_template, router_service, sid):
                    continue
                controls.append(_materialize_router_template(
                    control_template, topology, sid, control_counter, prefix="C"
                ))
                control_counter += 1

    vuln_ids = [vuln["id"] for vuln in vulns]
    control_ids = [control["id"] for control in controls]
    if len(vuln_ids) != len(set(vuln_ids)):
        raise ValueError(f"Duplicate vulnerability IDs in scenario S{sid}")
    if len(control_ids) != len(set(control_ids)):
        raise ValueError(f"Duplicate control IDs in scenario S{sid}")

    # Explicit footholds are starting conditions, not findings. Scenario files
    # may therefore remove the corresponding pack-generated vulnerability from
    # the scored oracle while retaining the reusable pack definition.
    excluded_vulnerabilities = {
        str(vulnerability_id)
        for vulnerability_id in scenario.get("excluded_vulnerabilities", [])
    }
    unknown_exclusions = excluded_vulnerabilities - set(vuln_ids)
    if unknown_exclusions:
        raise ValueError(
            f"Unknown excluded vulnerability IDs in scenario S{sid}: "
            f"{sorted(unknown_exclusions)}"
        )
    if excluded_vulnerabilities:
        vulns = [
            vulnerability for vulnerability in vulns
            if vulnerability["id"] not in excluded_vulnerabilities
        ]

    # Compute scoring
    max_score = sum(
        SEVERITY_WEIGHTS.get(v.get("severity", "low").lower(), 1) for v in vulns
    )

    # Build topology section for GT
    topo_section = {
        "router": {
            "name": topology["router"]["name_template"].format(sid=sid),
            "vmid": topology["base_vmid"],
            "ip": topology["router"]["ip"],
            "type": topology["router"]["type"],
        },
        "services": [],
    }
    for svc in topology["services"]:
        rendered_service = {
            "name": svc["name_template"].format(sid=sid),
            "vmid": topology["base_vmid"] + svc["vmid_offset"],
            "ip": svc["ip"],
            "role": svc["role"],
        }
        if "security_profile" in svc:
            rendered_service["security_profile"] = svc["security_profile"]
        for optional_key in ("vlan_id", "simulator"):
            if optional_key in svc:
                rendered_service[optional_key] = svc[optional_key]
        topo_section["services"].append(rendered_service)

    result = {
        "scenario_id": sid,
        "scenario_name": scenario["name"],
        "difficulty": scenario.get("difficulty", "medium"),
        "description": f"{scenario['name']} — {topology['description']}",
        "topology": topo_section,
        "vulnerabilities": vulns,
        "attack_paths": scenario.get("attack_paths", []),
        "scoring": {
            "total_vulnerabilities": len(vulns),
            "total_attack_paths": len(scenario.get("attack_paths", [])),
            "weights": SEVERITY_WEIGHTS,
            "max_weighted_score": max_score,
        },
        "bonus_types": scenario.get("bonus_types", []),
    }
    if scenario.get("schema_version", 1) >= 2 or controls:
        result["controls"] = controls
        # Keep scoring fields close to their legacy order while extending v2.
        result["scoring"]["total_controls"] = len(controls)
    return result


def main():
    parser = argparse.ArgumentParser(description="Compose ground truth from modular definitions")
    parser.add_argument("--scenario", "-s", help="Generate only this scenario ID")
    parser.add_argument("--validate", "-v", action="store_true",
                        help="Deep-validate schema-v2 GT; report legacy drift without failing")
    parser.add_argument("--strict-all", action="store_true",
                        help="With --validate, also make legacy schema-v1 drift fatal")
    parser.add_argument("--output-dir", "-o", default=str(GT_DIR),
                        help="Output directory for generated ground truths")
    args = parser.parse_args()
    if args.strict_all and not args.validate:
        parser.error("--strict-all requires --validate")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Find scenario files
    if args.scenario:
        files = [SCENARIOS_DIR / f"S{args.scenario}.yaml"]
        if not files[0].exists():
            raise SystemExit(f"Scenario file not found: {files[0]}")
    else:
        files = sorted(SCENARIOS_DIR.glob("S*.yaml"))

    if not files:
        raise SystemExit(f"No scenario files found in {SCENARIOS_DIR}/")

    had_difference = False
    processed = 0
    for scenario_file in files:
        scenario_definition = yaml.safe_load(scenario_file.read_text()) or {}
        strict_validation = bool(
            args.strict_all or scenario_definition.get("schema_version", 1) >= 2
        )
        try:
            gt = compose_scenario(scenario_file)
        except FileNotFoundError as e:
            label = "DIFF" if strict_validation else "LEGACY-SKIP"
            print(f"  {label} {scenario_file.name}: {e}")
            if args.validate and strict_validation:
                had_difference = True
            continue

        sid = gt["scenario_id"]
        out_path = out_dir / f"scenario_{sid}.yaml"
        processed += 1

        if args.validate:
            # Compare with existing
            if out_path.exists():
                existing = yaml.safe_load(out_path.read_text())
                difference = _first_difference(existing, gt)
                if difference:
                    if strict_validation:
                        had_difference = True
                        print(f"  S{sid}: [DIFF] {difference}")
                    else:
                        print(f"  S{sid}: [LEGACY-DIFF] {difference}")
                else:
                    print(f"  S{sid}: [OK] deep match")
            else:
                if strict_validation:
                    had_difference = True
                    print(f"  S{sid}: [DIFF] no existing GT file")
                else:
                    print(f"  S{sid}: [LEGACY-DIFF] no existing GT file")
        else:
            out_path.write_text(
                yaml.dump(gt, default_flow_style=False, allow_unicode=True, sort_keys=False)
            )
            print(f"  scenario_{sid}.yaml: {len(gt['vulnerabilities'])} vulns, "
                  f"max_score={gt['scoring']['max_weighted_score']}")

    print(f"\n{'Validated' if args.validate else 'Generated'} {processed} ground truths")
    if args.validate and had_difference:
        sys.exit(1)


if __name__ == "__main__":
    main()
