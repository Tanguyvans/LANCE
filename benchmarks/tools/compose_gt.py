#!/usr/bin/env python3
"""Generate ground_truth/ YAML files from scenarios/ + topologies/ + packs/.

Usage:
    python3 benchmarks/tools/compose_gt.py                    # generate all
    python3 benchmarks/tools/compose_gt.py --scenario 1       # generate one
    python3 benchmarks/tools/compose_gt.py --validate         # compare vs existing
"""

import argparse
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOPO_DIR = ROOT / "topologies"
PACKS_DIR = ROOT / "packs" / "definitions"
SCENARIOS_DIR = ROOT / "scenarios"
GT_DIR = ROOT / "ground_truth"

SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}


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


def compose_scenario(scenario_path: Path) -> dict:
    scenario = yaml.safe_load(scenario_path.read_text())
    sid = str(scenario["scenario_id"])
    topology = load_topology(scenario["topology"])

    vulns = []
    vuln_counter = 1

    for pack_id in scenario.get("packs", []):
        pack = load_pack(pack_id)
        pack_vulns = pack.get("vulnerabilities", {})

        # Match pack vulns to topology services by role
        for svc in topology.get("services", []):
            role = svc["role"]
            if role not in pack_vulns:
                continue

            device_name = svc["name_template"].format(sid=sid)
            ip = svc["ip"]

            for vuln_template in pack_vulns[role]:
                # Check scenario restriction
                allowed = vuln_template.get("scenarios")
                if allowed and sid not in allowed:
                    continue

                vuln = {
                    "id": f"V{vuln_counter}",
                    "device": device_name,
                    "ip": ip,
                    "role": role,
                }
                # Copy all fields from template (skip meta fields)
                for key, val in vuln_template.items():
                    if key == "scenarios":
                        continue  # meta field, not part of GT
                    elif key == "indicators":
                        vuln[key] = [ind.replace("{ip}", ip) for ind in val]
                    elif key == "verification":
                        vuln[key] = val.replace("{ip}", ip)
                    else:
                        vuln[key] = val

                vulns.append(vuln)
                vuln_counter += 1

        # Router vulns
        if "router" in pack_vulns:
            router = topology.get("router", {})
            router_name = router.get("name_template", "s{sid}-router").format(sid=sid)
            router_ip = router.get("ip", "10.10.0.1")

            for vuln_template in pack_vulns["router"]:
                allowed = vuln_template.get("scenarios")
                if allowed and sid not in allowed:
                    continue

                vuln = {
                    "id": f"V{vuln_counter}",
                    "device": router_name,
                    "ip": router_ip,
                    "role": "router",
                }
                for key, val in vuln_template.items():
                    if key == "scenarios":
                        continue
                    elif key == "indicators":
                        vuln[key] = [ind.replace("{ip}", router_ip) for ind in val]
                    elif key == "verification":
                        vuln[key] = val.replace("{ip}", router_ip)
                    else:
                        vuln[key] = val

                vulns.append(vuln)
                vuln_counter += 1

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
        topo_section["services"].append({
            "name": svc["name_template"].format(sid=sid),
            "vmid": topology["base_vmid"] + svc["vmid_offset"],
            "ip": svc["ip"],
            "role": svc["role"],
        })

    return {
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


def main():
    parser = argparse.ArgumentParser(description="Compose ground truth from modular definitions")
    parser.add_argument("--scenario", "-s", help="Generate only this scenario ID")
    parser.add_argument("--validate", "-v", action="store_true",
                        help="Compare generated GT vs existing (don't overwrite)")
    parser.add_argument("--output-dir", "-o", default=str(GT_DIR),
                        help="Output directory for generated ground truths")
    args = parser.parse_args()

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

    for scenario_file in files:
        try:
            gt = compose_scenario(scenario_file)
        except FileNotFoundError as e:
            print(f"  SKIP {scenario_file.name}: {e}")
            continue

        sid = gt["scenario_id"]
        out_path = out_dir / f"scenario_{sid}.yaml"

        if args.validate:
            # Compare with existing
            if out_path.exists():
                existing = yaml.safe_load(out_path.read_text())
                existing_count = len(existing.get("vulnerabilities", []))
                generated_count = len(gt["vulnerabilities"])
                match = "OK" if existing_count == generated_count else "DIFF"
                print(f"  S{sid}: existing={existing_count} generated={generated_count} [{match}]")
            else:
                print(f"  S{sid}: no existing GT file")
        else:
            out_path.write_text(
                yaml.dump(gt, default_flow_style=False, allow_unicode=True, sort_keys=False)
            )
            print(f"  scenario_{sid}.yaml: {len(gt['vulnerabilities'])} vulns, "
                  f"max_score={gt['scoring']['max_weighted_score']}")

    print(f"\n{'Validated' if args.validate else 'Generated'} {len(files)} ground truths")


if __name__ == "__main__":
    main()
