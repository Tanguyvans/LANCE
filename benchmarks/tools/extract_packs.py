#!/usr/bin/env python3
"""Extract vulnerability packs from ground_truth files, grouped by category and role.

Each pack contains vulns keyed by role. A vuln template can have a 'scenarios' field
listing which scenario IDs it applies to (empty = all scenarios with that role+pack).
"""

import yaml
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
GT_DIR = ROOT / "ground_truth"
PACKS_DIR = ROOT / "packs" / "definitions"
PACKS_DIR.mkdir(parents=True, exist_ok=True)

CATEGORY_TO_PACK = {
    "misconfiguration": "f2_misconfig",
    "default_credentials": "f1_weak_auth",
    "no_authentication": "f1_weak_auth",
    "data_exposure": "f3_data_exposure",
    "info_disclosure": "f8_info_disclosure",
    "missing_header": "f8_info_disclosure",
    "code_injection": "f5_injection",
    "cve": "f6_crypto",
    "weak_crypto": "f6_crypto",
    "insecure_update": "f9_insecure_update",
    "privilege_escalation": "f7_postexploit",
}

PACK_NAMES = {
    "f1_weak_auth": "Weak Authentication",
    "f2_misconfig": "Misconfigurations",
    "f3_data_exposure": "Data Exposure",
    "f5_injection": "Code Injection",
    "f6_crypto": "Weak Cryptography & CVEs",
    "f7_postexploit": "Post-Exploitation",
    "f8_info_disclosure": "Information Disclosure",
    "f9_insecure_update": "Insecure Updates",
}

# Collect: pack_id -> role -> list of {vuln_template, scenarios: [sid, ...]}
packs = defaultdict(lambda: defaultdict(list))
scenario_packs = defaultdict(set)

# Track unique vulns by signature to group scenario IDs
# key: (pack_id, role, title) -> {template, scenarios}
vuln_registry = {}

for gt_file in sorted(GT_DIR.glob("scenario_*.yaml")):
    gt = yaml.safe_load(gt_file.read_text())
    sid = str(gt.get("scenario_id", "?"))

    for v in gt.get("vulnerabilities", []):
        category = v.get("category", "misconfiguration")
        pack_id = CATEGORY_TO_PACK.get(category, "f2_misconfig")
        role = v.get("role", "unknown")
        title = v.get("title", "")

        scenario_packs[sid].add(pack_id)

        sig = (pack_id, role, title)

        if sig not in vuln_registry:
            # Build template
            tmpl = {
                "title": title,
                "severity": v.get("severity", "medium"),
                "category": category,
            }
            if v.get("owasp_iot"):
                tmpl["owasp_iot"] = v["owasp_iot"]
            if v.get("mitre_ics"):
                tmpl["mitre_ics"] = v["mitre_ics"]
            if v.get("description"):
                tmpl["description"] = v["description"].strip()
            if v.get("cve"):
                tmpl["cve"] = v["cve"]
            if v.get("indicators"):
                tmpl["indicators"] = [ind.replace(v.get("ip", ""), "{ip}") for ind in v["indicators"]]
            if v.get("verification"):
                tmpl["verification"] = v["verification"].replace(v.get("ip", ""), "{ip}")
            if v.get("confidence_required"):
                tmpl["confidence_required"] = v["confidence_required"]

            vuln_registry[sig] = {"template": tmpl, "scenarios": set()}

        vuln_registry[sig]["scenarios"].add(sid)

# Now build packs: group by pack_id -> role, add scenario restrictions
for (pack_id, role, title), entry in vuln_registry.items():
    tmpl = dict(entry["template"])
    # Only add scenarios field if the vuln doesn't apply to ALL scenarios that use this pack
    all_scenarios_with_pack = {s for s, ps in scenario_packs.items() if pack_id in ps}
    if entry["scenarios"] != all_scenarios_with_pack:
        tmpl["scenarios"] = sorted(entry["scenarios"])
    packs[pack_id][role].append(tmpl)

# Write pack files
for pack_id in sorted(packs):
    roles = packs[pack_id]
    pack_data = {
        "id": pack_id,
        "name": PACK_NAMES.get(pack_id, pack_id),
        "vulnerabilities": {},
    }
    total = 0
    for role in sorted(roles):
        pack_data["vulnerabilities"][role] = roles[role]
        total += len(roles[role])

    out = PACKS_DIR / f"{pack_id}.yaml"
    out.write_text(yaml.dump(pack_data, default_flow_style=False, allow_unicode=True, sort_keys=False))
    print(f"  {pack_id}: {total} vulns across {len(roles)} roles")

# Write scenario compositions
SCENARIOS_DIR = ROOT / "scenarios"
SCENARIOS_DIR.mkdir(exist_ok=True)

TOPO_NAMES = {
    "1": "flat", "2": "gateway", "3": "nato_lab", "4": "ics_scada",
    "5": "building", "6": "star", "7": "edge_cloud",
    "8": "multizone", "9": "mesh_iot", "10": "flat_variants",
}

for gt_file in sorted(GT_DIR.glob("scenario_*.yaml")):
    gt = yaml.safe_load(gt_file.read_text())
    sid = str(gt.get("scenario_id", "?"))
    scenario_data = {
        "scenario_id": sid,
        "name": gt.get("scenario_name", ""),
        "difficulty": gt.get("difficulty", "medium"),
        "posture": "vulnerable",
        "topology": TOPO_NAMES.get(sid, f"scenario_{sid}"),
        "packs": sorted(scenario_packs.get(sid, [])),
        "attack_paths": gt.get("attack_paths", []),
        "bonus_types": gt.get("bonus_types", []),
    }
    out = SCENARIOS_DIR / f"S{sid}.yaml"
    out.write_text(yaml.dump(scenario_data, default_flow_style=False, allow_unicode=True, sort_keys=False))

print(f"\nExtracted {len(packs)} packs, {len(scenario_packs)} scenarios")
