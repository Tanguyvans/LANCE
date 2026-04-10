#!/usr/bin/env python3
"""Extract topologies from group_vars/all/main.yml into separate YAML files."""

import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN_YML = ROOT / "ansible" / "group_vars" / "all" / "main.yml"
TOPO_DIR = ROOT / "topologies"
TOPO_DIR.mkdir(exist_ok=True)

# Mapping scenario_id -> topology name
TOPO_NAMES = {
    "1": "flat",
    "2": "gateway",
    "3": "nato_lab",
    "4": "ics_scada",
    "5": "building",
    "6": "star",
    "7": "edge_cloud",
    "8": "multizone",
    "9": "mesh_iot",
    "10": "flat_variants",
}

TOPO_DESCRIPTIONS = {
    "flat": "Reseau IoT sans segmentation, 3-4 devices sur 1 subnet",
    "gateway": "Gateway IoT exposee comme point d'entree, 5-6 devices",
    "nato_lab": "Replique du lab NATO physique, 7-8 devices multi-protocoles",
    "ics_scada": "Convergence IT/OT avec PLC Modbus et SCADA, 7-8 devices",
    "building": "Smart building : cameras, NVR, HVAC, controle d'acces",
    "star": "Hub central (Node-RED) connectant tous les peripheriques",
    "edge_cloud": "Architecture distribuee edge gateway + cloud API",
    "multizone": "Multi-zone IT/IoT/OT avec variantes de roles",
    "mesh_iot": "Reseau mesh de capteurs avec CoAP et SNMP",
    "flat_variants": "Reseau plat avec variantes de roles (Node-RED, FTP)",
}

data = yaml.safe_load(MAIN_YML.read_text())
scenarios = data["scenarios"]
vmid_ranges = data["scenario_vmid_ranges"]

for sid, scen in scenarios.items():
    topo_id = TOPO_NAMES.get(sid, f"scenario_{sid}")
    topo = {
        "id": topo_id,
        "name": scen["name"],
        "description": TOPO_DESCRIPTIONS.get(topo_id, scen["name"]),
        "base_vmid": vmid_ranges[sid],
        "router": {
            "name_template": f"s{{sid}}-router",
            "type": "openwrt",
            "ip": "192.168.100.1",
        },
        "services": [],
    }

    for svc in scen["services"]:
        topo["services"].append({
            "name_template": f"s{{sid}}-{svc['name']}",
            "vmid_offset": svc["vmid_offset"],
            "ip": svc["ip"],
            "role": svc["role"],
        })

    out = TOPO_DIR / f"{topo_id}.yaml"
    out.write_text(yaml.dump(topo, default_flow_style=False, allow_unicode=True, sort_keys=False))
    print(f"  {out.name}: {len(topo['services'])} services")

print(f"\nExtracted {len(scenarios)} topologies to {TOPO_DIR}/")
