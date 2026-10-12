"""Public topology and evidence-derived device results for scenario rules audits."""
from __future__ import annotations

import json
import re
from pathlib import Path


def public_topology(topology: dict) -> dict:
    nodes = []
    for node in _items(topology, "nodes"):
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", node["id"]):
            continue
        item = {key: node[key] for key in ("id", "ip", "type", "label", "color") if key in node}
        item.setdefault("label", item["id"])
        item.setdefault("ip", "")
        item["services"] = [
            service if isinstance(service, str) else
            f"{service.get('name', 'service')}:{service.get('port', '')}"
            for service in _items(node, "services") if isinstance(service, (str, dict))
        ]
        nodes.append(item)
    ids = {node["id"] for node in nodes}
    edges = [
        {key: edge[key] for key in ("id", "source", "target", "label") if key in edge}
        for edge in _items(topology, "edges") if isinstance(edge, dict)
        and edge.get("source") in ids and edge.get("target") in ids
    ]
    return {"nodes": nodes, "edges": edges}


def _items(data: dict, name: str) -> list:
    value = data.get(name, [])
    return value if isinstance(value, list) else []


def _read(run_dir: Path, name: str) -> dict:
    try:
        value = json.loads((run_dir / name).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def device_results(run_dir: Path) -> dict:
    """Confirm findings from the shared evidence evaluator, never report labels."""
    from src.agent.exploit_evidence import synthesize_exploit_result
    from src.agent.phases.verification.evidence import _tool_records_for_vuln

    topology = public_topology(_read(run_dir, "audit_topology.json"))
    status = _read(run_dir, "03_phase3_status.json")
    analysis = _read(run_dir, "03_vuln_analysis.json")
    verification = _read(run_dir, "04_exploitation.json")
    metadata = _read(run_dir, "run_meta.json")
    failed = {item.get("device_id") for item in _items(status, "devices_failed") if isinstance(item, dict)}
    scanner_errors = _items(status, "scanner_errors")
    unassigned_errors = [item for item in scanner_errors if not isinstance(item, dict)]
    tested = {item.get("vuln_id") or item.get("id") for item in _items(verification, "tests") if isinstance(item, dict)}
    devices = []
    for node in topology.get("nodes", []):
        identifier = node["id"]
        errors = [item for item in scanner_errors if isinstance(item, dict)
                  and (item.get("device_id") == identifier or item.get("device_ip") == node.get("ip"))]
        complete = (bool(analysis) and status.get("status") in {"completed", "completed_with_device_errors", "completed_with_worker_errors"}
                    and (run_dir / f"03_device_{identifier}.json").is_file())
        state = "incomplete" if identifier in failed or errors or unassigned_errors or status.get("surface_error") else "completed" if complete else "pending"
        if not complete and metadata.get("status") in {"failed", "stopped", "budget_exceeded", "partial"}:
            state = "incomplete"
        if not node.get("ip"):
            state = "not_targeted"
        findings = []
        for candidate in _items(analysis, "vulnerabilities"):
            if not isinstance(candidate, dict) or candidate.get("device_id") != identifier:
                continue
            finding = {key: candidate[key] for key in ("id", "type", "severity", "service", "port", "details", "cve_ids") if key in candidate}
            finding["verification"] = "not_run"
            if candidate.get("id") in tested:
                result = synthesize_exploit_result(candidate, _tool_records_for_vuln(run_dir, candidate["id"]), compact=False)
                finding["verification"] = {"EXPLOITED": "confirmed", "FAILED": "not_confirmed"}.get(result.get("status"), "error")
                finding["evidence"] = result.get("evidence", "")
            findings.append(finding)
        devices.append({"device_id": identifier, "device_ip": node.get("ip"),
                        "analysis_status": state, "findings": findings,
                        "confirmed_count": sum(item["verification"] == "confirmed" for item in findings),
                        "scanner_error_count": len(errors),
                        "verification_status": (
                            "incomplete" if any(item["verification"] == "error" for item in findings) else
                            "pending" if not verification or any(item["verification"] == "not_run" for item in findings) else "completed"
                        )})
    return {"schema_version": 1, "runner_kind": "rules", "available": bool(topology.get("nodes")),
            "topology": topology, "devices": devices, "diagnostics": scanner_errors,
            "run_status": metadata.get("status", "running")}


def write_summary(run_dir: Path) -> None:
    view = device_results(run_dir)
    lines = ["# Audit par règles", "", f"Statut : {view['run_status']}", "", "Analyse et vérification sans LLM, depuis la topologie publique du scénario.", "",
             "| Équipement | IP | Analyse | Détectées | Confirmées par les preuves | Erreurs de scan |",
             "| --- | --- | --- | ---: | ---: | ---: |"]
    for device in view["devices"]:
        name = str(device["device_id"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {name} | {device['device_ip']} | {device['analysis_status']} | {len(device['findings'])} | {device['confirmed_count']} | {device['scanner_error_count']} |")
    lines.extend(["", "Une absence de détection ne garantit pas l'absence de vulnérabilité. Les contrôles incomplets restent signalés."])
    (run_dir / "run_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
