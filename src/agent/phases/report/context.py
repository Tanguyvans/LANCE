"""Prepare report-facing data from run artifacts, without provider access."""
from __future__ import annotations
import json
import logging
from pathlib import Path
from src.agent.report_evidence import (
    is_verified_report_finding as _is_verified_report_finding,
    report_phase4_summary as _report_phase4_summary,
)


log = logging.getLogger(__name__)


# This is a prompt-facing bound, not an evidence bound.  The complete
# artifacts remain immutable in the run directory and are referenced below.
REPORT_CONTEXT_MAX_BYTES = 24_000
_TEXT_LIMIT = 360
_LIST_LIMITS = {
    "phase6.phase4_tests": 24,
    "phase6.top_critical_findings": 12,
    "phase6.top_devices_by_risk": 12,
    "phase6.cve_list": 32,
    "graph.nodes": 24,
    "graph.attack_paths": 10,
    "recon.devices": 24,
    "intrusion.compromised_devices": 12,
    "intrusion.credential_pool": 16,
    "intrusion.attack_chains": 8,
    "intrusion.crown_jewels": 8,
}


def _safe_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _short_text(value, *, path: str, omissions: dict[str, int], limit: int = _TEXT_LIMIT):
    """Project text without silently losing the existence of omitted data."""
    if not isinstance(value, str):
        return value
    if len(value) <= limit:
        return value
    omitted = len(value) - limit
    omissions[f"{path}.characters"] = omissions.get(f"{path}.characters", 0) + omitted
    return f"{value[:limit]}… [truncated; full value in referenced artifact]"


def _project_list(
    value, *, path: str, omissions: dict[str, int], projector, limit: int | None = None
) -> list:
    if not isinstance(value, list):
        return []
    limit = _LIST_LIMITS.get(path, 16) if limit is None else limit
    projected = [projector(item, f"{path}[{index}]") for index, item in enumerate(value[:limit])]
    omitted = max(0, len(value) - limit)
    if omitted:
        omissions[path] = omissions.get(path, 0) + omitted
    return projected


def _project_record(value, *, path: str, omissions: dict[str, int], fields: tuple[str, ...]) -> dict:
    if not isinstance(value, dict):
        return {"value": _short_text(str(value), path=path, omissions=omissions)}
    result = {}
    for field in fields:
        if field in value and value[field] is not None:
            item_path = f"{path}.{field}"
            item = value[field]
            if isinstance(item, str):
                result[field] = _short_text(item, path=item_path, omissions=omissions)
            else:
                result[field] = _project_value(
                    item, path=item_path, omissions=omissions, depth=0
                )
    return result


def _project_value(value, *, path: str, omissions: dict[str, int], depth: int):
    """Recursively bound nested maps/lists instead of copying raw structures."""
    if isinstance(value, str):
        return _short_text(value, path=path, omissions=omissions, limit=220)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if depth >= 2:
        omissions[path] = omissions.get(path, 0) + 1
        return "[nested value omitted; see referenced artifact]"
    if isinstance(value, dict):
        result = {}
        keys = list(value)[:12]
        if len(value) > len(keys):
            omissions[path] = omissions.get(path, 0) + len(value) - len(keys)
        for key in keys:
            raw_key = str(key)
            safe_key = _short_text(raw_key, path=f"{path}.keys", omissions=omissions, limit=96)
            result[safe_key] = _project_value(
                value[key], path=f"{path}.{safe_key}", omissions=omissions, depth=depth + 1
            )
        return result
    if isinstance(value, list):
        return _project_list(
            value,
            path=path,
            omissions=omissions,
            projector=lambda entry, entry_path: _project_value(
                entry, path=entry_path, omissions=omissions, depth=depth + 1
            ),
            limit=8,
        )
    return _short_text(str(value), path=path, omissions=omissions, limit=220)


def _project_context(phase6: dict, graph: dict, recon: dict, intrusion: dict) -> dict:
    omissions: dict[str, int] = {}
    phase6_projection = {
        key: phase6.get(key)
        for key in (
            "device_count", "devices_with_findings", "total_vulnerabilities",
        )
        if key in phase6
    }
    if phase6:
        phase6_projection["severity_breakdown"] = _project_value(
            phase6.get("severity_breakdown", {}), path="phase6.severity_breakdown",
            omissions=omissions, depth=0,
        )
        phase6_projection["phase4_summary"] = _project_value(
            phase6.get("phase4_summary", {}), path="phase6.phase4_summary",
            omissions=omissions, depth=0,
        )
        phase6_projection["phase4_tests"] = _project_list(
            phase6.get("phase4_tests"), path="phase6.phase4_tests", omissions=omissions,
            projector=lambda item, path: _project_record(
                item, path=path, omissions=omissions,
                fields=("vuln_id", "device_id", "device_ip", "type", "service", "port",
                        "status", "evidence_level", "tool_used", "evidence_refs", "evidence_excerpt"),
            ),
        )
        phase6_projection["top_critical_findings"] = _project_list(
            phase6.get("top_critical_findings"), path="phase6.top_critical_findings", omissions=omissions,
            projector=lambda item, path: _project_record(
                item, path=path, omissions=omissions,
                fields=("device_id", "device_ip", "type", "service", "title", "status"),
            ),
        )
        phase6_projection["top_devices_by_risk"] = _project_list(
            phase6.get("top_devices_by_risk"), path="phase6.top_devices_by_risk", omissions=omissions,
            projector=lambda item, path: _project_record(
                item, path=path, omissions=omissions,
                fields=("device_id", "device_ip", "severity_counts", "confirmed", "risk_score"),
            ),
        )
        phase6_projection["cve_list"] = _project_list(
            phase6.get("cve_list"), path="phase6.cve_list", omissions=omissions,
            projector=lambda item, path: _short_text(str(item), path=path, omissions=omissions, limit=120),
        )

    graph_projection = {
        key: graph.get(key)
        for key in (
            "scenario", "subnet", "node_count", "edge_count", "service_count",
            "attack_path_count", "attack_paths_note", "risk_scores_note", "note",
        )
        if key in graph
    }
    graph_projection["nodes"] = _project_list(
        graph.get("nodes"), path="graph.nodes", omissions=omissions,
        projector=lambda item, path: _project_record(
            item, path=path, omissions=omissions,
            fields=("id", "name", "ip", "type", "role"),
        ),
    )
    graph_projection["attack_paths"] = _project_list(
        graph.get("attack_paths"), path="graph.attack_paths", omissions=omissions,
        projector=lambda item, path: _project_record(
            item, path=path, omissions=omissions,
            fields=("path", "score", "impact", "entry", "target"),
        ),
    )

    recon_projection = {
        "device_count": recon.get("device_count", 0),
        "note": _short_text(recon.get("note", ""), path="recon.note", omissions=omissions),
        "devices": _project_list(
            recon.get("devices"), path="recon.devices", omissions=omissions,
            projector=lambda item, path: _project_record(
                item, path=path, omissions=omissions,
                fields=("device", "device_id", "ip", "open_ports", "services", "status"),
            ),
        ),
    }

    # Phase 5 is deliberately a raw declaration surface.  It can provide
    # context for the memo, but it is never promoted to a validated pivot or
    # compromise by report rendering.
    intrusion_projection = {}
    if intrusion:
        intrusion_projection = {
            "evidence_status": "raw_non_validated",
            "source": "05_intrusion.json",
            "summary": _project_value(
                intrusion.get("summary", {}), path="intrusion.summary",
                omissions=omissions, depth=0,
            ),
            "compromised_devices": _project_list(
                intrusion.get("compromised_devices"), path="intrusion.compromised_devices",
                omissions=omissions,
                projector=lambda item, path: _project_record(
                    item, path=path, omissions=omissions,
                    fields=("device_id", "device_ip", "access_method", "service", "source"),
                ),
            ),
            "credential_pool": _project_list(
                intrusion.get("credential_pool"), path="intrusion.credential_pool", omissions=omissions,
                projector=lambda item, path: _project_record(
                    item, path=path, omissions=omissions,
                    fields=("username", "user", "service", "source", "used_to_compromise"),
                ),
            ),
            "attack_chains": _project_list(
                intrusion.get("attack_chains"), path="intrusion.attack_chains", omissions=omissions,
                projector=lambda item, path: _project_record(
                    item, path=path, omissions=omissions,
                    fields=("entry_ip", "hops", "target", "status"),
                ),
            ),
            "crown_jewels": _project_list(
                intrusion.get("crown_jewels"), path="intrusion.crown_jewels", omissions=omissions,
                projector=lambda item, path: _project_record(
                    item, path=path, omissions=omissions,
                    fields=("device_id", "device_ip", "access_method", "data", "status"),
                ),
            ),
        }

    result = {
        "schema": "phase6_report_context_v2",
        "phase6": phase6_projection,
        "graph": graph_projection,
        "recon": recon_projection,
        "intrusion": intrusion_projection,
        "full_evidence_references": [
            "01_graph_evidence.json", "01_graph_analysis.md",
            "02_recon_evidence.json", "02_recon.md",
            "03_vuln_analysis_raw.json", "03_vuln_analysis.json",
            "04_exploitation.json", "05_intrusion.json",
            "tool_calls.jsonl", "model_outputs.jsonl",
        ],
        "omissions": omissions,
    }
    serialized = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    # The conservative per-field caps above should normally suffice.  If a
    # future artifact shape still exceeds the contract, remove optional list
    # members explicitly and report that fact instead of silently truncating.
    if len(serialized.encode("utf-8")) > REPORT_CONTEXT_MAX_BYTES:
        for section, key in (
            ("intrusion", "attack_chains"), ("intrusion", "credential_pool"),
            ("graph", "attack_paths"), ("recon", "devices"),
            ("phase6", "phase4_tests"),
        ):
            values = result[section].get(key, [])
            if values:
                result["omissions"][f"{section}.{key}"] = (
                    result["omissions"].get(f"{section}.{key}", 0) + len(values)
                )
                result[section][key] = []
                serialized = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
                if len(serialized.encode("utf-8")) <= REPORT_CONTEXT_MAX_BYTES:
                    break
    result["bounds"] = {
        "max_bytes": REPORT_CONTEXT_MAX_BYTES,
        "serialized_bytes": 0,
        "omitted_fields_are_referenced": True,
    }
    # The exact compact JSON string is the contract used in the prompt and in
    # the context artifact. Recompute after adding bounds so metadata itself is
    # included in the byte limit (UTF-8, not Python character count).
    for _ in range(10):
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        actual = len(encoded)
        if result["bounds"]["serialized_bytes"] == actual:
            break
        result["bounds"]["serialized_bytes"] = actual
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > REPORT_CONTEXT_MAX_BYTES:
        # This last-resort projection still carries references and omission
        # counters; it never slices the JSON string or drops data silently.
        result = {
            "schema": result["schema"],
            "phase6": {
                key: result["phase6"].get(key)
                for key in ("device_count", "devices_with_findings", "total_vulnerabilities", "severity_breakdown", "phase4_summary")
                if key in result["phase6"]
            },
            "graph": {key: result["graph"].get(key) for key in ("subnet", "node_count", "edge_count", "service_count", "attack_path_count") if key in result["graph"]},
            "recon": {"device_count": result["recon"].get("device_count", 0)},
            "intrusion": {"evidence_status": "raw_non_validated", "source": "05_intrusion.json"},
            "full_evidence_references": result["full_evidence_references"],
            "omissions": {
                "count": sum(
                    value if isinstance(value, int) else 1
                    for value in result["omissions"].values()
                ),
                "context_projection": "optional fields removed to satisfy byte bound",
            },
            "bounds": {"max_bytes": REPORT_CONTEXT_MAX_BYTES, "serialized_bytes": 0, "omitted_fields_are_referenced": True},
        }
        for _ in range(10):
            encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            actual = len(encoded)
            if result["bounds"]["serialized_bytes"] == actual:
                break
            result["bounds"]["serialized_bytes"] = actual
    # Defensive guarantee for future additions: if even the minimal projection
    # grows beyond the contract, retain references and aggregate omission data
    # only. This branch is intentionally explicit and still carries exact size
    # metadata.
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > REPORT_CONTEXT_MAX_BYTES:
        result = {
            "schema": "phase6_report_context_v2",
            "full_evidence_references": [
                "01_graph_evidence.json", "01_graph_analysis.md",
                "02_recon_evidence.json", "02_recon.md",
                "03_vuln_analysis_raw.json", "03_vuln_analysis.json",
                "04_exploitation.json", "05_intrusion.json",
                "tool_calls.jsonl", "model_outputs.jsonl",
            ],
            "omissions": {"context_projection": "refs_only", "count": 1},
            "bounds": {"max_bytes": REPORT_CONTEXT_MAX_BYTES, "serialized_bytes": 0, "omitted_fields_are_referenced": True},
        }
        for _ in range(10):
            encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            actual = len(encoded)
            if result["bounds"]["serialized_bytes"] == actual:
                break
            result["bounds"]["serialized_bytes"] = actual
    return result

def build_report_analysis_context(run_dir: Path) -> dict:
    """Prepare compact authoritative evidence for a one-shot local analysis."""
    return _project_context(
        _safe_json(run_dir / "06_phase6_context.json"),
        _safe_json(run_dir / "01_graph_evidence.json"),
        _safe_json(run_dir / "02_recon_evidence.json"),
        _safe_json(run_dir / "05_intrusion.json"),
    )

def generate_phase6_context(run_dir: Path, run_context: dict, *, compact: bool) -> None:
    """Generate a compact 06_phase6_context.json for the report agent.

    Aggregates 03_vuln_analysis.json and 04_exploitation.json by device,
    stripping verbose evidence/details fields. Reduces Phase 5 context
    from ~150 KB to ~5-10 KB for large scenarios (30+ devices).
    The full evidence remains in the original files for traceability.
    """
    # --- Load Phase 3 vulnerabilities ---
    vuln_path = run_dir / "03_vuln_analysis.json"
    phase3_vulns: list[dict] = []
    compact_observations: list[dict] = []
    if vuln_path.exists():
        data = json.loads(vuln_path.read_text(encoding="utf-8"))
        phase3_vulns = data.get("vulnerabilities", [])
        compact_observations = (
            data.get("configuration_observations", [])
            if compact
            else []
        )

    # --- Load Phase 4 exploitation results ---
    exploit_path = run_dir / "04_exploitation.json"
    exploit_by_vuln: dict[str, dict] = {}
    phase4_summary: dict = {}
    phase4_tests: list[dict] = []
    if exploit_path.exists():
        data = json.loads(exploit_path.read_text(encoding="utf-8"))
        raw_tests = data.get("tests", [])
        phase4_summary = _report_phase4_summary(data.get("summary", {}), raw_tests)
        # 04_exploitation.json uses "tests" key (from _aggregate_exploit_results)
        for t in raw_tests:
            vuln_id = t.get("vuln_id", "")
            if vuln_id:
                exploit_by_vuln[vuln_id] = t
            if not _is_verified_report_finding(t):
                continue
            phase4_tests.append({
                "vuln_id": vuln_id,
                "device_id": t.get("device_id", ""),
                "device_ip": t.get("device_ip", ""),
                "type": t.get("vuln_type", ""),
                "service": t.get("service", ""),
                "port": t.get("port"),
                "status": t.get("status", ""),
                "evidence_level": t.get("evidence_level", 0),
                "tool_used": t.get("tool_used", ""),
                "tools_used": t.get("tools_used", []),
                "evidence_refs": t.get("evidence_refs", []),
                "evidence_excerpt": (
                    str(t.get("evidence", ""))[:320]
                    + ("… [truncated; full evidence in 04_exploitation.json]"
                       if len(str(t.get("evidence", ""))) > 320 else "")
                ),
            })

    # --- Aggregate by device (compact — no per-vuln details, sections 5/6 are pre-generated) ---
    devices: dict[str, dict] = {}
    global_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    cve_set: set[str] = set()
    top_critical: list[dict] = []  # up to 10 critical findings for narrative

    for v in phase3_vulns:
        dev_ip = v.get("device_ip", "unknown")
        dev_id = v.get("device_id", "unknown")
        if dev_ip not in devices:
            devices[dev_ip] = {
                "device_id": dev_id,
                "device_ip": dev_ip,
                "severity_counts": {},
                "confirmed_count": 0,
            }
        vuln_id = v.get("id", "")
        exploit = exploit_by_vuln.get(vuln_id, {})
        status = exploit.get("status", "UNTESTED")
        severity = (v.get("severity") or "MEDIUM").upper()

        if not _is_verified_report_finding(exploit):
            continue

        devices[dev_ip]["severity_counts"][severity] = (
            devices[dev_ip]["severity_counts"].get(severity, 0) + 1
        )
        if status == "CONFIRMED":
            devices[dev_ip]["confirmed_count"] += 1

        if severity in global_sev:
            global_sev[severity] += 1

        for cve in v.get("cve_ids", []):
            if cve:
                cve_set.add(cve)

        if severity == "CRITICAL" and len(top_critical) < 10:
            top_critical.append({
                "device_id": dev_id,
                "device_ip": dev_ip,
                "type": v.get("type", ""),
                "service": v.get("service", ""),
                "title": (
                    str(v.get("details", ""))[:80]
                    + ("… [truncated; full title in 03_vuln_analysis.json]"
                       if len(str(v.get("details", ""))) > 80 else "")
                ),
                "status": status,
            })

    # --- Build compact output ---
    device_list = [d for d in sorted(devices.values(), key=lambda d: d["device_ip"]) if d["severity_counts"]]
    total_vulns = sum(
        sum(d["severity_counts"].values()) for d in device_list
    )

    # Top devices by risk (for Section 8)
    def _risk_score(d: dict) -> int:
        sc = d["severity_counts"]
        return sc.get("CRITICAL", 0) * 4 + sc.get("HIGH", 0) * 3 + sc.get("MEDIUM", 0) * 2 + sc.get("LOW", 0)

    top_devices = sorted(device_list, key=_risk_score, reverse=True)[:12]

    try:
        assessed_device_count = int(run_context.get("device_count", len(device_list)))
    except (TypeError, ValueError):
        assessed_device_count = len(device_list)
    context = {
        "generated_for": "phase6_report",
        "device_count": assessed_device_count,
        "devices_with_findings": len(device_list),
        "total_vulnerabilities": total_vulns,
        **({"configuration_observations": compact_observations} if compact_observations else {}),
        "severity_breakdown": global_sev,
        "phase4_summary": phase4_summary,
        "phase4_tests": phase4_tests[:120],
        "phase4_tests_omitted": max(0, len(phase4_tests) - 120),
        "phase4_tests_note": (
            "Only Phase 4 findings with status CONFIRMED and evidence level >= 2 "
            "are projected here. Unsupported confirmations are excluded from the "
            "report-facing context; full results remain in 04_exploitation.json "
            "and raw tool output in tool_calls.jsonl."
        ),
        "top_critical_findings": top_critical,
        "top_devices_by_risk": [
            {
                "device_id": d["device_id"],
                "device_ip": d["device_ip"],
                "severity_counts": d["severity_counts"],
                "confirmed": d["confirmed_count"],
                "risk_score": _risk_score(d),
            }
            for d in top_devices
        ],
        "cve_list": sorted(cve_set),
        "information_sources": {
            "graph_evidence": "01_graph_evidence.json",
            "raw_findings": "03_vuln_analysis_raw.json",
            "exploitation_results": "04_exploitation.json",
            "raw_tool_outputs": "tool_calls.jsonl",
            "model_outputs": "model_outputs.jsonl",
            "recon_evidence": "02_recon_evidence.json",
        },
        "NOTE": (
            "Sections 5 and 6 (vuln tables) are pre-generated in "
            "06_report_prefill.md. The primary inventory contains only "
            "Phase 4-verified findings (CONFIRMED, evidence level >= 2); "
            "the complete candidate registry remains in the raw artifacts."
        ),
    }

    out_path = run_dir / "06_phase6_context.json"
    out_path.write_text(
        json.dumps(context, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info(
        "Generated Phase 5 context: %d devices, %d vulns → %s (%d bytes)",
        len(device_list), total_vulns, out_path, out_path.stat().st_size,
    )
    print(
        f"  [context] 06_phase6_context.json "
        f"({len(device_list)} devices, {total_vulns} vulns, "
        f"{out_path.stat().st_size:,} bytes)"
    )
