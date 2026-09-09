"""Per-finding verification artifacts, test entries and recorded tool evidence."""
from __future__ import annotations
import json
from pathlib import Path
from src.agent.exploit_evidence import extract_endpoint_paths as _extract_endpoint_paths
from src.agent.report_evidence import verification_state


def _exploit_relpath(device_id: str, vuln_type: str, vuln_id: str) -> Path:
    """Relative path of a per-vuln Phase 4 exploit deliverable under the run dir."""
    safe_vuln_id = vuln_id.replace("/", "_")
    return Path("04_exploits") / device_id / f"{vuln_type}_{safe_vuln_id}.json"


def _make_test_entry(
    vuln: dict,
    *,
    status: str,
    result: dict | None = None,
    evidence: str | None = None,
    evidence_level: int | None = None,
) -> dict:
    """Build an aggregated test entry for 04_exploitation.json.

    Fields are pulled from `result` (Phase 4 output) when present, otherwise
    from `vuln` (Phase 3 finding). `status`, `evidence` and `evidence_level`
    can be overridden by explicit kwargs for the parse-error and pass-through
    branches.
    """
    result = result or {}
    entry = {
        "vuln_id": vuln.get("id", "VULN-???"),
        "device_id": result.get("device_id") or vuln.get("device_id", "unknown"),
        "device_ip": result.get("device_ip") or vuln.get("device_ip", ""),
        "vuln_type": result.get("vuln_type") or vuln.get("type", ""),
        "severity": result.get("severity") or vuln.get("severity", "MEDIUM"),
        "service": result.get("service") or vuln.get("service", ""),
        "port": (
            result.get("port")
            if result.get("port") is not None
            else vuln.get("port")
        ),
        "protocol": result.get("protocol") or vuln.get("protocol", ""),
        "endpoint": result.get("endpoint") or vuln.get("endpoint", ""),
        "endpoints": _extract_endpoint_paths(
            result.get("endpoints"), result.get("endpoint"),
            vuln.get("endpoints"), vuln.get("endpoint"),
        ),
        "product": result.get("product") or vuln.get("product", ""),
        "version": result.get("version") or vuln.get("version", ""),
        "status": status,
        "evidence": (
            evidence if evidence is not None
            else (result.get("evidence") or vuln.get("evidence", ""))
        ),
        "evidence_level": (
            evidence_level if evidence_level is not None
            else result.get("evidence_level", 1)
        ),
        "tool_used": result.get("tool_used", ""),
        "tools_used": list(dict.fromkeys(
            str(value).strip()
            for value in (result.get("tools_used") or [])
            if str(value).strip()
        )),
        "evidence_refs": list(dict.fromkeys(
            str(value).strip()
            for value in (result.get("evidence_refs") or [])
            if str(value).strip()
        )),
        "data_extracted": result.get("data_extracted", []),
        "description": result.get("description") or vuln.get("details", ""),
        "cve_ids": vuln.get("cve_ids", []),
    }
    entry["verification_status"] = verification_state(entry)
    return entry


def _tool_records_for_vuln(run_dir: Path, vuln_id: str) -> list[dict]:
    tool_log = run_dir / "tool_calls.jsonl"
    if not tool_log.is_file():
        return []
    records: list[dict] = []
    try:
        lines = tool_log.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    for line in lines:
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if str(record.get("vuln_id", "")).strip() == str(vuln_id).strip():
            records.append(record)
    return records
