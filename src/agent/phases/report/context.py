"""Prepare report-facing data from run artifacts, without provider access."""
from __future__ import annotations
import json
import logging
from pathlib import Path
from src.agent.phases.report.grouping import group_findings_for_report
from src.agent.report_evidence import (
    is_verified_report_finding as _is_verified_report_finding,
    report_phase4_summary as _report_phase4_summary,
)


log = logging.getLogger(__name__)


def _execution_facts(run_dir: Path) -> dict:
    """Ledger facts for the analyst, never proof or completion verdicts."""
    calls = cve_calls = 0
    intact = True
    try:
        with (run_dir / "tool_calls.jsonl").open(encoding="utf-8") as ledger:
            for line in ledger:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    intact = False
                    continue
                if not isinstance(record, dict) or not isinstance(record.get("tool"), str):
                    intact = False
                    continue
                calls += 1
                cve_calls += record["tool"] == "cve_search"
    except (OSError, UnicodeError):
        intact = False
    return {
        "source": "tool_calls.jsonl", "ledger_readable": intact,
        "recorded_calls": calls if intact else None,
        "cve_search_calls": cve_calls if intact else None,
        "interpretation": (
            "Counts are recorded calls, not successful searches or vulnerability proofs. "
            "An empty confirmed CVE inventory does not imply searches were absent. "
            "An unavailable ledger does not establish zero calls."
        ),
    }


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
        "finding_grouping": {
            "source": "06_report_groups.json", "purpose": "presentation_only",
            "hypotheses": len(phase3_vulns),
            "groups": len(group_findings_for_report(phase3_vulns)),
            "note": "Possible duplicate declarations; not unique flaws. Official metrics and all source hypotheses are unchanged.",
        },
        **({"configuration_observations": compact_observations} if compact_observations else {}),
        "severity_breakdown": global_sev,
        "phase4_summary": phase4_summary,
        "phase4_tests": phase4_tests[:120],
        "phase4_tests_omitted": max(0, len(phase4_tests) - 120),
        "phase4_tests_note": (
            "Only Phase 4 findings with status CONFIRMED and evidence level >= 2 "
            "are projected here. Unsupported confirmations are excluded from the "
            "report-facing context; full results remain in 04_exploitation.json "
            "and raw tool output in tool_calls.jsonl. This selection does not "
            "establish benchmark proof acceptance, unique flaws or code execution."
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
            "Phase 4-supported declarations (CONFIRMED, evidence level >= 2); "
            "the complete candidate registry remains in the raw artifacts."
        ),
    }

    out_path = run_dir / "06_phase6_context.json"
    out_path.write_text(
        json.dumps(context, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info(
        "Generated Phase 6 context: %d devices, %d declarations → %s (%d bytes)",
        len(device_list), total_vulns, out_path, out_path.stat().st_size,
    )
    print(
        f"  [context] 06_phase6_context.json "
        f"({len(device_list)} devices, {total_vulns} vulns, "
        f"{out_path.stat().st_size:,} bytes)"
    )
