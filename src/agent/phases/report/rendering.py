"""Compose report tables and fallback Markdown from run-local evidence."""
from __future__ import annotations
import json
import logging
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from src.agent.phases.report.context import build_report_analysis_context
from src.agent.report_evidence import is_verified_report_finding as _is_verified_report_finding


log = logging.getLogger(__name__)

def pregenerate_report_sections(run_dir: Path) -> None:
    """Pre-generate heavy Markdown tables for the Phase 6 report.

    Writes 06_report_prefill.md so the LLM only needs to produce narrative text
    (Sections 1, 2, 3, 4, 7, 8, 9, 10) rather than re-serialising 100+ table rows.
    This avoids MiniMax / smaller models truncating the report mid-generation.
    """
    # Load phase 3 vulnerabilities
    vuln_path = run_dir / "03_vuln_analysis.json"
    phase3_vulns: list[dict] = []
    compact_observations: list[dict] = []
    if vuln_path.exists():
        data = json.loads(vuln_path.read_text(encoding="utf-8"))
        phase3_vulns = data.get("vulnerabilities", [])

    # Load phase 4 exploitation results
    exploit_path = run_dir / "04_exploitation.json"
    exploit_by_vuln: dict[str, dict] = {}
    phase4_summary: dict = {}
    if exploit_path.exists():
        data = json.loads(exploit_path.read_text(encoding="utf-8"))
        phase4_summary = data.get("summary", {})
        for t in data.get("tests", []):
            vid = t.get("vuln_id", "")
            if vid:
                exploit_by_vuln[vid] = t

    # --- Section 5: Vulnerability table ---
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulns = sorted(
        phase3_vulns,
        key=lambda v: (sev_order.get((v.get("severity") or "LOW").upper(), 9), v.get("device_ip", ""))
    )
    sec5_rows = []
    for v in sorted_vulns:
        vid = v.get("id", "")
        exploit = exploit_by_vuln.get(vid, {})
        status_raw = exploit.get("status", "UNTESTED")

        if not _is_verified_report_finding(exploit):
            continue
        status_map = {
            "CONFIRMED": "**Confirmed**",
            "FAILED": "Not Exploitable",
            "ERROR": "Inconclusive",
            "SKIPPED": "Not tested",
            "UNTESTED": "Potential (untested)",
        }
        status = status_map.get(status_raw, "Potential (untested)")
        if v.get("type") == "known_cve" and status_raw == "UNTESTED":
            claim_status = v.get("cve_claim_status", "unverified")
            status = f"Potential (CVE-based; {claim_status})"
        title = (v.get("details") or "")[:80].replace("|", "/")
        sec5_rows.append(
            f"| {vid} | {v.get('device_id','')} ({v.get('device_ip','')}) "
            f"| {v.get('type','')} | {(v.get('severity') or '').upper()} "
            f"| {v.get('service','')}:{v.get('port','')} | {status} | {title} |"
        )
    sec5 = (
        "## 5. Verified Vulnerabilities\n\n"
        "Only Phase 4 findings with status `CONFIRMED` and evidence level >= 2 "
        "are included in this primary inventory.\n\n"
        "| ID | Device | Type | Severity | Service | Status | Evidence |\n"
        "|----|--------|------|----------|---------|--------|----------|\n"
        + "\n".join(sec5_rows)
    )

    if compact_observations:
        observation_rows = []
        for observation in compact_observations:
            title = (
                observation.get("details")
                or observation.get("evidence")
                or ""
            )[:120].replace("|", "/")
            observation_rows.append(
                f"| {observation.get('id', '')} | "
                f"{observation.get('device_id', '')} "
                f"({observation.get('device_ip', '')}) | "
                f"{observation.get('type', '')} | "
                f"{(observation.get('severity') or '').upper()} | {title} |"
            )
        sec5 += (
            "\n\n### Configuration observations (not exploitation candidates)\n\n"
            "| ID | Device | Type | Severity | Observation |\n"
            "|----|--------|------|----------|-------------|\n"
            + "\n".join(observation_rows)
        )

    # --- Section 6.1: Exploitation summary ---
    total_tested = phase4_summary.get("total_tested", len(phase3_vulns))
    confirmed = sum(1 for t in exploit_by_vuln.values() if _is_verified_report_finding(t))
    unverified_confirmed = sum(
        1
        for t in exploit_by_vuln.values()
        if str(t.get("status", "")).upper() == "CONFIRMED"
        and not _is_verified_report_finding(t)
    )
    not_exploitable = phase4_summary.get("not_exploitable", 0)
    errors = phase4_summary.get("errors", 0)
    # Count real evidence (level >= 2)
    data_exfil = sum(1 for t in exploit_by_vuln.values() if _is_verified_report_finding(t))
    sec61 = (
        "### 6.1 Exploitation Summary\n\n"
        "| Metric | Value |\n|--------|-------|\n"
        f"| Vulnerabilities tested | {total_tested} |\n"
        f"| Verified (confirmed, evidence >= 2) | {confirmed} |\n"
        f"| Unsupported confirmations excluded | {unverified_confirmed} |\n"
        f"| Data exfiltrated (level ≥ 2) | {data_exfil} |\n"
        f"| Not exploitable | {not_exploitable} |\n"
        f"| Errors | {errors} |"
    )

    # --- Section 6.2: Exploitation details (confirmed only, keep table manageable) ---
    confirmed_tests = [t for t in exploit_by_vuln.values() if _is_verified_report_finding(t)]
    sec62_rows = []
    for t in confirmed_tests:
        data_list = t.get("data_extracted", [])
        data_str = ("; ".join(str(d) for d in data_list[:2]) or "-")[:60].replace("|", "/")
        sec62_rows.append(
            f"| {t.get('vuln_id','')} | {t.get('device_id','')} "
            f"| {t.get('vuln_type','')} | {t.get('tool_used','-')} "
            f"| **Confirmed** | {t.get('evidence_level',1)} | {data_str} |"
        )
    sec62 = (
        "### 6.2 Exploitation Details (evidence level ≥ 2)\n\n"
        "| Test ID | Device | Vuln Type | Tool Used | Status | Evidence Level | Data Retrieved |\n"
        "|---------|--------|-----------|-----------|--------|----------------|----------------|\n"
        + ("\n".join(sec62_rows) if sec62_rows else "| — | No level-2+ exploits in this run | | | | | |")
    )

    # --- Section 6.3: Credentials recovered ---
    creds_rows = []
    for t in exploit_by_vuln.values():
        if not _is_verified_report_finding(t):
            continue
        for item in t.get("data_extracted", []):
            item_str = str(item)
            if any(kw in item_str.lower() for kw in ("password", "passwd", "cred", "login", "user", "key", "token")):
                creds_rows.append(f"| {t.get('device_id','')} | (see evidence) | {item_str[:80].replace('|','/')} | - | Phase 4 |")
    sec63 = (
        "### 6.3 Credentials Recovered\n\n"
        "| Source | Username | Password/Key | Access Level | Retrieved From |\n"
        "|--------|----------|--------------|--------------|----------------|\n"
        + ("\n".join(creds_rows) if creds_rows else "| — | No credentials extracted | | | |")
    )

    # Write prefill file
    prefill = "\n\n".join([sec5, "## 6. Exploitation Results (Phase 4)\n\n" + sec61, sec62, sec63])
    prefill_path = run_dir / "06_report_prefill.md"
    prefill_path.write_text(prefill, encoding="utf-8")
    print(f"  [prefill] 06_report_prefill.md ({prefill_path.stat().st_size:,} bytes, {len(sec5_rows)} verified vulns)")

def merge_report_with_prefill(
    run_dir: Path, run_context: dict, *, model: str,
    validate_report: Callable[[str], tuple[bool, str]],
) -> None:
    """Replace {{SECTION_5_TABLE}} / {{SECTION_6_TABLES}} placeholders in 06_report.md
    with the deterministically-generated tables from 06_report_prefill.md.

    This lets the LLM produce a lightweight ~1500-token narrative report using
    placeholders, while Python injects the full 100+ row tables afterwards.
    Also works as a fallback: if the LLM never saved the report at all,
    generate a minimal report from the prefill data so the pipeline never exits
    without a deliverable.
    """
    report_path = run_dir / "06_report.md"
    prefill_path = run_dir / "06_report_prefill.md"

    if not prefill_path.exists():
        return

    prefill = prefill_path.read_text(encoding="utf-8")

    if report_path.exists():
        content = report_path.read_text(encoding="utf-8")
        # If the file only contains a sentinel (max turns reached), treat it as absent
        if content.strip() in {"(max turns reached)", "(malformed tool call JSON — max retries)"}:
            report_path.unlink()
        else:
            valid, validation_error = validate_report("06_report.md")
            if not valid:
                log.warning(
                    "Phase 6 report invalid before merge (%s) — using deterministic fallback",
                    validation_error,
                )
                report_path.unlink()
            else:
                merged = content.replace("{{SECTION_5_TABLE}}", prefill).replace("{{SECTION_6_TABLES}}", "")
                if merged != content:
                    report_path.write_text(merged, encoding="utf-8")
                    print(f"  [merge] Injected prefill tables into 06_report.md ({report_path.stat().st_size:,} bytes)")
                return

    # Fallback: LLM never saved the report — build a complete one from prefill + context
    context_path = run_dir / "06_phase6_context.json"
    ctx: dict = {}
    if context_path.exists():
        ctx = json.loads(context_path.read_text(encoding="utf-8"))
    analysis_context = build_report_analysis_context(run_dir)
    graph_context = analysis_context.get("graph", {})
    recon_context = analysis_context.get("recon", {})
    intrusion_context = analysis_context.get("intrusion", {})

    run_date = datetime.now().astimezone().date().isoformat()
    n_devices = ctx.get("device_count", "?")
    n_vulns = ctx.get("total_vulnerabilities", "?")
    sev = ctx.get("severity_breakdown", {})
    p4 = ctx.get("phase4_summary", {})
    confirmed = p4.get("confirmed", "?")
    phase4_path = run_dir / "04_exploitation.json"
    if phase4_path.exists():
        try:
            phase4_data = json.loads(phase4_path.read_text(encoding="utf-8"))
            confirmed = sum(
                1 for test in phase4_data.get("tests", [])
                if _is_verified_report_finding(test)
            )
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    not_exploitable = p4.get("not_exploitable", 0)
    errors = p4.get("errors", 0)
    n_crit = sev.get("CRITICAL", 0)
    n_high = sev.get("HIGH", 0)
    overall_risk = (
        "CRITICAL" if n_crit else "HIGH" if n_high else
        "MEDIUM" if sev.get("MEDIUM", 0) else "LOW"
    )
    executed_phases = ["1", "2", "3", "4"]
    if (run_dir / "05_intrusion.json").exists():
        executed_phases.append("5")
    else:
        executed_phases.append("5 skipped")
    executed_phases.append("6")
    executed_phase_text = " -> ".join(executed_phases)

    # Section 7 — Top critical attack paths from context
    critical_findings = ctx.get("top_critical_findings", [])
    sec7_rows = "\n".join(
        f"| {f.get('device_id','?')} ({f.get('device_ip','?')}) "
        f"| {f.get('type','?')} | {f.get('service','?')} "
        f"| {f.get('title','?')[:70]} |"
        for f in critical_findings[:10]
    )
    intrusion_summary = intrusion_context.get("summary", {})
    compromised = intrusion_context.get("compromised_devices", [])
    sec73_rows = "\n".join(
        f"| {device.get('device_id', device.get('device', '?'))} "
        f"| {device.get('device_ip', device.get('ip', '?'))} "
        f"| {device.get('access_method', device.get('service', '?'))} |"
        for device in compromised
        if isinstance(device, dict)
    )
    sec7 = (
        "## 7. Attack Paths\n\n"
        "| Device | Vuln Type | Service | Description |\n"
        "|--------|-----------|---------|-------------|\n"
        + (sec7_rows if sec7_rows else "| — | — | — | No critical findings |\n")
        + "\n\n### 7.3 Infiltration Campaign\n\n"
        + "| Metric | Value |\n|--------|-------|\n"
        + f"| Devices attempted | {intrusion_summary.get('devices_attempted', intrusion_summary.get('devices_targeted', 0))} |\n"
        + f"| Devices compromised | {intrusion_summary.get('devices_compromised', len(compromised))} |\n"
        + f"| Credentials harvested | {intrusion_summary.get('credentials_harvested', 0)} |\n"
        + f"| Crown jewels reached | {intrusion_summary.get('crown_jewels_reached', 0)} |\n\n"
        + "| Compromised device | IP | Access |\n|--------------------|----|--------|\n"
        + (sec73_rows if sec73_rows else "| — | — | No successful compromise recorded |")
    )

    # Section 8 — Top devices by risk score
    top_devs = ctx.get("top_devices_by_risk", [])
    sec8_rows = "\n".join(
        f"| {d.get('device_id','?')} | {d.get('device_ip','?')} "
        f"| {d.get('risk_score','?')} "
        f"| C={d.get('severity_counts',{}).get('CRITICAL',0)} "
        f"H={d.get('severity_counts',{}).get('HIGH',0)} "
        f"M={d.get('severity_counts',{}).get('MEDIUM',0)} |"
        for d in top_devs[:10]
    )
    sec8 = (
        "## 8. Risk Scores (Top Devices)\n\n"
        "| Device | IP | Score | Breakdown |\n"
        "|--------|----|-------|-----------|\n"
        + (sec8_rows if sec8_rows else "| — | — | — | — |\n")
    )

    # Section 9 — Remediation by severity
    sec9 = (
        "## 9. Remediation Recommendations\n\n"
        "### 9.1 IMMEDIATE (CRITICAL)\n\n"
        f"Address all {n_crit} CRITICAL findings immediately, following the evidence and affected assets listed in Section 5.\n\n"
        "### 9.2 SHORT TERM (HIGH)\n\n"
        f"Address all {n_high} HIGH findings within 30 days, prioritised by confirmed exploitability and exposed assets.\n\n"
        "### 9.3 IMPROVEMENT (MEDIUM/LOW)\n\n"
        "Address MEDIUM and LOW findings according to the evidence in Section 5; apply service-specific hardening only to observed services and configurations.\n"
    )

    # Section 10 — CVE list
    cve_list = ctx.get("cve_list", [])
    sec10 = "## 10. Appendices\n\n"
    if cve_list:
        sec10 += "### CVEs identified\n\n" + "\n".join(f"- {c}" for c in sorted(cve_list)) + "\n\n"
    sec10 += "All raw tool outputs are saved in `tool_calls.jsonl` in the run directory.\n"
    analysis_path = run_dir / "06_report_analysis.md"
    if analysis_path.exists():
        model_analysis = analysis_path.read_text(encoding="utf-8").strip()
        if model_analysis:
            sec10 += (
                "\n### 10.3 Additional Model Analysis\n\n"
                + model_analysis
                + "\n"
            )

    topology_rows = "\n".join(
        f"| {node.get('id', node.get('name', '?'))} | {node.get('ip', '?')} "
        f"| {node.get('type', '?')} | {node.get('role', '?')} |"
        for node in (graph_context.get("nodes") or [])
        if isinstance(node, dict)
    )
    sec3 = (
        "## 3. Topology and Attack Surface\n\n"
        f"Declared topology: {graph_context.get('node_count', 0)} nodes, "
        f"{graph_context.get('edge_count', 0)} edges and "
        f"{graph_context.get('service_count', 0)} declared services.\n\n"
        "| Device | IP | Type | Role |\n|--------|----|------|------|\n"
        + (topology_rows if topology_rows else "| — | — | — | No graph evidence |")
    )
    recon_rows = "\n".join(
        "| {device} | {ip} | {ports} | {services} |".format(
            device=row.get("device") or "undocumented",
            ip=row.get("ip", "?"),
            ports=",".join(str(port) for port in row.get("open_ports", [])) or "none observed",
            services=", ".join(
                f"{svc.get('service', '?')}:{svc.get('port', '?')}"
                + (f" {svc.get('version')}" if svc.get("version") else "")
                for svc in row.get("services", [])
                if isinstance(svc, dict)
            ) or "none observed",
        )
        for row in (recon_context.get("devices") or [])
        if isinstance(row, dict)
    )
    sec4 = (
        "## 4. Reconnaissance Results\n\n"
        f"Live reconnaissance discovered {recon_context.get('device_count', 0)} devices. "
        "Observed services below come from the deterministic Phase 2 evidence projection.\n\n"
        "| Device | IP | Open Ports | Observed Services |\n"
        "|--------|----|------------|-------------------|\n"
        + (recon_rows if recon_rows else "| — | — | — | No live service evidence |")
    )

    fallback = (
        f"# Pentest Report — NATO Smart City IoT Lab\n\n"
        f"**Date:** {run_date}  **Model:** {model}\n\n"
        f"---\n\n"
        f"## 1. Executive Summary\n\n"
        f"| Metric | Value |\n|--------|-------|\n"
        f"| Devices scanned | {n_devices} |\n"
        f"| Vulnerabilities found | {n_vulns} |\n"
        f"| Critical | {n_crit} |\n"
        f"| High | {n_high} |\n"
        f"| Confirmed exploitable | {confirmed} |\n"
        f"| Not exploitable | {not_exploitable} |\n"
        f"| Errors | {errors} |\n"
        f"| Overall risk level | **{overall_risk}** |\n\n"
        f"The assessment identified **{n_vulns} canonical findings** across "
        f"{n_devices} assessed devices, including {n_crit} CRITICAL findings. "
        f"Phase 4 confirmed {confirmed} findings. Consult the evidence-linked "
        f"tables and raw candidate registry before remediation decisions.\n\n"
        f"## 2. Scope and Methodology\n\n"
        f"- **Target subnet:** {run_context.get('target_subnet', 'see topology')}\n"
        f"- **Phases executed:** {executed_phase_text}\n"
        f"- **Tools used:** see tool_calls.jsonl for the authoritative executed-tool ledger\n\n"
        f"{sec3}\n\n"
        f"{sec4}\n\n"
        f"{prefill}\n\n"
        f"{sec7}\n\n"
        f"{sec8}\n\n"
        f"{sec9}\n\n"
        f"{sec10}"
    )
    report_path.write_text(fallback, encoding="utf-8")
    print(f"  [fallback] 06_report.md generated from prefill ({report_path.stat().st_size:,} bytes)")
