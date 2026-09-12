"""Compose a deterministic report projection from run-local evidence.

The generated note is a presentation artifact: it preserves Phase 3
declarations, selected Phase 4-supported declarations, raw Phase 5 output and
source mappings without turning them into a unique-vulnerability count or a
new proof/evaluation system.
"""
from __future__ import annotations
import json
import logging
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from src.agent.report_evidence import (
    is_verified_report_finding as _is_verified_report_finding,
    report_phase4_summary,
)
from src.agent.phases.report.grouping import group_findings_for_report
from src.agent.phases.report.traceability import ReportTraceIndex
from src.agent.vuln_taxonomy import VULN_TYPE_ALIASES


log = logging.getLogger(__name__)


def _read_full_json(run_dir: Path, filename: str) -> dict:
    path = run_dir / filename
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _full_report_sources(run_dir: Path) -> dict:
    """Load complete sources for deterministic rendering, never prompt data."""
    return {
        "graph": _read_full_json(run_dir, "01_graph_evidence.json"),
        "recon": _read_full_json(run_dir, "02_recon_evidence.json"),
        "intrusion": _read_full_json(run_dir, "05_intrusion.json"),
        "phase3_status": _read_full_json(run_dir, "03_phase3_status.json"),
    }


def _display_text(value, *, limit: int, source: str) -> str:
    """Keep tables readable while making every presentation omission explicit."""
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}… [truncated; full value in {source}]"


def _table_cell(value, *, limit: int = 160, source: str = "report artifact") -> str:
    """Make a value safe for one Markdown table cell without hiding its shape."""

    return (
        _display_text(value, limit=limit, source=source)
        .replace("|", r"\|")
        .replace("\r\n", "<br>")
        .replace("\r", "<br>")
        .replace("\n", "<br>")
    )


def _list_cell(value, *, limit: int = 160, source: str = "report artifact") -> str:
    """Render scalar/list values as a compact, escaped table cell."""

    if isinstance(value, (list, tuple, set, frozenset)):
        value = "; ".join(str(item) for item in value)
    return _table_cell(value or "—", limit=limit, source=source)


_TYPE_ALIASES = {
    str(alias).casefold(): canonical
    for alias, canonical in VULN_TYPE_ALIASES.items()
}


def _canonical_type(value: object) -> str:
    raw = str(value or "").strip().casefold()
    return _TYPE_ALIASES.get(raw, raw)


def _declaration_nature(finding: dict) -> str:
    """Classify by the explicit vulnerability taxonomy, never by proof level."""

    raw_type = str(finding.get("type", finding.get("vuln_type")) or "").strip().casefold()
    # Legacy aliases collapse uploads/SSRF into code_injection, not evidence of execution.
    if raw_type in {"ssrf", "server_side_request_forgery", "file_upload_endpoint",
                    "unrestricted_file_upload", "arbitrary_file_upload"}:
        return "other"
    finding_type = _canonical_type(raw_type)
    if finding_type in {"misconfiguration", "weak_cipher", "missing_header", "insecure_update", "terrapin"}:
        return "configuration"
    if finding_type == "data_exposure":
        return "data access"
    if finding_type in {
        "directory_listing", "info_disclosure", "network_exposure",
        "insecure_protocol", "version_leak",
    }:
        return "exposure"
    if finding_type in {"no_auth", "default_credentials", "broken_access_control", "privilege_escalation"}:
        return "access"
    if finding_type == "code_injection":
        return "claimed code execution"
    return "other"


def _status_label(value: object) -> str:
    status = str(value or "UNTESTED").upper()
    return {
        "CONFIRMED": "Phase 4-supported declaration",
        "FAILED": "Phase 4 test recorded failure",
        "ERROR": "Phase 4 test error/inconclusive",
        "TIMEOUT": "Phase 4 test timeout",
        "SKIPPED": "Phase 4 test skipped",
        "NOT_TESTED": "No Phase 4 test recorded",
        "UNTESTED": "Phase 3 hypothesis; no Phase 4 observation",
    }.get(status, f"Phase 4 recorded state: {status}")


def _declared_data(test: dict) -> str:
    value = test.get("data_extracted")
    if not value:
        return "No data declaration"
    return _list_cell(value, limit=160, source="04_exploitation.json")


def _credential_usability(test: dict) -> str:
    if test.get("credential_used") is True or test.get("used_to_compromise") is True:
        return "Declared used by source record; not independently revalidated"
    return "Not established; data declaration alone is insufficient"


def _evidence_refs(test: dict) -> str:
    refs = test.get("evidence_refs")
    if isinstance(refs, (list, tuple, set, frozenset)):
        refs = "; ".join(str(ref) for ref in refs if str(ref).strip())
    return _table_cell(refs or "No references listed", source="04_exploitation.json")


def _count_declared(value: object, items: list[dict]) -> int | str:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return len(items)


def _available_artifacts(run_dir: Path) -> str:
    artifacts = (
        ("01_graph_evidence.json", "graph evidence"),
        ("02_recon_evidence.json", "recon evidence"),
        ("03_vuln_analysis.json", "Phase 3 declarations"),
        ("03_phase3_status.json", "Phase 3 status"),
        ("04_exploitation.json", "Phase 4 records"),
        ("05_intrusion.json", "raw Phase 5 declarations"),
        ("tool_calls.jsonl", "tool ledger"),
    )
    available = [label for filename, label in artifacts if (run_dir / filename).exists()]
    return ", ".join(available) or "no phase artifact available"


def _device_failure_rows(value: object) -> tuple[int, str]:
    if isinstance(value, list):
        rows = []
        for item in value:
            if isinstance(item, dict):
                device = item.get("device_id", item.get("device_ip", item.get("device", "unknown device")))
                cause = item.get("cause", item.get("error", item.get("reason", "unspecified failure")))
                rows.append(f"{_table_cell(device)}: {_table_cell(cause, limit=180)}")
            else:
                rows.append(_table_cell(item, limit=180))
        return len(value), "<br>".join(rows) or "none recorded"
    if isinstance(value, int) and not isinstance(value, bool):
        return value, "details not present in phase status artifact"
    if value:
        return 1, _table_cell(value, limit=180)
    return 0, "none recorded"


def pregenerate_report_sections(run_dir: Path) -> None:
    """Pre-generate bounded report tables without creating new metrics.

    The prefill is a deterministic presentation layer.  Its Phase 4 table uses
    the existing report-evidence selection policy; it does not re-evaluate
    proofs, ground truth, exploitability, or uniqueness.
    """
    # Load phase 3 vulnerabilities
    vuln_path = run_dir / "03_vuln_analysis.json"
    phase3_vulns: list[dict] = []
    compact_observations: list[dict] = []
    if vuln_path.exists():
        data = json.loads(vuln_path.read_text(encoding="utf-8"))
        phase3_vulns = data.get("vulnerabilities", [])
        compact_observations = data.get("configuration_observations", [])

    # Load phase 4 exploitation results
    exploit_path = run_dir / "04_exploitation.json"
    exploit_by_vuln: dict[str, dict] = {}
    phase4_summary: dict = {}
    if exploit_path.exists():
        data = json.loads(exploit_path.read_text(encoding="utf-8"))
        phase4_summary = report_phase4_summary(data.get("summary", {}), data.get("tests", []))
        for t in data.get("tests", []):
            vid = t.get("vuln_id", "")
            if vid:
                exploit_by_vuln[vid] = t

    trace_index = ReportTraceIndex(run_dir)

    # --- Section 5: separate Phase 3 hypotheses from Phase 4 observations ---
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulns = sorted(
        phase3_vulns,
        key=lambda v: (
            sev_order.get((v.get("severity") or "LOW").upper(), 9),
            str(v.get("device_ip") or ""),
        ),
    )
    supported_rows: list[tuple[dict, dict]] = []
    for v in sorted_vulns:
        vid = v.get("id", "")
        exploit = exploit_by_vuln.get(vid, {})
        if not _is_verified_report_finding(exploit):
            continue
        supported_rows.append((v, exploit))

    hypothesis_rows = "\n".join(
        f"| {_table_cell(v.get('id', ''), source='03_vuln_analysis.json')} "
        f"| {_table_cell(v.get('device_id', ''))} ({_table_cell(v.get('device_ip', ''))}) "
        f"| {_table_cell(_declaration_nature(v))} "
        f"| {_table_cell(v.get('type', ''))} "
        f"| {_table_cell((v.get('severity') or '').upper())} "
        f"| {_table_cell(v.get('service', ''))}:{_table_cell(v.get('port', ''))} "
        f"| {_table_cell(v.get('details') or 'No Phase 3 hypothesis text', limit=180, source='03_vuln_analysis.json')} |"
        for v, _ in supported_rows
    )
    observation_rows = "\n".join(
        f"| {_table_cell(v.get('id', ''), source='03_vuln_analysis.json')} "
        f"| {_table_cell(_status_label(test.get('status')))} "
        f"| {_table_cell(test.get('evidence') or 'No Phase 4 observation text', limit=220, source='04_exploitation.json')} "
        f"| {_table_cell(test.get('evidence_level', '—'), source='04_exploitation.json')} "
        f"| {_evidence_refs(test)} "
        f"| {_table_cell(trace_index.describe(test), limit=220, source='tool_calls.jsonl')} |"
        for v, test in supported_rows
    )
    sec5 = (
        "## 5. Phase 4-supported declarations\n\n"
        "The current selection criterion is unchanged: only Phase 3 declarations "
        "whose recorded Phase 4 state is `CONFIRMED` with evidence level >= 2 "
        "enter these tables. This label is not proof of equivalence, uniqueness, "
        "or a benchmark result.\n\n"
        "### 5.1 Phase 3 hypotheses represented\n\n"
        "| ID | Device | Declaration nature | Type | Severity | Service:port | Phase 3 hypothesis |\n"
        "|----|--------|--------------------|------|----------|--------------|--------------------|\n"
        + (hypothesis_rows or "| — | — | — | — | — | — | No selected Phase 3 hypothesis |")
        + "\n\n### 5.2 Phase 4 observations and reference diagnostics\n\n"
        "The observation and references below are recorded fields. A reference "
        "diagnostic does not accept the security property or proof.\n\n"
        "| ID | Recorded Phase 4 state | Phase 4 observation | Evidence level | Raw evidence_refs | Reference diagnostic (not proof acceptance) |\n"
        "|----|------------------------|---------------------|----------------|-------------------|---------------------------------------------|\n"
        + (observation_rows or "| — | — | — | — | — | No selected Phase 4 observation |")
    )

    if compact_observations:
        observation_rows = []
        for observation in compact_observations:
            title = (
                observation.get("details")
                or observation.get("evidence")
                or ""
            )
            title = _display_text(
                title, limit=120, source="03_vuln_analysis.json"
            )
            observation_rows.append(
                f"| {_table_cell(observation.get('id', ''), source='03_vuln_analysis.json')} | "
                f"{_table_cell(observation.get('device_id', ''))} "
                f"({_table_cell(observation.get('device_ip', ''))}) | "
                f"{_table_cell(_declaration_nature(observation))} | "
                f"{_table_cell(observation.get('type', ''))} | "
                f"{_table_cell((observation.get('severity') or '').upper())} | "
                f"{_table_cell(title, source='03_vuln_analysis.json')} |"
            )
        sec5 += (
            "\n\n### 5.3 Phase 3 configuration observations (not Phase 4 evidence)\n\n"
            "| ID | Device | Nature | Type | Severity | Observation |\n"
            "|----|--------|--------|------|----------|-------------|\n"
            + "\n".join(observation_rows)
        )

    # --- Section 6.1: Exploitation summary ---
    total_tested = phase4_summary.get("total_tested", "not recorded")
    confirmed = sum(1 for t in exploit_by_vuln.values() if _is_verified_report_finding(t))
    unverified_confirmed = sum(
        1
        for t in exploit_by_vuln.values()
        if str(t.get("status", "")).upper() == "CONFIRMED"
        and not _is_verified_report_finding(t)
    )
    inconclusive = phase4_summary.get("inconclusive", phase4_summary.get("not_exploitable", 0))
    errors = phase4_summary.get("errors", 0)
    sec61 = (
        "### 6.1 Phase 4 recorded results\n\n"
        "| Metric | Value |\n|--------|-------|\n"
        f"| Tests reported by Phase 4 | {total_tested} |\n"
        f"| Phase 4-supported declarations (evidence >= 2) | {confirmed} |\n"
        f"| Unsupported confirmations excluded | {unverified_confirmed} |\n"
        f"| Inconclusive attempts (not refutations) | {inconclusive} |\n"
        f"| Errors | {errors} |"
    )
    nature_counts = Counter(_declaration_nature(v) for v, _ in supported_rows)
    sec61 += (
        "\n\nNature is the declared property, not a capability verdict. Neither an "
        "evidence level nor a severity establishes code execution. Counts are "
        "declarations, not unique flaws, benchmark VP/FP or compromised targets.\n\n"
        "| Declared property | Selected declarations |\n|-------------------|-----------------------|\n"
        + ("\n".join(f"| {nature} | {count} |" for nature, count in sorted(nature_counts.items()))
           or "| — | 0 |")
    )

    # --- Section 6.2: Exploitation details (confirmed only, keep table manageable) ---
    confirmed_tests = [t for t in exploit_by_vuln.values() if _is_verified_report_finding(t)]
    sec62_rows = []
    for t in confirmed_tests:
        sec62_rows.append(
            f"| {_table_cell(t.get('vuln_id',''))} | {_table_cell(t.get('device_id',''))} "
            f"| {_table_cell(t.get('vuln_type',''))} | {_table_cell(t.get('tool_used','-'))} "
            f"| Phase 4-supported | {_table_cell(t.get('evidence_level',1))} | {_declared_data(t)} |"
        )
    sec62 = (
        "### 6.2 Phase 4 data declarations (evidence level ≥ 2)\n\n"
        "Data below is declared by Phase 4; it is not independently revalidated by this renderer.\n\n"
        "| Test ID | Device | Vuln Type | Tool Used | Status | Evidence Level | Declared data |\n"
        "|---------|--------|-----------|-----------|--------|----------------|----------------|\n"
        + ("\n".join(sec62_rows) if sec62_rows else "| — | No selected Phase 4 declaration | | | | | |")
    )

    creds_rows = [
        f"| {_table_cell(t.get('vuln_id',''))} | {_credential_usability(t)} |"
        for t in confirmed_tests if t.get("data_extracted")
    ]
    sec63 = (
        "### 6.3 Credential usability is separate\n\n"
        "Words such as user, password or key in retrieved data do not prove a usable "
        "credential or a successful login. The renderer does not infer either.\n\n"
        "| Source test | Usability diagnostic |\n|-------------|----------------------|\n"
        + ("\n".join(creds_rows) if creds_rows else "| — | No credential usability established |")
    )

    # Report-only groups preserve every hypothesis and do not change scoring
    # identity, the verification queue, or the phase artifacts.
    groups = group_findings_for_report(phase3_vulns)
    grouping = {
        "schema": "report_grouping_v1", "purpose": "presentation_only",
        "hypothesis_count": len(phase3_vulns), "group_count": len(groups),
        "groups": groups,
        "note": "Possible duplicates require review; groups are not unique vulnerability counts or scoring predictions.",
    }
    (run_dir / "06_report_groups.json").write_text(
        json.dumps(grouping, indent=2, ensure_ascii=False), encoding="utf-8",
    )
    related_rows = []
    for group in groups:
        if not group["possible_duplicate"]:
            continue
        members = []
        for index in group["member_indices"]:
            member = phase3_vulns[index]
            vid = member.get("id") or f"row {index + 1} (missing ID)"
            test = exploit_by_vuln.get(vid, {})
            members.append(f"{vid} ({test.get('status', 'UNTESTED')})")
        related_rows.append(f"| {group['group_id']} | {_table_cell('; '.join(members), limit=1000, source='06_report_groups.json')} | review possible duplicate declarations |")
    sec5 += (
        "\n\n### 5.4 Related declarations — possible duplicates\n\n"
        "These are report-only groupings on a shared target, service and property, "
        "not proven equivalence. All member IDs and their individual results remain "
        "available. VP/FP/FN, precision, recall, F1 and verification coverage are unchanged. "
        "Severity totals and priority indices count declarations, not unique flaws. "
        "Complete mapping: `06_report_groups.json`.\n\n"
        "| Group | Members and Phase 4 states | Interpretation |\n"
        "|-------|----------------------------|----------------|\n"
        + ("\n".join(related_rows) or "| — | — | No possible duplicate group identified |")
    )

    # Write prefill file
    prefill = "\n\n".join([sec5, "## 6. Verification Results (Phase 4)\n\n" + sec61, sec62, sec63])
    prefill_path = run_dir / "06_report_prefill.md"
    prefill_path.write_text(prefill, encoding="utf-8")
    print(f"  [prefill] 06_report_prefill.md ({prefill_path.stat().st_size:,} bytes, {len(supported_rows)} supported declarations)")

def merge_report_with_prefill(
    run_dir: Path, run_context: dict, *, model: str,
    validate_report: Callable[[str], tuple[bool, str]],
    analysis_status: str | None = None,
    analysis_cause: str | None = None,
) -> None:
    """Replace {{SECTION_5_TABLE}} / {{SECTION_6_TABLES}} placeholders in 06_report.md
    with the deterministically-generated tables from 06_report_prefill.md.

    The normal Phase 6 entry point always builds a fresh deterministic report
    and appends only the optional analyst note. Placeholder replacement remains
    solely for legacy callers; report existence is never an execution verdict.
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
    full_sources = _full_report_sources(run_dir)
    graph_context = full_sources["graph"]
    recon_context = full_sources["recon"]
    intrusion_context = full_sources["intrusion"]
    phase3_status = full_sources["phase3_status"]

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
    inconclusive = p4.get("inconclusive", p4.get("not_exploitable", 0))
    errors = p4.get("errors", 0)
    n_crit = sev.get("CRITICAL", 0)
    n_high = sev.get("HIGH", 0)
    highest_severity = (
        "CRITICAL" if n_crit else "HIGH" if n_high else
        "MEDIUM" if sev.get("MEDIUM", 0) else "LOW" if sev.get("LOW", 0)
        else "not established (no supported declaration)"
    )
    available_artifacts = _available_artifacts(run_dir)

    # Section 7 — deterministic attack-surface evidence.  Phase 5 is kept as
    # raw declarations: this renderer must not turn model/tool claims into
    # validated compromises or reconstructed pivots.
    critical_findings = ctx.get("top_critical_findings", [])
    sec7_rows = "\n".join(
        f"| {f.get('device_id','?')} ({f.get('device_ip','?')}) "
        f"| {f.get('type','?')} | {f.get('service','?')} "
        f"| {_display_text(f.get('title','?'), limit=70, source='03_vuln_analysis.json')} |"
        for f in critical_findings[:10]
    )
    intrusion_summary = intrusion_context.get("summary", {})
    compromised = intrusion_context.get("compromised_devices", [])
    if not isinstance(compromised, list):
        compromised = []
    raw_credentials = intrusion_context.get("credential_pool", [])
    raw_crown_jewels = intrusion_context.get(
        "crown_jewels_reached", intrusion_summary.get("crown_jewels_reached", [])
    )
    if not isinstance(raw_credentials, list):
        raw_credentials = []
    if not isinstance(raw_crown_jewels, list):
        raw_crown_jewels = []
    sec73_rows = "\n".join(
        f"| {device.get('device_id', device.get('device', '?'))} "
        f"| {device.get('device_ip', device.get('ip', '?'))} "
        f"| {device.get('access_method', device.get('service', '?'))} "
        "| raw Phase 5 declaration; not independently validated |"
        for device in compromised
        if isinstance(device, dict)
    )
    sec7 = (
        "## 7. Intrusion declarations and attack-path limitations\n\n"
        "The following critical declarations are review priorities, not verified paths.\n\n"
        "| Device | Vuln Type | Service | Description |\n"
        "|--------|-----------|---------|-------------|\n"
        + (sec7_rows if sec7_rows else "| — | — | — | No critical findings |\n")
        + "\n\n### 7.3 Phase 5 raw declarations (non-validées)\n\n"
        + "Les éléments ci-dessous proviennent de `05_intrusion.json` et sont "
        "des déclarations brutes/non validées. Ils ne constituent pas une preuve "
        "de compromission et aucun pivot n’est reconstruit ici.\n\n"
        + "| Metric | Value |\n|--------|-------|\n"
        + f"| Devices attempted | {intrusion_summary.get('devices_attempted', intrusion_summary.get('devices_targeted', 0))} |\n"
        + f"| Devices declared compromised (raw) | {intrusion_summary.get('devices_compromised', len(compromised))} |\n"
        + f"| Credentials declared harvested (raw) | {intrusion_summary.get('credentials_harvested', len(raw_credentials) if isinstance(raw_credentials, list) else 0)} |\n"
        + f"| Crown jewels declared reached (raw) | {_count_declared(intrusion_summary.get('crown_jewels_reached'), raw_crown_jewels)} |\n\n"
        + "| Declared device (raw) | IP | Access declaration | Validation state |\n"
        + "|----------------------|----|--------------------|------------------|\n"
        + (sec73_rows if sec73_rows else "| — | — | No Phase 5 raw declaration | — |")
        + "\n\n### 7.3.a Raw credential declarations (non-validées)\n\n"
        + "| User | Service | Source | State |\n|------|---------|--------|-------|\n"
        + "\n".join(
            f"| {item.get('username', item.get('user', '—'))} | "
            f"{item.get('service', '—')} | {item.get('source', '05_intrusion.json')} "
            "| raw declaration; not independently validated |"
            for item in raw_credentials if isinstance(item, dict)
        )
        + ("" if raw_credentials else "| — | — | — | no raw credential declaration |")
        + "\n\n### 7.3.b Raw crown-jewel declarations (non-validées)\n\n"
        + "| Device | Access | Data declaration | State |\n|--------|--------|------------------|-------|\n"
        + "\n".join(
            f"| {item.get('device_id', item.get('device', '—'))} | "
            f"{item.get('access_method', item.get('service', '—'))} | "
            f"{_display_text(item.get('data', item.get('evidence', '—')), limit=160, source='05_intrusion.json').replace('|', '/')} "
            "| raw declaration; not independently validated |"
            for item in raw_crown_jewels if isinstance(item, dict)
        )
        + ("" if raw_crown_jewels else "| — | — | no raw crown-jewel declaration | — |")
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
        "## 8. Remediation priority indices (Top Devices)\n\n"
        "This priority index counts severity-weighted declarations (C×4, H×3, M×2, L×1), "
        "not unique flaws. It is not a benchmark score or an audit/intrusion composite.\n\n"
        "| Device | IP | Priority index | Declaration breakdown |\n"
        "|--------|----|-------|-----------|\n"
        + (sec8_rows if sec8_rows else "| — | — | — | — |\n")
    )

    # Section 9 — Remediation by severity
    critical_action = (
        f"Review and address the {n_crit} CRITICAL declarations with priority, following the evidence and affected assets in Section 5."
        if n_crit else "No CRITICAL declaration in the selected inventory; this does not establish absence of critical vulnerabilities."
    )
    high_action = (
        f"Review the {n_high} HIGH declarations and plan remediation according to demonstrated impact and exposed assets."
        if n_high else "No HIGH declaration in the selected inventory."
    )
    sec9 = (
        "## 9. Remediation Recommendations\n\n"
        "### 9.1 IMMEDIATE (CRITICAL)\n\n"
        f"{critical_action}\n\n"
        "### 9.2 SHORT TERM (HIGH)\n\n"
        f"{high_action}\n\n"
        "### 9.3 IMPROVEMENT (MEDIUM/LOW)\n\n"
        "Address MEDIUM and LOW findings according to the evidence in Section 5; apply service-specific hardening only to observed services and configurations.\n"
    )

    # Section 10 — CVE list
    cve_list = ctx.get("cve_list", [])
    sec10 = "## 10. Appendices\n\n"
    if cve_list:
        sec10 += "### CVEs identified\n\n" + "\n".join(f"- {c}" for c in sorted(cve_list)) + "\n\n"
    sec10 += "All raw tool outputs are saved in `tool_calls.jsonl` in the run directory.\n"
    source_observations = ReportTraceIndex(run_dir).ssh_source_observations()
    if source_observations:
        sec10 += (
            "\n### SSH connection source observations\n\n"
            "These addresses are reported SSH client sources in tool stdout, not an additional target "
            "inventory. They establish neither a compromised device, runner identity nor a network pivot.\n\n"
            "| Observed client source | Server from matching tool input | Reference |\n"
            "|------------------------|---------------------------------|-----------|\n"
            + "\n".join(
                f"| {_table_cell(item['client_source_ip'])} | {_table_cell(item['server_ip'])} | {_table_cell(item['evidence_ref'])} |"
                for item in source_observations
            ) + "\n"
        )
    analysis_path = run_dir / "06_report_analysis.md"
    analysis_heading = "### 10.3 Analyse du modèle (non validée)"
    if analysis_path.exists() and analysis_path.read_text(encoding="utf-8").strip():
        model_analysis = analysis_path.read_text(encoding="utf-8").strip()
        if model_analysis:
            sec10 += (
                f"\n{analysis_heading}\n\n"
                "Cette note est un complément analyste non validé. Elle ne crée "
                "aucune confirmation, aucun pivot et ne modifie pas les preuves, "
                "chiffres ou inventaires déterministes.\n\n"
                + model_analysis
                + "\n"
            )
    else:
        status = analysis_status or "unavailable"
        cause = analysis_cause or "memo_absent"
        outcome = "completed" if status == "usable" else (
            "stopped" if cause == "stopped" else (
                "budget_exceeded" if cause == "budget_exceeded" else f"partial:{cause}"
            )
        )
        sec10 += (
            f"\n{analysis_heading}\n\n"
            f"Aucune note analyste utilisable n’a été promue. Issue phase6: `{outcome}`. État: `{status}`. "
            f"Cause: `{cause}`. Le rapport déterministe et les artefacts complets "
            "restent la seule source des preuves et chiffres.\n"
        )

    topology_rows = "\n".join(
        f"| {node.get('id', node.get('name', '?'))} | {node.get('ip', '?')} "
        f"| {node.get('type', '?')} | {node.get('role', '?')} |"
        for node in (graph_context.get("nodes") or [])
        if isinstance(node, dict)
    )
    sec3 = (
        "## 3. Topology and Attack Surface\n\n"
        f"Declared topology counts — nodes: {graph_context.get('node_count', 'not recorded')}; "
        f"edges: {graph_context.get('edge_count', 'not recorded')}; "
        f"services: {graph_context.get('service_count', 'not recorded')}.\n\n"
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
        f"Live reconnaissance device count: {recon_context.get('device_count', 'not recorded')}. "
        "Observed services below come from the deterministic Phase 2 evidence projection.\n\n"
        "| Device | IP | Open Ports | Observed Services |\n"
        "|--------|----|------------|-------------------|\n"
        + (recon_rows if recon_rows else "| — | — | — | No live service evidence |")
    )
    scanner_errors = phase3_status.get("scanner_errors", [])
    device_failures, failure_details = _device_failure_rows(phase3_status.get("devices_failed", 0))
    phase3_limits = ""
    if scanner_errors or device_failures:
        phase3_limits = (
            "\n\n### Upstream execution limits\n\n"
            f"Phase 3 recorded {len(scanner_errors) if isinstance(scanner_errors, list) else 1} "
            f"scanner error(s) and {device_failures} device worker failure(s). "
            "These are execution limitations, not negative security findings; "
            "see `03_phase3_status.json` for the complete record."
            f"\n\nAffected device workers: {failure_details}"
        )

    fallback = (
        f"# Pentest Report — NATO Smart City IoT Lab\n\n"
        f"**Date:** {run_date}  **Model:** {model}\n\n"
        f"---\n\n"
        f"## 1. Executive Summary\n\n"
        f"| Metric | Value |\n|--------|-------|\n"
        f"| Devices in declared scope | {n_devices} |\n"
        f"| Live reconnaissance devices | {recon_context.get('device_count', 'not recorded')} |\n"
        f"| Selected declarations in inventory | {n_vulns} |\n"
        f"| Critical declarations | {n_crit} |\n"
        f"| High declarations | {n_high} |\n"
        f"| Phase 4-supported declarations | {confirmed} |\n"
        f"| Inconclusive attempts (not refutations) | {inconclusive} |\n"
        f"| Errors | {errors} |\n"
        f"| Highest declared severity | {highest_severity} |\n\n"
        f"The inventory contains {n_vulns} Phase 4-supported declarations within a "
        f"declared scope of {n_devices} devices. These are not unique vulnerabilities, "
        f"accepted benchmark proofs or confirmed machine compromises. Consult the "
        f"observations, reference diagnostics and raw candidate registry before remediation decisions.\n\n"
        f"## 2. Scope and Methodology\n\n"
        f"- **Target subnet:** {run_context.get('target_subnet', 'see topology')}\n"
        f"- **Artifacts available (not execution status):** {available_artifacts}\n"
        f"- **Tools used:** see tool_calls.jsonl for the authoritative executed-tool ledger\n\n"
        f"{sec3}\n\n"
        f"{sec4}{phase3_limits}\n\n"
        f"{prefill}\n\n"
        f"{sec7}\n\n"
        f"{sec8}\n\n"
        f"{sec9}\n\n"
        f"{sec10}"
    )
    report_path.write_text(fallback, encoding="utf-8")
    print(f"  [fallback] 06_report.md generated from prefill ({report_path.stat().st_size:,} bytes)")


def render_deterministic_report(
    run_dir: Path,
    run_context: dict,
    *,
    model: str,
    validate_report: Callable[[str], tuple[bool, str]],
    analysis_status: str,
    analysis_cause: str,
) -> None:
    """Render the new Phase 6 report from evidence, never from an old draft.

    The report path is an active projection, not an append-only evidence log.
    Removing it before rendering prevents a validated report from a resumed
    attempt from hiding a new timeout, stop, or rejected note. Historical
    ledgers and source artifacts are untouched.
    """
    report_path = run_dir / "06_report.md"
    if report_path.exists():
        report_path.unlink()
    merge_report_with_prefill(
        run_dir,
        run_context,
        model=model,
        validate_report=validate_report,
        analysis_status=analysis_status,
        analysis_cause=analysis_cause,
    )
