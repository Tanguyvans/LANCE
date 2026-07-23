"""Deliverable validators — one function per validator name."""
from __future__ import annotations

import json
from pathlib import Path

OUTPUT_DIR = Path("output/agent")


def validate_default(filename: str) -> tuple[bool, str]:
    """Check that the file exists and is non-empty."""
    path = OUTPUT_DIR / filename
    if not path.exists():
        return False, f"Deliverable '{filename}' not found"
    if path.stat().st_size == 0:
        return False, f"Deliverable '{filename}' is empty"
    return True, "OK"


def validate_markdown_with_sections(filename: str) -> tuple[bool, str]:
    """Check markdown file has at least 2 heading sections (##)."""
    ok, msg = validate_default(filename)
    if not ok:
        return ok, msg
    content = (OUTPUT_DIR / filename).read_text(encoding="utf-8")
    headings = [line for line in content.splitlines() if line.startswith("## ")]
    if len(headings) < 2:
        return False, f"Expected at least 2 '## ' sections, found {len(headings)}"
    return True, "OK"


def _section(content: str, heading_prefix: str, next_prefix: str | None) -> str:
    """Return one numbered Markdown section for structural validation."""
    start = content.find(heading_prefix)
    if start < 0:
        return ""
    if next_prefix is None:
        return content[start:]
    end = content.find(next_prefix, start + len(heading_prefix))
    return content[start:] if end < 0 else content[start:end]


def _table_data_rows(section: str) -> list[str]:
    rows = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or all(not cell or set(cell) <= {"-", ":"} for cell in cells):
            continue
        if cells[0].lower() in {"device", "metric", "finding", "ip", "rank", "#"}:
            continue
        rows.append(stripped)
    return rows


def _phase4_summary_is_all_errors(filename: str = "04_exploitation.json") -> tuple[bool, str]:
    path = OUTPUT_DIR / filename
    if not path.is_file():
        return False, ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        return True, f"Phase 4 artifact is invalid: {exc}"
    summary = data.get("summary", {}) if isinstance(data, dict) else {}
    try:
        total = int(summary.get("total_tested", 0) or 0)
        confirmed = int(summary.get("confirmed", 0) or 0)
        failed = int(summary.get("not_exploitable", 0) or 0)
        errors = int(summary.get("errors", 0) or 0)
    except (TypeError, ValueError):
        return True, "Phase 4 summary contains non-numeric counters"
    if total > 0 and confirmed == 0 and failed == 0 and errors >= total:
        return True, "Phase 4 produced only ERROR results"
    return False, ""


def validate_recon_markdown(filename: str) -> tuple[bool, str]:
    """Require the complete Recon structure and at least two discovered devices."""
    ok, msg = validate_default(filename)
    if not ok:
        return ok, msg
    content = (OUTPUT_DIR / filename).read_text(encoding="utf-8")
    required = ("## 1. Summary", "## 2. Discovered Services per Device", "## 3. Key Findings")
    missing = [heading for heading in required if heading not in content]
    if missing:
        return False, f"Missing Recon sections: {missing}"
    service_section = _section(content, required[1], required[2])
    rows = _table_data_rows(service_section)
    if len(rows) < 2:
        return False, f"Expected at least 2 discovered-device rows, found {len(rows)}"
    if len(content.strip()) < 600:
        return False, f"Recon deliverable is implausibly short ({len(content.strip())} chars)"
    return True, "OK"


def validate_report_markdown(filename: str) -> tuple[bool, str]:
    """Require all report sections and deterministic-table placeholders."""
    ok, msg = validate_default(filename)
    if not ok:
        return ok, msg
    content = (OUTPUT_DIR / filename).read_text(encoding="utf-8")
    # Sections 5 and 6 are represented by placeholders until the deterministic
    # post-processing merge injects their complete tables.
    required = [f"## {number}." for number in (1, 2, 3, 4, 7, 8, 9, 10)]
    missing = [prefix for prefix in required if prefix not in content]
    if missing:
        return False, f"Missing report sections: {missing}"
    placeholders = ("{{SECTION_5_TABLE}}", "{{SECTION_6_TABLES}}")
    missing_placeholders = [value for value in placeholders if value not in content]
    if missing_placeholders:
        return False, f"Missing report placeholders: {missing_placeholders}"
    if len(content.strip()) < 1500:
        return False, f"Report is implausibly short ({len(content.strip())} chars)"
    return True, "OK"


def validate_final_report_markdown(filename: str) -> tuple[bool, str]:
    """Validate the post-merge report rather than the LLM draft contract."""
    ok, msg = validate_default(filename)
    if not ok:
        return ok, msg
    content = (OUTPUT_DIR / filename).read_text(encoding="utf-8")
    required = [f"## {number}." for number in range(1, 11)]
    missing = [prefix for prefix in required if prefix not in content]
    if missing:
        return False, f"Missing final report sections: {missing}"
    unresolved = [
        value for value in ("{{SECTION_5_TABLE}}", "{{SECTION_6_TABLES}}")
        if value in content
    ]
    if unresolved:
        return False, f"Unresolved report placeholders: {unresolved}"
    if "[Omit this line" in content or "[omit this line" in content.lower():
        return False, "Report contains unresolved analyst memo instructions"
    phase4_broken, phase4_msg = _phase4_summary_is_all_errors()
    if phase4_broken:
        return False, phase4_msg
    if "Phases executed:** 1 → 2 → 3 → 4 → 5 → 6" in content and not (OUTPUT_DIR / "05_intrusion.json").exists():
        return False, "Report claims Phase 5 executed but 05_intrusion.json is missing"
    if len(content.strip()) < 1500:
        return False, f"Final report is implausibly short ({len(content.strip())} chars)"
    return True, "OK"


def _validate_json_with_key(
    filename: str, key: str, expect_list: bool = False
) -> tuple[bool, str]:
    """Check JSON file is valid and contains a required key."""
    ok, msg = validate_default(filename)
    if not ok:
        return ok, msg
    content = (OUTPUT_DIR / filename).read_text(encoding="utf-8")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"
    if key not in data:
        return False, f"Missing '{key}' key"
    if expect_list and not isinstance(data[key], list):
        return False, f"'{key}' must be an array"
    return True, "OK"


def _validate_unique_ids(filename: str, collection: str, id_field: str) -> tuple[bool, str]:
    """Require stable, non-empty unique IDs for cross-phase correlation."""
    ok, msg = _validate_json_with_key(filename, collection, expect_list=True)
    if not ok:
        return ok, msg
    data = json.loads((OUTPUT_DIR / filename).read_text(encoding="utf-8"))
    seen: set[str] = set()
    for index, item in enumerate(data[collection]):
        if not isinstance(item, dict):
            return False, f"'{collection}[{index}]' must be an object"
        value = str(item.get(id_field, "")).strip()
        if not value:
            return False, f"'{collection}[{index}].{id_field}' must be non-empty"
        if value in seen:
            return False, f"Duplicate {id_field}: {value}"
        seen.add(value)
    return True, "OK"


def validate_json_device_vulns(filename: str) -> tuple[bool, str]:
    """Require a per-device envelope instead of accepting any JSON object."""
    ok, msg = _validate_json_with_key(filename, "vulnerabilities", expect_list=True)
    if not ok:
        return ok, msg
    data = json.loads((OUTPUT_DIR / filename).read_text(encoding="utf-8"))
    for index, finding in enumerate(data["vulnerabilities"]):
        if not isinstance(finding, dict):
            return False, f"'vulnerabilities[{index}]' must be an object"
    return True, "OK"


def validate_json_vuln_queue(filename: str) -> tuple[bool, str]:
    """Check Phase 3 IDs and the strict-v3 structural artifact contract."""
    ok, msg = _validate_unique_ids(filename, "vulnerabilities", "id")
    if not ok:
        return ok, msg
    data = json.loads((OUTPUT_DIR / filename).read_text(encoding="utf-8"))
    required = {"service", "port", "protocol", "endpoint", "product", "version"}
    for index, finding in enumerate(data["vulnerabilities"]):
        missing = required - set(finding)
        if missing:
            return False, f"'vulnerabilities[{index}]' missing structural fields: {sorted(missing)}"
        port = finding.get("port")
        if port not in (None, "") and (isinstance(port, bool) or not isinstance(port, int) or not 0 < port <= 65535):
            return False, f"'vulnerabilities[{index}].port' must be an integer in 1..65535 or null"
        if str(finding.get("protocol", "")).casefold() not in {"", "tcp", "udp"}:
            return False, f"'vulnerabilities[{index}].protocol' must be tcp, udp, or empty"
        for field in ("service", "endpoint", "product", "version"):
            if not isinstance(finding.get(field), str):
                return False, f"'vulnerabilities[{index}].{field}' must be a string"
    return True, "OK"


def validate_json_exploitation(filename: str) -> tuple[bool, str]:
    """Check Phase 4 tests have unique references to Phase 3 findings."""
    ok, msg = _validate_unique_ids(filename, "tests", "vuln_id")
    if not ok:
        return ok, msg
    data = json.loads((OUTPUT_DIR / filename).read_text(encoding="utf-8"))
    valid_statuses = {"CONFIRMED", "FAILED", "ERROR"}
    for index, test in enumerate(data.get("tests", [])):
        status = str(test.get("status", "")).upper()
        if status not in valid_statuses:
            return False, f"'tests[{index}].status' must be one of {sorted(valid_statuses)}"
        evidence = str(test.get("evidence", ""))
        if evidence == "No Phase 4 exploit result was produced":
            return False, "Missing per-vulnerability Phase 4 exploit result"
    phase4_broken, phase4_msg = _phase4_summary_is_all_errors(filename)
    if phase4_broken:
        return False, phase4_msg
    return True, "OK"


def validate_json_exploit_result(filename: str) -> tuple[bool, str]:
    """Validate a single exploit result JSON file (04_exploits/**/*.json)."""
    ok, msg = validate_default(filename)
    if not ok:
        return ok, msg
    content = (OUTPUT_DIR / filename).read_text(encoding="utf-8")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"
    required_keys = {"vuln_id", "device_id", "status"}
    missing = required_keys - set(data.keys())
    if missing:
        return False, f"Missing keys: {missing}"
    if not str(data.get("vuln_id", "")).strip():
        return False, "'vuln_id' must be non-empty"
    valid_statuses = {"EXPLOITED", "FAILED", "ERROR"}
    if data["status"] not in valid_statuses:
        return False, f"Invalid status '{data['status']}', expected one of {valid_statuses}"
    return True, "OK"


def validate_json_valid(filename: str) -> tuple[bool, str]:
    """Check that the file exists and contains valid JSON."""
    ok, msg = validate_default(filename)
    if not ok:
        return ok, msg
    try:
        json.loads((OUTPUT_DIR / filename).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON in '{filename}': {e}"
    return True, "OK"


VALIDATORS = {
    "default": validate_default,
    "markdown_with_sections": validate_markdown_with_sections,
    "recon_markdown": validate_recon_markdown,
    "report_markdown": validate_report_markdown,
    "final_report_markdown": validate_final_report_markdown,
    "json_device_vulns": validate_json_device_vulns,
    "json_vuln_queue": validate_json_vuln_queue,
    "json_exploitation": validate_json_exploitation,
    "json_exploit_result": validate_json_exploit_result,
    "json_valid": validate_json_valid,
}
