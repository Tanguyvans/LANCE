"""Deliverable validators — one function per validator name."""
from __future__ import annotations

import json
from pathlib import Path

from src.agent.artifacts import resolve_run_artifact


def validate_default(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Check that the file exists and is non-empty."""
    try:
        path = resolve_run_artifact(output_dir, filename)
    except (ValueError, OSError, RuntimeError):
        return False, "Deliverable path must stay inside its run directory"
    if not path.is_file():
        return False, f"Deliverable '{filename}' not found"
    if path.stat().st_size == 0:
        return False, f"Deliverable '{filename}' is empty"
    return True, "OK"


def validate_markdown_with_sections(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Check markdown file has at least 2 heading sections (##)."""
    ok, msg = validate_default(filename, output_dir=output_dir)
    if not ok:
        return ok, msg
    content = resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8")
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


def _phase4_summary_is_all_errors(filename: str = "04_exploitation.json", *, output_dir: Path) -> tuple[bool, str]:
    try:
        path = resolve_run_artifact(output_dir, filename)
    except (ValueError, OSError, RuntimeError):
        return True, "Phase 4 artifact path must stay inside its run directory"
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


def validate_recon_markdown(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Require the complete Recon structure and at least two discovered devices."""
    ok, msg = validate_default(filename, output_dir=output_dir)
    if not ok:
        return ok, msg
    content = resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8")
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


def validate_report_markdown(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Require all report sections and deterministic-table placeholders."""
    ok, msg = validate_default(filename, output_dir=output_dir)
    if not ok:
        return ok, msg
    content = resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8")
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


def validate_final_report_markdown(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Validate the post-merge report rather than the LLM draft contract."""
    ok, msg = validate_default(filename, output_dir=output_dir)
    if not ok:
        return ok, msg
    content = resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8")
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
    phase4_broken, phase4_msg = _phase4_summary_is_all_errors(output_dir=output_dir)
    if phase4_broken:
        return False, phase4_msg
    if "Phases executed:** 1 → 2 → 3 → 4 → 5 → 6" in content:
        try:
            intrusion_exists = resolve_run_artifact(output_dir, "05_intrusion.json").is_file()
        except (ValueError, OSError, RuntimeError):
            intrusion_exists = False
        if not intrusion_exists:
            return False, "Report claims Phase 5 executed but 05_intrusion.json is missing"
    if len(content.strip()) < 1500:
        return False, f"Final report is implausibly short ({len(content.strip())} chars)"
    return True, "OK"


def _validate_json_with_key(
    filename: str, key: str, expect_list: bool = False, *, output_dir: Path
) -> tuple[bool, str]:
    """Check JSON file is valid and contains a required key."""
    ok, msg = validate_default(filename, output_dir=output_dir)
    if not ok:
        return ok, msg
    content = resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"
    if key not in data:
        return False, f"Missing '{key}' key"
    if expect_list and not isinstance(data[key], list):
        return False, f"'{key}' must be an array"
    return True, "OK"


def _validate_unique_ids(filename: str, collection: str, id_field: str, *, output_dir: Path) -> tuple[bool, str]:
    """Require stable, non-empty unique IDs for cross-phase correlation."""
    ok, msg = _validate_json_with_key(filename, collection, expect_list=True, output_dir=output_dir)
    if not ok:
        return ok, msg
    data = json.loads(resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8"))
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


def validate_json_device_vulns(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Require a per-device envelope instead of accepting any JSON object."""
    ok, msg = _validate_json_with_key(filename, "vulnerabilities", expect_list=True, output_dir=output_dir)
    if not ok:
        return ok, msg
    data = json.loads(resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8"))
    for index, finding in enumerate(data["vulnerabilities"]):
        if not isinstance(finding, dict):
            return False, f"'vulnerabilities[{index}]' must be an object"
    return True, "OK"


def validate_json_vuln_queue(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Check Phase 3 IDs and the strict-v3 structural artifact contract."""
    ok, msg = _validate_unique_ids(filename, "vulnerabilities", "id", output_dir=output_dir)
    if not ok:
        return ok, msg
    data = json.loads(resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8"))
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


def validate_json_exploitation(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Check Phase 4 tests have unique references to Phase 3 findings."""
    ok, msg = _validate_unique_ids(filename, "tests", "vuln_id", output_dir=output_dir)
    if not ok:
        return ok, msg
    data = json.loads(resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8"))
    valid_statuses = {"CONFIRMED", "FAILED", "ERROR", "SKIPPED"}
    for index, test in enumerate(data.get("tests", [])):
        status = str(test.get("status", "")).upper()
        if status not in valid_statuses:
            return False, f"'tests[{index}].status' must be one of {sorted(valid_statuses)}"
        evidence = str(test.get("evidence", ""))
        if status != "SKIPPED" and evidence == "No Phase 4 exploit result was produced":
            return False, "Missing per-vulnerability Phase 4 exploit result"
    phase4_broken, phase4_msg = _phase4_summary_is_all_errors(filename, output_dir=output_dir)
    if phase4_broken:
        return False, phase4_msg
    return True, "OK"


def validate_json_exploit_result(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Validate a single exploit result JSON file (04_exploits/**/*.json)."""
    ok, msg = validate_default(filename, output_dir=output_dir)
    if not ok:
        return ok, msg
    content = resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8")
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


def validate_json_valid(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Check that the file exists and contains valid JSON."""
    ok, msg = validate_default(filename, output_dir=output_dir)
    if not ok:
        return ok, msg
    try:
        json.loads(resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON in '{filename}': {e}"
    return True, "OK"


def _intrusion_structure_error(path: str, reason: str) -> tuple[bool, str]:
    """Return a structural error without echoing deliverable values."""
    return False, f"Invalid intrusion structure at '{path}': {reason}"


def _non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _non_negative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def validate_json_intrusion(filename: str, *, output_dir: Path) -> tuple[bool, str]:
    """Validate the structural contract for the Phase 5 intrusion artifact.

    This validator deliberately checks shape and internal counters only. It
    does not establish that an access, pivot, command, credential, or crown
    jewel was proven by the network or by an evidence evaluator.
    """
    ok, msg = validate_default(filename, output_dir=output_dir)
    if not ok:
        return ok, msg

    def reject_non_json_constant(_value: str):
        raise ValueError("Non-standard JSON constant")

    try:
        data = json.loads(
            resolve_run_artifact(output_dir, filename).read_text(encoding="utf-8"),
            parse_constant=reject_non_json_constant,
        )
    except (OSError, TypeError, ValueError):
        return _intrusion_structure_error("$", "must contain valid JSON")

    if not isinstance(data, dict):
        return _intrusion_structure_error("$", "must be a JSON object")

    rejected_statuses = {
        "incomplete",
        "partial",
        "failed",
        "error",
        "draft",
        "raw_non_validated",
        "blocked", "stopped", "budget_exceeded",
    }
    if "status" in data:
        if not isinstance(data["status"], str):
            return _intrusion_structure_error("status", "must be a string when present")
        if data["status"].strip().casefold() in rejected_statuses:
            return _intrusion_structure_error("status", "is not promotable")
    if "completion" in data:
        completion = data["completion"]
        if not isinstance(completion, dict):
            return _intrusion_structure_error("completion", "must be an object")
        if "status" in completion:
            status = completion["status"]
            if not isinstance(status, str) or status.strip().casefold() != "completed":
                return _intrusion_structure_error("completion.status", "is not promotable")

    required_top_level = {
        "summary",
        "credential_pool",
        "compromised_devices",
        "chains",
    }
    missing = required_top_level - set(data)
    if missing:
        return _intrusion_structure_error("$", "missing required fields")

    summary = data["summary"]
    if not isinstance(summary, dict):
        return _intrusion_structure_error("summary", "must be an object")

    required_summary = {
        "devices_compromised",
        "devices_attempted",
        "credentials_harvested",
        "total_hops",
        "crown_jewels_reached",
    }
    if required_summary - set(summary):
        return _intrusion_structure_error("summary", "missing required fields")
    for field in (
        "devices_compromised",
        "devices_attempted",
        "credentials_harvested",
        "total_hops",
    ):
        if not _non_negative_integer(summary[field]):
            return _intrusion_structure_error(
                f"summary.{field}", "must be a non-negative integer"
            )
    if not isinstance(summary["crown_jewels_reached"], list):
        return _intrusion_structure_error(
            "summary.crown_jewels_reached", "must be a list"
        )
    for index, identifier in enumerate(summary["crown_jewels_reached"]):
        if not _non_empty_string(identifier):
            return _intrusion_structure_error(
                f"summary.crown_jewels_reached[{index}]",
                "must be a non-empty string",
            )

    credential_pool = data["credential_pool"]
    if not isinstance(credential_pool, list):
        return _intrusion_structure_error("credential_pool", "must be a list")
    credential_fields = ("user", "password", "service", "source_ip", "source_device")
    for index, credential in enumerate(credential_pool):
        path = f"credential_pool[{index}]"
        if not isinstance(credential, dict):
            return _intrusion_structure_error(path, "must be an object")
        if any(field not in credential for field in credential_fields):
            return _intrusion_structure_error(path, "missing required fields")
        if not isinstance(credential["user"], str):
            return _intrusion_structure_error(f"{path}.user", "must be a string")
        if not isinstance(credential["password"], str):
            return _intrusion_structure_error(
                f"{path}.password", "must be a string"
            )
        service = credential["service"]
        if service is not None and not _non_empty_string(service):
            return _intrusion_structure_error(
                f"{path}.service", "must be a non-empty string or null"
            )
        for field in ("source_ip", "source_device"):
            if not isinstance(credential[field], str):
                return _intrusion_structure_error(
                    f"{path}.{field}", "must be a string"
                )

    compromised_devices = data["compromised_devices"]
    if not isinstance(compromised_devices, list):
        return _intrusion_structure_error(
            "compromised_devices", "must be a list"
        )
    device_ids: set[str] = set()
    device_fields = (
        "device_id",
        "device_ip",
        "access_method",
        "access_via",
        "credentials_found",
        "data_exfiltrated",
    )
    for index, device in enumerate(compromised_devices):
        path = f"compromised_devices[{index}]"
        if not isinstance(device, dict):
            return _intrusion_structure_error(path, "must be an object")
        if any(field not in device for field in device_fields):
            return _intrusion_structure_error(path, "missing required fields")
        for field in ("device_id", "device_ip", "access_method", "access_via"):
            if not _non_empty_string(device[field]):
                return _intrusion_structure_error(
                    f"{path}.{field}", "must be a non-empty string"
                )
        if not isinstance(device["credentials_found"], list):
            return _intrusion_structure_error(
                f"{path}.credentials_found", "must be a list"
            )
        for credential_index, found in enumerate(device["credentials_found"]):
            if not isinstance(found, dict):
                return _intrusion_structure_error(
                    f"{path}.credentials_found[{credential_index}]",
                    "must be an object",
                )
        if not isinstance(device["data_exfiltrated"], str):
            return _intrusion_structure_error(
                f"{path}.data_exfiltrated", "must be a string"
            )
        device_id = device["device_id"]
        if device_id in device_ids:
            return _intrusion_structure_error(
                f"{path}.device_id", "must be unique"
            )
        device_ids.add(device_id)

    chains = data["chains"]
    if not isinstance(chains, list):
        return _intrusion_structure_error("chains", "must be a list")
    chain_ids: set[str] = set()
    transitions = 0
    for chain_index, chain in enumerate(chains):
        path = f"chains[{chain_index}]"
        if not isinstance(chain, dict):
            return _intrusion_structure_error(path, "must be an object")
        if any(field not in chain for field in ("id", "hops", "crown_jewel_reached")):
            return _intrusion_structure_error(path, "missing required fields")
        if not _non_empty_string(chain["id"]):
            return _intrusion_structure_error(f"{path}.id", "must be a non-empty string")
        if chain["id"] in chain_ids:
            return _intrusion_structure_error(f"{path}.id", "must be unique")
        chain_ids.add(chain["id"])
        if chain["crown_jewel_reached"] is not None and not _non_empty_string(
            chain["crown_jewel_reached"]
        ):
            return _intrusion_structure_error(
                f"{path}.crown_jewel_reached", "must be a non-empty string or null"
            )
        hops = chain["hops"]
        if not isinstance(hops, list) or not hops:
            return _intrusion_structure_error(f"{path}.hops", "must be a non-empty list")
        transitions += max(0, len(hops) - 1)
        hop_fields = (
            "hop_index",
            "device_id",
            "device_ip",
            "access_method",
            "commands_run",
            "output_summary",
            "pivot_to",
        )
        for hop_position, hop in enumerate(hops):
            hop_path = f"{path}.hops[{hop_position}]"
            if not isinstance(hop, dict):
                return _intrusion_structure_error(hop_path, "must be an object")
            if any(field not in hop for field in hop_fields):
                return _intrusion_structure_error(hop_path, "missing required fields")
            if not _positive_integer(hop["hop_index"]):
                return _intrusion_structure_error(
                    f"{hop_path}.hop_index", "must be a positive integer"
                )
            if hop["hop_index"] != hop_position + 1:
                return _intrusion_structure_error(
                    f"{hop_path}.hop_index", "must be contiguous and 1-based"
                )
            for field in ("device_id", "device_ip", "access_method"):
                if not _non_empty_string(hop[field]):
                    return _intrusion_structure_error(
                        f"{hop_path}.{field}", "must be a non-empty string"
                    )
            if not isinstance(hop["commands_run"], list):
                return _intrusion_structure_error(
                    f"{hop_path}.commands_run", "must be a list"
                )
            if any(not isinstance(command, str) for command in hop["commands_run"]):
                return _intrusion_structure_error(
                    f"{hop_path}.commands_run", "must contain only strings"
                )
            if not isinstance(hop["output_summary"], str):
                return _intrusion_structure_error(
                    f"{hop_path}.output_summary", "must be a string"
                )
            pivot_to = hop["pivot_to"]
            if pivot_to is not None and not _non_empty_string(pivot_to):
                return _intrusion_structure_error(
                    f"{hop_path}.pivot_to", "must be a non-empty string or null"
                )

    if summary["devices_compromised"] != len(device_ids):
        return _intrusion_structure_error(
            "summary.devices_compromised",
            "must equal the number of compromised device identifiers",
        )
    if summary["devices_attempted"] < summary["devices_compromised"]:
        return _intrusion_structure_error(
            "summary.devices_attempted",
            "must be greater than or equal to devices_compromised",
        )
    if summary["total_hops"] != transitions:
        return _intrusion_structure_error(
            "summary.total_hops",
            "must equal the number of chain transitions",
        )
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
    "json_intrusion": validate_json_intrusion,
}
