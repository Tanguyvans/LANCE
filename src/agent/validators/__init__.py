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


def validate_json_vuln_queue(filename: str) -> tuple[bool, str]:
    """Check JSON file is valid and has a 'vulnerabilities' list."""
    return _validate_json_with_key(filename, "vulnerabilities", expect_list=True)


def validate_json_exploitation(filename: str) -> tuple[bool, str]:
    """Check JSON file is valid and has a 'tests' array."""
    return _validate_json_with_key(filename, "tests", expect_list=True)


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
    valid_statuses = {"EXPLOITED", "FAILED", "ERROR"}
    if data["status"] not in valid_statuses:
        return False, f"Invalid status '{data['status']}', expected one of {valid_statuses}"
    return True, "OK"


VALIDATORS = {
    "default": validate_default,
    "markdown_with_sections": validate_markdown_with_sections,
    "json_vuln_queue": validate_json_vuln_queue,
    "json_exploitation": validate_json_exploitation,
    "json_exploit_result": validate_json_exploit_result,
}
