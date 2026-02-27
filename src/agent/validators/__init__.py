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


def validate_json_vuln_queue(filename: str) -> tuple[bool, str]:
    """Check JSON file is valid and has a 'vulnerabilities' key."""
    ok, msg = validate_default(filename)
    if not ok:
        return ok, msg
    content = (OUTPUT_DIR / filename).read_text(encoding="utf-8")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"
    if "vulnerabilities" not in data:
        return False, "Missing 'vulnerabilities' key"
    return True, "OK"


VALIDATORS = {
    "default": validate_default,
    "markdown_with_sections": validate_markdown_with_sections,
    "json_vuln_queue": validate_json_vuln_queue,
}
