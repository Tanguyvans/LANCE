#!/usr/bin/env python3
"""Add or validate canonical ``expected_type`` fields in benchmark GT files.

The editor is deliberately line-preserving: it inserts one scalar field into
each vulnerability block without reserializing the surrounding YAML.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml


BENCHMARKS_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BENCHMARKS_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.benchmark.evaluator import expected_type_for_vulnerability


def _vulnerability_blocks(lines: list[str]) -> list[tuple[int, int]]:
    try:
        section_start = next(
            index for index, line in enumerate(lines) if line == "vulnerabilities:\n"
        )
    except StopIteration as exc:
        raise ValueError("missing top-level vulnerabilities section") from exc

    section_end = len(lines)
    for index in range(section_start + 1, len(lines)):
        line = lines[index]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_-]*:", line):
            section_end = index
            break

    starts = [
        index
        for index in range(section_start + 1, section_end)
        if re.match(r"^(?:  )?- id:", lines[index])
    ]
    return [
        (start, starts[position + 1] if position + 1 < len(starts) else section_end)
        for position, start in enumerate(starts)
    ]


def annotate(path: Path, *, write: bool) -> tuple[int, int]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("vulnerabilities must be a list")
    if not vulnerabilities:
        return 0, 0

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    blocks = _vulnerability_blocks(lines)
    if len(blocks) != len(vulnerabilities):
        raise ValueError(
            f"parsed {len(vulnerabilities)} vulnerabilities but found "
            f"{len(blocks)} YAML blocks"
        )

    insertions: list[tuple[int, str]] = []
    checked = 0
    for vulnerability, (start, end) in zip(vulnerabilities, blocks):
        item_indent = lines[start][:-len(lines[start].lstrip(" "))]
        field_indent = item_indent + "  "
        category_lines = [
            index
            for index in range(start, end)
            if lines[index].startswith(f"{field_indent}category:")
        ]
        expected_lines = [
            index
            for index in range(start, end)
            if lines[index].startswith(f"{field_indent}expected_type:")
        ]
        vuln_id = vulnerability.get("id", "?")
        if len(category_lines) != 1:
            raise ValueError(f"{vuln_id}: expected exactly one category field")
        if len(expected_lines) > 1:
            raise ValueError(f"{vuln_id}: duplicate expected_type fields")
        if expected_lines:
            # Explicit annotations are authoritative; only validate that they
            # are canonical. This permits human-reviewed overrides for
            # semantically combined vulnerabilities.
            expected_type_for_vulnerability(vulnerability)
        else:
            expected = expected_type_for_vulnerability(vulnerability)
            insertions.append(
                (category_lines[0] + 1, f"{field_indent}expected_type: {expected}\n")
            )
        checked += 1

    if write and insertions:
        for index, line in reversed(insertions):
            lines.insert(index, line)
        path.write_text("".join(lines), encoding="utf-8")
    return checked, len(insertions)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add or validate strict-v3 expected_type GT annotations"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="GT YAML files (default: all ground_truth/scenario_*.yaml)",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="insert missing fields; without this flag the command is check-only",
    )
    args = parser.parse_args()

    paths = args.paths or sorted(
        (BENCHMARKS_ROOT / "ground_truth").glob("scenario_*.yaml")
    )
    changes_total = 0
    checked_total = 0
    for path in paths:
        checked, changes = annotate(path, write=args.write)
        checked_total += checked
        changes_total += changes
        if changes:
            state = "updated" if args.write else "changes required"
        else:
            state = "ok"
        print(f"{path}: {state} ({checked} vulnerabilities, {changes} changes)")

    if changes_total and not args.write:
        raise SystemExit(
            f"{changes_total} expected_type changes are required; rerun with --write"
        )
    print(f"validated {checked_total} vulnerabilities across {len(paths)} files")


if __name__ == "__main__":
    main()
