#!/usr/bin/env python3
"""Build reviewed strict-v3 matching contracts for public ground truths."""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.benchmark.strict_v3 import derive_matching_contract


ROOT = Path(__file__).resolve().parent.parent
GT_DIR = ROOT / "ground_truth"
DEFAULT_OUTPUT = GT_DIR / "matching_contracts.yaml"
PUBLIC_FIELDS = (
    "accepted_types", "services", "ports", "protocols", "endpoints", "products", "versions",
    "required_dimensions",
)


def build() -> dict:
    scenarios: dict[str, dict] = {}
    source_hashes: dict[str, str] = {}
    for path in sorted(GT_DIR.glob("scenario_*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        scenario_id = str(data.get("scenario_id", path.stem.removeprefix("scenario_")))
        source_hashes[scenario_id] = hashlib.sha256(path.read_bytes()).hexdigest()
        entries = {}
        for vulnerability in data.get("vulnerabilities", []) or []:
            vulnerability_id = str(vulnerability.get("id", "")).strip()
            if not vulnerability_id:
                raise ValueError(f"{path}: vulnerability without id")
            contract = derive_matching_contract(vulnerability)
            if not contract["accepted_types"]:
                raise ValueError(f"{path}:{vulnerability_id}: no accepted_types")
            entries[vulnerability_id] = {
                field: contract[field] for field in PUBLIC_FIELDS
            }
        scenarios[scenario_id] = entries
    return {"schema_version": "strict-v3.4", "source_hashes": source_hashes, "scenarios": scenarios}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = yaml.safe_dump(build(), sort_keys=False, allow_unicode=True)
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current != rendered:
            raise SystemExit(f"outdated strict-v3 contracts: {args.output}")
        return
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
