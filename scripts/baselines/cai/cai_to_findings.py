"""Normalize CAI raw outputs in an existing run directory."""
from __future__ import annotations

import argparse
from pathlib import Path

from src.baselines.normalizer import normalize_tool_outputs, write_exploitation_results, write_vuln_analysis


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert CAI raw JSON files to evaluator format")
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--scenario", default=None)
    args = parser.parse_args()

    raw_dir = args.run_dir / "raw"
    outputs = [(None, p) for p in sorted(raw_dir.glob("*.json"))]
    scenario = args.scenario or args.run_dir.parent.name.replace("scenario_", "")
    findings = normalize_tool_outputs("cai", outputs)
    write_exploitation_results("cai", scenario, findings, args.run_dir)
    write_vuln_analysis("cai", scenario, findings, args.run_dir)
    print(args.run_dir / "04_exploitation.json")


if __name__ == "__main__":
    main()

