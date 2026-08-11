#!/usr/bin/env python3
"""Compose one manually authored Scenario Lab specification.

The command writes only under output/generated_scenarios/ by default and never
updates the official scenarios, topologies or Ground Truth files.

Usage:
    python3 benchmarks/tools/compose_custom.py path/to/scenario.yaml
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.benchmark.scenario_generator import ScenarioGenerator
from src.benchmark.scenario_spec import ScenarioSpecError, load_scenario_spec


def main() -> None:
    parser = argparse.ArgumentParser(description="Compose a manual Scenario Lab bundle")
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()

    try:
        spec = load_scenario_spec(args.scenario)
        generator = ScenarioGenerator(args.repo_root)
        result = generator.compose_custom(spec)
    except (ScenarioSpecError, ValueError) as exc:
        raise SystemExit(f"scenario composition failed: {exc}") from exc

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
