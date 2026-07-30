#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    path = ROOT / "benchmarks" / "external" / "manifest.yaml"
    manifest = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if manifest.get("status") not in {"draft-not-authorized", "frozen-authorized"}:
        raise SystemExit("invalid external manifest status")
    for suite, config in manifest.get("suites", {}).items():
        commit = str(config.get("commit", ""))
        if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
            raise SystemExit(f"{suite}: commit is not a full SHA-1")
        runlist = ROOT / str(config["runlist"])
        cases = [
            line.strip() for line in runlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        expected = int(config["expected_cases"])
        if len(cases) != expected or len(cases) != len(set(cases)):
            raise SystemExit(f"{suite}: expected {expected} unique cases, got {len(cases)}")
        if cases != sorted(cases):
            raise SystemExit(f"{suite}: runlist must be sorted")
        print(f"{suite}: {len(cases)} cases @ {commit}")


if __name__ == "__main__":
    main()
