"""Derived labelling index for the scenario corpus.

Reads the ground-truth files (benchmarks/ground_truth/{dev,test}/) and
computes, for every expected vulnerability, the experimental axes used
to draw pilot/campaign sets:

- type: "logique" when the category is an authorization/logic class,
  otherwise "signature";
- chainage: hop_depth as recorded in the ground truth (decoupled from
  scenario size);
- surface / bruit: "base" / "none" unless an alteration manifest says
  otherwise (see --alterations);
- protocole: "connu" by default; the corpus encodes no unknown protocol.

Nothing here writes to the catalogue or to the ground truth: the output
is a generated sidecar (benchmarks/labels/derived_index.json by default)
that can be regenerated identically, with a SHA-256 of every source.

Usage:
    python -m src.benchmark.derived_index
    python -m src.benchmark.derived_index --output /tmp/index.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import yaml

# Categories whose detection requires reasoning about authorization or
# application logic (who may do what, on which object, in which state),
# as opposed to matching a known technical signature.
LOGIC_CATEGORIES = frozenset({"broken_access_control", "auth_bypass"})

_REPO_ROOT = Path(__file__).resolve().parents[2]
GT_DIRS = (
    _REPO_ROOT / "benchmarks" / "ground_truth" / "dev",
    _REPO_ROOT / "benchmarks" / "ground_truth" / "test",
)
DEFAULT_OUTPUT = _REPO_ROOT / "benchmarks" / "labels" / "derived_index.json"


def derive_type(category: object) -> str:
    """Map a ground-truth category to the signature/logique axis."""
    return "logique" if category in LOGIC_CATEGORIES else "signature"


def build_index(gt_dirs=GT_DIRS, alterations: dict | None = None) -> dict:
    """Compute the derived index from ground-truth directories.

    ``alterations`` optionally maps an instance key "<scenario_id>" to
    {"surface": ..., "bruit": ...} as actually applied at deployment;
    defaults are surface="base" and bruit="none".
    """
    alterations = alterations or {}
    entries: list[dict] = []
    sources: dict[str, str] = {}
    scenario_count = 0
    for gt_dir in gt_dirs:
        for path in sorted(Path(gt_dir).glob("scenario_*.yaml")):
            raw = path.read_bytes()
            try:
                source_key = str(path.relative_to(_REPO_ROOT))
            except ValueError:
                source_key = path.name
            sources[source_key] = hashlib.sha256(raw).hexdigest()
            data = yaml.safe_load(raw) or {}
            scenario_id = str(data.get("scenario_id", path.stem.removeprefix("scenario_")))
            scenario_count += 1
            applied = alterations.get(scenario_id, {})
            for vuln in data.get("vulnerabilities") or []:
                hop = vuln.get("hop_depth", 0)
                entries.append({
                    "scenario_id": scenario_id,
                    "vuln_id": vuln.get("id"),
                    "device": vuln.get("device"),
                    "category": vuln.get("category"),
                    "severity": vuln.get("severity"),
                    "type": derive_type(vuln.get("category")),
                    "chainage": hop if isinstance(hop, int) else 0,
                    "surface": applied.get("surface", "base"),
                    "bruit": applied.get("bruit", "none"),
                    "protocole": applied.get("protocole", "connu"),
                })
    entries.sort(key=lambda e: (e["scenario_id"], str(e["vuln_id"])))
    return {
        "schema_version": 1,
        "generated_by": "src.benchmark.derived_index",
        "logic_categories": sorted(LOGIC_CATEGORIES),
        "summary": {
            "scenarios": scenario_count,
            "vulnerabilities": len(entries),
            "by_type": dict(sorted(Counter(e["type"] for e in entries).items())),
            "by_category": dict(sorted(Counter(e["category"] for e in entries).items())),
            "by_chainage": dict(sorted(
                Counter(str(e["chainage"]) for e in entries).items())),
        },
        "sources_sha256": sources,
        "entries": entries,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--alterations", type=Path, default=None,
                        help="Optional JSON mapping scenario_id -> applied axes")
    args = parser.parse_args(argv)
    alterations = None
    if args.alterations is not None:
        alterations = json.loads(args.alterations.read_text(encoding="utf-8"))
    index = build_index(alterations=alterations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(index["summary"], indent=2, ensure_ascii=False))
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
