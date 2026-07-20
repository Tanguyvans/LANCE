"""Annotate a remote run snapshot with Git compatibility information."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable


class CompatibilityError(RuntimeError):
    """Raised when a snapshot cannot be annotated safely."""


def _git(repo_root: Path, *args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CompatibilityError(f"Git command failed: git {' '.join(args)}") from exc


def _numstat(
    repo_root: Path,
    source_commit: str,
    paths: Iterable[str],
) -> dict[str, Any]:
    output = _git(repo_root, "diff", "--numstat", f"{source_commit}..HEAD", "--", *paths)
    added = 0
    deleted = 0
    for line in output.splitlines():
        fields = line.split("\t", 2)
        if len(fields) < 2 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        added += int(fields[0])
        deleted += int(fields[1])
    return {
        "changed": bool(added or deleted),
        "lines_added": added,
        "lines_deleted": deleted,
    }


def annotate_snapshot(snapshot_dir: Path) -> dict[str, Any]:
    """Add per-run source/current Git deltas to a snapshot manifest."""
    snapshot_dir = Path(snapshot_dir)
    manifest_path = snapshot_dir / "remote_snapshot_manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise CompatibilityError(f"Snapshot manifest not found: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CompatibilityError(f"Invalid snapshot manifest: {manifest_path}") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("runs"), list):
        raise CompatibilityError("Invalid remote snapshot manifest schema")

    repo_root = Path(__file__).resolve().parents[2]
    current_commit = _git(repo_root, "rev-parse", "HEAD")
    ground_truth_unchanged = 0
    for run in manifest["runs"]:
        if not isinstance(run, dict):
            raise CompatibilityError("Invalid run entry in snapshot manifest")
        source_short = str(run.get("source_commit") or "")
        scenario_id = str(run.get("scenario") or "").removeprefix("S")
        try:
            source_commit = _git(repo_root, "rev-parse", source_short)
            compatibility = {
                "available": True,
                "source_commit": source_commit,
                "current_commit": current_commit,
                "ground_truth": _numstat(
                    repo_root,
                    source_commit,
                    [f"benchmarks/ground_truth/scenario_{scenario_id}.yaml"],
                ),
                "evaluator": _numstat(
                    repo_root,
                    source_commit,
                    ["src/benchmark/evaluator.py", "src/agent/vuln_taxonomy.py"],
                ),
                "pipeline": _numstat(
                    repo_root,
                    source_commit,
                    ["src/agent/pipeline.py", "src/agent/prompts", "src/agent/tools"],
                ),
                "learning_reference": "current evaluator with strict-v2 policy",
            }
            if not compatibility["ground_truth"]["changed"]:
                ground_truth_unchanged += 1
        except CompatibilityError:
            compatibility = {
                "available": False,
                "source_commit": source_short or None,
                "current_commit": current_commit,
                "learning_reference": "current evaluator with strict-v2 policy",
            }
        run["git_compatibility"] = compatibility

    manifest["compatibility_summary"] = {
        "current_commit": current_commit,
        "runs_checked": len(manifest["runs"]),
        "runs_with_unchanged_ground_truth": ground_truth_unchanged,
        "learning_reference": "current evaluator with strict-v2 policy",
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest["compatibility_summary"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        summary = annotate_snapshot(args.snapshot_dir)
    except CompatibilityError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
