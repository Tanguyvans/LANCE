#!/usr/bin/env python3
"""Synchronize canonical training code to an execution-only LANCE workspace.

The Tanguy workspace is the only Git source of truth. The Leo workspace receives
an explicit allowlist of small source/configuration files and returns only
allowlisted JSON reports. Datasets, environments, checkpoints and model weights
never cross this boundary through this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

CANONICAL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = CANONICAL_ROOT / "training" / "workspace_sync.json"
DEFAULT_REMOTE_ROOT = Path(
    os.environ.get("LANCE_TRAINING_WORKSPACE", "/home/leo/LANCE")
)
DEFAULT_REPORT_ROOT = CANONICAL_ROOT / "output" / "training-workspace" / "leo"
DEFAULT_ADAPTER_ROOT = CANONICAL_ROOT / "output" / "adapters" / "lance-qlora_moe_3b"


@dataclass(frozen=True)
class CopyOperation:
    source: Path
    destination: Path
    relative_path: Path
    status: str
    size_bytes: int
    sha256: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    required = {
        "schema_version",
        "push_files",
        "pull_report_globs",
        "pull_adapter_experts",
        "pull_adapter_files",
        "blocked_roots",
        "max_report_size_bytes",
        "max_total_report_size_bytes",
        "max_adapter_file_size_bytes",
        "max_total_adapter_size_bytes",
    }
    missing = sorted(required - set(manifest))
    if missing:
        raise ValueError(f"Sync manifest is missing: {', '.join(missing)}")
    if not isinstance(manifest["push_files"], list) or not manifest["push_files"]:
        raise ValueError("push_files must be a non-empty list")
    return manifest


def safe_relative_path(value: str | Path, blocked_roots: Iterable[str]) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError(f"Unsafe relative path: {value}")
    if relative.parts[0] in set(blocked_roots):
        raise ValueError(f"Blocked workspace root: {relative.parts[0]}")
    return relative


def contained_path(root: Path, relative: Path) -> Path:
    root = root.resolve()
    candidate = root.joinpath(relative)
    resolved_parent = candidate.parent.resolve()
    if not resolved_parent.is_relative_to(root):
        raise ValueError(f"Path escapes workspace root: {candidate}")
    if candidate.is_symlink():
        raise ValueError(f"Symbolic-link destination is forbidden: {candidate}")
    return candidate


def operation_for(source: Path, destination: Path, relative: Path) -> CopyOperation:
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"Source must be a regular file: {source}")
    source_hash = sha256_file(source)
    if destination.is_file() and not destination.is_symlink():
        destination_hash = sha256_file(destination)
        status = "unchanged" if destination_hash == source_hash else "update"
    else:
        status = "create"
    return CopyOperation(
        source=source,
        destination=destination,
        relative_path=relative,
        status=status,
        size_bytes=source.stat().st_size,
        sha256=source_hash,
    )


def build_push_plan(
    source_root: Path,
    remote_root: Path,
    manifest: dict,
) -> list[CopyOperation]:
    blocked = manifest["blocked_roots"]
    operations: list[CopyOperation] = []
    for value in manifest["push_files"]:
        relative = safe_relative_path(value, blocked)
        source = contained_path(source_root, relative)
        destination = contained_path(remote_root, relative)
        operations.append(operation_for(source, destination, relative))
    return operations


def build_pull_plan(
    remote_root: Path,
    report_root: Path,
    manifest: dict,
) -> list[CopyOperation]:
    max_file_size = int(manifest["max_report_size_bytes"])
    max_total_size = int(manifest["max_total_report_size_bytes"])
    matched: dict[Path, Path] = {}
    for pattern in manifest["pull_report_globs"]:
        for source in remote_root.glob(pattern):
            if not source.is_file() or source.is_symlink():
                continue
            relative = source.relative_to(remote_root)
            if source.suffix != ".json":
                raise ValueError(f"Only JSON reports may be collected: {relative}")
            matched[relative] = source

    operations: list[CopyOperation] = []
    total_size = 0
    for relative, source in sorted(matched.items()):
        size = source.stat().st_size
        if size > max_file_size:
            raise ValueError(
                f"Report exceeds {max_file_size} bytes: {relative} ({size} bytes)"
            )
        total_size += size
        if total_size > max_total_size:
            raise ValueError(
                f"Collected reports exceed {max_total_size} total bytes"
            )
        destination = contained_path(report_root, relative)
        operations.append(operation_for(source, destination, relative))
    return operations


def build_pull_adapter_plan(
    remote_root: Path,
    adapter_root: Path,
    manifest: dict,
) -> list[CopyOperation]:
    """Collect only complete final adapters, never checkpoints or training state."""
    experts = manifest["pull_adapter_experts"]
    filenames = manifest["pull_adapter_files"]
    if not isinstance(experts, list) or not experts or len(set(experts)) != len(experts):
        raise ValueError("pull_adapter_experts must be a non-empty unique list")
    if not isinstance(filenames, list) or not filenames or len(set(filenames)) != len(filenames):
        raise ValueError("pull_adapter_files must be a non-empty unique list")
    max_file_size = int(manifest["max_adapter_file_size_bytes"])
    max_total_size = int(manifest["max_total_adapter_size_bytes"])
    operations: list[CopyOperation] = []
    total_size = 0
    for expert in experts:
        expert_path = safe_relative_path(str(expert), ())
        if len(expert_path.parts) != 1:
            raise ValueError(f"Invalid adapter expert: {expert}")
        for filename in filenames:
            file_path = safe_relative_path(str(filename), ())
            if len(file_path.parts) != 1:
                raise ValueError(f"Invalid adapter filename: {filename}")
            source_relative = (
                Path("output/adapters/lance-qlora_moe_3b") / expert_path / file_path
            )
            source = contained_path(remote_root, source_relative)
            destination_relative = expert_path / file_path
            destination = contained_path(adapter_root, destination_relative)
            operation = operation_for(source, destination, destination_relative)
            if operation.size_bytes > max_file_size:
                raise ValueError(
                    f"Adapter file exceeds {max_file_size} bytes: "
                    f"{source_relative} ({operation.size_bytes} bytes)"
                )
            total_size += operation.size_bytes
            if total_size > max_total_size:
                raise ValueError(
                    f"Adapters exceed {max_total_size} total bytes"
                )
            operations.append(operation)
    return operations


def apply_plan(operations: Iterable[CopyOperation]) -> int:
    changed = 0
    for operation in operations:
        if operation.status == "unchanged":
            continue
        operation.destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = operation.destination.with_name(
            f".{operation.destination.name}.lance-sync-tmp"
        )
        if temporary.exists():
            temporary.unlink()
        shutil.copy2(operation.source, temporary)
        if sha256_file(temporary) != operation.sha256:
            temporary.unlink(missing_ok=True)
            raise RuntimeError(f"Hash mismatch while copying {operation.relative_path}")
        temporary.replace(operation.destination)
        changed += 1
    return changed


def git_provenance(root: Path) -> dict:
    def run(*args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    try:
        commit = run("rev-parse", "HEAD")
        branch = run("branch", "--show-current")
        dirty = bool(run("status", "--porcelain"))
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "branch": None, "dirty": None}
    return {"commit": commit, "branch": branch, "dirty": dirty}


def write_source_manifest(
    remote_root: Path,
    manifest_path: Path,
    operations: Iterable[CopyOperation],
) -> Path:
    destination = remote_root / "output" / "training-source-manifest.json"
    payload = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "canonical_workspace": str(CANONICAL_ROOT),
        "execution_workspace": str(remote_root.resolve()),
        "sync_manifest": str(manifest_path.relative_to(CANONICAL_ROOT)),
        "git": git_provenance(CANONICAL_ROOT),
        "files": {
            str(operation.relative_path): {
                "sha256": operation.sha256,
                "size_bytes": operation.size_bytes,
            }
            for operation in operations
        },
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination


def print_plan(label: str, operations: Iterable[CopyOperation]) -> None:
    operations = list(operations)
    print(f"{label}: {len(operations)} allowlisted file(s)")
    if not operations:
        print("  no matching files")
        return
    for operation in operations:
        print(
            f"  {operation.status:9} {operation.relative_path} "
            f"({operation.size_bytes} bytes)"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tanguy canonical source ↔ Leo training execution boundary"
    )
    parser.add_argument(
        "command",
        choices=("status", "push", "pull-reports", "pull-adapters"),
    )
    parser.add_argument("--remote-root", type=Path, default=DEFAULT_REMOTE_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    parser.add_argument("--adapter-root", type=Path, default=DEFAULT_ADAPTER_ROOT)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform copies. Without this flag every command is read-only.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = args.manifest.resolve()
    manifest = load_manifest(manifest_path)
    remote_root = args.remote_root.expanduser().resolve()
    if not remote_root.is_dir():
        raise FileNotFoundError(f"Training workspace not found: {remote_root}")
    if remote_root == CANONICAL_ROOT.resolve():
        raise ValueError("Canonical and execution workspaces must be different")

    push_plan = build_push_plan(CANONICAL_ROOT, remote_root, manifest)
    if args.command == "status":
        print_plan("Canonical → training status", push_plan)
        pull_plan = build_pull_plan(remote_root, args.report_root, manifest)
        print_plan("Training → local reports", pull_plan)
        return 0

    if args.command == "push":
        print_plan("Canonical → training", push_plan)
        if not args.apply:
            print("Dry run only; use --apply to copy allowlisted files.")
            return 0
        changed = apply_plan(push_plan)
        source_manifest = write_source_manifest(
            remote_root, manifest_path, push_plan
        )
        print(f"Applied {changed} file change(s).")
        print(f"Provenance: {source_manifest}")
        return 0

    if args.command == "pull-reports":
        pull_plan = build_pull_plan(remote_root, args.report_root, manifest)
        print_plan("Training → local reports", pull_plan)
        if not args.apply:
            print("Dry run only; use --apply to collect allowlisted JSON reports.")
            return 0
        changed = apply_plan(pull_plan)
        print(f"Collected {changed} report change(s) into {args.report_root}.")
        return 0

    adapter_plan = build_pull_adapter_plan(
        remote_root, args.adapter_root.expanduser(), manifest,
    )
    print_plan("Training → local final adapters", adapter_plan)
    if not args.apply:
        print("Dry run only; use --apply to collect final adapter files.")
        return 0
    changed = apply_plan(adapter_plan)
    print(f"Collected {changed} adapter file change(s) into {args.adapter_root}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
