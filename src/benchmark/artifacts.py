"""Allowlisted artifact collection and integrity verification.

Sealed submissions are constructed from a positive allowlist.  Files such as
``ground_truth.yaml``, Ansible logs, controller responses and arbitrary run
attachments can therefore never enter a submission bundle by accident.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from src.benchmark.contracts import ArtifactDigest, ChallengeContract, ContractError, SubmissionManifest


MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
MAX_BUNDLE_INPUT_BYTES = 100 * 1024 * 1024
_HASH_CHUNK_SIZE = 1024 * 1024

_ALLOWED_ROOT_FILES = frozenset(
    {
        "run_meta.json",
        "01_graph_analysis.md",
        "02_recon.md",
        "02_topology_edges.json",
        "03_vuln_analysis.json",
        "04_exploitation.json",
        "05_intrusion.json",
        "06_report.md",
        "scenario_meta.json",
        "tool_calls.jsonl",
        "cost_summary.json",
    }
)
_ALLOWED_ROOT_PATTERNS = ("03_device_*.json",)


class ArtifactError(ContractError):
    """Raised when run artifacts cannot be safely submitted."""


def _relative_posix(path: str | os.PathLike[str]) -> PurePosixPath:
    raw = os.fspath(path)
    if not raw or "\\" in raw or "\x00" in raw:
        raise ArtifactError("artifact path must be a non-empty POSIX relative path")
    candidate = PurePosixPath(raw)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ArtifactError(f"unsafe artifact path: {raw!r}")
    return candidate


def is_allowed_artifact(path: str | os.PathLike[str]) -> bool:
    """Return whether a normalized run-relative path may be submitted.

    Unsafe paths raise :class:`ArtifactError` instead of being treated as a
    harmless non-match; callers must not accidentally normalize traversal.
    """

    candidate = _relative_posix(path)
    parts = candidate.parts
    if len(parts) == 1:
        name = parts[0]
        return name in _ALLOWED_ROOT_FILES or any(fnmatchcase(name, pattern) for pattern in _ALLOWED_ROOT_PATTERNS)
    if len(parts) == 2 and parts[0] == "03_scans":
        return fnmatchcase(parts[1], "*.json")
    if len(parts) == 3 and parts[0] == "04_exploits":
        return fnmatchcase(parts[2], "*.json")
    return False


def sha256_file(path: str | Path) -> str:
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ArtifactError(f"artifact must be a regular non-symlink file: {source}")
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_source(run_dir: Path, relative_path: str) -> Path:
    if not is_allowed_artifact(relative_path):
        raise ArtifactError(f"artifact is not allowlisted: {relative_path}")
    root = run_dir.resolve(strict=True)
    source = run_dir / Path(*PurePosixPath(relative_path).parts)
    if source.is_symlink():
        raise ArtifactError(f"symlink artifacts are forbidden: {relative_path}")
    try:
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise ArtifactError(f"artifact is missing: {relative_path}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ArtifactError(f"artifact escapes the run directory: {relative_path}") from exc
    if not resolved.is_file():
        raise ArtifactError(f"artifact is not a regular file: {relative_path}")
    return resolved


def collect_artifacts(run_dir: str | Path) -> tuple[ArtifactDigest, ...]:
    """Hash every allowlisted regular file in ``run_dir`` in stable order."""

    root = Path(run_dir)
    if not root.is_dir():
        raise ArtifactError(f"run directory does not exist: {root}")
    root_resolved = root.resolve(strict=True)
    candidates: list[str] = []
    for path in root.rglob("*"):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as exc:  # defensive: rglob should always remain below root
            raise ArtifactError(f"artifact path escaped run directory: {path}") from exc
        if is_allowed_artifact(relative):
            candidates.append(relative)

    artifacts: list[ArtifactDigest] = []
    total_bytes = 0
    for relative in sorted(set(candidates)):
        source = _safe_source(root_resolved, relative)
        size = source.stat().st_size
        if size > MAX_ARTIFACT_BYTES:
            raise ArtifactError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes: {relative}")
        total_bytes += size
        if total_bytes > MAX_BUNDLE_INPUT_BYTES:
            raise ArtifactError(f"allowlisted artifacts exceed {MAX_BUNDLE_INPUT_BYTES} bytes")
        artifacts.append(ArtifactDigest(path=relative, sha256=sha256_file(source), size_bytes=size))
    if not artifacts:
        raise ArtifactError("run directory contains no allowlisted artifacts")
    return tuple(artifacts)


def build_submission_manifest(
    run_dir: str | Path,
    contract: ChallengeContract,
    *,
    run_id: str,
) -> SubmissionManifest:
    manifest = SubmissionManifest(
        session_id=contract.session_id,
        scenario_id=contract.scenario_id,
        run_id=run_id,
        benchmark_version=contract.benchmark_version,
        artifacts=collect_artifacts(run_dir),
        artifact_schema_version=contract.artifact_schema_version,
    )
    # Round-trip through the strict parser so programmatic construction is held
    # to the same invariants as untrusted JSON received over the wire.
    return SubmissionManifest.from_dict(manifest.to_dict())


def manifest_sha256(manifest: SubmissionManifest) -> str:
    return hashlib.sha256(manifest.to_json().encode("utf-8")).hexdigest()


def verify_submission_manifest(
    run_dir: str | Path,
    manifest: SubmissionManifest,
    *,
    require_complete_allowlist: bool = True,
) -> None:
    """Verify paths, sizes and hashes against the current filesystem state."""

    root = Path(run_dir)
    expected = {artifact.path: artifact for artifact in manifest.artifacts}
    for relative, artifact in expected.items():
        source = _safe_source(root, relative)
        size = source.stat().st_size
        if size != artifact.size_bytes:
            raise ArtifactError(f"artifact size mismatch: {relative}")
        if sha256_file(source) != artifact.sha256:
            raise ArtifactError(f"artifact digest mismatch: {relative}")

    if require_complete_allowlist:
        current = {artifact.path for artifact in collect_artifacts(root)}
        if current != set(expected):
            added = sorted(current - set(expected))
            removed = sorted(set(expected) - current)
            raise ArtifactError(f"allowlisted artifact set changed (added={added}, removed={removed})")


def create_submission_bundle(
    run_dir: str | Path,
    contract: ChallengeContract,
    *,
    run_id: str,
    output_path: str | Path,
) -> tuple[Path, SubmissionManifest, str]:
    """Create a zip containing only allowlisted files plus ``manifest.json``."""

    root = Path(run_dir)
    destination = Path(output_path)
    try:
        destination.resolve().relative_to(root.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise ArtifactError("submission bundle must be written outside the run directory")
    if destination.exists() and destination.is_symlink():
        raise ArtifactError(f"refusing to replace symlink bundle path: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_submission_manifest(root, contract, run_id=run_id)
    verify_submission_manifest(root, manifest)
    manifest_json = json.dumps(
        manifest.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    try:
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", manifest_json)
            for artifact in manifest.artifacts:
                source = _safe_source(root, artifact.path)
                archive.write(source, arcname=artifact.path)
        # Detect mutations that happened while the archive was being written.
        verify_submission_manifest(root, manifest)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination, manifest, manifest_sha256(manifest)
