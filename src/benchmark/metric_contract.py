"""Versioned metadata for benchmark metrics that depend on run artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path


METRIC_CONTRACT_VERSION = "strict-v3.4"
EVIDENCE_CONTRACT_VERSION = "evidence-v2"


def _tree_sha256(root: Path, pattern: str) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.glob(pattern)):
        if not path.is_file():
            continue
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def metric_contract_metadata(root: Path | None = None) -> dict[str, str]:
    """Return reproducibility metadata for prompts and exposed tool schemas."""
    repository_root = root or Path(__file__).resolve().parents[2]
    return {
        "metric_contract_version": METRIC_CONTRACT_VERSION,
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
        "prompt_manifest_sha256": _tree_sha256(
            repository_root, "src/agent/prompts/**/*.txt"
        ),
        "tool_manifest_sha256": _tree_sha256(
            repository_root, "src/agent/tools/definitions/*.yaml"
        ),
    }
