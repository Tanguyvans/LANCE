"""Conservative Phase 5 intrusion observations.

This module is deliberately separate from the model deliverable and from the
benchmark evaluator.  The model JSON contributes declarations only; accesses
come from executor-owned Phase 5 tool records and the shared evidence rules.
"""
from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

from src.agent.evidence.capabilities import access_supported
from src.agent.evidence.records import observed_targets
from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION


OBSERVATIONS_SCHEMA_VERSION = "intrusion-observations-v1"
_MAX_DECLARATION_ITEMS = 10_000
_EVIDENCE_REF_RE = re.compile(r"tc-[0-9a-f]{32}")


def _projection(
    *,
    available: bool,
    reason: str | None,
    accesses: list[dict[str, Any]] | None = None,
    declarations: dict[str, int] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": OBSERVATIONS_SCHEMA_VERSION,
        "available": available,
        "reason": reason,
        "accesses": accesses or [],
        "transitions": [],
        "transition_evidence_available": False,
        "declarations": declarations,
    }


def _regular_file(run_dir: Path, name: str) -> Path | None:
    """Return a required regular file without following symlinks or FIFOs."""
    path = run_dir / name
    try:
        info = path.lstat()
    except (FileNotFoundError, OSError):
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return None
    return path


def _read_object(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _bounded_length(value: object) -> int:
    if not isinstance(value, list):
        return 0
    return min(len(value), _MAX_DECLARATION_ITEMS)


def _declarations(model: dict[str, Any]) -> dict[str, int]:
    """Count model lists without validating or trusting their contents."""
    chains = model.get("chains")
    chain_count = _bounded_length(chains)

    transitions_value = model.get("transitions")
    if isinstance(transitions_value, list):
        transition_count = _bounded_length(transitions_value)
    else:
        transition_count = 0
        if isinstance(chains, list):
            for chain in chains[:_MAX_DECLARATION_ITEMS]:
                if not isinstance(chain, dict):
                    continue
                hops = chain.get("hops")
                if isinstance(hops, list):
                    transition_count += max(0, len(hops) - 1)
                    if transition_count >= _MAX_DECLARATION_ITEMS:
                        transition_count = _MAX_DECLARATION_ITEMS
                        break

    return {
        "accesses": _bounded_length(model.get("compromised_devices")),
        "chains": chain_count,
        "transitions": transition_count,
    }


def _valid_run_dir(run_dir: Path) -> bool:
    try:
        info = run_dir.lstat()
    except (FileNotFoundError, OSError):
        return False
    return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _phase5_access(record: dict[str, Any]) -> tuple[str, str] | None:
    """Return one corroborated target/reference pair, or no access."""
    if record.get("phase") not in (5, "5"):
        return None
    if record.get("execution_origin") != "runner":
        return None

    evidence_ref = record.get("evidence_ref")
    if not isinstance(evidence_ref, str):
        return None
    evidence_ref = evidence_ref.strip()
    if not _EVIDENCE_REF_RE.fullmatch(evidence_ref):
        return None

    try:
        if not access_supported(record):
            return None
        targets = observed_targets(record)
    except Exception:
        return None
    if len(targets) != 1:
        return None
    return next(iter(targets)), evidence_ref


def _read_phase5_records(path: Path) -> list[dict[str, Any]] | None:
    """Read the complete JSONL ledger; any malformed/non-object line fails closed."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None

    records: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict):
            return None
        records.append(value)
    return records


def project_intrusion_observations(
    run_dir: Path | str, *, evidence_integrity_failed: bool = False
) -> dict[str, Any]:
    """Build the read-only UI/API projection for one run directory."""
    run_path = Path(run_dir)
    if not _valid_run_dir(run_path):
        return _projection(available=False, reason="run directory is unavailable")

    if evidence_integrity_failed:
        return _projection(available=False, reason="evidence integrity is not valid")

    meta_path = _regular_file(run_path, "run_meta.json")
    if meta_path is None:
        return _projection(available=False, reason="run_meta.json is missing or not a regular file")
    metadata = _read_object(meta_path)
    if metadata is None:
        return _projection(available=False, reason="run_meta.json is malformed or not an object")
    if metadata.get("evidence_contract_version") != EVIDENCE_CONTRACT_VERSION:
        return _projection(available=False, reason="evidence contract is missing or incompatible")
    if (
        metadata.get("evidence_integrity") is False
        or metadata.get("integrity") is False
        or metadata.get("evidence_contract_compatible") is False
    ):
        return _projection(available=False, reason="evidence integrity is not valid")

    # The model artifact is optional for corroboration. It can contribute
    # bounded declaration counts when readable, but never gates ledger access.
    model_path = _regular_file(run_path, "05_intrusion.json")
    model = _read_object(model_path) if model_path is not None else None
    declarations = _declarations(model) if model is not None else None

    journal_path = _regular_file(run_path, "tool_calls.jsonl")
    if journal_path is None:
        return _projection(
            available=False,
            reason="tool_calls.jsonl is missing or not a regular file",
            declarations=declarations,
        )
    records = _read_phase5_records(journal_path)
    if records is None:
        return _projection(
            available=False,
            reason="tool_calls.jsonl is malformed or contains a non-object",
            declarations=declarations,
        )

    # A runner reference is intended to identify one archived invocation. Do
    # this integrity check over the complete journal, before verdict/phase
    # filtering, so a reused reference cannot hide behind a failed or Phase 4
    # record.
    journal_refs: set[str] = set()
    for record in records:
        evidence_ref = record.get("evidence_ref")
        if not isinstance(evidence_ref, str):
            continue
        evidence_ref = evidence_ref.strip()
        if not _EVIDENCE_REF_RE.fullmatch(evidence_ref):
            continue
        if evidence_ref in journal_refs:
            return _projection(
                available=False,
                reason="duplicate evidence reference is ambiguous",
                declarations=declarations,
            )
        journal_refs.add(evidence_ref)

    by_ip: dict[str, list[str]] = {}
    for record in records:
        observation = _phase5_access(record)
        if observation is None:
            continue
        device_ip, evidence_ref = observation
        refs = by_ip.setdefault(device_ip, [])
        if evidence_ref not in refs:
            refs.append(evidence_ref)

    accesses = [
        {"device_ip": device_ip, "evidence_refs": refs}
        for device_ip, refs in by_ip.items()
    ]
    return _projection(
        available=True,
        reason=None,
        accesses=accesses,
        declarations=declarations,
    )
