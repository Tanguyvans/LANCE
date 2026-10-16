"""Verify historical pilot bundles and export aggregate diagnostics only.

Run on nato: raw evidence, arguments, responses and credentials stay there.
This helper never imports or executes the audit pipeline or changes its freeze.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,100}")


def label(value):
    text = str(value)
    return text if TOKEN.fullmatch(text) else "other"


def review_archive(directory: Path) -> dict:
    manifest_path = directory / "evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    archive = directory / "evidence.tar.gz"
    with archive.open("rb") as handle:
        archive_hash = hashlib.file_digest(handle, "sha256").hexdigest()
    if archive_hash != manifest["archive_sha256"]:
        raise ValueError("Archive digest mismatch")
    data = {}
    with tarfile.open(archive, "r:gz") as bundle:
        files = {}
        for item in bundle:
            path = PurePosixPath(item.name)
            if path.is_absolute() or ".." in path.parts or item.issym() or item.islnk():
                raise ValueError("Unsafe archive member")
            if item.isdir():
                continue
            if not item.isfile() or item.name in files:
                raise ValueError("Special or duplicate archive member")
            files[item.name] = item
        if set(files) != set(manifest["files"]):
            raise ValueError("Archive file set differs from manifest")
        for name, item in files.items():
            expected = manifest["files"][name]
            digest = hashlib.sha256()
            size = 0
            retain = name.endswith(("/run_meta.json", "/cost_summary.json", "/tool_calls.jsonl"))
            retain = retain or name.startswith("trial/preflight-") or name.startswith("trial/comparison-")
            chunks = []
            with bundle.extractfile(item) as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
                    if retain:
                        chunks.append(chunk)
            if size != expected["size"] or digest.hexdigest() != expected["sha256"]:
                raise ValueError("Evidence file digest mismatch")
            if retain:
                data[name] = b"".join(chunks)
    result = {
        "trial_id": label(manifest["trial_id"]),
        "archive_sha256": archive_hash,
        "verified_files": len(files),
        "arms": {},
        "preflights": {},
        "comparisons": [],
    }
    for policy in ("rules", "llm"):
        relative = manifest["runs"].get(policy)
        if relative is None:
            result["arms"][policy] = {"present": False}
            continue
        meta = json.loads(data.get(relative + "/run_meta.json", b"{}"))
        cost = json.loads(data.get(relative + "/cost_summary.json", b"{}"))
        ledger = data.get(relative + "/tool_calls.jsonl")
        calls, phases, repeats, origins = Counter(), Counter(), Counter(), Counter()
        malformed = 0
        for line in (ledger or b"").splitlines():
            try:
                entry = json.loads(line)
                tool, phase = label(entry["tool"]), label(entry.get("phase", "unknown"))
                calls[tool] += 1
                phases[phase] += 1
                origins[label(entry.get("execution_origin", "unknown"))] += 1
                # Export only a count, never raw arguments or their fingerprints.
                args_hash = hashlib.sha256(json.dumps(entry.get("args"), sort_keys=True).encode()).hexdigest()
                repeats[(tool, args_hash)] += 1
            except (ValueError, KeyError, TypeError):
                malformed += 1
        result["arms"][policy] = {
            "present": True,
            "metadata_present": bool(meta),
            "status": label(meta.get("status", "unknown")),
            "resource_manifest_sha256": label(meta.get("resource_manifest_sha256", "unknown")),
            "ledger_present": ledger is not None,
            "ledger_entries": sum(calls.values()),
            "malformed_ledger_entries": malformed,
            "calls_by_tool": dict(calls),
            "calls_by_phase": dict(phases),
            "calls_by_origin": dict(origins),
            "repeated_tool_arguments": sum(n - 1 for n in repeats.values()),
            "resources": {k: cost.get(k) for k in (
                "total_tool_calls", "wall_clock_duration_s", "total_cost_usd", "cost_is_estimate",
            )},
            "limits": {k: meta.get(k) for k in ("max_tool_calls", "max_duration_s", "max_cost_usd")},
        }
    for name, content in data.items():
        if name.startswith("trial/preflight-"):
            obj = json.loads(content)
            result["preflights"][label(PurePosixPath(name).name)] = {
                "sha256": manifest["files"][name]["sha256"],
                "declared_status": label(obj.get("status", "unknown")),
                "human_validated": False,
            }
        if name.startswith("trial/comparison-"):
            obj = json.loads(content)
            result["comparisons"].append({"name": label(PurePosixPath(name).name),
                                          "comparable": obj.get("comparable") is True})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.evidence_root.is_dir():
        raise SystemExit("Evidence root is unavailable")
    reports = []
    for manifest in sorted(args.evidence_root.glob("*/*/evidence-manifest.json")):
        try:
            report = review_archive(manifest.parent)
            report["attempt"] = label(manifest.parent.name)
            reports.append(report)
        except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
            # Avoid logging archive contents or exception values containing secrets.
            reports.append({"trial_id": label(manifest.parent.parent.name),
                            "attempt": label(manifest.parent.name), "verification_failed": True})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"schema_version": 1, "archives": reports}, indent=2) + "\n")
    if not reports or any(r.get("verification_failed") for r in reports):
        raise SystemExit("Missing or invalid archives; inspect the aggregate report on nato")


if __name__ == "__main__":
    main()
