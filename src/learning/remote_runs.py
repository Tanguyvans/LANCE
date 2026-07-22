"""Import eligible public runs from a remote LANCE API."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
IMPORTABLE_FILES = (
    "scenario_meta.json",
    "run_meta.json",
    "01_graph_evidence.json",
    "02_recon_evidence.json",
    "03_vuln_analysis.json",
    "03_vuln_analysis_raw.json",
    "04_exploitation.json",
    "05_intrusion.json",
    "cost_summary.json",
    "tool_calls.jsonl",
    "deliverable_attempts.jsonl",
    "model_outputs.jsonl",
    "06_report.md",
    "06_report_analysis_context.json",
    "06_report_analysis.md",
)
REQUIRED_FILES = frozenset({"scenario_meta.json", "03_vuln_analysis.json"})


class RemoteImportError(RuntimeError):
    """Raised when a remote run snapshot cannot be imported safely."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _request_json(url: str, *, timeout: float) -> Any:
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "LANCE-learning-import/1"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise RemoteImportError(f"Remote API returned HTTP {response.status}: {url}")
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, UnicodeError, json.JSONDecodeError) as exc:
        raise RemoteImportError(f"Remote API request failed: {url}") from exc


def _normalise_base_url(value: str) -> str:
    base_url = value.rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RemoteImportError("Remote base URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RemoteImportError(
            "Remote base URL must not contain credentials, query or fragment"
        )
    return base_url


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_remote_file(path: Path, payload: Any, file_type: str) -> None:
    if file_type == "json":
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return
    if not isinstance(payload, str):
        raise RemoteImportError(f"Expected text content for {path.name}")
    path.write_text(payload, encoding="utf-8")


def list_remote_runs(base_url: str, *, timeout: float = 30.0) -> list[dict[str, Any]]:
    """Return the benchmark index used to select model-aware learning runs."""
    base_url = _normalise_base_url(base_url)
    benchmark = _request_json(f"{base_url}/api/runs/benchmark", timeout=timeout)
    inventory = _request_json(f"{base_url}/api/runs", timeout=timeout)
    if not isinstance(benchmark, list) or not all(
        isinstance(item, dict) for item in benchmark
    ):
        raise RemoteImportError("Remote benchmark endpoint returned an invalid payload")
    if not isinstance(inventory, list) or not all(
        isinstance(item, dict) for item in inventory
    ):
        raise RemoteImportError("Remote runs endpoint returned an invalid payload")
    inventory_by_id = {
        str(item.get("id")): item
        for item in inventory
        if item.get("id") is not None
    }
    merged: list[dict[str, Any]] = []
    for item in benchmark:
        run_id = str(item.get("id") or "")
        combined = dict(inventory_by_id.get(run_id, {}))
        combined.update(item)
        if "files" not in combined:
            combined["files"] = []
        merged.append(combined)
    return merged


def select_runs(
    runs: Iterable[dict[str, Any]],
    *,
    models: Iterable[str] | None = None,
    statuses: Iterable[str] = ("done",),
    run_ids: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Select non-sealed runs deterministically from remote benchmark metadata."""
    model_filters = tuple(item.lower() for item in (models or ()))
    accepted_statuses = set(statuses)
    accepted_ids = set(run_ids or ())
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for run in runs:
        run_id = str(run.get("id") or "")
        if not RUN_ID_RE.fullmatch(run_id) or run_id in seen:
            continue
        if accepted_ids and run_id not in accepted_ids:
            continue
        if run.get("sealed") is True or run.get("status") not in accepted_statuses:
            continue
        model = str(run.get("model") or "")
        if model_filters and not any(token in model.lower() for token in model_filters):
            continue
        files = run.get("files")
        if not isinstance(files, list) or not REQUIRED_FILES.issubset(set(files)):
            continue
        selected.append(run)
        seen.add(run_id)
    missing = accepted_ids - seen
    if missing:
        raise RemoteImportError(
            f"Requested runs are unavailable or ineligible: {sorted(missing)}"
        )
    return sorted(selected, key=lambda item: str(item["id"]))


def import_runs(
    base_url: str,
    destination: Path,
    runs: Iterable[dict[str, Any]],
    *,
    timeout: float = 30.0,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Create a local snapshot of selected remote run artifacts."""
    base_url = _normalise_base_url(base_url)
    destination = Path(destination)
    selected = list(runs)
    if destination.exists():
        if not overwrite:
            raise RemoteImportError(f"Destination already exists: {destination}")
        if destination.is_symlink() or not destination.is_dir():
            raise RemoteImportError(f"Unsafe destination: {destination}")
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    imported: list[dict[str, Any]] = []
    try:
        for run in selected:
            run_id = str(run.get("id") or "")
            if not RUN_ID_RE.fullmatch(run_id) or run.get("sealed") is True:
                raise RemoteImportError(f"Unsafe or sealed run: {run_id!r}")
            available = set(run.get("files") or ())
            if not REQUIRED_FILES.issubset(available):
                raise RemoteImportError(
                    f"Required learning artifacts missing for {run_id}"
                )
            run_dir = destination / run_id
            run_dir.mkdir()
            file_entries: list[dict[str, Any]] = []
            for filename in IMPORTABLE_FILES:
                if filename not in available:
                    continue
                payload = _request_json(
                    f"{base_url}/api/runs/{quote(run_id, safe='')}/{quote(filename, safe='')}",
                    timeout=timeout,
                )
                if not isinstance(payload, dict) or payload.get("filename") != filename:
                    raise RemoteImportError(
                        f"Invalid file response for {run_id}/{filename}"
                    )
                target = run_dir / filename
                _write_remote_file(
                    target,
                    payload.get("content"),
                    str(payload.get("type") or "text"),
                )
                file_entries.append({
                    "path": filename,
                    "size_bytes": target.stat().st_size,
                    "sha256": _sha256(target),
                })
            imported.append({
                "run_id": run_id,
                "run_date": run_id.split("_", 1)[0],
                "scenario": run.get("scenario"),
                "model": run.get("model"),
                "source_commit": run.get("commit"),
                "remote_score": run.get("score"),
                "files": file_entries,
            })
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise

    manifest = {
        "schema_version": "1.0",
        "snapshot_kind": "remote-learning-runs",
        "created_at": _utc_now(),
        "source_base_url": base_url,
        "run_count": len(imported),
        "runs": imported,
    }
    (destination / "remote_snapshot_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--model", action="append", dest="models")
    parser.add_argument("--run-id", action="append", dest="run_ids")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--list-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        index = list_remote_runs(args.base_url, timeout=args.timeout)
        selected = select_runs(index, models=args.models, run_ids=args.run_ids)
        if args.list_only:
            result: Any = selected
        else:
            result = import_runs(
                args.base_url,
                args.destination,
                selected,
                timeout=args.timeout,
                overwrite=args.overwrite,
            )
    except RemoteImportError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
