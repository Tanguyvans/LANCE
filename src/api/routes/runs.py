"""Runs route — list, read, and download past pipeline runs."""
from __future__ import annotations

import io
import json
import os
import re
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

router = APIRouter()

ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = ROOT / "output" / "agent"

_PRIVATE_RUN_FILES = {"ground_truth.yaml"}
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _read_scenario_meta(run_dir: Path) -> dict[str, Any] | None:
    """Read run metadata without following an agent-controlled symlink."""
    meta_file = run_dir / "scenario_meta.json"
    if meta_file.is_symlink():
        raise ValueError("scenario_meta.json must not be a symlink")
    if not meta_file.exists():
        return None
    if not meta_file.is_file():
        raise ValueError("scenario_meta.json is not a regular file")
    data = json.loads(meta_file.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("scenario_meta.json must contain an object")
    return data


def _read_run_meta(run_dir: Path) -> dict[str, Any] | None:
    meta_file = run_dir / "run_meta.json"
    if meta_file.is_symlink():
        raise ValueError("run_meta.json must not be a symlink")
    if not meta_file.exists():
        return None
    if not meta_file.is_file():
        raise ValueError("run_meta.json is not a regular file")
    data = json.loads(meta_file.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("run_meta.json must contain an object")
    return data


def _normalized_scenario_id(value: object) -> str:
    return str(value).strip().removeprefix("S").removeprefix("s")


def _scenario_descriptor(run_dir: Path):
    try:
        meta = _read_scenario_meta(run_dir)
        if meta is None:
            return None
        scenario_id = meta.get("scenario_id")
        if scenario_id is None:
            return None
        from src.benchmark.catalog import get_scenario
        return get_scenario(_normalized_scenario_id(scenario_id))
    except Exception:
        return None


def _is_sealed_run(run_dir: Path) -> bool:
    """Classify sealed runs fail-closed from metadata and the trusted catalog."""
    try:
        meta = _read_scenario_meta(run_dir)
        run_meta = _read_run_meta(run_dir)
    except Exception:
        # A malformed/tampered benchmark marker must never make raw artifacts
        # visible through the public run-file endpoints.
        return True
    if run_meta and run_meta.get("benchmark_split") == "eval-sealed":
        return True
    if meta is None:
        return False
    if meta.get("split") == "eval-sealed":
        return True
    scenario_id = meta.get("scenario_id")
    if scenario_id is None:
        return False
    normalized = _normalized_scenario_id(scenario_id)
    if normalized.isdigit() and 20 <= int(normalized) <= 25:
        return True
    descriptor = _scenario_descriptor(run_dir)
    return bool(descriptor and descriptor.sealed)


def _is_safe_run_dir(run_dir: Path) -> bool:
    if (
        not _RUN_ID_RE.fullmatch(run_dir.name)
        or run_dir.is_symlink()
        or not run_dir.is_dir()
    ):
        return False
    try:
        run_dir.resolve().relative_to(OUTPUT_DIR.resolve())
    except ValueError:
        return False
    return run_dir.parent == OUTPUT_DIR


def _resolve_run_dir(run_id: str) -> Path:
    if not _RUN_ID_RE.fullmatch(run_id):
        raise HTTPException(status_code=400, detail="Invalid run ID")
    run_dir = OUTPUT_DIR / run_id
    if not _is_safe_run_dir(run_dir):
        raise HTTPException(status_code=404, detail="Run not found")
    return run_dir


def _visible_files(run_dir: Path) -> list[str]:
    if _is_sealed_run(run_dir):
        return []
    return sorted(
        f.name for f in run_dir.iterdir()
        if f.is_file() and not f.is_symlink()
        and not f.name.startswith(".") and f.name not in _PRIVATE_RUN_FILES
    )


def _load_sealed_summary(run_dir: Path, expected_scenario_id: str) -> dict | None:
    """Load a controller-owned summary, never a run-local agent artifact.

    The controller (or deployment glue) may publish summaries in the directory
    named by SEALED_EVALUATION_DIR, keyed as ``<run_id>.json``. The directory is
    deliberately outside OUTPUT_DIR so an evaluated agent cannot forge a score.
    """
    trusted_raw = os.environ.get("SEALED_EVALUATION_DIR")
    if not trusted_raw:
        return None
    trusted_dir = Path(trusted_raw)
    if not trusted_dir.is_absolute() or trusted_dir.is_symlink() or not trusted_dir.is_dir():
        raise ValueError("SEALED_EVALUATION_DIR must be an absolute trusted directory")
    trusted_resolved = trusted_dir.resolve()
    try:
        trusted_resolved.relative_to(OUTPUT_DIR.resolve())
    except ValueError:
        pass
    else:
        raise ValueError("SEALED_EVALUATION_DIR must be outside the agent output directory")

    run_id = run_dir.name
    if not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError("invalid sealed run ID")
    summary_path = trusted_dir / f"{run_id}.json"
    if not summary_path.exists():
        return None
    if summary_path.is_symlink() or not summary_path.is_file():
        raise ValueError("sealed evaluation summary must be a regular file")
    try:
        summary_path.resolve().relative_to(trusted_resolved)
    except ValueError as exc:
        raise ValueError("sealed evaluation summary escapes the trusted directory") from exc

    from src.benchmark.contracts import EvaluationSummary
    from src.benchmark.catalog import load_catalog

    summary = EvaluationSummary.from_dict(
        json.loads(summary_path.read_text(encoding="utf-8"))
    )
    if summary.scenario_id != expected_scenario_id:
        raise ValueError("sealed evaluation summary scenario mismatch")
    if summary.benchmark_version != load_catalog().benchmark_version:
        raise ValueError("sealed evaluation summary benchmark version mismatch")
    public_summary = asdict(summary)
    public_summary.pop("signature", None)
    return public_summary


def _extract_cost(run_dir: Path) -> float | None:
    """Extract total cost from cost_summary.json, falling back to markdown scan."""
    cost_file = run_dir / "cost_summary.json"
    if cost_file.exists():
        try:
            data = json.loads(cost_file.read_text())
            val = data.get("total_cost_usd")
            if val is not None:
                return float(val)
        except Exception:
            pass
    for f in sorted(run_dir.glob("*.md"), reverse=True):
        try:
            text = f.read_text()
            m = re.search(r"TOTAL.*?\$([\d.]+)", text)
            if m:
                return float(m.group(1))
        except Exception:
            pass
    return None


def _extract_commit(run_dir: Path) -> str | None:
    """Extract git commit hash from run_meta.json or scenario_meta.json."""
    for fname in ("run_meta.json", "scenario_meta.json"):
        f = run_dir / fname
        if f.exists():
            try:
                data = json.loads(f.read_text())
                commit = data.get("git_commit")
                if commit:
                    return commit
            except Exception:
                pass
    return None


def _detect_scenario(run_dir: Path) -> str | None:
    """Detect scenario ID from scenario_meta.json if present."""
    try:
        data = _read_scenario_meta(run_dir)
        if data is not None:
            sid = data.get("scenario_id")
            return f"S{_normalized_scenario_id(sid)}" if sid is not None else None
    except Exception:
        pass
    return None


def _run_status(run_dir: Path) -> str:
    """Infer run status from deliverable files."""
    files = list(run_dir.glob("*"))
    names = [f.name for f in files]
    if "06_report.md" in names or "05_report.md" in names:
        return "done"
    if any(n.startswith("04_") or n.startswith("05_") for n in names):
        return "partial"
    return "incomplete"


@router.get("")
def list_runs():
    """Return all past runs sorted newest first."""
    if not OUTPUT_DIR.exists():
        return []
    runs = []
    for d in sorted(OUTPUT_DIR.iterdir(), reverse=True):
        if not _is_safe_run_dir(d):
            continue
        sealed = _is_sealed_run(d)
        files = _visible_files(d)
        runs.append({
            "id": d.name,
            "files": files,
            "cost": None if sealed else _extract_cost(d),
            "scenario": _detect_scenario(d),
            "status": _run_status(d),
            "commit": _extract_commit(d),
            "sealed": sealed,
        })
    return runs


@router.get("/benchmark")
def get_benchmark():
    """Return all scenario runs with their benchmark scores."""
    if not OUTPUT_DIR.exists():
        return []

    results = []
    for d in sorted(OUTPUT_DIR.iterdir(), reverse=True):
        if not _is_safe_run_dir(d):
            continue
        scenario = _detect_scenario(d)
        if not scenario:
            continue  # Only include scenario runs in benchmark view
        sealed = _is_sealed_run(d)

        entry = {
            "id": d.name,
            "scenario": scenario,
            "cost": None if sealed else _extract_cost(d),
            "status": _run_status(d),
            "model": None,
            "score": None,
            "commit": _extract_commit(d),
            "sealed": sealed,
        }

        try:
            meta = _read_scenario_meta(d)
            if meta is not None:
                entry["model"] = meta.get("model")
        except Exception:
            pass

        vuln_file = d / "03_vuln_analysis.json"
        sid = scenario.removeprefix("S")
        if sealed:
            try:
                entry["score"] = _load_sealed_summary(d, sid)
            except Exception:
                pass
        elif vuln_file.exists():
            gt_path = ROOT / "benchmarks" / "ground_truth" / f"scenario_{sid}.yaml"
            if gt_path.exists():
                try:
                    from src.benchmark.evaluator import evaluate
                    result = evaluate(d, gt_path, policy="strict-v2")
                    entry["score"] = asdict(result)
                except Exception:
                    pass

        results.append(entry)

    return results


@router.get("/{run_id}")
def get_run(run_id: str):
    """Return metadata and file list for a specific run."""
    run_dir = _resolve_run_dir(run_id)
    sealed = _is_sealed_run(run_dir)
    files = _visible_files(run_dir)
    return {
        "id": run_id,
        "files": files,
        "cost": None if sealed else _extract_cost(run_dir),
        "scenario": _detect_scenario(run_dir),
        "status": _run_status(run_dir),
        "commit": _extract_commit(run_dir),
        "sealed": sealed,
    }


@router.get("/{run_id}/score")
def score_run(run_id: str):
    """Score a run against its scenario ground truth using the benchmark evaluator."""
    run_dir = _resolve_run_dir(run_id)

    try:
        meta = _read_scenario_meta(run_dir)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Corrupt scenario_meta.json: {exc}") from exc
    if meta is None:
        raise HTTPException(status_code=404, detail="No scenario metadata — lab physique runs have no ground truth")

    raw_scenario_id = meta.get("scenario_id")
    if raw_scenario_id is None:
        raise HTTPException(status_code=400, detail="scenario_id missing from metadata")
    scenario_id = _normalized_scenario_id(raw_scenario_id)

    # Sealed classification precedes custom-mode handling. Run metadata is not
    # trusted, so setting custom_config must never switch a sealed run back to a
    # run-local ground truth.
    if _is_sealed_run(run_dir):
        if not scenario_id.isdigit() or not 20 <= int(scenario_id) <= 25:
            raise HTTPException(status_code=500, detail="Invalid sealed scenario metadata")
        try:
            summary = _load_sealed_summary(run_dir, scenario_id)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Invalid sealed evaluation summary: {exc}") from exc
        if summary is None:
            raise HTTPException(status_code=404, detail="Sealed evaluation is not available yet")
        return summary

    if meta.get("custom_config"):
        gt_path = run_dir / "ground_truth.yaml"
        if not gt_path.is_file() or gt_path.is_symlink():
            raise HTTPException(status_code=404, detail="Custom ground truth not generated")
        vuln_file = run_dir / "03_vuln_analysis.json"
        if not vuln_file.exists():
            raise HTTPException(status_code=404, detail="03_vuln_analysis.json not found — run Phase 3 first")
        try:
            from src.benchmark.evaluator import evaluate
            return asdict(evaluate(run_dir, gt_path, policy="strict-v2"))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Evaluation failed: {exc}") from exc

    from src.agent.batch import SealedScenarioError, _parse_single_scenario_id
    try:
        scenario_id = _parse_single_scenario_id(scenario_id)
    except SealedScenarioError as exc:
        # Defense in depth if a future sealed ID falls outside the numeric range
        # used by _is_sealed_run.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Public scores resolve the oracle only from the trusted evaluator store.
    # A run-local ground_truth.yaml is intentionally ignored.
    gt_path = ROOT / "benchmarks" / "ground_truth" / f"scenario_{scenario_id}.yaml"
    if not gt_path.exists():
        raise HTTPException(status_code=404, detail=f"No ground truth file for scenario {scenario_id}")

    try:
        gt_data = yaml.safe_load(gt_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Invalid trusted ground truth: {exc}") from exc
    if str(gt_data.get("scenario_id")) != str(scenario_id):
        raise HTTPException(status_code=500, detail="Trusted ground truth scenario mismatch")

    vuln_file = run_dir / "03_vuln_analysis.json"
    if not vuln_file.exists():
        raise HTTPException(status_code=404, detail="03_vuln_analysis.json not found — run Phase 3 first")

    try:
        from src.benchmark.evaluator import evaluate
        result = evaluate(run_dir, gt_path, policy="strict-v2")
        return asdict(result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {exc}") from exc


@router.get("/{run_id}/download/zip")
def download_run(run_id: str):
    """Download all deliverables for a run as a zip archive."""
    run_dir = _resolve_run_dir(run_id)
    if _is_sealed_run(run_dir):
        raise HTTPException(
            status_code=403,
            detail="Sealed runs expose aggregate evaluation summaries only",
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        files = [
            f for f in sorted(run_dir.rglob("*"))
            if f.is_file() and not f.is_symlink()
            and not any(part.startswith(".") for part in f.relative_to(run_dir).parts)
            and f.name not in _PRIVATE_RUN_FILES
        ]
        for f in files:
            try:
                relative = f.resolve().relative_to(run_dir.resolve())
            except ValueError:
                continue
            zf.write(f, str(relative))
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={run_id}.zip"},
    )


@router.get("/{run_id}/{filename}")
def get_run_file(run_id: str, filename: str):
    """Return the content of a specific deliverable file."""
    if (
        Path(filename).name != filename
        or filename.startswith(".")
        or filename in _PRIVATE_RUN_FILES
    ):
        raise HTTPException(status_code=404, detail="File not found")
    run_dir = _resolve_run_dir(run_id)
    if _is_sealed_run(run_dir):
        raise HTTPException(
            status_code=403,
            detail="Sealed runs expose aggregate evaluation summaries only",
        )
    filepath = run_dir / filename
    if not filepath.is_file() or filepath.is_symlink():
        raise HTTPException(status_code=404, detail="File not found")
    # Security: ensure path stays within run_dir
    try:
        filepath.resolve().relative_to(run_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")

    content = filepath.read_text(encoding="utf-8", errors="replace")
    ext = filepath.suffix.lower()
    if ext == ".json":
        try:
            return {"filename": filename, "type": "json", "content": json.loads(content)}
        except json.JSONDecodeError:
            pass
    return {"filename": filename, "type": "text", "content": content}
