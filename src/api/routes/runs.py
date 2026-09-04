"""Runs route — list, read, and download past pipeline runs."""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

import yaml
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from src.benchmark.scenario_exports import default_export_store, resolve_ground_truth_path

router = APIRouter()
log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = ROOT / "output" / "agent"

_BENCHMARK_CACHE_SCHEMA = 1
_BENCHMARK_CACHE_INPUTS = (
    "scenario_meta.json",
    "run_meta.json",
    "03_phase3_status.json",
    "03_vuln_analysis.json",
    "04_exploitation.json",
    "05_intrusion.json",
    "05_intrusion_context.json",
    "cost_summary.json",
    "tool_calls.jsonl",
    "benchmark_llm.json",
)
_COMPACT_SCORE_FIELDS = frozenset({
    "status",
    "metrics",
    "scoring_policy",
    "evidence_contract_compatible",
    "metrics_compatibility_reason",
    "is_zero_gt",
    "recall",
    "precision",
    "f1_score",
    "detection_f1",
    "credited_f1",
    "severity_adjusted_f1",
    "quality_adjusted_f1",
    "specificity",
    "weighted_score",
    "max_weighted_score",
    "score_pct",
    "scenario_score_pct",
    "false_positives",
    "hallucination_rate",
    "negative_control_violations",
    "negative_controls_declared",
    "negative_controls_unevaluable",
    "evidence_metrics_available",
    "evidence_precision",
    "evidence_recall",
    "evidence_f1",
    "traceable_evidence_coverage",
    "evidence_faithfulness",
    "evidence_contradiction_rate",
    "evidence_claims_supported",
    "evidence_claims_total",
    "exploitation_coverage",
    "phase4_candidates",
    "phase4_conclusive",
    "phase4_completion_rate",
    "verified_f1",
    "tp_exploited",
    "true_positives",
    "total_attack_paths",
    "attack_paths_detected",
    "quality_path_coverage",
    "verified_path_coverage",
    "mhr_1",
    "mhr_2",
    "mhr_3",
    "mhr_1_credited",
    "mhr_2_credited",
    "mhr_3_credited",
    "mhr_1_verified",
    "mhr_2_verified",
    "mhr_3_verified",
    "phase5_metrics_available",
    "phase5_evidence_available",
    "phase5_targets_total",
    "phase5_targets_attempted",
    "phase5_targets_compromised",
    "phase5_target_attempt_coverage",
    "phase5_target_coverage",
    "phase5_pivot_attempts",
    "phase5_pivot_successes",
    "phase5_pivot_success_rate",
    "phase5_expected_hops",
    "phase5_verified_hops",
    "phase5_hop_coverage",
    "phase5_chain_faithfulness",
    "phase5_compromise_rate",
    "phase5_target_coverage_by_depth",
    "cost_per_tp",
    "cost_per_expected_vulnerability",
    "turns_per_tp",
    "total_tokens",
    "total_tool_calls",
    "cost_is_estimate",
    "process_metrics_available",
    "validation_successes",
    "validation_attempts",
    "validation_success_rate",
    "format_fallbacks",
    "format_attempts",
    "format_fallback_rate",
    "total_tool_errors",
    "tool_error_rate",
    "llm_judge_data",
})

_PRIVATE_RUN_FILES = {
    "ground_truth.yaml",
    # Evaluation artifacts are produced after the agent has finished. Scores
    # are still recomputed by the trusted evaluator in the API routes.
    "evaluation.json",
    "evaluation_summary.json",
}
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


def _is_trusted_exported_scenario(scenario_id: str) -> bool:
    """Recognize exported oracles without trusting run-local files."""
    try:
        return default_export_store().exists(scenario_id)
    except Exception:
        return False


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
    split = meta.get("split")
    if split == "eval-sealed":
        return True
    if split in {"dev-public", "test-public", "lab-export"}:
        return False
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


def _extract_execution_profile(run_dir: Path) -> str | None:
    """Read profile metadata without making legacy/corrupt runs unlistable."""
    for reader in (_read_run_meta, _read_scenario_meta):
        try:
            metadata = reader(run_dir)
        except Exception:
            continue
        if metadata and metadata.get("execution_profile"):
            return str(metadata["execution_profile"])
    return None


def _benchmark_cache_dir() -> Path:
    """Keep trusted derived scores outside individual agent-controlled runs."""
    return OUTPUT_DIR / ".benchmark-score-cache"


def _benchmark_fingerprint(run_dir: Path, ground_truth: Path) -> str:
    """Fingerprint every input that can change a strict-v3 score.

    Stat metadata keeps cache validation cheap. Evaluator source files are part
    of the key so a deployment that changes scoring logic invalidates existing
    entries automatically.
    """
    digest = hashlib.sha256()
    digest.update(f"benchmark-cache-v{_BENCHMARK_CACHE_SCHEMA}\0strict-v3\0".encode())
    paths = [run_dir / name for name in _BENCHMARK_CACHE_INPUTS]
    paths.append(ground_truth)
    paths.extend(sorted((ROOT / "src" / "benchmark").glob("*.py")))
    for path in paths:
        digest.update(str(path).encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        try:
            stat = path.lstat()
        except OSError:
            digest.update(b"missing\0")
            continue
        digest.update(
            f"{stat.st_mode}:{stat.st_size}:{stat.st_mtime_ns}".encode("ascii")
        )
        digest.update(b"\0")
    return digest.hexdigest()


def _benchmark_cache_path(run_dir: Path) -> Path:
    cache_name = hashlib.sha256(run_dir.name.encode("utf-8")).hexdigest()
    return _benchmark_cache_dir() / f"{cache_name}.json"


def _read_benchmark_cache(run_dir: Path, fingerprint: str) -> dict[str, Any] | None:
    cache_dir = _benchmark_cache_dir()
    cache_path = _benchmark_cache_path(run_dir)
    if cache_dir.is_symlink() or cache_path.is_symlink() or not cache_path.is_file():
        return None
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("fingerprint") != fingerprint:
        return None
    score = payload.get("score")
    return score if isinstance(score, dict) else None


def _write_benchmark_cache(
    run_dir: Path,
    fingerprint: str,
    score: dict[str, Any],
) -> None:
    cache_dir = _benchmark_cache_dir()
    if cache_dir.is_symlink():
        return
    try:
        cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if cache_dir.is_symlink() or not cache_dir.is_dir():
            return
        cache_path = _benchmark_cache_path(run_dir)
        tmp_path = cache_dir / f".{cache_path.name}.{uuid4().hex}.tmp"
        try:
            tmp_path.write_text(
                json.dumps({"fingerprint": fingerprint, "score": score}),
                encoding="utf-8",
            )
            tmp_path.chmod(0o600)
            tmp_path.replace(cache_path)
        finally:
            tmp_path.unlink(missing_ok=True)
    except (OSError, TypeError, ValueError):
        log.warning("Could not persist benchmark cache for %s", run_dir.name)


def _evaluate_cached(run_dir: Path, ground_truth: Path) -> dict[str, Any]:
    fingerprint = _benchmark_fingerprint(run_dir, ground_truth)
    cached = _read_benchmark_cache(run_dir, fingerprint)
    if cached is not None:
        return cached

    from src.benchmark.evaluator import evaluate

    score = asdict(evaluate(run_dir, ground_truth, policy="strict-v3"))
    llm_file = run_dir / "benchmark_llm.json"
    if llm_file.exists() and not llm_file.is_symlink():
        try:
            llm_data = json.loads(llm_file.read_text(encoding="utf-8"))
            if isinstance(llm_data, dict):
                score["llm_judge_data"] = llm_data
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass
    _write_benchmark_cache(run_dir, fingerprint, score)
    return score


def _compact_score(score: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return only the fields rendered by the benchmark table."""
    if score is None:
        return None
    compact = {key: score[key] for key in sorted(_COMPACT_SCORE_FIELDS) if key in score}
    matches = score.get("matches")
    if isinstance(matches, list):
        compact["matches"] = [
            {
                key: match.get(key)
                for key in ("matched", "match_method", "gt_severity")
            }
            for match in matches
            if isinstance(match, dict)
        ]
    return compact


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
    phase5 = run_dir / "05_intrusion.json"
    if phase5.exists():
        try:
            phase5_data = json.loads(phase5.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            phase5_data = None
        if isinstance(phase5_data, dict) and phase5_data.get("status") in {"incomplete", "blocked"}:
            return "partial"
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
            "execution_profile": _extract_execution_profile(d),
            "sealed": sealed,
        })
    return runs


def _benchmark_candidate(run_dir: Path) -> dict[str, Any] | None:
    if not _is_safe_run_dir(run_dir):
        return None
    try:
        metadata = _read_scenario_meta(run_dir)
    except Exception:
        return None
    if metadata is None or metadata.get("scenario_id") is None:
        return None
    return {
        "run_dir": run_dir,
        "scenario": f"S{_normalized_scenario_id(metadata['scenario_id'])}",
        "model": metadata.get("model"),
        "sealed": _is_sealed_run(run_dir),
    }


def _benchmark_entry(candidate: dict[str, Any], *, compact: bool) -> dict[str, Any]:
    run_dir = candidate["run_dir"]
    scenario = candidate["scenario"]
    sealed = candidate["sealed"]
    entry = {
        "id": run_dir.name,
        "scenario": scenario,
        "cost": None if sealed else _extract_cost(run_dir),
        "status": _run_status(run_dir),
        "model": candidate["model"],
        "score": None,
        "score_error": None,
        "commit": _extract_commit(run_dir),
        "execution_profile": _extract_execution_profile(run_dir),
        "sealed": sealed,
    }

    vuln_file = run_dir / "03_vuln_analysis.json"
    scenario_id = scenario.removeprefix("S")
    if sealed:
        try:
            entry["score"] = _load_sealed_summary(run_dir, scenario_id)
        except Exception as exc:
            log.warning("Sealed evaluation loading failed for %s: %s", run_dir.name, exc)
            entry["score_error"] = f"Evaluation failed: {exc}"
    elif vuln_file.exists():
        ground_truth = resolve_ground_truth_path(scenario_id)
        if ground_truth.exists():
            try:
                entry["score"] = _evaluate_cached(run_dir, ground_truth)
            except Exception as exc:
                log.warning("Benchmark evaluation failed for %s: %s", run_dir.name, exc)
                entry["score_error"] = f"Evaluation failed: {exc}"

    if compact:
        entry["score"] = _compact_score(entry["score"])
    return entry


@router.get("/benchmark")
def get_benchmark(
    limit: Annotated[int | None, Query(ge=1, le=200)] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    compact: Annotated[bool, Query()] = False,
    scenario: Annotated[str | None, Query(max_length=128)] = None,
    model: Annotated[str | None, Query(max_length=256)] = None,
):
    """Return benchmark scores, optionally filtered and paginated.

    Calls without query parameters keep the historical list response. The SPA
    requests compact pages so it never evaluates, transfers, or renders the
    complete benchmark history at once.
    """
    if not OUTPUT_DIR.exists():
        if limit is None and not compact and offset == 0 and not scenario and not model:
            return []
        return {
            "items": [],
            "total": 0,
            "limit": limit or 50,
            "offset": offset,
            "models": [],
            "scenarios": [],
        }

    candidates = [
        candidate
        for run_dir in sorted(OUTPUT_DIR.iterdir(), reverse=True)
        if (candidate := _benchmark_candidate(run_dir)) is not None
    ]
    all_models = sorted({
        candidate["model"]
        for candidate in candidates
        if isinstance(candidate["model"], str) and candidate["model"]
    })
    all_scenarios = sorted({candidate["scenario"] for candidate in candidates})

    filtered = [
        candidate
        for candidate in candidates
        if (not scenario or candidate["scenario"] == scenario)
        and (not model or candidate["model"] == model)
    ]
    paginated = limit is not None or compact or offset > 0 or bool(scenario) or bool(model)
    if not paginated:
        return [_benchmark_entry(candidate, compact=False) for candidate in filtered]

    page_limit = limit or 50
    page = filtered[offset:offset + page_limit]
    return {
        "items": [_benchmark_entry(candidate, compact=compact) for candidate in page],
        "total": len(filtered),
        "limit": page_limit,
        "offset": offset,
        "models": all_models,
        "scenarios": all_scenarios,
    }


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
            return asdict(evaluate(run_dir, gt_path, policy="strict-v3"))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Evaluation failed: {exc}") from exc

    exported_scenario = _is_trusted_exported_scenario(scenario_id)

    if not exported_scenario:
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
    gt_path = resolve_ground_truth_path(scenario_id)
    if not gt_path.exists():
        raise HTTPException(status_code=404, detail=f"No ground truth file for scenario {scenario_id}")

    try:
        gt_data = yaml.safe_load(gt_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Invalid trusted ground truth: {exc}") from exc
    # Official scenarios must match their requested ID exactly.  Exported
    # custom bundles are trusted through ExportedScenarioStore; older bundles
    # may still contain the logical composer ID in their ground truth.
    if not exported_scenario and str(gt_data.get("scenario_id")) != str(scenario_id):
        raise HTTPException(status_code=500, detail="Trusted ground truth scenario mismatch")

    vuln_file = run_dir / "03_vuln_analysis.json"
    if not vuln_file.exists():
        raise HTTPException(status_code=404, detail="03_vuln_analysis.json not found — run Phase 3 first")

    try:
        from src.benchmark.evaluator import evaluate
        result = evaluate(run_dir, gt_path, policy="strict-v3")
        score_dict = asdict(result)
        
        llm_file = run_dir / "benchmark_llm.json"
        if llm_file.exists():
            try:
                score_dict["llm_judge_data"] = json.loads(llm_file.read_text())
            except json.JSONDecodeError:
                pass

        return score_dict
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {exc}") from exc


class LLMJudgeRequest(BaseModel):
    model: str = Field(min_length=1, max_length=200)
    provider: str = Field(min_length=1, max_length=50, pattern=r"^[A-Za-z0-9._-]+$")

@router.post("/{run_id}/evaluate/llm")
def evaluate_run_llm(run_id: str, request: LLMJudgeRequest):
    run_dir = _resolve_run_dir(run_id)
    if _is_sealed_run(run_dir):
        raise HTTPException(status_code=403, detail="Sealed runs cannot be re-evaluated")
    if not request.model.strip():
        raise HTTPException(status_code=400, detail="Judge model must not be blank")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", request.provider):
        raise HTTPException(status_code=400, detail="Invalid judge provider")

    try:
        meta = _read_scenario_meta(run_dir)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Corrupt scenario_meta.json: {exc}") from exc
    if meta is None:
        raise HTTPException(status_code=404, detail="scenario_meta.json not found")
    if meta.get("scenario_id") is None:
        raise HTTPException(status_code=400, detail="scenario_id missing from metadata")
    scenario_id = _normalized_scenario_id(meta.get("scenario_id"))

    if meta.get("custom_config"):
        gt_path = run_dir / "ground_truth.yaml"
        if not gt_path.is_file() or gt_path.is_symlink():
            raise HTTPException(status_code=404, detail="Custom ground truth not generated")
    else:
        gt_path = resolve_ground_truth_path(scenario_id)
        if not gt_path.exists():
            raise HTTPException(status_code=404, detail=f"No ground truth file for scenario {scenario_id}")
        try:
            gt_data = yaml.safe_load(gt_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Invalid trusted ground truth: {exc}") from exc
        if not _is_trusted_exported_scenario(scenario_id) and str(gt_data.get("scenario_id")) != scenario_id:
            raise HTTPException(status_code=500, detail="Trusted ground truth scenario mismatch")

    bench_llm_file = run_dir / "benchmark_llm.json"
    if bench_llm_file.is_symlink():
        raise HTTPException(status_code=400, detail="benchmark_llm.json must not be a symlink")

    try:
        from src.agent.judge import evaluate_with_llm
        llm_score = evaluate_with_llm(run_dir, gt_path, request.model, request.provider)

        tmp_file = run_dir / f".benchmark_llm.{uuid4().hex}.tmp"
        try:
            tmp_file.write_text(json.dumps(llm_score, indent=2), encoding="utf-8")
            tmp_file.replace(bench_llm_file)
        finally:
            tmp_file.unlink(missing_ok=True)
        return llm_score
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"LLM Judge failed: {exc}") from exc


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
