"""Small, bounded execution summaries; observed counts are never benchmark scores."""
from __future__ import annotations

from datetime import datetime
import math
from pathlib import Path

from fastapi import HTTPException

from src.agent.procedures import get_procedure
from src.api.routes import runs


def _number(value, *, integer=False):
    if type(value) not in (int, float) or not 0 <= value <= 9007199254740991 or not math.isfinite(value):
        return None
    if integer and int(value) != value:
        return None
    return int(value) if integer else value


def _date(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _candidate(path: Path):
    if not runs._is_safe_run_dir(path):
        return None
    try:
        metadata = runs._procedure_json(path, "run_meta.json") or {}
        scenario = runs._procedure_json(path, "scenario_meta.json") or {}
        if runs._is_sealed_run(path) or metadata.get("runner_kind") not in {"scripted", "rules"}:
            return None
    except HTTPException:
        # An unreadable classification must not expose a sealed execution.
        return None
    identifier = "rules-audit-v1" if metadata["runner_kind"] == "rules" else metadata.get("script_id")
    if not isinstance(identifier, str):
        return None
    sid = scenario.get("scenario_id")
    scenario_id = str(sid) if type(sid) in (str, int) and 0 < len(str(sid)) <= 128 else None
    network = metadata.get("target_network")
    target = f"S{runs._normalized_scenario_id(scenario_id)}" if scenario_id is not None else network
    return {"path": path, "metadata": metadata, "identifier": identifier,
            "scenario": f"S{runs._normalized_scenario_id(scenario_id)}" if scenario_id is not None else None,
            "target": target if isinstance(target, str) else None,
            "diagnostic": identifier == "smoke-v1"}


def summarize(candidate: dict) -> dict:
    path, metadata = candidate["path"], candidate["metadata"]
    identifier = candidate["identifier"]
    try:
        title = get_procedure(identifier)["title"]
    except ValueError:
        title = identifier
    item = {
        "id": path.name, "runner_kind": metadata["runner_kind"],
        "procedure": {"id": identifier, "title": title, "version": None},
        "diagnostic": candidate["diagnostic"], "scenario": candidate["scenario"],
        "target": candidate["target"], "status": runs._run_status(path),
        "started_at": metadata.get("started_at"), "duration_s": None,
        "duration_scope": None, "tool_calls": None, "tool_errors": None,
        "observations": None, "coverage": "unavailable", "available": False,
        "evaluation": {"status": "not_applicable" if candidate["diagnostic"] else "not_evaluated",
                       "reason": "offline_diagnostic" if candidate["diagnostic"] else
                       "scenario_not_recorded" if candidate["scenario"] is None else "reference_comparison_not_recorded"},
    }
    try:
        usage = runs._procedure_json(path, "cost_summary.json") or {}
        start, end = _date(metadata.get("started_at")), _date(metadata.get("finished_at"))
        if start is not None and end is not None and end >= start:
            item.update(duration_s=round((end - start).total_seconds(), 3), duration_scope="total")
        elif _number(usage.get("wall_clock_duration_s")) is not None:
            item.update(duration_s=usage["wall_clock_duration_s"], duration_scope="tools")
        item["tool_calls"] = _number(metadata.get("total_tool_calls"), integer=True)
        if item["tool_calls"] is None:
            item["tool_calls"] = _number(usage.get("total_tool_calls"), integer=True)
        item["tool_errors"] = _number(usage.get("total_tool_errors"), integer=True)
        if metadata["runner_kind"] == "scripted":
            data = runs.get_procedure_results(path.name)
            if not data["available"]:
                return item
            results = data["results"]
            item["procedure"] = data["procedure"]
            item["available"] = True
            if candidate["diagnostic"]:
                item["coverage"] = "diagnostic"
            else:
                item["observations"] = {"hosts": len(results["hosts"]),
                    "services": sum(len(host["services"]) for host in results["hosts"]),
                    "inspected_hosts": results["counts"].get("inspected_hosts")}
                coverage = results["coverage"]
                if results["status"] in {"pending", "waiting", "running"}:
                    item["coverage"] = "running"
                elif coverage.get("partial") or results["status"] != "completed":
                    item["coverage"] = "partial"
                else:
                    item["coverage"] = "collected"
        else:
            # Do not read declaration counts as confirmations. The selected-run
            # proof endpoint performs the expensive evidence projection instead.
            progress = runs._procedure_json(path, "procedure_progress.json")
            if progress is not None:
                from src.agent.procedure_progress import RUN_STATUSES
                if (type(progress.get("schema_version")) is not int or progress.get("schema_version") != 1
                        or progress.get("runner_kind") != "rules"
                        or progress.get("status") not in RUN_STATUSES
                        or type(progress.get("controls_complete")) not in (bool, type(None))):
                    raise HTTPException(status_code=422, detail="Invalid procedure progress")
                runs._validate_procedure_steps(progress.get("steps"))
                item["procedure"] = runs._archived_procedure(progress.get("procedure"), identifier)
                item["available"] = True
                item["coverage"] = ("running" if progress["status"] in {"pending", "waiting", "running"}
                    else "checked" if progress.get("controls_complete") is True else "partial")
        return item
    except (HTTPException, OSError, ValueError, TypeError, KeyError, RecursionError):
        item.update(available=False, observations=None, coverage="unavailable")
        return item


def execution_summary(run_id: str) -> dict:
    path = runs._resolve_run_dir(run_id)
    candidate = _candidate(path)
    if candidate is None:
        raise HTTPException(status_code=404, detail="Public automation execution not found")
    return summarize(candidate)


def execution_page(*, procedure_id: str | None, target: str | None,
                   include_diagnostics: bool, offset: int, limit: int) -> dict:
    candidates = []
    if runs.OUTPUT_DIR.exists():
        for path in sorted(runs.OUTPUT_DIR.iterdir(), reverse=True):
            candidate = _candidate(path)
            if candidate is not None and (include_diagnostics or not candidate["diagnostic"]):
                candidates.append(candidate)
    procedures = sorted({item["identifier"] for item in candidates})
    targets = sorted({item["target"] for item in candidates if item["target"] is not None})
    filtered = [item for item in candidates if
                (not procedure_id or item["identifier"] == procedure_id)
                and (not target or item["target"] == target)]
    return {"schema_version": 1, "items": [summarize(item) for item in filtered[offset:offset + limit]],
            "total": len(filtered), "offset": offset, "limit": limit,
            "procedures": procedures, "targets": targets}
