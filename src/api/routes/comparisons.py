"""Public comparison records; launches use the common pipeline coordinator."""
import json
import math
import re

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from src.benchmark import policy_pair_runner as pairs

router = APIRouter()
PAIR_ID = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}_[a-f0-9]{12}\Z")
MAX_RECORD_BYTES = 8 * 1024 * 1024


def record(identifier):
    if not PAIR_ID.fullmatch(identifier):
        raise HTTPException(404, "Comparaison introuvable.")
    directory = pairs.OUTPUT / identifier
    path = directory / "pair.json"
    if directory.is_symlink() or path.is_symlink() or not path.is_file() or directory.resolve().parent != pairs.OUTPUT.resolve():
        raise HTTPException(404, "Comparaison introuvable.")
    if path.stat().st_size > MAX_RECORD_BYTES:
        raise HTTPException(413, "Le résultat dépasse la limite de lecture.")
    try:
        def reject(value):
            raise ValueError("Invalid number")
        def finite(value):
            number = float(value)
            if not math.isfinite(number):
                raise ValueError("Non-finite number")
            return number
        value = json.loads(path.read_text(), parse_constant=reject, parse_float=finite)
        if (not isinstance(value, dict) or value.get("id") != identifier
                or type(value.get("schema_version")) is not int or value.get("schema_version") != 1):
            raise ValueError("Invalid comparison")
        # Records are controller-authored. A tampered sealed marker fails closed.
        pairs.public_spec(value["scenario"]["id"])
    except Exception as exc:
        raise HTTPException(422, "Résultat de comparaison illisible ou scénario non public.") from exc
    if value.get("status") in {"pending", "running"}:
        from src.api.routes.pipeline import get_status
        active = get_status()
        if not active["running"] or active.get("comparison_id") != identifier:
            value.update(status="incomplete", interrupted=True,
                         error="Le suivi de cette comparaison a été interrompu. Vérifiez le laboratoire et les traces avant un nouveau lancement.")
    return value, path


@router.get("/options")
def options():
    from src.api.routes.scenarios import list_scenarios
    scenarios = []
    for item in list_scenarios()["scenarios"]:
        if item.get("sealed"):
            continue
        try:
            spec = pairs.public_spec(item["id"])
            scenarios.append({"id": spec["scenario_id"], "name": spec["name"],
                              "target_network": spec["target_network"], "devices": len(spec["devices"])})
        except (ValueError, KeyError, OSError, TypeError):
            continue
    return {"scenarios": scenarios, "runtime": pairs.runtime_readiness(),
            "scope": "analysis-verification", "profile": "full", "workers": 1}


@router.get("")
def list_pairs(offset: int = Query(0, ge=0), limit: int = Query(10, ge=1, le=50)):
    items = []
    for directory in sorted(pairs.OUTPUT.glob("*"), reverse=True):
        try:
            data, _ = record(directory.name)
        except HTTPException:
            continue
        items.append({key: data.get(key) for key in ("id", "status", "started_at", "scenario", "config")}
                     | {"comparable": data.get("comparison", {}).get("comparable") if data.get("comparison") else None})
    return {"items": items[offset:offset + limit], "total": len(items), "offset": offset, "limit": limit}


@router.get("/{identifier}/download")
def download(identifier: str):
    _, path = record(identifier)
    return FileResponse(path, media_type="application/json", filename=f"comparaison-{identifier}.json")


@router.get("/{identifier}")
def get_pair(identifier: str):
    return record(identifier)[0]
