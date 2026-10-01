"""Read-only activity across the three co-located LANCE instances.

Only fixed loopback peers are queried, never addresses supplied by a client.
No credentials, run artifacts, event logs or database contents are forwarded.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import os
from typing import Literal

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field
import requests

from src.api.routes import pipeline

router = APIRouter()
INSTANCES = {"main": 8501, "dev-1": 8502, "dev-2": 8503}


class Activity(BaseModel):
    instance: str = Field(max_length=64)
    state: Literal["idle", "running", "waiting", "stopping", "deploying", "teardown", "unavailable"]
    scenario_id: str | None = Field(default=None, max_length=160)
    model: str | None = Field(default=None, max_length=256)
    phase: int = Field(default=0, ge=0, le=6)
    started_at: str | None = Field(default=None, max_length=64)


def snapshot() -> Activity:
    with pipeline._state_lock:
        state = dict(pipeline._state)
    busy = bool(state.get("running") or state.get("teardown_running"))
    activity = "idle"
    if busy:
        if state.get("lab_waiting"):
            activity = "waiting"
        elif state.get("stopping"):
            activity = "stopping"
        elif state.get("teardown_running"):
            activity = "teardown"
        elif state.get("deploy_status") == "deploying":
            activity = "deploying"
        else:
            activity = "running"
    teardown = state.get("teardown_running")
    scenario = state.get("teardown_scenario_id") if teardown else state.get("scenario_id")
    return Activity(
        instance=os.environ.get("LANCE_INSTANCE", "standalone"),
        state=activity,
        scenario_id=str(scenario) if busy and scenario is not None else None,
        model=state.get("model") if busy and not teardown else None,
        phase=state.get("phase", 0) if busy and not teardown else 0,
        started_at=state.get("started_at") if busy and not teardown else None,
    )


@router.get("/local", response_model=Activity)
def local_activity(response: Response):
    response.headers["Cache-Control"] = "no-store"
    return snapshot()


def _peer(instance: str, port: int) -> Activity:
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(f"http://127.0.0.1:{port}/api/activity/local",
                                   timeout=(0.5, 1), allow_redirects=False)
            if response.status_code != 200:
                raise ValueError("Peer is unavailable")
            activity = Activity.model_validate(response.json())
            if activity.instance != instance:
                raise ValueError("Unexpected peer identity")
            return activity
    except (requests.RequestException, ValueError):
        return Activity(instance=instance, state="unavailable")


@router.get("")
def shared_activity(response: Response):
    response.headers["Cache-Control"] = "no-store"
    local = snapshot()
    items = {local.instance: local}
    enabled = local.instance in INSTANCES
    if enabled:
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = {name: pool.submit(_peer, name, port)
                       for name, port in INSTANCES.items() if name != local.instance}
            items.update({name: task.result() for name, task in pending.items()})
    return {
        "current": local.instance,
        "enabled": enabled,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "instances": [{**items[name].model_dump(), "port": port}
                      for name, port in (INSTANCES.items() if enabled else [(local.instance, None)])],
    }
