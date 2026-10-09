"""In-process coordination of one dashboard run and its event stream.

The HTTP route owns request validation; workers own execution.  This object owns
the shared run state, stream queue and cancellation signal.  State is passed in
by the route for compatibility with existing dashboard consumers.
"""
from __future__ import annotations

import asyncio
import threading
from datetime import datetime
from typing import Any


class RunCoordinator:
    MAX_RECENT_EVENTS = 200

    def __init__(self, lock: threading.Lock):
        self.lock = lock

    def begin(
        self,
        state: dict[str, Any],
        *,
        loop: asyncio.AbstractEventLoop,
        runner_kind: str,
        scenario_id: str | None,
        model: str | None,
        execution_profile: str | None,
        execution_profile_policy: str | None,
    ) -> None:
        with self.lock:
            if state["running"]:
                raise RuntimeError("Pipeline already running or stopping")
            if state["teardown_running"]:
                raise RuntimeError("Scenario teardown is still running")
            state.update({
                "running": True,
                "lab_waiting": False,
                "stopping": False,
                "phase": 0,
                "phase_name": "",
                "cost": 0.0,
                "run_dir": None,
                "run_status": None,
                "queue": asyncio.Queue(),
                "loop": loop,
                "stop_event": threading.Event(),
                "runner_kind": runner_kind,
                "scenario_id": scenario_id,
                "model": model,
                "execution_profile": execution_profile,
                "execution_profile_policy": execution_profile_policy,
                "started_at": datetime.now().isoformat(),
                "phases_done": [],
                "current_devices": [],
                "devices_done": [],
                "deploy_status": None,
                "recent_events": [],
            })

    def request_stop(self, state: dict[str, Any]) -> bool:
        with self.lock:
            if not state["running"]:
                return False
            event = state.get("stop_event")
            if event:
                event.set()
            state["stopping"] = True
        return True

    def finish(self, state: dict[str, Any]) -> None:
        with self.lock:
            # Keep the terminal marker bound to this run's stream. A new start
            # may replace state["queue"] immediately after running becomes false.
            loop, queue = state.get("loop"), state.get("queue")
            state["running"] = False
            state["lab_waiting"] = False
            state["stopping"] = False
        if loop and queue:
            loop.call_soon_threadsafe(queue.put_nowait, {"type": "__done__"})

    def begin_teardown(
        self, state: dict[str, Any], *, scenario_id: str, loop: asyncio.AbstractEventLoop
    ) -> None:
        with self.lock:
            if state["running"]:
                raise RuntimeError("Pipeline is running or stopping — wait for it to finish before teardown")
            if state["teardown_running"]:
                raise RuntimeError("Scenario teardown is already running")
            state["teardown_running"] = True
            state["teardown_scenario_id"] = scenario_id
            # A completed run may leave __done__ in its old queue.  Manual
            # teardown gets a fresh stream so teardown_done cannot be lost.
            state["queue"] = asyncio.Queue()
            state["loop"] = loop

    def finish_teardown(self, state: dict[str, Any]) -> None:
        with self.lock:
            state["teardown_running"] = False
            state["lab_waiting"] = False

    @staticmethod
    def enqueue(state: dict[str, Any], event: dict) -> None:
        loop, queue = state.get("loop"), state.get("queue")
        if loop and queue:
            loop.call_soon_threadsafe(queue.put_nowait, event)

    def lab_event(self, state: dict[str, Any], event: dict, *, publish: bool = False) -> None:
        if event.get("type") in {"lab_waiting", "lab_acquired"}:
            state["lab_waiting"] = event["type"] == "lab_waiting"
            state["phase_name"] = "En attente du laboratoire" if state["lab_waiting"] else ""
            if publish:
                self.enqueue(state, event)

    def publish(self, state: dict[str, Any], event: dict, *, track_progress: bool = True) -> None:
        self.enqueue(state, event)
        event_type = event.get("type")
        if event_type not in {"__done__", "ping", "text_chunk"}:
            recent = state.setdefault("recent_events", [])
            recent.append(event)
            if len(recent) > self.MAX_RECENT_EVENTS:
                del recent[:-self.MAX_RECENT_EVENTS]
        if not track_progress:
            return
        if event_type == "phase_start":
            state["phase"] = event.get("phase", state.get("phase", 0))
            state["phase_name"] = event.get("agent", "")
            state["current_devices"] = []
            state["devices_done"] = []
        elif event_type == "phase_done":
            cost = event.get("cost_usd", 0.0)
            state["cost"] = state.get("cost", 0.0) + cost
            state.setdefault("phases_done", []).append({
                "phase": event.get("phase"),
                "name": event.get("agent", ""),
                "cost": cost,
                "duration_s": event.get("duration_s", 0),
            })
        elif event_type == "device_start":
            device = event.get("device_id", "")
            if device and device not in state.setdefault("current_devices", []):
                state["current_devices"].append(device)
        elif event_type == "device_done":
            device = event.get("device_id", "")
            if device and device not in state.setdefault("devices_done", []):
                state["devices_done"].append(device)
        elif event_type == "deploy_start":
            state["deploy_status"] = "deploying"
        elif event_type == "deploy_done":
            state["deploy_status"] = "deployed" if event.get("success") else "failed"
        elif event_type in {"inject_done", "verify_done"} and not event.get("success"):
            state["deploy_status"] = "failed"
        elif event_type in {"pipeline_done", "runner_done"}:
            state["run_dir"] = event.get("run_dir", state.get("run_dir"))
            state["cost"] = event.get("total_cost_usd", state.get("cost", 0.0))
            if event.get("status") is not None:
                state["run_status"] = event["status"]
        elif event_type == "error":
            state["run_status"] = "failed"

    def status(self, state: dict[str, Any]) -> dict[str, Any]:
        return {
            "running": state["running"],
            "lab_waiting": state.get("lab_waiting", False),
            "stopping": state.get("stopping", False),
            "teardown_running": state.get("teardown_running", False),
            "phase": state["phase"],
            "phase_name": state.get("phase_name", ""),
            "cost": round(state["cost"], 4),
            "runner_kind": state.get("runner_kind", "lance"),
            "scenario_id": state.get("scenario_id"),
            "model": state.get("model"),
            "execution_profile": state.get("execution_profile"),
            "execution_profile_policy": state.get("execution_profile_policy"),
            "started_at": state.get("started_at"),
            "deploy_status": state.get("deploy_status"),
            "phases_done": state.get("phases_done", []),
            "current_devices": state.get("current_devices", []),
            "devices_done": state.get("devices_done", []),
            "run_dir": state["run_dir"],
            "run_status": state.get("run_status"),
            "recent_events": state.get("recent_events", []),
        }
